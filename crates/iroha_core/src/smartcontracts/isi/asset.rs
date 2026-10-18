//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.
use super::prelude::*;
use iroha_data_model::{
    asset::definition::ConfidentialPolicyMode,
    fastpq::{TransferDeltaTranscript, TransferSmtWitness, normalized_numeric_to_u64},
    isi::error::{
        AssetTransferAdmissionError, InstructionExecutionError, MathError, Mismatch, TypeError,
    },
    prelude::*,
    query::error::FindError,
};
use iroha_model_base::name::Name;
use iroha_telemetry::metrics;
/// ISI module contains all instructions related to assets:
/// - minting/burning assets
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use super::*;
    use crate::{
        privacy_state::{PrivacyPublicReserveOwnerV1, privacy_public_reserve_owner_v1},
        smartcontracts::isi::account_admission::ensure_receiving_account,
        state::{WorldTransaction, retail_daily_limit_state as retail_state},
    };
    use iroha_crypto::Hash;
    use iroha_data_model::{
        asset::{
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, ASSET_TRANSFER_CONTROL_METADATA_KEY,
            AssetBalancePolicy, AssetIssuerUsagePolicyV1, AssetSubjectBindingV1,
            AssetTransferControlRecord, AssetTransferControlStoreV1, AssetTransferControlWindow,
            AssetTransferLimit, AssetTransferUsageBucket, DOMAIN_ASSET_USAGE_POLICY_METADATA_KEY,
            DomainAssetUsagePolicyV1, RetailDailyLimitPolicyV1, RetailDailyUsageKeyV1,
            RetailIdentityCommitmentV1, RetailMonetaryPurposeV1,
            validate_asset_transfer_availability_reason,
        },
        events::data::prelude::{
            AccountEvent, AssetBatchTransferLegStatus, AssetBatchTransferOutcome,
            AssetBatchTransferRejection, AssetBatchTransferRejectionCode, AssetEvent,
            AssetTransferred, MetadataChanged,
        },
        isi::{
            RemoveAssetKeyValue, SetAssetHoldingLimit, SetAssetKeyValue,
            SetAssetTransferAvailability, SetAssetTransferBlacklist, SetAssetTransferControl,
            error::MintabilityError,
        },
        nexus::{CapabilityRequest, ManifestVerdict},
        privacy::{PrivacyStatementDigestV1, PrivacyValueBalanceDirectionV1},
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::NumericSpec;
    use iroha_primitives::{
        json::Json,
        numeric::{Numeric, Quantity},
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::LazyLock,
    };
    use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time as WallClockTime};
    // Use elided lifetimes to avoid single-use lifetime warnings in this inherent impl.
    impl WorldTransaction<'_, '_> {
        /// Decrease a numeric asset balance; removes the asset entry if it reaches zero.
        /// Does not emit events; callers remain responsible for event emission.
        #[cfg(test)]
        fn withdraw_numeric_asset(
            &mut self,
            network_id: &iroha_data_model::NetworkId,
            id: &AssetId,
            amount: &Quantity,
        ) -> Result<(), Error> {
            let (resolved_id, candidate) =
                self.precheck_numeric_asset_debit(network_id, id, amount)?;
            self.apply_prechecked_numeric_asset_debit_exact(&resolved_id, candidate)
        }
        /// Retain the original debit calculation after every source and reserve check.
        fn precheck_numeric_asset_debit(
            &mut self,
            network_id: &iroha_data_model::NetworkId,
            id: &AssetId,
            amount: &Quantity,
        ) -> Result<(AssetId, Quantity), Error> {
            let resolved_id = self.resolve_asset_id_for_current_scope(id)?;
            if privacy_public_reserve_owner_v1(&self.privacy_commitments, &resolved_id)
                .map_err(|message| InstructionExecutionError::InvariantViolation(message.into()))?
                .is_some()
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "governed privacy public reserve cannot be burned".into(),
                ));
            }
            crate::retail_fee::settle_balance(self, &resolved_id)?;
            if self
                .game_custody_by_account
                .get(resolved_id.account())
                .is_some()
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "native game custody requires an exact game movement capability".into(),
                ));
            }
            let spec = self.asset_definition(resolved_id.definition())?.spec();
            assert_numeric_spec_with(amount.as_numeric(), spec)?;
            if fx_registry_references_escrow_asset(self.parameters.get(), network_id, &resolved_id)?
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "FX corridor escrow can only be debited by the sealed native FX settlement or owner-refund path"
                        .into(),
                )
                .into());
            }
            if crate::smartcontracts::isi::sorafs_reserve::is_reserve_custody_asset(
                self,
                &resolved_id,
            )? {
                return Err(InstructionExecutionError::InvariantViolation(
                    "SoraFS reserve custody can only be debited by a verified native reserve withdrawal"
                        .into(),
                )
                    .into());
            }
            ensure_not_kagemusha_reserve_source(self, &resolved_id)?;
            let quantity = self
                .assets
                .get(&resolved_id)
                .ok_or_else(|| FindError::Asset(resolved_id.clone().into()))?
                .as_ref()
                .clone();
            assert_numeric_spec_with(quantity.as_numeric(), spec)?;
            let candidate = quantity
                .checked_sub(amount)
                .map_err(|_| MathError::NotEnoughQuantity)?;
            assert_numeric_spec_with(candidate.as_numeric(), spec)?;
            crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
                self,
                &resolved_id,
                &candidate,
            )
            .map_err(|error| self.attempt_error_to_instruction_error(error))?;
            crate::smartcontracts::isi::sorafs_moderation::ensure_moderation_bond_reserve_after_debit(
                self,
                &resolved_id,
                &candidate,
            )?;
            Ok((resolved_id, candidate))
        }
        /// Consume the original checked debit without recomputing its arithmetic.
        fn apply_prechecked_numeric_asset_debit_exact(
            &mut self,
            resolved_id: &AssetId,
            candidate: Quantity,
        ) -> Result<(), Error> {
            self.quantity_mutation_observation.changed();
            if candidate.is_zero() {
                assert!(self.remove_asset_and_metadata(resolved_id).is_some());
            } else {
                self.assign_quantity_balance_exact(resolved_id, candidate)?;
            }
            crate::retail_fee::observe_balance(self, resolved_id)?;
            Ok(())
        }
        /// Validate an exact-id numeric transfer and compute its complete balance transcript.
        ///
        /// This is read-only; both ids must already be canonicalized for their intended scopes.
        #[cfg(test)]
        pub(crate) fn precheck_numeric_asset_transfer_delta_exact(
            &self,
            source_id: &AssetId,
            destination_id: &AssetId,
            amount: &Quantity,
        ) -> Result<TransferDeltaTranscript, Error> {
            self.precheck_numeric_asset_transfer_delta_exact_with_control_policy(
                source_id,
                destination_id,
                amount,
                NumericAssetTransferControlPolicy::Enforce,
            )
        }
        /// Precheck a movement using the controls selected by its verified typed purpose.
        fn precheck_numeric_asset_transfer_delta_exact_with_control_policy(
            &self,
            source_id: &AssetId,
            destination_id: &AssetId,
            amount: &Quantity,
            control_policy: NumericAssetTransferControlPolicy,
        ) -> Result<TransferDeltaTranscript, Error> {
            if source_id.definition() != destination_id.definition() {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "prechecked transfer source definition {} does not match destination definition {}",
                        source_id.definition(),
                        destination_id.definition()
                    )
                    .into(),
                ));
            }
            // Retained protocol debits have the same outbound availability exception
            // as their blacklist/cap exception. Receiver controls remain independent;
            // only finality-owned staking/moderation custody also exempts the credit.
            // Custody, usage, privacy, and scope admission are separate gates.
            let (enforce_debit_controls, enforce_credit_controls) = match control_policy {
                NumericAssetTransferControlPolicy::Enforce => (true, true),
                NumericAssetTransferControlPolicy::OraclePenalty
                | NumericAssetTransferControlPolicy::OracleDisputeResolution
                | NumericAssetTransferControlPolicy::StakingUnbond
                | NumericAssetTransferControlPolicy::GovernanceSlash
                | NumericAssetTransferControlPolicy::GovernanceRestitution
                | NumericAssetTransferControlPolicy::GovernanceUnlock
                | NumericAssetTransferControlPolicy::CitizenshipRelease
                | NumericAssetTransferControlPolicy::BondVaultRelease => (false, true),
                NumericAssetTransferControlPolicy::StakingSlash
                | NumericAssetTransferControlPolicy::ModerationChallengeSettlement => {
                    (false, false)
                }
            };
            if !amount.is_zero() {
                if enforce_debit_controls {
                    self.ensure_numeric_asset_transfer_availability(
                        source_id,
                        amount.clone(),
                        AssetTransferDirection::Outgoing,
                    )?;
                }
                if enforce_credit_controls {
                    self.ensure_numeric_asset_transfer_availability(
                        destination_id,
                        amount.clone(),
                        AssetTransferDirection::Incoming,
                    )?;
                }
            }
            let source_spec = self.asset_definition(source_id.definition())?.spec();
            assert_numeric_spec_with(amount.as_numeric(), source_spec)?;
            let source_current = self
                .assets
                .get(source_id)
                .ok_or_else(|| FindError::Asset(source_id.clone().into()))?
                .as_ref()
                .clone();
            assert_numeric_spec_with(source_current.as_numeric(), source_spec)?;
            let from_balance_after = source_current
                .checked_sub(amount)
                .map_err(|_| MathError::NotEnoughQuantity)?;
            self.account(destination_id.account())?;
            let to_balance_before = if source_id == destination_id {
                from_balance_after.clone()
            } else {
                self.assets
                    .get(destination_id)
                    .map(|value| value.as_ref().clone())
                    .unwrap_or_else(Quantity::zero)
            };
            assert_numeric_spec_with(to_balance_before.as_numeric(), source_spec)?;
            let to_balance_after = to_balance_before
                .checked_add(amount)
                .map_err(|_| MathError::Overflow)?;
            assert_numeric_spec_with(to_balance_after.as_numeric(), source_spec)?;
            let source_after = if source_id == destination_id {
                &to_balance_after
            } else {
                &from_balance_after
            };
            crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
                self,
                source_id,
                source_after,
            )
            .map_err(|error| self.attempt_error_to_instruction_error(error))?;
            if enforce_credit_controls {
                self.ensure_numeric_asset_holding_limit(destination_id, &to_balance_after)?;
            }
            Ok(TransferDeltaTranscript {
                from_account: source_id.account().clone(),
                to_account: destination_id.account().clone(),
                asset_definition: source_id.definition().clone(),
                amount: amount.clone(),
                from_balance_before: source_current,
                from_balance_after,
                to_balance_before,
                to_balance_after,
                from_smt_witness: TransferSmtWitness::default(),
                to_smt_witness: TransferSmtWitness::default(),
            })
        }
        fn apply_prechecked_numeric_asset_transfer_delta_exact(
            &mut self,
            source_id: &AssetId,
            destination_id: &AssetId,
            expected_amount: &Quantity,
            delta: &TransferDeltaTranscript,
            source_policy: NumericAssetTransferSourcePolicy,
        ) -> Result<(), Error> {
            crate::retail_fee::settle_balance(self, source_id)?;
            crate::retail_fee::settle_balance(self, destination_id)?;
            // Custody may change after preparation. Check the original typed purpose
            // again before either balance is mutated.
            let reserve_owner =
                privacy_public_reserve_owner_v1(&self.privacy_commitments, source_id).map_err(
                    |message| InstructionExecutionError::InvariantViolation(message.into()),
                )?;
            ensure_privacy_public_reserve_source_policy_for_owner(reserve_owner, source_policy)?;
            if &delta.amount != expected_amount {
                return Err(InstructionExecutionError::InvariantViolation(
                    "prepared transfer delta amount differs from its authorized amount".into(),
                )
                .into());
            }
            if reserve_owner.is_some() {
                // The public leg of a verified private-pool withdrawal still moves
                // exact transparent units. Rejoin its prepared delta to the live
                // authoritative balances before either side is written.
                let source_balance = self
                    .assets
                    .get(source_id)
                    .ok_or_else(|| FindError::Asset(source_id.clone().into()))?;
                let destination_balance_matches = match self.assets.get(destination_id) {
                    Some(asset) => asset.as_ref() == &delta.to_balance_before,
                    None => delta.to_balance_before.is_zero(),
                };
                if source_id == destination_id
                    || source_id.definition() != destination_id.definition()
                    || &delta.from_account != source_id.account()
                    || &delta.to_account != destination_id.account()
                    || &delta.asset_definition != source_id.definition()
                    || source_balance.as_ref() != &delta.from_balance_before
                    || !destination_balance_matches
                    || !delta
                        .from_balance_after
                        .checked_add_equals(&delta.amount, &delta.from_balance_before)
                    || !delta
                        .to_balance_before
                        .checked_add_equals(&delta.amount, &delta.to_balance_after)
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "governed privacy public reserve delta must conserve exact live balances"
                            .into(),
                    )
                    .into());
                }
            }
            // Reservation-only instructions can change a source's available funds
            // without changing its balance. Recheck at consumption as well as preparation.
            let balance_after = if source_id == destination_id {
                &delta.to_balance_after
            } else {
                &delta.from_balance_after
            };
            crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
                self,
                source_id,
                balance_after,
            )
            .map_err(|error| self.attempt_error_to_instruction_error(error))?;
            if source_id == destination_id {
                self.precheck_quantity_balance_assignment(source_id, &delta.to_balance_after)?;
                self.quantity_mutation_observation.changed();
                self.assign_prechecked_quantity_balance(source_id, delta.to_balance_after.clone());
                if !delta.to_balance_after.is_zero() {
                    self.track_nonzero_asset_holder(destination_id);
                }
                crate::retail_fee::observe_balance(self, source_id)?;
                return Ok(());
            }
            // Repeat all fallible checks before the first write. The original exclusive
            // World transaction retains both keys through the paired infallible writes.
            self.precheck_quantity_balance_assignment(source_id, &delta.from_balance_after)?;
            self.precheck_quantity_balance_assignment(destination_id, &delta.to_balance_after)?;
            self.quantity_mutation_observation.changed();
            if delta.from_balance_after.is_zero() {
                assert!(self.remove_asset_and_metadata(source_id).is_some());
            } else {
                self.assign_prechecked_quantity_balance(
                    source_id,
                    delta.from_balance_after.clone(),
                );
            }
            self.assign_prechecked_quantity_balance(destination_id, delta.to_balance_after.clone());
            if !delta.to_balance_after.is_zero() {
                self.track_nonzero_asset_holder(destination_id);
            }
            crate::retail_fee::observe_balance(self, source_id)?;
            crate::retail_fee::observe_balance(self, destination_id)?;
            Ok(())
        }
        /// Validate a numeric credit after canonicalizing the balance id for the current scope.
        ///
        /// Returns the canonical balance id and its post-credit value without mutating state.
        pub(crate) fn precheck_numeric_asset_credit(
            &self,
            id: &AssetId,
            amount: &Quantity,
        ) -> Result<(AssetId, Quantity), Error> {
            let resolved_id = self.resolve_asset_id_for_current_scope(id)?;
            let candidate = self.precheck_numeric_asset_credit_exact(&resolved_id, amount)?;
            Ok((resolved_id, candidate))
        }
        /// Validate a numeric credit for an already-canonicalized exact balance id.
        ///
        /// Returns the post-credit value without mutating state. Callers using this exact-id
        /// variant must preserve the balance scope selected by the path that produced `id`.
        pub(crate) fn precheck_numeric_asset_credit_exact(
            &self,
            id: &AssetId,
            amount: &Quantity,
        ) -> Result<Quantity, Error> {
            if self.game_custody_by_account.get(id.account()).is_some() {
                return Err(InstructionExecutionError::InvariantViolation(
                    "native game custody accepts only exact native entry funding".into(),
                ));
            }
            self.account(id.account())?;
            let spec = self.asset_definition(id.definition())?.spec();
            assert_numeric_spec_with(amount.as_numeric(), spec)?;
            let current = crate::retail_fee::projected_balance(self, id, self.retail_fee_now_ms)
                .map_err(|error| {
                    self.attempt_error_to_instruction_error(
                        error.map_rejection(InstructionExecutionError::Conversion),
                    )
                })?
                .unwrap_or_else(|| {
                    self.assets
                        .get(id)
                        .map(|value| value.as_ref().clone())
                        .unwrap_or_else(Quantity::zero)
                });
            assert_numeric_spec_with(current.as_numeric(), spec)?;
            let candidate = current
                .checked_add(amount)
                .map_err(|_| MathError::Overflow)?;
            assert_numeric_spec_with(candidate.as_numeric(), spec)?;
            self.ensure_numeric_asset_holding_limit(id, &candidate)?;
            Ok(candidate)
        }
        fn apply_prechecked_numeric_asset_credit_exact(
            &mut self,
            id: &AssetId,
            candidate: Quantity,
        ) -> Result<(), Error> {
            crate::retail_fee::settle_balance(self, id)?;
            self.quantity_mutation_observation.changed();
            let is_nonzero = !candidate.is_zero();
            self.assign_quantity_balance_exact(id, candidate)?;
            if is_nonzero {
                self.track_nonzero_asset_holder(id);
            }
            crate::retail_fee::observe_balance(self, id)?;
            Ok(())
        }
        /// Increase an already-canonicalized exact numeric balance, creating it if missing.
        ///
        /// This validates the complete post-credit balance before mutation and assigns that
        /// precomputed value. It does not emit an `Added` event; callers remain responsible for
        /// balance-change event emission.
        #[cfg(test)]
        fn deposit_numeric_asset_exact(
            &mut self,
            id: &AssetId,
            amount: &Quantity,
        ) -> Result<(), Error> {
            let candidate = self.precheck_numeric_asset_credit_exact(id, amount)?;
            self.apply_prechecked_numeric_asset_credit_exact(id, candidate)
        }
        /// Increase a numeric asset balance, creating it if missing.
        ///
        /// The balance id is canonicalized for the current scope before applying the exact
        /// checked credit. This does not emit an `Added` event; callers remain responsible for
        /// balance-change event emission.
        #[cfg(test)]
        fn deposit_numeric_asset(&mut self, id: &AssetId, amount: &Quantity) -> Result<(), Error> {
            let (resolved_id, candidate) = self.precheck_numeric_asset_credit(id, amount)?;
            self.apply_prechecked_numeric_asset_credit_exact(&resolved_id, candidate)
        }
        fn ensure_numeric_asset_holding_limit(
            &self,
            asset_id: &AssetId,
            candidate: &Quantity,
        ) -> Result<(), Error> {
            let account = self.account(asset_id.account())?;
            let store =
                load_asset_transfer_control_store_from_account(account.id(), account.metadata())?;
            let Some(limit) = store
                .find(asset_id.definition())
                .and_then(|record| record.holding_limit.as_ref())
            else {
                return Ok(());
            };
            if candidate > limit {
                return Err(InstructionExecutionError::AssetTransferAdmission(
                    AssetTransferAdmissionError::HoldingLimitExceeded(
                        format!(
                            "account {} balance for {} would be {}, above {}",
                            asset_id.account(),
                            asset_id.definition(),
                            candidate,
                            limit
                        )
                        .into(),
                    ),
                ));
            }
            Ok(())
        }
        pub(crate) fn ensure_numeric_asset_transfer_availability(
            &self,
            asset_id: &AssetId,
            amount: Quantity,
            direction: AssetTransferDirection,
        ) -> Result<(), Error> {
            if amount.is_zero() {
                return Ok(());
            }
            let account = self.account(asset_id.account())?;
            let store =
                load_asset_transfer_control_store_from_account(account.id(), account.metadata())?;
            let Some(record) = store.find(asset_id.definition()) else {
                return Ok(());
            };
            let enabled = match direction {
                AssetTransferDirection::Incoming => record.incoming_availability.is_enabled(),
                AssetTransferDirection::Outgoing => record.outgoing_availability.is_enabled(),
            };
            if enabled {
                return Ok(());
            }
            let detail = format!(
                "account {} on asset definition {} at availability revision {}",
                asset_id.account(),
                asset_id.definition(),
                record.availability_revision
            )
            .into();
            let admission = match direction {
                AssetTransferDirection::Incoming => {
                    AssetTransferAdmissionError::IncomingDisabled(detail)
                }
                AssetTransferDirection::Outgoing => {
                    AssetTransferAdmissionError::OutgoingDisabled(detail)
                }
            };
            Err(InstructionExecutionError::AssetTransferAdmission(admission).into())
        }
    }
    /// Credit a balance directly for focused state-fixture construction.
    #[cfg(test)]
    pub(crate) fn seed_numeric_asset_balance_for_test(
        world: &mut WorldTransaction<'_, '_>,
        id: &AssetId,
        amount: &Quantity,
    ) -> Result<(), Error> {
        world.deposit_numeric_asset(id, amount)
    }
    /// Credit an already-canonicalized balance id for focused state-fixture construction.
    #[cfg(test)]
    pub(super) fn seed_numeric_asset_balance_exact_for_test(
        world: &mut WorldTransaction<'_, '_>,
        id: &AssetId,
        amount: &Quantity,
    ) -> Result<(), Error> {
        world.deposit_numeric_asset_exact(id, amount)
    }
    /// Debit a balance directly for focused state-fixture construction.
    #[cfg(test)]
    pub(crate) fn debit_numeric_asset_balance_for_test(
        world: &mut WorldTransaction<'_, '_>,
        network_id: &iroha_data_model::NetworkId,
        id: &AssetId,
        amount: &Quantity,
    ) -> Result<(), Error> {
        world.withdraw_numeric_asset(network_id, id, amount)
    }
    /// Replace one balance without policy checks to construct corrupt-state regressions.
    #[cfg(test)]
    pub(crate) fn replace_numeric_asset_balance_for_corruption_test(
        world: &mut WorldTransaction<'_, '_>,
        id: &AssetId,
        value: Quantity,
    ) {
        let asset = world
            .assets
            .get_mut(id)
            .expect("corruption fixture asset must exist");
        **asset = value;
    }
    /// Exercise prepared-transfer freshness without exposing the private movement plan.
    #[cfg(test)]
    pub(super) fn apply_prepared_numeric_transfer_after_source_credit_for_test(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        intervening_credit: Quantity,
    ) -> Result<(), Error> {
        let plan = PreparedNumericTransferPlan::prepare_user(
            state_transaction,
            authority,
            source_id.clone(),
            destination_id,
            amount,
        )?;
        state_transaction
            .world
            .deposit_numeric_asset(&source_id, &intervening_credit)?;
        plan.apply(state_transaction).map(|_| ())
    }
    /// Exercise the consumed movement boundary after a controlled prepare/apply interleave.
    #[cfg(test)]
    pub(super) fn apply_prepared_numeric_movement_for_test(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        before_apply: impl FnOnce(&mut StateTransaction<'_, '_>),
        record_observability: bool,
    ) -> Result<(), Error> {
        let movement = PreparedNumericAssetMovement::prepare(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::SocialSend(vec![0x71]),
            ),
        )?;
        before_apply(state_transaction);
        movement.apply_with_observability(state_transaction, record_observability)
    }
    /// Resolve the typed social-send transcript identity through the private authorization type.
    #[cfg(test)]
    pub(super) fn resolve_social_send_movement_identity_for_test(
        state_transaction: &StateTransaction<'_, '_>,
        authority: &AccountId,
        legs: &[(AssetId, AssetId, Quantity)],
        binding: Vec<u8>,
    ) -> Result<iroha_crypto::Hash, Error> {
        NumericAssetMovementAuthorization::embedded_user(
            authority,
            EmbeddedNumericAssetMovementPurpose::SocialSend(binding),
        )
        .resolve_transcript_identity(state_transaction, legs)
    }
    /// Validate the user transfer route without exposing the internal policy enum.
    #[cfg(test)]
    pub(super) fn validate_user_numeric_asset_transfer_policies_for_test(
        state_transaction: &mut StateTransaction<'_, '_>,
        source_id: &AssetId,
        destination_id: &AssetId,
        amount: &Quantity,
    ) -> Result<(AssetId, AssetId), Error> {
        ensure_numeric_asset_transfer_policies(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetTransferSourcePolicy::User,
        )
    }
    #[derive(Clone, Copy)]
    pub(crate) enum AssetTransferDirection {
        Incoming,
        Outgoing,
    }
    /// Assert that `object` matches the provided `asset_spec`.
    pub(crate) fn assert_numeric_spec_with(
        object: &Numeric,
        asset_spec: NumericSpec,
    ) -> Result<NumericSpec, Error> {
        let object_spec = NumericSpec::fractional(object.scale());
        asset_spec.check(object).map_err(|_| {
            TypeError::from(Mismatch {
                expected: asset_spec,
                actual: object_spec,
            })
        })?;
        Ok(asset_spec)
    }
    fn ensure_transparent_allowed(
        state_transaction: &StateTransaction<'_, '_>,
        asset_def_id: &AssetDefinitionId,
        violation_message: &'static str,
    ) -> Result<(), Error> {
        let policy_mode = state_transaction
            .world
            .asset_definition(asset_def_id)
            .map_err(Error::from)?
            .confidential_policy()
            .effective_mode(state_transaction.block_height());
        if matches!(policy_mode, ConfidentialPolicyMode::ShieldedOnly) {
            return Err(InstructionExecutionError::InvariantViolation(
                violation_message.into(),
            ));
        }
        Ok(())
    }
    fn ensure_not_native_escrow_source(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
    ) -> Result<(), Error> {
        if crate::smartcontracts::isi::escrow::is_native_escrow_custody_asset(
            state_transaction,
            source_id,
        )? {
            return Err(InstructionExecutionError::InvariantViolation(
                "direct debit from native escrow custody account is not allowed; use escrow instructions".into(),
            ));
        }
        if crate::smartcontracts::isi::bond::is_bond_vault_account(
            state_transaction.world(),
            source_id.account(),
        ) {
            return Err(iroha_data_model::bond::BondError::VaultCustody(
                "direct debit from a bond vault is not allowed; use bond instructions".to_owned(),
            )
            .into());
        }
        Ok(())
    }
    static ASSET_ISSUER_POLICY_KEY: LazyLock<Name> = LazyLock::new(|| {
        ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
            .parse()
            .expect("asset issuer usage policy metadata key must be a valid Name")
    });
    static DOMAIN_ASSET_POLICY_KEY: LazyLock<Name> = LazyLock::new(|| {
        DOMAIN_ASSET_USAGE_POLICY_METADATA_KEY
            .parse()
            .expect("domain asset usage policy metadata key must be a valid Name")
    });
    static ASSET_TRANSFER_CONTROL_KEY: LazyLock<Name> = LazyLock::new(|| {
        ASSET_TRANSFER_CONTROL_METADATA_KEY
            .parse()
            .expect("asset transfer control metadata key must be a valid Name")
    });
    /// Decode and validate one account's persisted native transfer-control store.
    pub(crate) fn load_asset_transfer_control_store_from_account(
        account_id: &AccountId,
        metadata: &Metadata,
    ) -> Result<AssetTransferControlStoreV1, Error> {
        let Some(raw) = metadata.get(&*ASSET_TRANSFER_CONTROL_KEY) else {
            return Ok(AssetTransferControlStoreV1::default());
        };
        let store = raw
            .try_into_any_norito::<AssetTransferControlStoreV1>()
            .map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "invalid account metadata `{ASSET_TRANSFER_CONTROL_METADATA_KEY}` on {account_id}: {err}"
                    )
                    .into(),
                )
            })?;
        if store.controls.is_empty() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "invalid account metadata `{ASSET_TRANSFER_CONTROL_METADATA_KEY}` on {account_id}: persisted transfer-control stores must not be empty"
                )
                .into(),
            )
            .into());
        }
        store.validate_canonical().map_err(|err| {
            Error::from(InstructionExecutionError::InvariantViolation(
                format!(
                    "invalid account metadata `{ASSET_TRANSFER_CONTROL_METADATA_KEY}` on {account_id}: {err}"
                )
                .into(),
            ))
        })?;
        Ok(store)
    }
    /// Reject removal of definitions still referenced by native transfer-control state.
    ///
    /// # Errors
    /// Returns an invariant violation for malformed stores or for the first
    /// retained record whose definition belongs to `asset_definition_ids`.
    pub(crate) fn ensure_asset_definitions_not_retained_by_transfer_controls(
        state_transaction: &StateTransaction<'_, '_>,
        asset_definition_ids: &BTreeSet<AssetDefinitionId>,
        removal_target: &str,
    ) -> Result<(), Error> {
        if asset_definition_ids.is_empty() {
            return Ok(());
        }
        for (account_id, account) in state_transaction.world.accounts.iter() {
            if account
                .metadata()
                .get(ASSET_TRANSFER_CONTROL_METADATA_KEY)
                .is_none()
            {
                continue;
            }
            let store =
                load_asset_transfer_control_store_from_account(account_id, account.metadata())?;
            if let Some(record) = store
                .controls
                .iter()
                .find(|record| asset_definition_ids.contains(&record.asset_definition_id))
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot {removal_target}: account {account_id} retains native asset transfer-control state for {}; clear it through dedicated instructions first",
                        record.asset_definition_id
                    )
                    .into(),
                )
                .into());
            }
        }
        Ok(())
    }
    /// Reject asset-definition or domain teardown while any first-release
    /// retail policy, signed binding or DAY usage still refers to a definition.
    /// No owner-governed retirement transition is admitted yet.
    pub(crate) fn ensure_asset_definitions_not_retained_by_retail_daily_limit(
        state_transaction: &StateTransaction<'_, '_>,
        asset_definition_ids: &BTreeSet<AssetDefinitionId>,
        removal_target: &str,
    ) -> Result<(), Error> {
        if asset_definition_ids.is_empty() {
            return Ok(());
        }
        let retained_definition =
            retail_state::retained_definition(state_transaction.world(), asset_definition_ids)
                .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        if let Some(definition) = retained_definition {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("cannot {removal_target}: asset definition {definition} retains retail DAY policy, identity or usage state").into(),
            ).into());
        }
        Ok(())
    }
    /// Reject account teardown before its balance or issuer identity can be
    /// discarded while any governed retail value or trust reference remains.
    pub(crate) fn ensure_account_not_retained_by_retail_daily_limit(
        state_transaction: &StateTransaction<'_, '_>,
        account_id: &AccountId,
    ) -> Result<(), Error> {
        let has_binding_or_issuer =
            retail_state::account_is_retained(state_transaction.world(), account_id)
                .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        let holds_governed_asset = state_transaction
            .world
            .assets_in_account_iter(account_id)
            .try_fold(false, |found, asset| {
                retail_state::has_policy_for_definition(
                    state_transaction.world(),
                    asset.id().definition(),
                )
                .map(|governed| found || governed)
            })
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        if has_binding_or_issuer || holds_governed_asset {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("cannot unregister account {account_id}: retail DAY identity, issuer or governed balance is retained").into(),
            ).into());
        }
        Ok(())
    }
    fn load_asset_transfer_control_store(
        state_transaction: &StateTransaction<'_, '_>,
        account_id: &AccountId,
    ) -> Result<AssetTransferControlStoreV1, Error> {
        let account = state_transaction.world.account(account_id)?;
        load_asset_transfer_control_store_from_account(account.id(), account.metadata())
    }
    fn persist_asset_transfer_control_store(
        state_transaction: &mut StateTransaction<'_, '_>,
        account_id: &AccountId,
        store: &AssetTransferControlStoreV1,
    ) -> Result<(), Error> {
        if !store.controls.is_empty() {
            store.validate_canonical().map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "refusing to persist non-canonical account metadata `{ASSET_TRANSFER_CONTROL_METADATA_KEY}` on {account_id}: {err}"
                    )
                    .into(),
                )
            })?;
        }
        let account = state_transaction.world.account_mut(account_id)?;
        if store.controls.is_empty() {
            if let Some(value) = account.remove(&ASSET_TRANSFER_CONTROL_KEY) {
                state_transaction
                    .world
                    .emit_events(Some(AccountEvent::MetadataRemoved(MetadataChanged {
                        target: account_id.clone(),
                        key: ASSET_TRANSFER_CONTROL_KEY.clone(),
                        value,
                    })));
            }
            return Ok(());
        }
        let value = Json::new(store.clone());
        account.insert(ASSET_TRANSFER_CONTROL_KEY.clone(), value.clone());
        state_transaction
            .world
            .emit_events(Some(AccountEvent::MetadataInserted(MetadataChanged {
                target: account_id.clone(),
                key: ASSET_TRANSFER_CONTROL_KEY.clone(),
                value,
            })));
        Ok(())
    }
    #[derive(Clone, Copy)]
    enum TransferControlCapability {
        Availability,
        DailyLimit,
        HoldingLimit,
        OwnerOnly,
    }
    fn ensure_asset_transfer_control_authority(
        state_transaction: &StateTransaction<'_, '_>,
        authority: &AccountId,
        account_id: &AccountId,
        asset_definition_id: &AssetDefinitionId,
        capability: TransferControlCapability,
    ) -> Result<(), Error> {
        let owner = state_transaction
            .world
            .asset_definition(asset_definition_id)?
            .owned_by()
            .clone();
        if state_transaction._curr_block.is_genesis() {
            return Ok(());
        }
        if owner == *authority {
            return Ok(());
        }
        let required: Option<Permission> = match capability {
            TransferControlCapability::Availability => Some(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability {
                    account: account_id.clone(),
                    asset_definition: asset_definition_id.clone(),
                }
                .into(),
            ),
            TransferControlCapability::DailyLimit => {
                let account = state_transaction.world.account(account_id)?;
                let account_label = account.label().ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        format!(
                            "transfer-control target account {account_id} has no canonical on-chain alias label"
                        )
                        .into(),
                    )
                })?;
                if crate::sns::resolve_active_account_alias(
                    &state_transaction.world,
                    &state_transaction.nexus.dataspace_catalog,
                    account_label,
                    state_transaction.block_unix_timestamp_ms(),
                )
                .map_err(|error| {
                    InstructionExecutionError::InvariantViolation(error.to_string().into())
                })?
                .as_ref()
                    != Some(account_id)
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "transfer-control target account {account_id} has no strictly active alias binding"
                        )
                        .into(),
                    )
                    .into());
                }
                let account_domain = account_label.domain.clone().ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        format!(
                            "transfer-control target account {account_id} has no canonical on-chain domain label"
                        )
                        .into(),
                    )
                })?;
                Some(
                    iroha_executor_data_model::permission::asset::CanSetAssetTransferDailyLimit {
                        asset_definition: asset_definition_id.clone(),
                        account_domain,
                        account_dataspace: account_label.dataspace,
                    }
                    .into(),
                )
            }
            TransferControlCapability::HoldingLimit => Some(
                iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit {
                    account: account_id.clone(),
                    asset_definition: asset_definition_id.clone(),
                }
                .into(),
            ),
            TransferControlCapability::OwnerOnly => None,
        };
        if required.as_ref().is_some_and(|required| {
            state_transaction
                .world
                .account_permissions_iter(authority)
                .is_ok_and(|permissions| permissions.into_iter().any(|actual| actual == required))
                || state_transaction
                    .world
                    .account_roles_iter(authority)
                    .any(|role_id| {
                        state_transaction
                            .world
                            .roles
                            .get(role_id)
                            .is_some_and(|role| role.permissions().any(|actual| actual == required))
                    })
        }) {
            return Ok(());
        }
        let required_scope = match capability {
            TransferControlCapability::Availability | TransferControlCapability::HoldingLimit => {
                "exact account-and-asset"
            }
            TransferControlCapability::DailyLimit => "account-domain-and-dataspace",
            TransferControlCapability::OwnerOnly => "asset-owner",
        };
        Err(InstructionExecutionError::InvariantViolation(
            format!(
                "account {authority} lacks the required {required_scope} transfer-control permission for {account_id} and {asset_definition_id}; owner is {owner}"
            )
            .into(),
        ))
    }
    fn canonicalize_asset_transfer_limits(
        limits: Vec<AssetTransferLimit>,
    ) -> Result<Vec<AssetTransferLimit>, Error> {
        let mut by_window = BTreeMap::<AssetTransferControlWindow, Option<Quantity>>::new();
        for limit in limits {
            if by_window.insert(limit.window, limit.cap_amount).is_some() {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!("duplicate asset transfer limit window {}", limit.window).into(),
                ));
            }
        }
        Ok(by_window
            .into_iter()
            .filter_map(|(window, cap_amount)| {
                cap_amount.map(|cap_amount| AssetTransferLimit {
                    window,
                    cap_amount: Some(cap_amount),
                })
            })
            .collect())
    }
    fn bucket_start_ms(window: AssetTransferControlWindow, now_ms: u64) -> Result<u64, Error> {
        let now = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
            .map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!("invalid block timestamp for asset transfer controls: {err}").into(),
                )
            })?;
        let date = now.date();
        let start_date = match window {
            AssetTransferControlWindow::Day => date,
            AssetTransferControlWindow::Week => {
                let offset = i64::from(date.weekday().number_days_from_monday());
                date.checked_sub(time::Duration::days(offset))
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "failed to compute UTC week bucket start".into(),
                        )
                    })?
            }
            AssetTransferControlWindow::Month => Date::from_calendar_date(
                date.year(),
                Month::try_from(u8::from(date.month())).map_err(|err| {
                    InstructionExecutionError::InvariantViolation(
                        format!("failed to compute UTC month bucket start: {err}").into(),
                    )
                })?,
                1,
            )
            .map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!("failed to compute UTC month bucket start: {err}").into(),
                )
            })?,
        };
        let start = PrimitiveDateTime::new(start_date, WallClockTime::MIDNIGHT).assume_utc();
        u64::try_from(start.unix_timestamp_nanos() / 1_000_000).map_err(|_| {
            InstructionExecutionError::InvariantViolation(
                "bucket start timestamp exceeds supported range".into(),
            )
        })
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct PreparedRetailDailyUsageUpdate {
        policy: RetailDailyLimitPolicyV1,
        pub(super) key: RetailDailyUsageKeyV1,
        before: Option<Quantity>,
        pub(super) after: Quantity,
    }
    /// An installed policy governs every scope of its definition. A wrong or
    /// global balance scope cannot make the policy disappear from admission.
    fn installed_retail_policy_for_source(
        state_transaction: &StateTransaction<'_, '_>,
        source: &AssetId,
    ) -> Result<Option<RetailDailyLimitPolicyV1>, Error> {
        let governed_definition =
            retail_state::has_policy_for_definition(state_transaction.world(), source.definition())
                .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        if !governed_definition {
            return Ok(None);
        }
        let AssetBalanceScope::Dataspace(dataspace) = source.scope() else {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail-governed asset debit requires its exact physical dataspace balance".into(),
            ));
        };
        let policy = retail_state::policy_for_exact(
            state_transaction.world(),
            source.definition(),
            *dataspace,
        )
        .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?
        .ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "retail-governed asset debit has no policy for its balance dataspace".into(),
            )
        })?;
        let definition = state_transaction
            .world
            .asset_definition(source.definition())?;
        if &policy.asset_definition_id != source.definition()
            || policy.physical_dataspace != *dataspace
            || definition.balance_scope_policy() != AssetBalancePolicy::DataspaceRestricted
            || definition.spec().scale() != Some(2)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail DAY policy does not bind the exact restricted asset and physical dataspace"
                    .into(),
            ));
        }
        policy
            .validate_shape()
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        let activation = retail_state::activation_for_exact(state_transaction.world(), &policy)
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        if state_transaction.block_unix_timestamp_ms() < activation.enforce_from_day_start_ms {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail DAY governed debits remain closed until the next UTC day after activation"
                    .into(),
            ));
        }
        // The exact owner-signed exception roster has not yet been given an
        // executable typed-purpose admission path. Reject it until that path exists.
        if !policy.institutional_exceptions.is_empty() {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail DAY institutional exception admission is not implemented".into(),
            ));
        }
        Ok(Some(policy))
    }
    /// Until the owner specifies a typed monetary/protocol purpose, an installed
    /// retail policy may only move value through the checked transfer kernel.
    fn reject_uncovered_retail_asset_mutation(
        state_transaction: &StateTransaction<'_, '_>,
        asset_id: &AssetId,
        operation: &str,
    ) -> Result<(), Error> {
        if installed_retail_policy_for_source(state_transaction, asset_id)?.is_some() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("retail-governed asset {operation} has no admitted typed purpose").into(),
            ));
        }
        Ok(())
    }
    fn bound_retail_identity(
        state_transaction: &StateTransaction<'_, '_>,
        policy: &RetailDailyLimitPolicyV1,
        account: &AccountId,
    ) -> Result<RetailIdentityCommitmentV1, Error> {
        let attestation = retail_state::identity_for_exact(
            state_transaction.world(),
            &policy.asset_definition_id,
            policy.physical_dataspace,
            account,
        )
        .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?
        .ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                format!("retail-governed account {account} has no issuer-signed identity binding")
                    .into(),
            )
        })?;
        attestation
            .verify_for(policy, account)
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))
    }
    /// Prepare one same-identity debit without mutating usage. The signed
    /// account binding and DAY bucket are checked again immediately before apply.
    pub(super) fn prepare_retail_daily_usage_update(
        state_transaction: &StateTransaction<'_, '_>,
        source: &AssetId,
        destination: &AssetId,
        amount: &Quantity,
        source_policy: NumericAssetTransferSourcePolicy,
    ) -> Result<Option<PreparedRetailDailyUsageUpdate>, Error> {
        let Some(policy) = installed_retail_policy_for_source(state_transaction, source)? else {
            return Ok(None);
        };
        if source.scope() != destination.scope() {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail-governed debit cannot change physical balance scope".into(),
            ));
        }
        let source_is_reserve = source.account() == &policy.reserve_account;
        let destination_is_reserve = destination.account() == &policy.reserve_account;
        match source_policy {
            NumericAssetTransferSourcePolicy::RetailMonetary(
                RetailMonetaryPurposeV1::CreditRetail,
            ) if source_is_reserve && !destination_is_reserve => {
                bound_retail_identity(state_transaction, &policy, destination.account())?;
                return Ok(None);
            }
            NumericAssetTransferSourcePolicy::RetailMonetary(
                RetailMonetaryPurposeV1::DefundRetail,
            ) if !source_is_reserve && destination_is_reserve => {}
            NumericAssetTransferSourcePolicy::RetailMonetary(_) => {
                return Err(InstructionExecutionError::InvariantViolation(
                    "retail monetary purpose has an invalid reserve and retail direction".into(),
                ));
            }
            _ if source_is_reserve || destination_is_reserve => {
                return Err(InstructionExecutionError::InvariantViolation(
                    "retail monetary reserve cannot use a generic asset transfer".into(),
                ));
            }
            _ => {}
        }
        let identity = bound_retail_identity(state_transaction, &policy, source.account())?;
        if !destination_is_reserve {
            bound_retail_identity(state_transaction, &policy, destination.account())?;
        }
        let key = RetailDailyUsageKeyV1 {
            asset_definition_id: policy.asset_definition_id.clone(),
            physical_dataspace: policy.physical_dataspace,
            identity,
            utc_day_start_ms: bucket_start_ms(
                AssetTransferControlWindow::Day,
                state_transaction.block_unix_timestamp_ms(),
            )?,
        };
        let before = retail_state::usage_for_exact(state_transaction.world(), &key)
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        let after = before
            .clone()
            .unwrap_or_else(Quantity::zero)
            .checked_add(amount)
            .map_err(|_| MathError::Overflow)?;
        if after > policy.daily_cap {
            return Err(InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::PolicyRejected(
                    "identity-wide retail DAY cap exceeded".into(),
                ),
            ));
        }
        Ok(Some(PreparedRetailDailyUsageUpdate {
            policy,
            key,
            before,
            after,
        }))
    }
    fn active_control_record(
        state_transaction: &StateTransaction<'_, '_>,
        account_id: &AccountId,
        asset_definition_id: &AssetDefinitionId,
    ) -> Result<Option<AssetTransferControlRecord>, Error> {
        let store = load_asset_transfer_control_store(state_transaction, account_id)?;
        Ok(store.find(asset_definition_id).cloned())
    }
    /// Persist the active outbound transfer-control record for an account.
    pub(crate) fn update_control_record(
        state_transaction: &mut StateTransaction<'_, '_>,
        account_id: &AccountId,
        record: AssetTransferControlRecord,
    ) -> Result<(), Error> {
        // Freeze/unfreeze must not change availability retroactively at an unmaterialized boundary.
        crate::retail_fee::settle_balance(
            &mut state_transaction.world,
            &AssetId::new(record.asset_definition_id.clone(), account_id.clone()),
        )?;
        let mut store = load_asset_transfer_control_store(state_transaction, account_id)?;
        if record.is_empty() {
            store.remove(&record.asset_definition_id);
        } else {
            store.upsert(record);
        }
        persist_asset_transfer_control_store(state_transaction, account_id, &store)
    }
    /// Validate outbound transfer controls and return the record update to persist on success.
    pub(crate) fn prepare_outbound_asset_transfer_control_update(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
        amount: &Quantity,
    ) -> Result<Option<AssetTransferControlRecord>, Error> {
        let Some(mut record) = active_control_record(
            state_transaction,
            source_id.account(),
            source_id.definition(),
        )?
        else {
            return Ok(None);
        };
        if record.blacklisted {
            return Err(InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::Blacklisted(
                    format!(
                        "account {} on asset definition {}",
                        source_id.account(),
                        source_id.definition()
                    )
                    .into(),
                ),
            ));
        }
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let mut current_usages =
            BTreeMap::<AssetTransferControlWindow, AssetTransferUsageBucket>::new();
        for usage in record.usages.iter().cloned() {
            current_usages.insert(usage.window, usage);
        }
        let mut next_usages = Vec::new();
        for limit in record.limits.iter().filter_map(|limit| {
            limit
                .cap_amount
                .clone()
                .map(|cap_amount| (limit.window, cap_amount))
        }) {
            let (window, cap_amount) = limit;
            let bucket_start = bucket_start_ms(window, now_ms)?;
            let spent_before = current_usages
                .remove(&window)
                .filter(|usage| usage.bucket_start_ms == bucket_start)
                .map(|usage| usage.spent_amount)
                .unwrap_or_else(Quantity::zero);
            let spent_after = spent_before
                .checked_add(amount)
                .map_err(|_| MathError::Overflow)?;
            if spent_after > cap_amount {
                return Err(InstructionExecutionError::AssetTransferAdmission(
                    AssetTransferAdmissionError::PolicyRejected(
                        format!(
                            "outbound transfer cap exceeded for {} on {} {} bucket: {} + {} > {}",
                            source_id.account(),
                            source_id.definition(),
                            window.as_str(),
                            spent_before,
                            amount,
                            cap_amount
                        )
                        .into(),
                    ),
                ));
            }
            next_usages.push(AssetTransferUsageBucket {
                window,
                bucket_start_ms: bucket_start,
                spent_amount: spent_after,
            });
        }
        record.usages = next_usages;
        record.updated_at_ms = Some(now_ms);
        Ok(Some(record))
    }
    fn load_issuer_usage_policy(
        definition: &AssetDefinition,
    ) -> Result<AssetIssuerUsagePolicyV1, Error> {
        let Some(raw) = definition.metadata().get(&*ASSET_ISSUER_POLICY_KEY) else {
            return Ok(AssetIssuerUsagePolicyV1::default());
        };
        raw.try_into_any_norito::<AssetIssuerUsagePolicyV1>()
            .map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "invalid metadata `{}` on asset definition {}: {err}",
                        ASSET_ISSUER_USAGE_POLICY_METADATA_KEY,
                        definition.id()
                    )
                    .into(),
                )
            })
    }
    fn load_domain_usage_policy(domain: &Domain) -> Result<DomainAssetUsagePolicyV1, Error> {
        let Some(raw) = domain.metadata().get(&*DOMAIN_ASSET_POLICY_KEY) else {
            return Ok(DomainAssetUsagePolicyV1::default());
        };
        raw.try_into_any_norito::<DomainAssetUsagePolicyV1>()
            .map_err(|err| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "invalid metadata `{}` on domain {}: {err}",
                        DOMAIN_ASSET_USAGE_POLICY_METADATA_KEY,
                        domain.id()
                    )
                    .into(),
                )
            })
    }
    fn ensure_domain_binding_allows_asset(
        state_transaction: &StateTransaction<'_, '_>,
        definition_id: &AssetDefinitionId,
        subject: &AccountId,
        binding: &AssetSubjectBindingV1,
    ) -> Result<(), Error> {
        if binding.allowed_domains.is_empty() {
            return Ok(());
        }
        let mut alias_domains = BTreeSet::new();
        for alias in state_transaction.world.bound_account_aliases(subject) {
            let resolved = crate::sns::resolve_active_account_alias(
                &state_transaction.world,
                &state_transaction.nexus.dataspace_catalog,
                &alias,
                state_transaction.block_unix_timestamp_ms(),
            )
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(error.to_string().into())
            })?;
            if resolved.as_ref() == Some(subject)
                && let Some(domain_id) = alias
                    .domain_id(&state_transaction.nexus.dataspace_catalog)
                    .map_err(|error| {
                        InstructionExecutionError::InvariantViolation(error.to_string().into())
                    })?
            {
                alias_domains.insert(domain_id);
            }
        }
        let matching_domains = binding
            .allowed_domains
            .iter()
            .filter(|domain_id| alias_domains.contains(*domain_id));
        let mut matched_any = false;
        let mut denied_domains = Vec::new();
        for domain_id in matching_domains {
            matched_any = true;
            let domain = state_transaction
                .world
                .domain(domain_id)
                .map_err(Error::from)?;
            let domain_policy = load_domain_usage_policy(domain)?;
            if domain_policy.allows(definition_id) {
                return Ok(());
            }
            denied_domains.push(domain_id.to_string());
        }
        if !matched_any {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "asset subject binding requires account {subject} to hold an alias in at least one allowed domain for asset definition {definition_id}"
                )
                .into(),
            ));
        }
        Err(InstructionExecutionError::InvariantViolation(
            format!(
                "domain policy for matched domains [{}] denies usage of asset definition {definition_id}",
                denied_domains.join(", ")
            )
            .into(),
        ))
    }
    fn ensure_dataspace_binding_allows_asset(
        state_transaction: &StateTransaction<'_, '_>,
        definition_id: &AssetDefinitionId,
        subject: &AccountId,
        amount: Option<&Quantity>,
        dataspace: Option<DataSpaceId>,
        binding: &AssetSubjectBindingV1,
    ) -> Result<(), Error> {
        if binding.allowed_dataspaces.is_empty() {
            return Ok(());
        }
        let current_dataspace = dataspace
            .or(state_transaction.current_dataspace_id)
            .or(state_transaction.world.current_dataspace_id)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "asset subject binding for {subject} requires dataspace context for {definition_id}"
                    )
                    .into(),
                )
            })?;
        if !binding.allows_dataspace(current_dataspace) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "asset subject binding for {subject} does not allow dataspace {}",
                    current_dataspace.as_u64()
                )
                .into(),
            ));
        }
        let account = state_transaction
            .world
            .account(subject)
            .map_err(Error::from)?;
        let uaid = account.value().uaid().copied().ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                format!(
                    "asset subject binding for {subject} requires a UAID for dataspace policy checks"
                )
                .into(),
            )
        })?;
        let manifest_record = state_transaction
            .world
            .space_directory_manifests
            .get(&uaid)
            .and_then(|set| set.get(&current_dataspace))
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "missing Space Directory manifest for UAID {uaid} in dataspace {}",
                        current_dataspace.as_u64()
                    )
                    .into(),
                )
            })?;
        if !manifest_record.is_active() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "inactive Space Directory manifest for UAID {uaid} in dataspace {}",
                    current_dataspace.as_u64()
                )
                .into(),
            ));
        }
        let request = CapabilityRequest::new(
            current_dataspace,
            None,
            None,
            Some(definition_id),
            None,
            amount.cloned(),
            state_transaction.block_height(),
        );
        match manifest_record.manifest.evaluate(&request) {
            ManifestVerdict::Allowed(_) => Ok(()),
            ManifestVerdict::Denied(reason) => Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "dataspace policy denied asset definition {definition_id} for account {subject} in dataspace {}: {reason:?}",
                    current_dataspace.as_u64()
                )
                .into(),
            )),
        }
    }
    fn ensure_subject_usage_policy(
        state_transaction: &StateTransaction<'_, '_>,
        definition_id: &AssetDefinitionId,
        policy: &AssetIssuerUsagePolicyV1,
        subject: &AccountId,
        amount: Option<&Quantity>,
        dataspace: Option<DataSpaceId>,
    ) -> Result<(), Error> {
        let binding = policy.binding_for(subject);
        if policy.require_subject_binding && binding.is_none() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "asset definition {definition_id} requires explicit subject binding for account {subject}"
                )
                .into(),
            ));
        }
        let Some(binding) = binding else {
            return Ok(());
        };
        ensure_domain_binding_allows_asset(state_transaction, definition_id, subject, binding)?;
        ensure_dataspace_binding_allows_asset(
            state_transaction,
            definition_id,
            subject,
            amount,
            dataspace,
            binding,
        )?;
        Ok(())
    }
    #[allow(single_use_lifetimes)]
    fn ensure_usage_policy_for_accounts<'a>(
        state_transaction: &StateTransaction<'_, '_>,
        definition_id: &AssetDefinitionId,
        participants: impl IntoIterator<Item = (&'a AccountId, Option<DataSpaceId>)>,
        amount: Option<&Quantity>,
    ) -> Result<(), Error> {
        let definition = state_transaction
            .world
            .asset_definition(definition_id)
            .map_err(Error::from)?;
        let policy = load_issuer_usage_policy(&definition)?;
        for (subject, dataspace) in participants {
            ensure_subject_usage_policy(
                state_transaction,
                definition_id,
                &policy,
                subject,
                amount,
                dataspace,
            )?;
        }
        Ok(())
    }
    fn asset_id_dataspace_hint(
        state_transaction: &StateTransaction<'_, '_>,
        asset_id: &AssetId,
    ) -> Option<DataSpaceId> {
        match asset_id.scope() {
            iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace) => Some(*dataspace),
            iroha_data_model::asset::AssetBalanceScope::Global => state_transaction
                .current_dataspace_id
                .or(state_transaction.world.current_dataspace_id),
        }
    }
    pub(crate) fn unique_account_dataspace_hint(
        state_transaction: &StateTransaction<'_, '_>,
        account_id: &AccountId,
    ) -> Result<Option<DataSpaceId>, Error> {
        state_transaction.world.account(account_id)?;
        let mut linked_dataspaces = BTreeSet::new();
        for alias in state_transaction.world.bound_account_aliases(account_id) {
            let resolved = crate::sns::resolve_active_account_alias(
                &state_transaction.world,
                &state_transaction.nexus.dataspace_catalog,
                &alias,
                state_transaction.block_unix_timestamp_ms(),
            )
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(error.to_string().into())
            })?;
            if resolved.as_ref() == Some(account_id) && alias.dataspace != DataSpaceId::UNIVERSAL {
                linked_dataspaces.insert(alias.dataspace);
            }
        }
        if let Ok(account) = state_transaction.world.account(account_id)
            && let Some(uaid) = account.as_ref().uaid().copied()
            && let Some(bindings) = state_transaction.world.uaid_dataspaces.get(&uaid)
        {
            linked_dataspaces.extend(bindings.iter().filter_map(|(dataspace, accounts)| {
                (*dataspace != DataSpaceId::UNIVERSAL && accounts.contains(account_id))
                    .then_some(*dataspace)
            }));
        }
        let mut dataspaces = linked_dataspaces.into_iter();
        let first = dataspaces.next();
        if let (Some(first), Some(second)) = (first, dataspaces.next()) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "account {account_id} is bound to multiple dataspaces ({} and {}); use an explicit dataspace-scoped asset id for transparent cross-dataspace asset use",
                    first.as_u64(),
                    second.as_u64()
                )
                .into(),
            ));
        }
        Ok(first)
    }
    fn transfer_source_dataspace_hint(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
    ) -> Result<Option<DataSpaceId>, Error> {
        let route_dataspace = state_transaction
            .current_dataspace_id
            .or(state_transaction.world.current_dataspace_id);
        if let iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace) = source_id.scope()
        {
            if let Some(route_dataspace) = route_dataspace
                && route_dataspace != DataSpaceId::UNIVERSAL
                && route_dataspace != *dataspace
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "source asset scope must match the non-universal execution dataspace".into(),
                ));
            }
            return Ok(Some(*dataspace));
        }
        if route_dataspace.is_some_and(|dataspace| dataspace != DataSpaceId::UNIVERSAL) {
            return Ok(route_dataspace);
        }
        if let Some(home_dataspace) =
            bare_restricted_asset_home_dataspace_hint(state_transaction, source_id)?
        {
            return Ok(Some(home_dataspace));
        }
        unique_account_dataspace_hint(state_transaction, source_id.account())
            .map(|hint| hint.or(route_dataspace))
    }
    fn transfer_destination_dataspace_hint(
        state_transaction: &StateTransaction<'_, '_>,
        destination_id: &AssetId,
    ) -> Result<Option<DataSpaceId>, Error> {
        let route_dataspace = state_transaction
            .current_dataspace_id
            .or(state_transaction.world.current_dataspace_id);
        if let iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace) =
            destination_id.scope()
        {
            if let Some(route_dataspace) = route_dataspace
                && route_dataspace != DataSpaceId::UNIVERSAL
                && route_dataspace != *dataspace
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "destination asset scope must match the non-universal execution dataspace"
                        .into(),
                ));
            }
            return Ok(Some(*dataspace));
        }
        let hint = unique_account_dataspace_hint(state_transaction, destination_id.account())?;
        if let (Some(route_dataspace), Some(destination_dataspace)) = (route_dataspace, hint)
            && route_dataspace != DataSpaceId::UNIVERSAL
            && route_dataspace != destination_dataspace
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "destination account scope must match the non-universal execution dataspace".into(),
            ));
        }
        Ok(hint.or(route_dataspace))
    }
    include!("asset/public_balance_scope.rs");
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum NumericAssetTransferSourcePolicy {
        User,
        RetailMonetary(RetailMonetaryPurposeV1),
        PrivacyPoolBridge(PrivacyPublicReserveOwnerV1),
        GameSessionFunding,
        FxEscrowDeposit,
        NativeEscrowCustody,
        SorafsReserveCustody,
        KagemushaReserveCustody,
        FxEscrowRelease,
        FeeSponsorCustody,
        OracleReward,
        OraclePenalty,
        OracleDisputeResolution,
        SocialReward,
        SocialEscrow,
        StakingUnbond,
        StakingSlash,
        ModerationChallengeRefund,
        ModerationChallengeSlash,
        GovernanceSlash,
        GovernanceRestitution,
        GovernanceUnlock,
        CitizenshipRelease,
        SccpEscrowLock,
        SccpEscrowRelease,
        BondVaultFunding,
        BondVaultCustody,
    }
    impl NumericAssetTransferSourcePolicy {
        const fn is_moderation_challenge_settlement(self) -> bool {
            matches!(
                self,
                Self::ModerationChallengeRefund | Self::ModerationChallengeSlash
            )
        }

        const fn uses_protocol_custody_precheck(self) -> bool {
            matches!(
                self,
                Self::StakingSlash
                    | Self::ModerationChallengeRefund
                    | Self::ModerationChallengeSlash
            )
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NumericAssetTransferScopePolicy {
        Ambient,
        ExplicitBilateral,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NumericAssetTransferAuthorityPolicy {
        UserSource,
        ProtocolAuthorized,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NumericAssetTransferControlPolicy {
        Enforce,
        OraclePenalty,
        OracleDisputeResolution,
        StakingUnbond,
        StakingSlash,
        ModerationChallengeSettlement,
        GovernanceSlash,
        GovernanceRestitution,
        GovernanceUnlock,
        CitizenshipRelease,
        /// Key-less bond vault paying an entitled holder: no outbound controls on the vault.
        BondVaultRelease,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NumericAssetDestinationAdmissionPolicy {
        ImplicitReceive,
        ExistingAccount,
    }
    fn ensure_user_numeric_asset_source_authority(
        state_transaction: &StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: &AssetId,
    ) -> Result<(), Error> {
        if source_id.account() == authority {
            return Ok(());
        }
        let exact_asset: Permission =
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: source_id.clone(),
            }
            .into();
        let exact_definition: Permission =
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                asset_definition: source_id.definition().clone(),
            }
            .into();
        let has_required_permission =
            |actual: &Permission| actual == &exact_asset || actual == &exact_definition;
        let has_direct = state_transaction
            .world
            .account_permissions_iter(authority)
            .is_ok_and(|permissions| permissions.into_iter().any(has_required_permission));
        let has_role = state_transaction
            .world
            .account_roles_iter(authority)
            .any(|role_id| {
                state_transaction
                    .world
                    .roles
                    .get(role_id)
                    .is_some_and(|role| role.permissions().any(has_required_permission))
            });
        if has_direct || has_role {
            return Ok(());
        }
        Err(InstructionExecutionError::InvariantViolation(
            format!(
                "account {authority} lacks authority to transfer source asset {source_id}; require source ownership or an exact CanTransferAsset/CanTransferAssetWithDefinition permission"
            )
            .into(),
        )
        .into())
    }
    fn fx_registry_references_escrow_asset(
        parameters: &Parameters,
        network_id: &iroha_data_model::NetworkId,
        asset_id: &AssetId,
    ) -> Result<bool, Error> {
        use iroha_data_model::isi::settlement::FxCorridorPolicyRegistry;
        let Some(custom) = parameters
            .custom()
            .get(&FxCorridorPolicyRegistry::parameter_id())
        else {
            return Ok(false);
        };
        let registry = FxCorridorPolicyRegistry::from_custom_parameter(custom)
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("invalid retained FX corridor registry: {error}").into(),
                )
            })?
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "retained FX corridor registry has the wrong parameter identity".into(),
                )
            })?;
        Ok(registry.policies.values().any(|policy| {
            iroha_data_model::isi::settlement::fx_corridor_escrow_account_id_v1(
                network_id,
                &policy.corridor_id(),
                &policy.destination_asset_definition_id,
            ) == *asset_id.account()
        }))
    }
    /// Return whether an asset balance belongs to a governed native FX reserve account.
    pub(crate) fn is_fx_corridor_escrow_asset(
        state_transaction: &StateTransaction<'_, '_>,
        asset_id: &AssetId,
    ) -> Result<bool, Error> {
        fx_registry_references_escrow_asset(
            state_transaction.world.parameters.get(),
            &state_transaction.network_id,
            asset_id,
        )
    }
    /// Return whether an account is a deterministic native FX reserve.
    pub(crate) fn is_fx_corridor_escrow_account(
        state_transaction: &StateTransaction<'_, '_>,
        account_id: &AccountId,
    ) -> Result<bool, Error> {
        use iroha_data_model::isi::settlement::FxCorridorPolicyRegistry;
        let Some(custom) = state_transaction
            .world
            .parameters
            .get()
            .custom()
            .get(&FxCorridorPolicyRegistry::parameter_id())
        else {
            return Ok(false);
        };
        let registry = FxCorridorPolicyRegistry::from_custom_parameter(custom)
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("invalid retained FX corridor registry: {error}").into(),
                )
            })?
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "retained FX corridor registry has the wrong parameter identity".into(),
                )
            })?;
        Ok(registry.policies.values().any(|policy| {
            iroha_data_model::isi::settlement::fx_corridor_escrow_account_id_v1(
                &state_transaction.network_id,
                &policy.corridor_id(),
                &policy.destination_asset_definition_id,
            ) == *account_id
        }))
    }
    /// Return whether an asset definition is retained by a native FX corridor.
    pub(crate) fn is_fx_corridor_asset_definition(
        state_transaction: &StateTransaction<'_, '_>,
        definition_id: &AssetDefinitionId,
    ) -> Result<bool, Error> {
        use iroha_data_model::isi::settlement::FxCorridorPolicyRegistry;
        let Some(custom) = state_transaction
            .world
            .parameters
            .get()
            .custom()
            .get(&FxCorridorPolicyRegistry::parameter_id())
        else {
            return Ok(false);
        };
        let registry = FxCorridorPolicyRegistry::from_custom_parameter(custom)
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("invalid retained FX corridor registry: {error}").into(),
                )
            })?
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "retained FX corridor registry has the wrong parameter identity".into(),
                )
            })?;
        Ok(registry.policies.values().any(|policy| {
            policy.source_asset_definition_id == *definition_id
                || policy.destination_asset_definition_id == *definition_id
        }))
    }
    fn ensure_not_fx_corridor_escrow_source(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
    ) -> Result<(), Error> {
        if is_fx_corridor_escrow_asset(state_transaction, source_id)? {
            return Err(InstructionExecutionError::InvariantViolation(
                "FX corridor escrow can only be debited by the sealed native FX settlement or owner-refund path"
                    .into(),
            )
            .into());
        }
        Ok(())
    }
    fn ensure_not_fx_corridor_escrow_destination(
        state_transaction: &StateTransaction<'_, '_>,
        destination_id: &AssetId,
    ) -> Result<(), Error> {
        if is_fx_corridor_escrow_asset(state_transaction, destination_id)? {
            return Err(InstructionExecutionError::InvariantViolation(
                "FX corridor escrow can only be credited by its exact owner-funded instruction"
                    .into(),
            )
            .into());
        }
        Ok(())
    }
    pub(crate) fn kagemusha_custody_error(error: crate::kagemusha_wallet_v1::Error) -> Error {
        InstructionExecutionError::InvariantViolation(
            format!("KAGEMUSHA reserve custody: {error}").into(),
        )
    }
    fn ensure_not_kagemusha_reserve_source(
        world: &impl WorldReadOnly,
        source: &AssetId,
    ) -> Result<(), Error> {
        if crate::kagemusha_wallet_v1::custody::reserve_registration(world, source)
            .map_err(kagemusha_custody_error)?
            .is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA reserve requires a verified native payout capability".into(),
            ));
        }
        Ok(())
    }
    fn ensure_not_sorafs_reserve_custody_source(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
    ) -> Result<(), Error> {
        if crate::smartcontracts::isi::sorafs_reserve::is_reserve_custody_asset(
            state_transaction.world(),
            source_id,
        )? {
            return Err(InstructionExecutionError::InvariantViolation(
                "SoraFS reserve custody can only be debited by a verified native reserve withdrawal"
                    .into(),
            )
                .into());
        }
        Ok(())
    }
    /// Return whether `account` is the escrow of a registered SCCP route (`specs/sccp.md` §4.15).
    fn is_sccp_escrow_account(
        state_transaction: &StateTransaction<'_, '_>,
        account: &AccountId,
    ) -> bool {
        crate::smartcontracts::isi::sccp::escrow::is_escrow(state_transaction.world(), account)
    }
    /// Reject a debit of an SCCP route escrow outside the SCCP release paths (§4.15).
    fn ensure_not_sccp_escrow_source(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
    ) -> Result<(), Error> {
        if is_sccp_escrow_account(state_transaction, source_id.account()) {
            return Err(InstructionExecutionError::InvariantViolation(
                "SCCP route escrow can only be debited by an SCCP inbound release, outbound refund or Parliament-enacted stranded release"
                    .into(),
            ));
        }
        Ok(())
    }
    /// Reject a credit of a bond vault outside `FundBondCashflow` (`specs/finance/bond_ops.md`).
    fn ensure_not_bond_vault_destination(
        state_transaction: &StateTransaction<'_, '_>,
        destination_id: &AssetId,
    ) -> Result<(), Error> {
        if crate::smartcontracts::isi::bond::is_bond_vault_account(
            state_transaction.world(),
            destination_id.account(),
        ) {
            return Err(iroha_data_model::bond::BondError::VaultCustody(
                "a bond vault can only be credited by FundBondCashflow".to_owned(),
            )
            .into());
        }
        Ok(())
    }
    /// Reject a credit of an SCCP route escrow outside `RecordSccpMessage` (§4.15).
    fn ensure_not_sccp_escrow_destination(
        state_transaction: &StateTransaction<'_, '_>,
        destination_id: &AssetId,
    ) -> Result<(), Error> {
        if is_sccp_escrow_account(state_transaction, destination_id.account()) {
            return Err(InstructionExecutionError::InvariantViolation(
                "SCCP route escrow can only be credited by RecordSccpMessage".into(),
            ));
        }
        Ok(())
    }
    #[derive(Debug)]
    enum NumericMovementDebitAuthorization {
        ExactUser(AccountId),
        InitialGenesisBootstrap(AccountId),
        Protocol,
    }
    #[derive(Debug)]
    enum NumericMovementTranscriptRequirement {
        TransactionRequired(&'static str),
        TransactionOrTypedPurpose { tag: &'static str, binding: Vec<u8> },
    }
    /// Closed set of voluntary embedded numeric movement purposes.
    #[derive(Debug)]
    enum EmbeddedNumericAssetMovementPurpose {
        /// Charge the payer while admitting an implicit account.
        AccountAdmissionFee(Vec<u8>),
        /// Reserve an Oracle dispute bond.
        OracleDisputeBond(Vec<u8>),
        /// Reserve a public moderation challenge bond.
        ModerationChallengeBond(Vec<u8>),
        /// Send value through the social incentive flow.
        SocialSend(Vec<u8>),
        /// Bond stake for a public-lane validator or delegator.
        StakingBond {
            /// Exact stake owner.
            source_authority: AccountId,
            /// Whether this is the genesis validator bootstrap exception.
            genesis: bool,
            /// Exact lane/validator/staker binding.
            binding: Vec<u8>,
        },
        /// Lock a governance voting bond.
        GovernanceBond(Vec<u8>),
        /// Lock a citizenship bond.
        CitizenshipBond {
            /// Exact citizen whose prefunded balance supplies the bond.
            source_authority: AccountId,
            /// Whether the signed initial genesis is seeding the citizen record.
            initial_genesis: bool,
            /// Exact citizen and amount binding.
            binding: Vec<u8>,
        },
        /// Fund a sponsor-owned fee vault from signed initial genesis.
        InitialGenesisFeeSponsorFunding {
            /// Exact sponsor whose prefunded balance supplies the vault.
            source_authority: AccountId,
            /// Exact program, source, custody destination, and amount binding.
            binding: Vec<u8>,
        },
        /// Fund a native escrow retained record.
        NativeEscrow(Vec<u8>),
        /// Fund one original signed-root AMX transfer escrow.
        NativeAmx(Vec<u8>),
        /// Fund an exact native racing seat.
        GameSession(Vec<u8>),
        /// Fund a VPN lease retained record.
        VpnLease(Vec<u8>),
        /// Fund one exact owner-funded native FX reserve.
        FxCorridorEscrowDeposit(Vec<u8>),
        /// Charge one exact SNS auto-renewal quote.
        SnsAutoRenewal(Vec<u8>),
        /// Lock one exact SCCP outbound amount into its route escrow.
        SccpEscrowLock(Vec<u8>),
        /// Fund one exact recorded bond cash flow into its vault.
        BondFunding(Vec<u8>),
    }
    /// Closed set of retained-state protocol movement purposes.
    #[derive(Debug)]
    enum RetainedNumericAssetMovementPurpose {
        /// Pay an Oracle reward from the configured pool.
        OracleReward(Vec<u8>),
        /// Apply a mandatory Oracle penalty.
        OraclePenalty(Vec<u8>),
        /// Resolve the exact retained Oracle dispute.
        OracleDisputeResolution(Vec<u8>),
        /// Refund an exact retained moderation challenge bond.
        ModerationChallengeRefund(Vec<u8>),
        /// Slash an exact retained moderation challenge bond.
        ModerationChallengeSlash(Vec<u8>),
        /// Pay a social reward from the configured pool.
        SocialReward(Vec<u8>),
        /// Release or refund a retained social escrow.
        SocialEscrow(Vec<u8>),
        /// Release a matured staking unbond.
        StakingUnbond(Vec<u8>),
        /// Apply a mandatory retained staking slash.
        StakingSlash(Vec<u8>),
        /// Slash a retained governance lock.
        GovernanceSlash(Vec<u8>),
        /// Restitute a retained governance slash.
        GovernanceRestitution(Vec<u8>),
        /// Unlock a retained governance bond.
        GovernanceUnlock(Vec<u8>),
        /// Release a retained citizenship bond.
        CitizenshipRelease(Vec<u8>),
        /// Move value according to an exact native escrow record.
        NativeEscrow(Vec<u8>),
        /// Apply or release only an authenticated global AMX decision.
        NativeAmx(Vec<u8>),
        /// Settle or refund an exact native racing liability.
        GameSession(Vec<u8>),
        /// Move value according to an exact VPN lease record.
        VpnLease(Vec<u8>),
        /// Release one exact approved SoraFS reserve withdrawal.
        SorafsReserve(Vec<u8>),
        /// Move value from verified fee-sponsor custody.
        FeeSponsor(Vec<u8>),
        /// Refund one exact inactive native FX reserve to its immutable owner.
        FxCorridorEscrowRefund(Vec<u8>),
        /// Move one exact transparent balance effect authorized by a native privacy proof.
        PrivacyPublicBridge(Vec<u8>),
        /// Deposit an exact native pool effect into its public reserve.
        PrivacyPoolDeposit(Vec<u8>),
        /// Release an exact native pool effect from its governed public reserve.
        PrivacyPoolBridge(PrivacyPublicReserveOwnerV1, Vec<u8>),
        /// Release one exact SCCP inbound, refund or stranded amount from its route escrow.
        SccpEscrowRelease(Vec<u8>),
        /// Pay a holder or return a residual from an exact bond vault record.
        BondVault(Vec<u8>),
    }
    /// One-shot authorization and deterministic execution context for a numeric movement.
    ///
    /// This value is intentionally neither [`Clone`] nor [`Copy`]. Callers must choose one of
    /// the closed typed purposes above; there is no caller-selectable `skip_controls` flag.
    #[derive(Debug)]
    struct NumericAssetMovementAuthorization {
        debit: NumericMovementDebitAuthorization,
        transcript_authority: AccountId,
        transcript: NumericMovementTranscriptRequirement,
        source_policy: NumericAssetTransferSourcePolicy,
        control_policy: NumericAssetTransferControlPolicy,
        destination_admission: NumericAssetDestinationAdmissionPolicy,
    }
    /// Measure before output allocation and debit the logical frame quota, including its delimiter.
    /// Independent owned-frame oracle; production contexts stream borrowed values.
    #[cfg(test)]
    fn bounded_quantity_frame<T: norito::NoritoSerialize>(
        value: &T,
        remaining: &mut u64,
    ) -> Option<Vec<u8>> {
        let length = u64::try_from(norito::canonical_frame_len(value).ok()?)
            .ok()?
            .checked_add(8)?;
        *remaining = remaining.checked_sub(length)?;
        norito::encode_canonical(value).ok()
    }
    /// Private projections of the existing canonical authorization frames.
    mod quantity_authorization {
        include!("asset/quantity_authorization.rs");
    }
    impl NumericAssetMovementAuthorization {
        /// Reject a purpose that would carry registered bond units into protocol custody
        /// the bond kernel does not attribute (`specs/finance/bond_ops.md` §4).
        fn ensure_admits_bond_units(
            &self,
            state_transaction: &StateTransaction<'_, '_>,
            definition: &AssetDefinitionId,
        ) -> Result<(), Error> {
            let purpose = match &self.transcript {
                NumericMovementTranscriptRequirement::TransactionRequired(_) => None,
                NumericMovementTranscriptRequirement::TransactionOrTypedPurpose { tag, .. } => {
                    Some(*tag)
                }
            };
            crate::smartcontracts::isi::bond::ensure_bond_custody_supported(
                state_transaction.world(),
                definition,
                purpose,
            )
        }
        fn transaction_user(authority: &AccountId, context: &'static str) -> Self {
            Self {
                debit: NumericMovementDebitAuthorization::ExactUser(authority.clone()),
                transcript_authority: authority.clone(),
                transcript: NumericMovementTranscriptRequirement::TransactionRequired(context),
                source_policy: NumericAssetTransferSourcePolicy::User,
                control_policy: NumericAssetTransferControlPolicy::Enforce,
                destination_admission: NumericAssetDestinationAdmissionPolicy::ImplicitReceive,
            }
        }
        fn retail_monetary(authority: &AccountId, purpose: RetailMonetaryPurposeV1) -> Self {
            let mut authorization = Self::transaction_user(authority, "retail monetary movement");
            authorization.source_policy = NumericAssetTransferSourcePolicy::RetailMonetary(purpose);
            authorization.destination_admission =
                NumericAssetDestinationAdmissionPolicy::ExistingAccount;
            authorization
        }
        /// Bind an embedded voluntary debit to an exact user or initial-genesis authority.
        fn embedded_user(
            submitting_authority: &AccountId,
            purpose: EmbeddedNumericAssetMovementPurpose,
        ) -> Self {
            let is_fx_deposit = matches!(
                &purpose,
                EmbeddedNumericAssetMovementPurpose::FxCorridorEscrowDeposit(_)
            );
            let is_game_funding = matches!(
                &purpose,
                EmbeddedNumericAssetMovementPurpose::GameSession(_)
            );
            let is_sccp_lock = matches!(
                &purpose,
                EmbeddedNumericAssetMovementPurpose::SccpEscrowLock(_)
            );
            let is_bond_funding = matches!(
                &purpose,
                EmbeddedNumericAssetMovementPurpose::BondFunding(_)
            );
            let (debit, tag, binding) = match purpose {
                EmbeddedNumericAssetMovementPurpose::AccountAdmissionFee(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "account-admission-fee",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::OracleDisputeBond(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "oracle-dispute-bond",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::ModerationChallengeBond(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "moderation-challenge-bond",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::SocialSend(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "social-send",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::StakingBond {
                    source_authority,
                    genesis,
                    binding,
                } => (
                    if genesis {
                        NumericMovementDebitAuthorization::InitialGenesisBootstrap(source_authority)
                    } else {
                        NumericMovementDebitAuthorization::ExactUser(source_authority)
                    },
                    "staking-bond",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::GovernanceBond(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "governance-bond",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::CitizenshipBond {
                    source_authority,
                    initial_genesis,
                    binding,
                } => (
                    if initial_genesis {
                        NumericMovementDebitAuthorization::InitialGenesisBootstrap(source_authority)
                    } else {
                        NumericMovementDebitAuthorization::ExactUser(source_authority)
                    },
                    "citizenship-bond",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::InitialGenesisFeeSponsorFunding {
                    source_authority,
                    binding,
                } => (
                    NumericMovementDebitAuthorization::InitialGenesisBootstrap(source_authority),
                    "initial-genesis-fee-sponsor-funding",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::NativeEscrow(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "native-escrow-funding",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::NativeAmx(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "native-amx-prepare",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::GameSession(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "game-seat-funding",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::VpnLease(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "vpn-lease-funding",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::FxCorridorEscrowDeposit(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "fx-corridor-owner-funding",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::SnsAutoRenewal(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "sns-auto-renewal",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::SccpEscrowLock(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "sccp-escrow-lock",
                    binding,
                ),
                EmbeddedNumericAssetMovementPurpose::BondFunding(binding) => (
                    NumericMovementDebitAuthorization::ExactUser(submitting_authority.clone()),
                    "bond-vault-funding",
                    binding,
                ),
            };
            Self {
                debit,
                transcript_authority: submitting_authority.clone(),
                transcript: NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    tag,
                    binding,
                },
                source_policy: if is_fx_deposit {
                    NumericAssetTransferSourcePolicy::FxEscrowDeposit
                } else if is_game_funding {
                    NumericAssetTransferSourcePolicy::GameSessionFunding
                } else if is_sccp_lock {
                    NumericAssetTransferSourcePolicy::SccpEscrowLock
                } else if is_bond_funding {
                    NumericAssetTransferSourcePolicy::BondVaultFunding
                } else {
                    NumericAssetTransferSourcePolicy::User
                },
                control_policy: NumericAssetTransferControlPolicy::Enforce,
                destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
            }
        }
        /// Bind a protocol debit to an exact retained-state purpose.
        fn retained(
            transcript_authority: &AccountId,
            purpose: RetainedNumericAssetMovementPurpose,
        ) -> Self {
            let (tag, binding, source_policy, control_policy) = match purpose {
                RetainedNumericAssetMovementPurpose::OracleReward(binding) => (
                    "oracle-reward",
                    binding,
                    NumericAssetTransferSourcePolicy::OracleReward,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::OraclePenalty(binding) => (
                    "oracle-penalty",
                    binding,
                    NumericAssetTransferSourcePolicy::OraclePenalty,
                    NumericAssetTransferControlPolicy::OraclePenalty,
                ),
                RetainedNumericAssetMovementPurpose::OracleDisputeResolution(binding) => (
                    "oracle-dispute-resolution",
                    binding,
                    NumericAssetTransferSourcePolicy::OracleDisputeResolution,
                    NumericAssetTransferControlPolicy::OracleDisputeResolution,
                ),
                RetainedNumericAssetMovementPurpose::ModerationChallengeRefund(binding) => (
                    "moderation-challenge-refund",
                    binding,
                    NumericAssetTransferSourcePolicy::ModerationChallengeRefund,
                    NumericAssetTransferControlPolicy::ModerationChallengeSettlement,
                ),
                RetainedNumericAssetMovementPurpose::ModerationChallengeSlash(binding) => (
                    "moderation-challenge-slash",
                    binding,
                    NumericAssetTransferSourcePolicy::ModerationChallengeSlash,
                    NumericAssetTransferControlPolicy::ModerationChallengeSettlement,
                ),
                RetainedNumericAssetMovementPurpose::SocialReward(binding) => (
                    "social-reward",
                    binding,
                    NumericAssetTransferSourcePolicy::SocialReward,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::SocialEscrow(binding) => (
                    "social-escrow",
                    binding,
                    NumericAssetTransferSourcePolicy::SocialEscrow,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::StakingUnbond(binding) => (
                    "staking-unbond",
                    binding,
                    NumericAssetTransferSourcePolicy::StakingUnbond,
                    NumericAssetTransferControlPolicy::StakingUnbond,
                ),
                RetainedNumericAssetMovementPurpose::StakingSlash(binding) => (
                    "staking-slash",
                    binding,
                    NumericAssetTransferSourcePolicy::StakingSlash,
                    NumericAssetTransferControlPolicy::StakingSlash,
                ),
                RetainedNumericAssetMovementPurpose::GovernanceSlash(binding) => (
                    "governance-slash",
                    binding,
                    NumericAssetTransferSourcePolicy::GovernanceSlash,
                    NumericAssetTransferControlPolicy::GovernanceSlash,
                ),
                RetainedNumericAssetMovementPurpose::GovernanceRestitution(binding) => (
                    "governance-restitution",
                    binding,
                    NumericAssetTransferSourcePolicy::GovernanceRestitution,
                    NumericAssetTransferControlPolicy::GovernanceRestitution,
                ),
                RetainedNumericAssetMovementPurpose::GovernanceUnlock(binding) => (
                    "governance-unlock",
                    binding,
                    NumericAssetTransferSourcePolicy::GovernanceUnlock,
                    NumericAssetTransferControlPolicy::GovernanceUnlock,
                ),
                RetainedNumericAssetMovementPurpose::CitizenshipRelease(binding) => (
                    "citizenship-release",
                    binding,
                    NumericAssetTransferSourcePolicy::CitizenshipRelease,
                    NumericAssetTransferControlPolicy::CitizenshipRelease,
                ),
                RetainedNumericAssetMovementPurpose::NativeEscrow(binding) => (
                    "native-escrow-retained",
                    binding,
                    NumericAssetTransferSourcePolicy::NativeEscrowCustody,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::NativeAmx(binding) => (
                    "native-amx-certified-settlement",
                    binding,
                    NumericAssetTransferSourcePolicy::NativeEscrowCustody,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::GameSession(binding) => (
                    "game-proof-settlement",
                    binding,
                    NumericAssetTransferSourcePolicy::NativeEscrowCustody,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::VpnLease(binding) => (
                    "vpn-lease-retained",
                    binding,
                    NumericAssetTransferSourcePolicy::NativeEscrowCustody,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::SorafsReserve(binding) => (
                    "sorafs-reserve-withdrawal",
                    binding,
                    NumericAssetTransferSourcePolicy::SorafsReserveCustody,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::FeeSponsor(binding) => (
                    "fee-sponsor-custody",
                    binding,
                    NumericAssetTransferSourcePolicy::FeeSponsorCustody,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::FxCorridorEscrowRefund(binding) => (
                    "fx-corridor-owner-refund",
                    binding,
                    NumericAssetTransferSourcePolicy::FxEscrowRelease,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::PrivacyPublicBridge(binding) => (
                    "privacy-public-bridge",
                    binding,
                    NumericAssetTransferSourcePolicy::User,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::PrivacyPoolDeposit(binding) => (
                    "privacy-pool-deposit",
                    binding,
                    NumericAssetTransferSourcePolicy::User,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::PrivacyPoolBridge(owner, binding) => (
                    "privacy-pool-bridge",
                    binding,
                    NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner),
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::SccpEscrowRelease(binding) => (
                    "sccp-escrow-release",
                    binding,
                    NumericAssetTransferSourcePolicy::SccpEscrowRelease,
                    NumericAssetTransferControlPolicy::Enforce,
                ),
                RetainedNumericAssetMovementPurpose::BondVault(binding) => (
                    "bond-vault-payment",
                    binding,
                    NumericAssetTransferSourcePolicy::BondVaultCustody,
                    NumericAssetTransferControlPolicy::BondVaultRelease,
                ),
            };
            Self {
                debit: NumericMovementDebitAuthorization::Protocol,
                transcript_authority: transcript_authority.clone(),
                transcript: NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    tag,
                    binding,
                },
                source_policy,
                control_policy,
                destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
            }
        }
        fn bilateral(
            transcript_authority: &AccountId,
            tag: &'static str,
            binding: Vec<u8>,
        ) -> Self {
            Self {
                debit: NumericMovementDebitAuthorization::Protocol,
                transcript_authority: transcript_authority.clone(),
                transcript: NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    tag,
                    binding,
                },
                source_policy: NumericAssetTransferSourcePolicy::User,
                control_policy: NumericAssetTransferControlPolicy::Enforce,
                destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
            }
        }
        fn authority_policy(
            &self,
            state_transaction: &StateTransaction<'_, '_>,
            source_id: &AssetId,
        ) -> Result<NumericAssetTransferAuthorityPolicy, Error> {
            match &self.debit {
                NumericMovementDebitAuthorization::ExactUser(authority) => {
                    ensure_user_numeric_asset_source_authority(
                        state_transaction,
                        authority,
                        source_id,
                    )?;
                    Ok(NumericAssetTransferAuthorityPolicy::ProtocolAuthorized)
                }
                NumericMovementDebitAuthorization::InitialGenesisBootstrap(source_authority) => {
                    if !crate::executor::is_initial_genesis_context(state_transaction)
                        || source_id.account() != source_authority
                    {
                        return Err(InstructionExecutionError::InvariantViolation(
                            "initial-genesis debit requires the exact prefunded source owner"
                                .into(),
                        ));
                    }
                    Ok(NumericAssetTransferAuthorityPolicy::ProtocolAuthorized)
                }
                NumericMovementDebitAuthorization::Protocol => {
                    Ok(NumericAssetTransferAuthorityPolicy::ProtocolAuthorized)
                }
            }
        }
        /// Hash the actual already-checked typed authorization without deriving source ownership.
        /// Unlike the legacy transcript identity, this retains purpose when a call hash exists.
        fn quantity_authorization_context_inputs(
            &self,
            bindings: &quantity_authorization::BindingFrame<'_>,
        ) -> Option<Hash> {
            self.quantity_authorization_context_stream(bindings, u64::MAX)
        }
        // One canonical byte stream; tests retain independent small-cap oracles.
        // The production entry above is independent of optional proof limits.
        fn quantity_authorization_context_stream(
            &self,
            bindings: &quantity_authorization::BindingFrame<'_>,
            limit: u64,
        ) -> Option<Hash> {
            use quantity_authorization::{
                ControlFrame, DebitFrame, SourceDetail, SourceFrame, TranscriptFrame,
                write_delimited_frame,
            };
            let mut remaining = limit.checked_sub(64)?;
            let (debit, owner) = match &self.debit {
                NumericMovementDebitAuthorization::ExactUser(owner) => ("user", Some(owner)),
                NumericMovementDebitAuthorization::InitialGenesisBootstrap(owner) => {
                    ("genesis", Some(owner))
                }
                NumericMovementDebitAuthorization::Protocol => ("protocol", None),
            };
            let (requirement, tag, binding) = match &self.transcript {
                NumericMovementTranscriptRequirement::TransactionRequired(tag) => {
                    ("transaction", *tag, &[][..])
                }
                NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    tag,
                    binding,
                } => ("typed-purpose", *tag, binding.as_slice()),
            };
            if u64::try_from(binding.len()).ok()? > remaining {
                return None;
            }
            let (source, detail) = match self.source_policy {
                NumericAssetTransferSourcePolicy::User => ("User", SourceDetail::Empty),
                NumericAssetTransferSourcePolicy::GameSessionFunding => {
                    ("GameSessionFunding", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::FxEscrowDeposit => {
                    ("FxEscrowDeposit", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::NativeEscrowCustody => {
                    ("NativeEscrowCustody", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::BondVaultFunding => {
                    ("BondVaultFunding", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::BondVaultCustody => {
                    ("BondVaultCustody", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::SorafsReserveCustody => {
                    ("SorafsReserveCustody", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::KagemushaReserveCustody => {
                    ("KagemushaReserveCustody", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::FxEscrowRelease => {
                    ("FxEscrowRelease", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::FeeSponsorCustody => {
                    ("FeeSponsorCustody", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::OracleReward => {
                    ("OracleReward", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::OraclePenalty => {
                    ("OraclePenalty", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::OracleDisputeResolution => {
                    ("OracleDisputeResolution", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::SocialReward => {
                    ("SocialReward", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::SocialEscrow => {
                    ("SocialEscrow", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::StakingUnbond => {
                    ("StakingUnbond", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::StakingSlash => {
                    ("StakingSlash", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::ModerationChallengeRefund => {
                    ("ModerationChallengeRefund", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::ModerationChallengeSlash => {
                    ("ModerationChallengeSlash", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::GovernanceSlash => {
                    ("GovernanceSlash", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::GovernanceRestitution => {
                    ("GovernanceRestitution", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::GovernanceUnlock => {
                    ("GovernanceUnlock", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::CitizenshipRelease => {
                    ("CitizenshipRelease", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::SccpEscrowLock => {
                    ("SccpEscrowLock", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::SccpEscrowRelease => {
                    ("SccpEscrowRelease", SourceDetail::Empty)
                }
                NumericAssetTransferSourcePolicy::RetailMonetary(purpose) => {
                    ("RetailMonetary", SourceDetail::Retail(purpose))
                }
                NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner) => {
                    ("PrivacyPoolBridge", SourceDetail::Privacy(owner))
                }
            };
            let control = match self.control_policy {
                NumericAssetTransferControlPolicy::Enforce => "Enforce",
                NumericAssetTransferControlPolicy::OraclePenalty => "OraclePenalty",
                NumericAssetTransferControlPolicy::OracleDisputeResolution => {
                    "OracleDisputeResolution"
                }
                NumericAssetTransferControlPolicy::StakingUnbond => "StakingUnbond",
                NumericAssetTransferControlPolicy::StakingSlash => "StakingSlash",
                NumericAssetTransferControlPolicy::ModerationChallengeSettlement => {
                    "ModerationChallengeSettlement"
                }
                NumericAssetTransferControlPolicy::GovernanceSlash => "GovernanceSlash",
                NumericAssetTransferControlPolicy::GovernanceRestitution => "GovernanceRestitution",
                NumericAssetTransferControlPolicy::GovernanceUnlock => "GovernanceUnlock",
                NumericAssetTransferControlPolicy::CitizenshipRelease => "CitizenshipRelease",
                NumericAssetTransferControlPolicy::BondVaultRelease => "BondVaultRelease",
            };
            let destination = match self.destination_admission {
                NumericAssetDestinationAdmissionPolicy::ImplicitReceive => "implicit-receive",
                NumericAssetDestinationAdmissionPolicy::ExistingAccount => "existing-account",
            };
            Hash::new_from_writer(|writer| {
                writer.write_all(b"iroha:fastpq:quantity-authorization:v1\0")?;
                write_delimited_frame(&DebitFrame(debit, owner), &mut remaining, writer)?;
                write_delimited_frame(
                    &TranscriptFrame(requirement, tag, binding),
                    &mut remaining,
                    writer,
                )?;
                write_delimited_frame(&SourceFrame(source, detail), &mut remaining, writer)?;
                write_delimited_frame(&ControlFrame(control, destination), &mut remaining, writer)?;
                write_delimited_frame(&self.transcript_authority, &mut remaining, writer)?;
                write_delimited_frame(bindings, &mut remaining, writer)
            })
            .ok()
        }
        #[cfg(test)]
        fn quantity_authorization_context(
            &self,
            bindings: &[(AssetId, AssetId, Quantity)],
            limit: u64,
        ) -> Option<Hash> {
            self.quantity_authorization_context_stream(
                &quantity_authorization::BindingFrame::Owned(bindings),
                limit,
            )
        }
        /// Hash the actual already-checked typed authorization without deriving source ownership.
        /// Unlike the legacy transcript identity, this retains purpose when a call hash exists.
        #[cfg(test)]
        fn quantity_authorization_context_owned_reference(
            &self,
            bindings: &[(AssetId, AssetId, Quantity)],
            limit: u64,
        ) -> Option<Hash> {
            let mut remaining = limit.checked_sub(64)?;
            let (debit, owner) = match &self.debit {
                NumericMovementDebitAuthorization::ExactUser(owner) => ("user", Some(owner)),
                NumericMovementDebitAuthorization::InitialGenesisBootstrap(owner) => {
                    ("genesis", Some(owner))
                }
                NumericMovementDebitAuthorization::Protocol => ("protocol", None),
            };
            let (requirement, tag, binding) = match &self.transcript {
                NumericMovementTranscriptRequirement::TransactionRequired(tag) => {
                    ("transaction", *tag, &[][..])
                }
                NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    tag,
                    binding,
                } => ("typed-purpose", *tag, binding.as_slice()),
            };
            if u64::try_from(binding.len()).ok()? > remaining {
                return None;
            }
            let (source, detail) = match self.source_policy {
                NumericAssetTransferSourcePolicy::User => ("User", Vec::new()),
                NumericAssetTransferSourcePolicy::GameSessionFunding => {
                    ("GameSessionFunding", Vec::new())
                }
                NumericAssetTransferSourcePolicy::FxEscrowDeposit => {
                    ("FxEscrowDeposit", Vec::new())
                }
                NumericAssetTransferSourcePolicy::NativeEscrowCustody => {
                    ("NativeEscrowCustody", Vec::new())
                }
                NumericAssetTransferSourcePolicy::BondVaultFunding => {
                    ("BondVaultFunding", Vec::new())
                }
                NumericAssetTransferSourcePolicy::BondVaultCustody => {
                    ("BondVaultCustody", Vec::new())
                }
                NumericAssetTransferSourcePolicy::SorafsReserveCustody => {
                    ("SorafsReserveCustody", Vec::new())
                }
                NumericAssetTransferSourcePolicy::KagemushaReserveCustody => {
                    ("KagemushaReserveCustody", Vec::new())
                }
                NumericAssetTransferSourcePolicy::FxEscrowRelease => {
                    ("FxEscrowRelease", Vec::new())
                }
                NumericAssetTransferSourcePolicy::FeeSponsorCustody => {
                    ("FeeSponsorCustody", Vec::new())
                }
                NumericAssetTransferSourcePolicy::OracleReward => ("OracleReward", Vec::new()),
                NumericAssetTransferSourcePolicy::OraclePenalty => ("OraclePenalty", Vec::new()),
                NumericAssetTransferSourcePolicy::OracleDisputeResolution => {
                    ("OracleDisputeResolution", Vec::new())
                }
                NumericAssetTransferSourcePolicy::SocialReward => ("SocialReward", Vec::new()),
                NumericAssetTransferSourcePolicy::SocialEscrow => ("SocialEscrow", Vec::new()),
                NumericAssetTransferSourcePolicy::StakingUnbond => ("StakingUnbond", Vec::new()),
                NumericAssetTransferSourcePolicy::StakingSlash => ("StakingSlash", Vec::new()),
                NumericAssetTransferSourcePolicy::ModerationChallengeRefund => {
                    ("ModerationChallengeRefund", Vec::new())
                }
                NumericAssetTransferSourcePolicy::ModerationChallengeSlash => {
                    ("ModerationChallengeSlash", Vec::new())
                }
                NumericAssetTransferSourcePolicy::GovernanceSlash => {
                    ("GovernanceSlash", Vec::new())
                }
                NumericAssetTransferSourcePolicy::GovernanceRestitution => {
                    ("GovernanceRestitution", Vec::new())
                }
                NumericAssetTransferSourcePolicy::GovernanceUnlock => {
                    ("GovernanceUnlock", Vec::new())
                }
                NumericAssetTransferSourcePolicy::CitizenshipRelease => {
                    ("CitizenshipRelease", Vec::new())
                }
                NumericAssetTransferSourcePolicy::SccpEscrowLock => ("SccpEscrowLock", Vec::new()),
                NumericAssetTransferSourcePolicy::SccpEscrowRelease => {
                    ("SccpEscrowRelease", Vec::new())
                }
                NumericAssetTransferSourcePolicy::RetailMonetary(purpose) => {
                    ("RetailMonetary", norito::encode_canonical(&purpose).ok()?)
                }
                NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner) => {
                    ("PrivacyPoolBridge", norito::encode_canonical(&owner).ok()?)
                }
            };
            let control = match self.control_policy {
                NumericAssetTransferControlPolicy::Enforce => "Enforce",
                NumericAssetTransferControlPolicy::OraclePenalty => "OraclePenalty",
                NumericAssetTransferControlPolicy::OracleDisputeResolution => {
                    "OracleDisputeResolution"
                }
                NumericAssetTransferControlPolicy::StakingUnbond => "StakingUnbond",
                NumericAssetTransferControlPolicy::StakingSlash => "StakingSlash",
                NumericAssetTransferControlPolicy::ModerationChallengeSettlement => {
                    "ModerationChallengeSettlement"
                }
                NumericAssetTransferControlPolicy::GovernanceSlash => "GovernanceSlash",
                NumericAssetTransferControlPolicy::GovernanceRestitution => "GovernanceRestitution",
                NumericAssetTransferControlPolicy::GovernanceUnlock => "GovernanceUnlock",
                NumericAssetTransferControlPolicy::CitizenshipRelease => "CitizenshipRelease",
                NumericAssetTransferControlPolicy::BondVaultRelease => "BondVaultRelease",
            };
            let destination = match self.destination_admission {
                NumericAssetDestinationAdmissionPolicy::ImplicitReceive => "implicit-receive",
                NumericAssetDestinationAdmissionPolicy::ExistingAccount => "existing-account",
            };
            let parts = [
                bounded_quantity_frame(&(debit.to_owned(), owner.cloned()), &mut remaining)?,
                bounded_quantity_frame(
                    &(requirement.to_owned(), tag.to_owned(), binding.to_vec()),
                    &mut remaining,
                )?,
                bounded_quantity_frame(&(source.to_owned(), detail), &mut remaining)?,
                bounded_quantity_frame(
                    &(control.to_owned(), destination.to_owned()),
                    &mut remaining,
                )?,
                bounded_quantity_frame(&self.transcript_authority, &mut remaining)?,
                bounded_quantity_frame(&bindings.to_vec(), &mut remaining)?,
            ];
            let mut preimage = b"iroha:fastpq:quantity-authorization:v1\0".to_vec();
            for part in parts {
                preimage.extend_from_slice(&u64::try_from(part.len()).ok()?.to_le_bytes());
                preimage.extend_from_slice(&part);
            }
            Some(Hash::new(preimage))
        }
        fn apply_with_quantity_candidate<T>(
            &self,
            state: &mut StateTransaction<'_, '_>,
            entry_hash: Hash,
            legs: &[(AssetId, AssetId, TransferDeltaTranscript)],
            apply: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<T, Error>,
        ) -> Result<T, Error> {
            let Some(context) = self.quantity_authorization_context_inputs(
                &quantity_authorization::BindingFrame::Transfers(legs),
            ) else {
                state.poison_quantity_candidate_owner();
                return apply(state);
            };
            state.apply_with_quantity_transfer_candidate(
                &self.transcript_authority,
                entry_hash,
                context,
                legs,
                apply,
            )
        }
        fn resolve_transcript_identity(
            &self,
            state_transaction: &StateTransaction<'_, '_>,
            legs: &[(AssetId, AssetId, Quantity)],
        ) -> Result<iroha_crypto::Hash, Error> {
            if matches!(
                &self.transcript,
                NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                    binding,
                    ..
                } if binding.is_empty()
            ) {
                return Err(InstructionExecutionError::InvariantViolation(
                    "typed numeric movement purpose binding must not be empty".into(),
                ));
            }
            if let Some(call_hash) = state_transaction.tx_call_hash {
                return Ok(call_hash);
            }
            let NumericMovementTranscriptRequirement::TransactionOrTypedPurpose { tag, binding } =
                &self.transcript
            else {
                let NumericMovementTranscriptRequirement::TransactionRequired(context) =
                    &self.transcript
                else {
                    unreachable!("numeric movement transcript requirement is exhaustive")
                };
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "{context} requires a transaction call_hash before balance or transcript mutation"
                    )
                    .into(),
                ));
            };
            let direct_identity =
                state_transaction
                    .direct_execution_identity()
                    .map_err(|error| {
                        InstructionExecutionError::InvariantViolation(
                            format!(
                                "failed to derive numeric movement execution identity: {error}"
                            )
                            .into(),
                        )
                    })?;
            let authority =
                norito::encode_canonical(&self.transcript_authority).map_err(|error| {
                    InstructionExecutionError::InvariantViolation(
                        format!("failed to encode numeric movement authority: {error}").into(),
                    )
                })?;
            let legs = norito::encode_canonical(&legs.to_vec()).map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("failed to encode numeric movement binding: {error}").into(),
                )
            })?;
            let mut preimage = Vec::from(&b"iroha:numeric-movement-context:v1\0"[..]);
            preimage.extend_from_slice(direct_identity.as_ref());
            for part in [
                tag.as_bytes(),
                binding.as_slice(),
                authority.as_slice(),
                legs.as_slice(),
            ] {
                preimage.extend_from_slice(
                    &u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes(),
                );
                preimage.extend_from_slice(part);
            }
            Ok(iroha_crypto::Hash::new(preimage))
        }
    }
    /// Fully prepared, non-reusable numeric movement capability.
    #[must_use]
    struct PreparedNumericAssetMovement {
        plan: PreparedNumericTransferPlan,
        authorization: NumericAssetMovementAuthorization,
    }
    impl PreparedNumericAssetMovement {
        /// Prepare one exact numeric movement through the central authorization and policy path.
        fn prepare(
            state_transaction: &mut StateTransaction<'_, '_>,
            source_id: AssetId,
            destination_id: AssetId,
            amount: Quantity,
            authorization: NumericAssetMovementAuthorization,
        ) -> Result<Self, Error> {
            Self::prepare_with_scope(
                state_transaction,
                source_id,
                destination_id,
                amount,
                authorization,
                NumericAssetTransferScopePolicy::Ambient,
            )
        }
        fn prepare_with_scope(
            state_transaction: &mut StateTransaction<'_, '_>,
            source_id: AssetId,
            destination_id: AssetId,
            amount: Quantity,
            authorization: NumericAssetMovementAuthorization,
            scope_policy: NumericAssetTransferScopePolicy,
        ) -> Result<Self, Error> {
            authorization.ensure_admits_bond_units(state_transaction, source_id.definition())?;
            let resolved_source = state_transaction
                .world
                .resolve_asset_id_for_current_scope(&source_id)?;
            let authority_policy =
                authorization.authority_policy(state_transaction, &resolved_source)?;
            let plan = PreparedNumericTransferPlan::prepare(
                state_transaction,
                &authorization.transcript_authority,
                source_id,
                destination_id,
                amount,
                scope_policy,
                authority_policy,
                authorization.source_policy,
                authorization.control_policy,
                authorization.destination_admission,
            )?;
            Ok(Self {
                plan,
                authorization,
            })
        }
        fn transcript_identity(
            &self,
            state: &StateTransaction<'_, '_>,
        ) -> Result<iroha_crypto::Hash, Error> {
            self.authorization.resolve_transcript_identity(
                state,
                &[(
                    self.plan.source_id.clone(),
                    self.plan.destination_id.clone(),
                    self.plan.amount.clone(),
                )],
            )
        }
        /// Apply the prepared movement, transcript and canonical events as one consumed action.
        fn apply(self, state_transaction: &mut StateTransaction<'_, '_>) -> Result<(), Error> {
            self.apply_with_observability(state_transaction, true)
        }
        /// Apply into a disposable transaction without publishing operational telemetry.
        fn apply_without_observability(
            self,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            self.apply_with_observability(state_transaction, false)
        }
        fn apply_with_observability(
            self,
            state_transaction: &mut StateTransaction<'_, '_>,
            record_observability: bool,
        ) -> Result<(), Error> {
            let transcript_identity = self.transcript_identity(state_transaction)?;
            let applied = if record_observability {
                // The precheck owns the exact full-quantity delta. Finish transcript and
                // source-context preparation before the main movement writes balances;
                // stage that same occurrence only when the existing plan succeeds.
                state_transaction.apply_with_prepared_transfer_transcripts(
                    &self.authorization.transcript_authority,
                    transcript_identity,
                    vec![self.plan.prechecked_delta.clone()],
                    |state_transaction| {
                        let legs = [(
                            self.plan.source_id.clone(),
                            self.plan.destination_id.clone(),
                            self.plan.prechecked_delta.clone(),
                        )];
                        self.authorization.apply_with_quantity_candidate(
                            state_transaction,
                            transcript_identity,
                            &legs,
                            |state_transaction| self.plan.apply(state_transaction),
                        )
                    },
                )?
            } else {
                self.plan.apply(state_transaction)?
            };
            #[allow(clippy::float_arithmetic)]
            #[cfg(feature = "telemetry")]
            if record_observability {
                state_transaction
                    .telemetry
                    .observe_tx_amount(applied.amount.as_numeric().clone().to_f64_lossy());
            }
            #[cfg(not(feature = "telemetry"))]
            let _ = record_observability;
            emit_numeric_asset_transfer_events(
                state_transaction,
                applied.source_id,
                applied.destination_id,
                applied.amount,
            );
            Ok(())
        }
    }
    /// Reject overlap with every custody owner that ordinary balance debits already protect.
    pub(crate) fn ensure_kagemusha_reserve_available(
        state: &StateTransaction<'_, '_>,
        id: &AssetId,
    ) -> Result<(), Error> {
        ensure_not_native_escrow_source(state, id)?;
        ensure_not_sorafs_reserve_custody_source(state, id)?;
        ensure_not_sccp_escrow_source(state, id)?;
        ensure_not_fx_corridor_escrow_source(state, id)?;
        ensure_privacy_public_reserve_source_policy(
            state,
            id,
            NumericAssetTransferSourcePolicy::User,
        )?;
        if state
            .world
            .game_custody_by_account
            .get(id.account())
            .is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA reserve overlaps game custody".into(),
            ));
        }
        ensure_not_kagemusha_reserve_source(state.world(), id)
    }
    /// Consume one source-verified KAGEMUSHA deposit or payout and its complete transfer batch.
    pub(crate) fn execute_verified_kagemusha_movements(
        state_transaction: &mut StateTransaction<'_, '_>,
        capability: crate::kagemusha_wallet_v1::wsv::VerifiedMovements,
    ) -> Result<(), Error> {
        let (authority, reserve, release, binding, entries) = capability.into_parts();
        if entries.is_empty()
            || entries.len() > 2
            || entries.iter().any(|(source, destination, _)| {
                source.definition() != reserve.definition()
                    || destination.definition() != reserve.definition()
                    || (release && source != &reserve)
                    || (!release && source.account() != &authority)
            })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA movement binding differs".into(),
            ));
        }
        let authorization = NumericAssetMovementAuthorization {
            debit: if release {
                NumericMovementDebitAuthorization::Protocol
            } else {
                NumericMovementDebitAuthorization::ExactUser(authority.clone())
            },
            transcript_authority: authority,
            transcript: NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                tag: if release {
                    "kagemusha-reserve-payout"
                } else {
                    "kagemusha-load-issuance"
                },
                binding,
            },
            source_policy: if release {
                NumericAssetTransferSourcePolicy::KagemushaReserveCustody
            } else {
                NumericAssetTransferSourcePolicy::User
            },
            control_policy: NumericAssetTransferControlPolicy::Enforce,
            destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
        };
        let prepared = PreparedNumericAssetMovementBatch::prepare_with_authorization(
            state_transaction,
            &entries,
            authorization,
        )?;
        if prepared
            .plans
            .iter()
            .zip(&entries)
            .any(|(plan, (source, destination, _))| {
                &plan.source_id != source || &plan.destination_id != destination
            })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA movement must preserve both registered balance buckets".into(),
            ));
        }
        // §6 preserves the claim's face value. Ordinary asset controls still apply; the
        // offline blacklist is deliberately absent from this redemption boundary.
        let applied = prepared.apply(state_transaction)?;
        for movement in applied {
            emit_numeric_asset_transfer_events(
                state_transaction,
                movement.source_id,
                movement.destination_id,
                movement.amount,
            );
        }
        Ok(())
    }
    /// Prepare and atomically apply one typed numeric asset movement.
    fn execute_numeric_asset_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        authorization: NumericAssetMovementAuthorization,
    ) -> Result<(), Error> {
        PreparedNumericAssetMovement::prepare(
            state_transaction,
            source_id,
            destination_id,
            amount,
            authorization,
        )?
        .apply(state_transaction)
    }
    enum VerifiedPrivacyPublicBalancePurpose {
        General,
        PoolDeposit(PrivacyPublicReserveOwnerV1),
        PoolWithdrawal(PrivacyPublicReserveOwnerV1),
    }
    /// Apply one exact transparent balance mutation authorized by a verified
    /// ZK-ACE public statement.
    pub(crate) fn execute_verified_privacy_public_balance_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        statement_digest: PrivacyStatementDigestV1,
        definition_id: &AssetDefinitionId,
        public_balance_scope: AssetBalanceScope,
        source_account: &AccountId,
        destination_account: &AccountId,
        amount: Quantity,
    ) -> Result<(), Error> {
        execute_verified_privacy_public_balance_transfer_with_purpose(
            state_transaction,
            submitting_authority,
            statement_digest,
            definition_id,
            public_balance_scope,
            source_account,
            destination_account,
            amount,
            VerifiedPrivacyPublicBalancePurpose::General,
        )
    }
    /// Apply one direction of an exact Orchard/private-IVM verified pool bridge.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_verified_privacy_pool_public_balance_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        statement_digest: PrivacyStatementDigestV1,
        owner: PrivacyPublicReserveOwnerV1,
        definition_id: &AssetDefinitionId,
        public_balance_scope: AssetBalanceScope,
        reserve_account: &AccountId,
        direction: PrivacyValueBalanceDirectionV1,
        amount: Quantity,
    ) -> Result<(), Error> {
        let reserve_asset_id = AssetId::with_scope(
            definition_id.clone(),
            reserve_account.clone(),
            public_balance_scope,
        );
        if privacy_public_reserve_owner_v1(
            &state_transaction.world.privacy_commitments,
            &reserve_asset_id,
        )
        .map_err(|message| InstructionExecutionError::InvariantViolation(message.into()))?
            != Some(owner)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "verified privacy pool bridge does not match governed reserve custody".into(),
            ));
        }
        let (source_account, destination_account, purpose) = match direction {
            PrivacyValueBalanceDirectionV1::IntoPool => (
                submitting_authority,
                reserve_account,
                VerifiedPrivacyPublicBalancePurpose::PoolDeposit(owner),
            ),
            PrivacyValueBalanceDirectionV1::OutOfPool => (
                reserve_account,
                submitting_authority,
                VerifiedPrivacyPublicBalancePurpose::PoolWithdrawal(owner),
            ),
            PrivacyValueBalanceDirectionV1::Balanced => {
                return Err(InstructionExecutionError::InvariantViolation(
                    "balanced privacy effect has no public-reserve transfer".into(),
                ));
            }
        };
        execute_verified_privacy_public_balance_transfer_with_purpose(
            state_transaction,
            submitting_authority,
            statement_digest,
            definition_id,
            public_balance_scope,
            source_account,
            destination_account,
            amount,
            purpose,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn execute_verified_privacy_public_balance_transfer_with_purpose(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        statement_digest: PrivacyStatementDigestV1,
        definition_id: &AssetDefinitionId,
        public_balance_scope: AssetBalanceScope,
        source_account: &AccountId,
        destination_account: &AccountId,
        amount: Quantity,
        purpose: VerifiedPrivacyPublicBalancePurpose,
    ) -> Result<(), Error> {
        validate_committed_public_balance_scope(
            state_transaction,
            definition_id,
            public_balance_scope,
            "privacy bridge transfer",
        )?;
        if source_account == destination_account {
            return Err(InstructionExecutionError::InvariantViolation(
                "privacy public bridge source and destination must differ".into(),
            ));
        }
        let source_id = AssetId::with_scope(
            definition_id.clone(),
            source_account.clone(),
            public_balance_scope,
        );
        let destination_id = AssetId::with_scope(
            definition_id.clone(),
            destination_account.clone(),
            public_balance_scope,
        );
        let exact_movement = (
            statement_digest,
            definition_id.clone(),
            public_balance_scope,
            source_account.clone(),
            destination_account.clone(),
            amount.clone(),
        );
        let retained_purpose = match purpose {
            VerifiedPrivacyPublicBalancePurpose::General => {
                RetainedNumericAssetMovementPurpose::PrivacyPublicBridge(
                    canonical_numeric_movement_binding(&exact_movement)?,
                )
            }
            VerifiedPrivacyPublicBalancePurpose::PoolDeposit(owner) => {
                RetainedNumericAssetMovementPurpose::PrivacyPoolDeposit(
                    canonical_numeric_movement_binding(&(owner, exact_movement))?,
                )
            }
            VerifiedPrivacyPublicBalancePurpose::PoolWithdrawal(owner) => {
                RetainedNumericAssetMovementPurpose::PrivacyPoolBridge(
                    owner,
                    canonical_numeric_movement_binding(&(owner, exact_movement))?,
                )
            }
        };
        PreparedNumericAssetMovement::prepare_with_scope(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(submitting_authority, retained_purpose),
            NumericAssetTransferScopePolicy::ExplicitBilateral,
        )?
        .apply(state_transaction)
    }
    fn canonical_numeric_movement_binding<T: norito::NoritoSerialize>(
        value: &T,
    ) -> Result<Vec<u8>, Error> {
        norito::encode_canonical(value).map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("failed to encode typed numeric movement purpose: {error}").into(),
            )
        })
    }
    #[derive(Clone, Copy, Debug)]
    enum NumericAssetBurnSourcePolicy {
        AccountAdmissionFee,
        FeeSponsorCustody,
        BondRedemption,
        BondTreasuryRetirement,
    }
    // Created only while consuming the executor's original sponsor-charge
    // capability. This private value retains the original invocation and signed
    // revision; arbitrary purpose hashes cannot grant a sponsor burn source.
    struct FeeSponsorBurnQuantityOwner {
        authority: AccountId,
        execution_entry: Hash,
        binding: Vec<u8>,
    }
    /// Apply one fully prechecked numeric supply burn through the central policy path.
    fn execute_checked_numeric_asset_burn(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: Option<&AccountId>,
        source_id: AssetId,
        amount: Quantity,
        source_policy: NumericAssetBurnSourcePolicy,
        sponsor_quantity_owner: Option<FeeSponsorBurnQuantityOwner>,
    ) -> Result<(), Error> {
        ensure_global_asset_write_on_authoritative_route(
            state_transaction,
            source_id.definition(),
            "burn",
        )?;
        let source_id = state_transaction
            .world
            .resolve_asset_id_for_current_scope(&source_id)?;
        reject_uncovered_retail_asset_mutation(state_transaction, &source_id, "burn")?;
        crate::retail_fee::settle_balance(&mut state_transaction.world, &source_id)?;
        crate::validation_fee_rewards::ensure_reward_custody_debit(
            state_transaction,
            &source_id,
            &amount,
        )?;
        match source_policy {
            NumericAssetBurnSourcePolicy::AccountAdmissionFee => {
                let authority = authority.ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "account-admission fee burn requires an exact authority".into(),
                    )
                })?;
                ensure_user_numeric_asset_source_authority(
                    state_transaction,
                    authority,
                    &source_id,
                )?;
                ensure_not_native_escrow_source(state_transaction, &source_id)?;
                ensure_not_sorafs_reserve_custody_source(state_transaction, &source_id)?;
                ensure_not_kagemusha_reserve_source(state_transaction.world(), &source_id)?;
                ensure_not_sccp_escrow_source(state_transaction, &source_id)?;
            }
            NumericAssetBurnSourcePolicy::FeeSponsorCustody => {
                if source_id.account()
                    != crate::executor::root_fees::sponsor_vault_custody(state_transaction)?
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "fee sponsor burn source does not match configured custody".into(),
                    ));
                }
                ensure_not_native_escrow_source(state_transaction, &source_id)?;
                ensure_not_sorafs_reserve_custody_source(state_transaction, &source_id)?;
                ensure_not_kagemusha_reserve_source(state_transaction.world(), &source_id)?;
                ensure_not_sccp_escrow_source(state_transaction, &source_id)?;
            }
            NumericAssetBurnSourcePolicy::BondTreasuryRetirement => {
                // The issuer burns units of its own global balance.
                let authority = authority.ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "bond treasury retirement requires an exact authority".into(),
                    )
                })?;
                ensure_user_numeric_asset_source_authority(
                    state_transaction,
                    authority,
                    &source_id,
                )?;
                ensure_privacy_public_reserve_source_policy(
                    state_transaction,
                    &source_id,
                    NumericAssetTransferSourcePolicy::User,
                )?;
                ensure_not_native_escrow_source(state_transaction, &source_id)?;
                ensure_not_fx_corridor_escrow_source(state_transaction, &source_id)?;
                ensure_not_sorafs_reserve_custody_source(state_transaction, &source_id)?;
                ensure_not_kagemusha_reserve_source(state_transaction.world(), &source_id)?;
                ensure_not_sccp_escrow_source(state_transaction, &source_id)?;
            }
            NumericAssetBurnSourcePolicy::BondRedemption => {
                // The bond kernel selected the holder's exact entitled units; the
                // claim may be pushed by the paying agent, so no signer ownership
                // of the source is required here.
                ensure_privacy_public_reserve_source_policy(
                    state_transaction,
                    &source_id,
                    NumericAssetTransferSourcePolicy::User,
                )?;
                ensure_not_native_escrow_source(state_transaction, &source_id)?;
                ensure_not_sorafs_reserve_custody_source(state_transaction, &source_id)?;
                ensure_not_kagemusha_reserve_source(state_transaction.world(), &source_id)?;
                ensure_not_sccp_escrow_source(state_transaction, &source_id)?;
            }
        }
        // Only the bond kernel's verified burns change a registered bond's supply.
        if !matches!(
            source_policy,
            NumericAssetBurnSourcePolicy::BondRedemption
                | NumericAssetBurnSourcePolicy::BondTreasuryRetirement
        ) {
            crate::smartcontracts::isi::bond::ensure_bond_supply_unlocked(
                state_transaction.world(),
                source_id.definition(),
            )?;
        }
        let spec = state_transaction
            .numeric_spec_for(source_id.definition())
            .map_err(Error::from)?;
        assert_numeric_spec_with(amount.as_numeric(), spec)?;
        // A redemption burn retires units the holder is owed principal for. The
        // definition owner's later confidential or usage policy changes must not
        // block it and trap the funded redemption in the vault.
        if !matches!(source_policy, NumericAssetBurnSourcePolicy::BondRedemption) {
            ensure_transparent_allowed(
                state_transaction,
                source_id.definition(),
                "transparent burn not permitted by policy",
            )?;
            ensure_usage_policy_for_accounts(
                state_transaction,
                source_id.definition(),
                [(
                    source_id.account(),
                    asset_id_dataspace_hint(state_transaction, &source_id),
                )],
                Some(&amount),
            )?;
        }
        let (control_before, control_update) = match source_policy {
            NumericAssetBurnSourcePolicy::AccountAdmissionFee
            | NumericAssetBurnSourcePolicy::BondTreasuryRetirement => {
                if !amount.is_zero() {
                    state_transaction
                        .world
                        .ensure_numeric_asset_transfer_availability(
                            &source_id,
                            amount.clone(),
                            AssetTransferDirection::Outgoing,
                        )?;
                }
                (
                    Some(active_control_record(
                        state_transaction,
                        source_id.account(),
                        source_id.definition(),
                    )?),
                    prepare_outbound_asset_transfer_control_update(
                        state_transaction,
                        &source_id,
                        &amount,
                    )?,
                )
            }
            NumericAssetBurnSourcePolicy::FeeSponsorCustody
            | NumericAssetBurnSourcePolicy::BondRedemption => (None, None),
        };
        let source_before = state_transaction
            .world
            .assets
            .get(&source_id)
            .ok_or_else(|| FindError::Asset(source_id.clone().into()))?
            .as_ref()
            .clone();
        let source_after = source_before
            .checked_sub(&amount)
            .map_err(|_| MathError::NotEnoughQuantity)?;
        assert_numeric_spec_with(source_after.as_numeric(), spec)?;
        let total_before = state_transaction
            .world
            .asset_definition(source_id.definition())?
            .total_quantity()
            .clone();
        let _total_after = total_before
            .checked_sub(&amount)
            .map_err(|_| MathError::NotEnoughQuantity)?;
        let current_source = state_transaction
            .world
            .assets
            .get(&source_id)
            .map(|value| value.as_ref().clone());
        let current_total = state_transaction
            .world
            .asset_definition(source_id.definition())?
            .total_quantity()
            .clone();
        let controls_changed = if let Some(expected) = &control_before {
            active_control_record(
                state_transaction,
                source_id.account(),
                source_id.definition(),
            )? != *expected
        } else {
            false
        };
        if current_source.as_ref() != Some(&source_before)
            || current_total != total_before
            || controls_changed
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "numeric burn state changed between preparation and apply".into(),
            ));
        }
        let captured_source = source_id.clone();
        let captured_amount = amount.clone();
        let apply = |state_transaction: &mut StateTransaction<'_, '_>,
                     original: PreparedNumericSupplyChange| {
            original
                .apply_balance(&mut state_transaction.world)?
                .apply(&mut state_transaction.world, &amount)?;
            if let Some(record) = control_update {
                update_control_record(state_transaction, source_id.account(), record)?;
            }
            state_transaction
                .world
                .emit_asset_event(AssetEvent::Removed(AssetChanged {
                    asset: source_id,
                    amount,
                }));
            Ok(())
        };
        match (source_policy, authority, sponsor_quantity_owner) {
            (NumericAssetBurnSourcePolicy::AccountAdmissionFee, Some(authority), None) => {
                apply_with_supply_quantity_candidate(
                    state_transaction,
                    authority,
                    &captured_source,
                    &captured_amount,
                    false,
                    (
                        "account-admission-fee-burn",
                        Some(quantity_authorization::SupplyBinding::Bytes(&[])),
                    ),
                    apply,
                )
            }
            (NumericAssetBurnSourcePolicy::BondRedemption, Some(authority), None) => {
                apply_with_supply_quantity_candidate(
                    state_transaction,
                    authority,
                    &captured_source,
                    &captured_amount,
                    false,
                    (
                        "bond-redemption-burn",
                        Some(quantity_authorization::SupplyBinding::Bytes(&[])),
                    ),
                    apply,
                )
            }
            (NumericAssetBurnSourcePolicy::BondTreasuryRetirement, Some(authority), None) => {
                apply_with_supply_quantity_candidate(
                    state_transaction,
                    authority,
                    &captured_source,
                    &captured_amount,
                    false,
                    (
                        "bond-treasury-retirement",
                        Some(quantity_authorization::SupplyBinding::Bytes(&[])),
                    ),
                    apply,
                )
            }
            (NumericAssetBurnSourcePolicy::FeeSponsorCustody, None, Some(owner))
                if state_transaction.tx_call_hash == Some(owner.execution_entry) =>
            {
                apply_with_supply_quantity_candidate(
                    state_transaction,
                    &owner.authority,
                    &captured_source,
                    &captured_amount,
                    false,
                    (
                        "verified-fee-sponsor-burn",
                        Some(quantity_authorization::SupplyBinding::Bytes(&owner.binding)),
                    ),
                    apply,
                )
            }
            _ => {
                state_transaction.poison_quantity_candidate_owner();
                let original = PreparedNumericSupplyChange::prepare(
                    state_transaction,
                    &captured_source,
                    &captured_amount,
                    false,
                )?;
                apply(state_transaction, original)
            }
        }
    }
    /// Charge an exact user while admitting `created_account`.
    pub(crate) fn execute_account_admission_fee_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        created_account: &AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let binding = canonical_numeric_movement_binding(&(
            created_account.clone(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::AccountAdmissionFee(binding),
            ),
        )
    }
    /// Burn an exact user's account-admission fee through the central burn policy path.
    pub(crate) fn execute_account_admission_fee_burn(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        _created_account: &AccountId,
        source_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        execute_checked_numeric_asset_burn(
            state_transaction,
            Some(authority),
            source_id,
            amount,
            NumericAssetBurnSourcePolicy::AccountAdmissionFee,
            None,
        )
    }
    /// Reserve an exact user's Oracle dispute bond.
    pub(crate) fn execute_oracle_dispute_bond_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        dispute_id: iroha_data_model::oracle::OracleDisputeId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        if source_id.account() != authority
            || source_id.definition() != &state_transaction.oracle.economics.dispute_bond_asset
            || destination_id.account() != &state_transaction.oracle.economics.slash_receiver
            || destination_id.definition() != &state_transaction.oracle.economics.dispute_bond_asset
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "Oracle dispute bond movement does not match configured custody".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&dispute_id)?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::OracleDisputeBond(binding),
            ),
        )
    }
    /// Consume one exact moderation challenge bond funding or settlement capability.
    pub(in crate::smartcontracts::isi) fn execute_verified_moderation_challenge_bond_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::sorafs_moderation::VerifiedModerationChallengeBondMovement,
    ) -> Result<(), Error> {
        use crate::smartcontracts::isi::sorafs_moderation::{
            ModerationChallengeBondSettlementLeg, VerifiedModerationChallengeBondPurpose,
            moderation_challenge_rejected_slash_amount, read_case, read_challenge,
        };
        use iroha_data_model::sorafs::moderation_ledger::ModerationCaseStatusV1;

        let (purpose, source_id, destination_id, amount) = authorization.into_parts();
        let movement_authorization = match purpose {
            VerifiedModerationChallengeBondPurpose::Funding {
                authority,
                case_id,
                round_id,
                challenge_id,
            } => {
                let case = read_case(state_transaction.world(), &case_id, &round_id)?.ok_or_else(
                    || {
                        InstructionExecutionError::InvariantViolation(
                            "moderation challenge bond funding has no retained case".into(),
                        )
                    },
                )?;
                let expected_source = AssetId::new(
                    case.policy.challenge_voting_asset_id.clone(),
                    authority.clone(),
                );
                let expected_destination = AssetId::new(
                    case.policy.challenge_voting_asset_id.clone(),
                    case.policy.challenge_escrow_account.clone(),
                );
                if source_id != expected_source
                    || destination_id != expected_destination
                    || amount != case.policy.challenge_bond_amount
                    || authority == case.policy.challenge_escrow_account
                    || authority == case.policy.challenge_slash_receiver_account
                    || case.status != ModerationCaseStatusV1::Open
                    || read_challenge(
                        state_transaction.world(),
                        &case_id,
                        &round_id,
                        &challenge_id,
                    )?
                    .is_some()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "moderation challenge bond funding does not match its case-pinned governance custody"
                            .into(),
                    )
                    .into());
                }
                let binding = canonical_numeric_movement_binding(&(
                    case_id,
                    round_id,
                    challenge_id,
                    authority.clone(),
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                ))?;
                NumericAssetMovementAuthorization::embedded_user(
                    &authority,
                    EmbeddedNumericAssetMovementPurpose::ModerationChallengeBond(binding),
                )
            }
            VerifiedModerationChallengeBondPurpose::Settlement {
                case_id,
                round_id,
                challenge_id,
                decision,
                leg,
            } => {
                let record = read_challenge(
                    state_transaction.world(),
                    &case_id,
                    &round_id,
                    &challenge_id,
                )?
                .ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "moderation challenge bond settlement has no retained challenge".into(),
                    )
                })?;
                if record.decision.is_some() || record.bond.settled_at_unix_ms.is_some() {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "moderation challenge bond is already settled".into(),
                    )
                    .into());
                }
                let numeric_spec = state_transaction
                    .numeric_spec_for(&record.bond.asset_definition_id)
                    .map_err(InstructionExecutionError::Find)?;
                let case = read_case(state_transaction.world(), &case_id, &round_id)?.ok_or_else(
                    || {
                        InstructionExecutionError::InvariantViolation(
                            "moderation challenge bond settlement has no retained case".into(),
                        )
                    },
                )?;
                let slash_amount = moderation_challenge_rejected_slash_amount(
                    &record.bond.amount,
                    numeric_spec,
                    case.policy.challenge_rejected_slash_bps,
                )?;
                let refund_amount = record
                    .bond
                    .amount
                    .checked_sub(&slash_amount)
                    .map_err(|_| MathError::Overflow)?;
                let expected_source = AssetId::new(
                    record.bond.asset_definition_id.clone(),
                    record.bond.escrow_account.clone(),
                );
                let (expected_destination, expected_amount, retained_purpose) = match (decision, leg)
                {
                    (
                        iroha_data_model::sorafs::moderation_ledger::ModerationChallengeDecisionV1::Accepted
                        | iroha_data_model::sorafs::moderation_ledger::ModerationChallengeDecisionV1::Expired,
                        ModerationChallengeBondSettlementLeg::Refund,
                    ) => (
                        AssetId::new(
                            record.bond.asset_definition_id.clone(),
                            record.challenger.clone(),
                        ),
                        record.bond.amount.clone(),
                        RetainedNumericAssetMovementPurpose::ModerationChallengeRefund(Vec::new()),
                    ),
                    (
                        iroha_data_model::sorafs::moderation_ledger::ModerationChallengeDecisionV1::Rejected,
                        ModerationChallengeBondSettlementLeg::Refund,
                    ) => (
                        AssetId::new(
                            record.bond.asset_definition_id.clone(),
                            record.challenger.clone(),
                        ),
                        refund_amount,
                        RetainedNumericAssetMovementPurpose::ModerationChallengeRefund(Vec::new()),
                    ),
                    (
                        iroha_data_model::sorafs::moderation_ledger::ModerationChallengeDecisionV1::Rejected,
                        ModerationChallengeBondSettlementLeg::Slash,
                    ) => (
                        AssetId::new(
                            record.bond.asset_definition_id.clone(),
                            record.bond.slash_receiver_account.clone(),
                        ),
                        slash_amount,
                        RetainedNumericAssetMovementPurpose::ModerationChallengeSlash(Vec::new()),
                    ),
                    _ => {
                        return Err(InstructionExecutionError::InvariantViolation(
                            "moderation challenge bond settlement leg does not match its decision"
                                .into(),
                        )
                        .into());
                    }
                };
                if source_id != expected_source
                    || destination_id != expected_destination
                    || amount != expected_amount
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "moderation challenge bond settlement does not match retained custody"
                            .into(),
                    )
                    .into());
                }
                let binding = canonical_numeric_movement_binding(&(
                    case_id,
                    round_id,
                    challenge_id,
                    decision,
                    leg as u8,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                    record.bond.amount,
                ))?;
                match retained_purpose {
                    RetainedNumericAssetMovementPurpose::ModerationChallengeRefund(_) => {
                        NumericAssetMovementAuthorization::retained(
                            &record.challenger,
                            RetainedNumericAssetMovementPurpose::ModerationChallengeRefund(binding),
                        )
                    }
                    RetainedNumericAssetMovementPurpose::ModerationChallengeSlash(_) => {
                        NumericAssetMovementAuthorization::retained(
                            &record.challenger,
                            RetainedNumericAssetMovementPurpose::ModerationChallengeSlash(binding),
                        )
                    }
                    _ => unreachable!("moderation settlement selects a moderation purpose"),
                }
            }
        };
        if source_id == destination_id {
            let retained_balance = state_transaction
                .world
                .assets
                .get(&source_id)
                .map(|value| value.as_ref().clone())
                .unwrap_or_else(Quantity::zero);
            if retained_balance < amount {
                return Err(InstructionExecutionError::InvariantViolation(
                    "moderation challenge slash custody is undercollateralized".into(),
                )
                .into());
            }
            return Ok(());
        }
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            movement_authorization,
        )
    }
    /// Move an exact user's social send into its verified recipient or configured escrow.
    pub(crate) fn execute_social_send_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        binding_digest: Hash,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let config = &state_transaction.gov.viral_incentives;
        if source_id.account() != authority
            || source_id.definition() != &config.reward_asset_definition_id
            || destination_id.definition() != &config.reward_asset_definition_id
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "social send movement does not match its exact authority and configured asset"
                    .into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&binding_digest)?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::SocialSend(binding),
            ),
        )
    }
    /// Pay a configured social reward from the incentive pool for an exact binding.
    pub(crate) fn execute_social_reward_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        binding_digest: Hash,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let config = &state_transaction.gov.viral_incentives;
        let expected_source = AssetId::new(
            config.reward_asset_definition_id.clone(),
            config.incentive_pool_account.clone(),
        );
        if source_id != expected_source
            || destination_id.definition() != &config.reward_asset_definition_id
            || state_transaction
                .world
                .twitter_bindings
                .get(&binding_digest)
                .is_none()
            || (amount != config.follow_reward_amount && amount != config.sender_bonus_amount)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "social reward movement does not match the configured pool, binding, and reward"
                    .into(),
            ));
        }
        let transcript_authority = source_id.account().clone();
        let binding = canonical_numeric_movement_binding(&(
            binding_digest,
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                &transcript_authority,
                RetainedNumericAssetMovementPurpose::SocialReward(binding),
            ),
        )
    }
    /// Release or refund one exact retained social escrow record.
    pub(crate) fn execute_social_escrow_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        binding_digest: Hash,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let config = &state_transaction.gov.viral_incentives;
        let Some(record) = state_transaction.world.viral_escrows.get(&binding_digest) else {
            return Err(InstructionExecutionError::InvariantViolation(
                "social escrow movement requires an exact retained escrow record".into(),
            ));
        };
        let expected_source = AssetId::new(
            config.reward_asset_definition_id.clone(),
            config.escrow_account.clone(),
        );
        let bound_recipient = state_transaction
            .world
            .twitter_bindings
            .get(&binding_digest)
            .and_then(|binding| {
                state_transaction
                    .world
                    .uaid_accounts
                    .get(&binding.attestation.uaid)
            });
        let destination_is_authorized = destination_id.account() == &record.sender
            || bound_recipient.is_some_and(|recipient| destination_id.account() == recipient);
        if source_id != expected_source
            || destination_id.definition() != &config.reward_asset_definition_id
            || amount != record.amount
            || !destination_is_authorized
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "social escrow movement does not match its retained record".into(),
            ));
        }
        let transcript_authority = record.sender.clone();
        let binding = canonical_numeric_movement_binding(&(
            binding_digest,
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                &transcript_authority,
                RetainedNumericAssetMovementPurpose::SocialEscrow(binding),
            ),
        )
    }
    /// Consume one exact Oracle movement capability created after Oracle admission.
    pub(in crate::smartcontracts::isi) fn execute_verified_oracle_numeric_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::oracle::VerifiedOracleNumericMovement,
    ) -> Result<(), Error> {
        use crate::smartcontracts::isi::oracle::VerifiedOracleNumericPurpose;
        let (purpose, source_id, destination_id, amount) = authorization.into_parts();
        let economics = &state_transaction.oracle.economics;
        let (transcript_authority, retained_purpose) = match purpose {
            VerifiedOracleNumericPurpose::Reward {
                feed_id,
                feed_config_version,
                slot,
                request_hash,
                provider,
            } => {
                let expected_source = AssetId::new(
                    economics.reward_asset.clone(),
                    economics.reward_pool.clone(),
                );
                let expected_destination =
                    AssetId::new(economics.reward_asset.clone(), provider.clone());
                let feed_matches = state_transaction
                    .world
                    .oracle_feeds
                    .get(&feed_id)
                    .is_some_and(|feed| feed.feed_config_version == feed_config_version);
                if source_id != expected_source
                    || destination_id != expected_destination
                    || amount != economics.reward_amount
                    || !feed_matches
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "Oracle reward capability does not match live economics and feed state"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    feed_id,
                    feed_config_version,
                    slot,
                    request_hash,
                    provider,
                    amount.clone(),
                ))?;
                (
                    source_id.account().clone(),
                    RetainedNumericAssetMovementPurpose::OracleReward(binding),
                )
            }
            VerifiedOracleNumericPurpose::Penalty {
                feed_id,
                feed_config_version,
                slot,
                request_hash,
                provider,
                kind,
            } => {
                let expected_source = AssetId::new(economics.slash_asset.clone(), provider.clone());
                let expected_destination = AssetId::new(
                    economics.slash_asset.clone(),
                    economics.slash_receiver.clone(),
                );
                let expected_amount = match kind {
                    iroha_data_model::oracle::OraclePenaltyKind::Outlier
                    | iroha_data_model::oracle::OraclePenaltyKind::Dispute => {
                        &economics.slash_outlier_amount
                    }
                    iroha_data_model::oracle::OraclePenaltyKind::Error
                    | iroha_data_model::oracle::OraclePenaltyKind::BadSignature => {
                        &economics.slash_error_amount
                    }
                    iroha_data_model::oracle::OraclePenaltyKind::NoShow => {
                        &economics.slash_no_show_amount
                    }
                };
                let feed_matches = state_transaction
                    .world
                    .oracle_feeds
                    .get(&feed_id)
                    .is_some_and(|feed| feed.feed_config_version == feed_config_version);
                if source_id != expected_source
                    || destination_id != expected_destination
                    || &amount != expected_amount
                    || !feed_matches
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "Oracle penalty capability does not match live economics and feed state"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    feed_id,
                    feed_config_version,
                    slot,
                    request_hash,
                    provider.clone(),
                    kind,
                    amount.clone(),
                ))?;
                (
                    provider,
                    RetainedNumericAssetMovementPurpose::OraclePenalty(binding),
                )
            }
            VerifiedOracleNumericPurpose::DisputeEscrow { dispute_id } => {
                let dispute = state_transaction
                    .world
                    .oracle_disputes
                    .get(&dispute_id)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "Oracle dispute movement has no retained dispute".into(),
                        )
                    })?;
                if !matches!(
                    dispute.status,
                    iroha_data_model::oracle::OracleDisputeStatus::Open
                ) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "Oracle dispute movement requires an open retained dispute".into(),
                    ));
                }
                let expected_source = AssetId::new(
                    economics.dispute_bond_asset.clone(),
                    economics.slash_receiver.clone(),
                );
                let challenger = AssetId::new(
                    economics.dispute_bond_asset.clone(),
                    dispute.challenger.clone(),
                );
                let target =
                    AssetId::new(economics.dispute_bond_asset.clone(), dispute.target.clone());
                let allowed = (destination_id == challenger
                    && (amount == dispute.bond || amount == economics.dispute_reward_amount))
                    || (destination_id == target && amount == economics.frivolous_slash_amount);
                if source_id != expected_source || !allowed {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "Oracle dispute movement does not match its retained dispute and economics"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    dispute_id,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                ))?;
                (
                    dispute.challenger.clone(),
                    RetainedNumericAssetMovementPurpose::OracleDisputeResolution(binding),
                )
            }
        };
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(&transcript_authority, retained_purpose),
        )
    }
    /// Bond an exact user's stake, with one explicitly checked genesis bootstrap exception.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_staking_bond_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        lane_id: iroha_model_base::topology::LaneId,
        validator: &AccountId,
        staker: &AccountId,
        genesis: bool,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        if source_id.account() != staker {
            return Err(InstructionExecutionError::InvariantViolation(
                "staking bond source does not match the exact staker".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            lane_id,
            validator.clone(),
            staker.clone(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        let movement = PreparedNumericAssetMovement::prepare(
            state_transaction,
            source_id,
            destination_id,
            amount.clone(),
            NumericAssetMovementAuthorization::embedded_user(
                submitting_authority,
                EmbeddedNumericAssetMovementPurpose::StakingBond {
                    source_authority: staker.clone(),
                    genesis,
                    binding,
                },
            ),
        )?;
        let custody = crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
            &state_transaction.world,
            lane_id,
            validator,
            &movement.plan.destination_id,
            &amount,
            &movement.plan.prechecked_delta.to_balance_after,
        )
        .map_err(|error| {
            state_transaction
                .world
                .attempt_error_to_instruction_error(error)
        })?;
        movement.apply(state_transaction)?;
        custody.apply(&mut state_transaction.world);
        Ok(())
    }

    /// Release one exact matured public-lane unbonding record.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_staking_unbond_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        lane_id: iroha_model_base::topology::LaneId,
        validator: &AccountId,
        staker: &AccountId,
        request_id: iroha_crypto::Hash,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let key = (lane_id, validator.clone(), staker.clone());
        let pending_matches = state_transaction
            .world
            .public_lane_stake_shares
            .get(&key)
            .and_then(|share| share.pending_unbonds.get(&request_id))
            .is_some_and(|pending| {
                pending.amount == amount
                    && pending.release_at_ms <= state_transaction.block_unix_timestamp_ms()
            });
        if authority != staker
            || !crate::smartcontracts::isi::staking::is_retained_staking_unbond_movement(
                state_transaction,
                lane_id,
                validator,
                staker,
                &source_id,
                &destination_id,
            )?
            || !pending_matches
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "staking unbond movement does not match its exact matured retained record".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            lane_id,
            validator.clone(),
            staker.clone(),
            request_id,
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        let custody = crate::smartcontracts::isi::staking::prepare_stake_custody_debit(
            &state_transaction.world,
            lane_id,
            validator,
            &source_id,
            &amount,
        )?;
        custody.apply(&mut state_transaction.world);
        let result = execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                authority,
                RetainedNumericAssetMovementPurpose::StakingUnbond(binding),
            ),
        );
        if result.is_err() {
            custody.restore(&mut state_transaction.world);
        }
        result
    }
    /// Consume an exact retained public-lane slash capability from a transaction entrypoint.
    pub(in crate::smartcontracts::isi) fn execute_verified_staking_slash_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::staking::VerifiedStakingSlashDebit,
    ) -> Result<(), Error> {
        execute_verified_staking_slash_transfer_inner(state_transaction, authorization, true)
    }
    /// Apply a consensus slash without transaction-execution evidence.
    pub(in crate::smartcontracts::isi) fn execute_verified_consensus_staking_slash_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::staking::VerifiedStakingSlashDebit,
    ) -> Result<(), Error> {
        execute_verified_staking_slash_transfer_inner(state_transaction, authorization, false)
    }
    fn execute_verified_staking_slash_transfer_inner(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::staking::VerifiedStakingSlashDebit,
        record_observability: bool,
    ) -> Result<(), Error> {
        let (lane_id, validator, slash_id, source_id, destination_id, amount, slashable_exposure) =
            authorization.into_parts();
        let key = (lane_id, validator.clone());
        let _record = state_transaction
            .world
            .public_lane_validators
            .get(&key)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "staking slash capability has no retained validator record".into(),
                )
            })?;
        if slashable_exposure < amount
            || !crate::smartcontracts::isi::staking::is_retained_staking_slash_movement(
                state_transaction,
                lane_id,
                &validator,
                &source_id,
                &destination_id,
            )
            .map_err(|error| state_transaction.attempt_error_to_instruction_error(error))?
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "staking slash capability does not match retained stake and configured custody"
                    .into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            lane_id,
            validator.clone(),
            slash_id,
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
            slashable_exposure,
        ))?;
        let custody = crate::smartcontracts::isi::staking::prepare_stake_custody_debit(
            &state_transaction.world,
            lane_id,
            &validator,
            &source_id,
            &amount,
        )?;
        custody.apply(&mut state_transaction.world);
        let result = (|| {
            let movement = PreparedNumericAssetMovement::prepare(
                state_transaction,
                source_id,
                destination_id,
                amount,
                NumericAssetMovementAuthorization::retained(
                    &validator,
                    RetainedNumericAssetMovementPurpose::StakingSlash(binding),
                ),
            )?;
            if record_observability {
                movement.apply(state_transaction)
            } else {
                movement.apply_without_observability(state_transaction)
            }
        })();
        if result.is_err() {
            custody.restore(&mut state_transaction.world);
        }
        result
    }
    fn prepare_verified_governance_numeric_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::world::isi::VerifiedGovernanceNumericMovement,
    ) -> Result<PreparedNumericAssetMovement, Error> {
        use crate::smartcontracts::isi::world::isi::VerifiedGovernanceNumericPurpose;
        let (purpose, source_id, destination_id, amount) = authorization.into_parts();
        let (transcript_authority, retained_purpose) = match purpose {
            VerifiedGovernanceNumericPurpose::LockSlash {
                referendum_id,
                owner,
                reason,
            } => {
                let record = state_transaction
                    .world
                    .governance_locks
                    .get(&referendum_id)
                    .and_then(|locks| locks.locks.get(&owner))
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "governance slash capability has no retained lock".into(),
                        )
                    })?;
                let custody = &record.custody;
                let expected_source = AssetId::new(
                    custody.asset_definition_id.clone(),
                    custody.bond_escrow_account.clone(),
                );
                let expected_destination = AssetId::new(
                    custody.asset_definition_id.clone(),
                    custody.slash_receiver_account.clone(),
                );
                if !custody.escrowed
                    || source_id != expected_source
                    || destination_id != expected_destination
                    || amount > record.amount
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "governance slash capability does not match its retained lock custody"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    referendum_id,
                    owner.clone(),
                    reason,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                    record.amount.clone(),
                    record.slashed.clone(),
                ))?;
                (
                    owner,
                    RetainedNumericAssetMovementPurpose::GovernanceSlash(binding),
                )
            }
            VerifiedGovernanceNumericPurpose::LockRestitution {
                referendum_id,
                owner,
                reason,
            } => {
                let record = state_transaction
                    .world
                    .governance_locks
                    .get(&referendum_id)
                    .and_then(|locks| locks.locks.get(&owner))
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "governance restitution capability has no retained lock".into(),
                        )
                    })?;
                let custody = &record.custody;
                let expected_source = AssetId::new(
                    custody.asset_definition_id.clone(),
                    custody.slash_receiver_account.clone(),
                );
                let expected_destination = AssetId::new(
                    custody.asset_definition_id.clone(),
                    custody.bond_escrow_account.clone(),
                );
                let ledger_available = state_transaction
                    .world
                    .governance_slashes
                    .get(&referendum_id)
                    .and_then(|ledger| ledger.slashes.get(&owner))
                    .and_then(|entry| {
                        entry
                            .total_slashed
                            .checked_sub(&entry.total_restituted)
                            .ok()
                    });
                if !custody.escrowed
                    || source_id != expected_source
                    || destination_id != expected_destination
                    || amount > record.slashed
                    || ledger_available.is_none_or(|available| amount > available)
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "governance restitution capability does not match its lock and slash ledger"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    referendum_id,
                    owner.clone(),
                    reason,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                    record.amount.clone(),
                    record.slashed.clone(),
                ))?;
                (
                    owner,
                    RetainedNumericAssetMovementPurpose::GovernanceRestitution(binding),
                )
            }
            VerifiedGovernanceNumericPurpose::CitizenshipRelease { owner } => {
                let record = state_transaction
                    .world
                    .citizens
                    .get(&owner)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "citizenship release capability has no retained citizenship record"
                                .into(),
                        )
                    })?;
                let expected_source = AssetId::new(
                    state_transaction.gov.citizenship_asset_id.clone(),
                    state_transaction.gov.citizenship_escrow_account.clone(),
                );
                let expected_destination = AssetId::new(
                    state_transaction.gov.citizenship_asset_id.clone(),
                    owner.clone(),
                );
                if source_id != expected_source
                    || destination_id != expected_destination
                    || amount != record.amount
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "citizenship release capability does not match its retained bond".into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    owner.clone(),
                    amount.clone(),
                    record.bonded_height,
                ))?;
                (
                    owner,
                    RetainedNumericAssetMovementPurpose::CitizenshipRelease(binding),
                )
            }
        };
        PreparedNumericAssetMovement::prepare(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(&transcript_authority, retained_purpose),
        )
    }
    /// Validate one exact governance movement without mutating balances or observability state.
    pub(in crate::smartcontracts::isi) fn validate_verified_governance_numeric_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::world::isi::VerifiedGovernanceNumericMovement,
    ) -> Result<(), Error> {
        prepare_verified_governance_numeric_movement(state_transaction, authorization).map(drop)
    }
    /// Consume one exact governance movement capability created after retained-state checks.
    pub(in crate::smartcontracts::isi) fn execute_verified_governance_numeric_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::world::isi::VerifiedGovernanceNumericMovement,
    ) -> Result<(), Error> {
        prepare_verified_governance_numeric_movement(state_transaction, authorization)?
            .apply(state_transaction)
    }
    /// Consume one exact expired-governance-lock capability produced by the block-start sweep.
    pub(crate) fn execute_verified_governance_unlock(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::state::VerifiedGovernanceUnlock,
    ) -> Result<(), Error> {
        let (referendum_id, owner, source_id, destination_id, amount) = authorization.into_parts();
        let record = state_transaction
            .world
            .governance_locks
            .get(&referendum_id)
            .and_then(|locks| locks.locks.get(&owner))
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "governance unlock capability has no retained lock".into(),
                )
            })?;
        let custody = &record.custody;
        let expected_source = AssetId::new(
            custody.asset_definition_id.clone(),
            custody.bond_escrow_account.clone(),
        );
        let expected_destination = AssetId::new(custody.asset_definition_id.clone(), owner.clone());
        if !custody.escrowed
            || record.expiry_height >= state_transaction.block_height()
            || source_id != expected_source
            || destination_id != expected_destination
            || amount != record.amount
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "governance unlock capability does not match its expired retained lock".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            referendum_id,
            owner.clone(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
            record.expiry_height,
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                &owner,
                RetainedNumericAssetMovementPurpose::GovernanceUnlock(binding),
            ),
        )
    }
    /// Consume one exact approved SoraFS reserve withdrawal capability.
    pub(in crate::smartcontracts::isi) fn execute_verified_sorafs_reserve_withdrawal(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::sorafs_reserve::VerifiedSorafsReserveWithdrawal,
    ) -> Result<(), Error> {
        let (
            provider_id,
            movement_id,
            policy_digest,
            expected_provider_revision,
            decision_authority,
            source_id,
            destination_id,
            amount,
        ) = authorization.into_parts();
        crate::smartcontracts::isi::sorafs_reserve::validate_verified_reserve_withdrawal(
            state_transaction.world(),
            provider_id,
            movement_id,
            policy_digest,
            expected_provider_revision,
            &decision_authority,
            &source_id,
            &destination_id,
            &amount,
        )?;
        let binding = canonical_numeric_movement_binding(&(
            provider_id,
            movement_id,
            policy_digest,
            expected_provider_revision,
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                &decision_authority,
                RetainedNumericAssetMovementPurpose::SorafsReserve(binding),
            ),
        )
    }
    /// Lock `amount` of the submitting authority's `source_id` balance into the SCCP route
    /// escrow `escrow_id` for the outbound message `message_id` (`specs/sccp.md` §4.15).
    ///
    /// Only `RecordSccpMessage` calls this; every other credit of an escrow is rejected.
    pub(in crate::smartcontracts::isi) fn execute_sccp_escrow_lock(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: AssetId,
        escrow_id: AssetId,
        amount: Quantity,
        message_id: [u8; 32],
    ) -> Result<(), Error> {
        if source_id.account() != authority || escrow_id.definition() != source_id.definition() {
            return Err(InstructionExecutionError::InvariantViolation(
                "SCCP escrow lock must debit the submitting authority's own balance of the escrowed asset"
                    .into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            message_id,
            source_id.clone(),
            escrow_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            escrow_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::SccpEscrowLock(binding),
            ),
        )
    }
    /// Release `amount` from the SCCP route escrow `escrow_id` to the existing account of
    /// `destination_id` for the record `record_id` (inbound release, outbound refund or
    /// Parliament-enacted stranded release, `specs/sccp.md` §4.15).
    pub(in crate::smartcontracts::isi) fn execute_sccp_escrow_release(
        state_transaction: &mut StateTransaction<'_, '_>,
        escrow_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        record_id: [u8; 32],
    ) -> Result<(), Error> {
        if escrow_id.definition() != destination_id.definition() {
            return Err(InstructionExecutionError::InvariantViolation(
                "SCCP escrow release must credit the escrowed asset".into(),
            ));
        }
        let transcript_authority = destination_id.account().clone();
        let binding = canonical_numeric_movement_binding(&(
            record_id,
            escrow_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            escrow_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                &transcript_authority,
                RetainedNumericAssetMovementPurpose::SccpEscrowRelease(binding),
            ),
        )
    }
    /// Check, without mutating state, that [`execute_sccp_escrow_release`] of `amount` from the
    /// SCCP route escrow `escrow_id` to the existing account of `destination_id` passes every
    /// guard of the release movement (`specs/sccp.md` §4.12.3, §4.16).
    ///
    /// It mirrors `PreparedNumericTransferPlan::prepare` for the retained
    /// `SccpEscrowRelease` authorization (ambient scope, enforced transfer control, existing
    /// destination) and shares its policy gate
    /// ([`ensure_resolved_numeric_asset_transfer_policies`]), so SCCP settlement holds a
    /// message whose credit the movement would refuse instead of failing the proof or void
    /// that triggered it.
    ///
    /// TODO(ws41): the movement settles retail-fee balances before its balance precheck; this
    /// read-only precheck evaluates the stored balances.
    pub(in crate::smartcontracts::isi) fn precheck_sccp_escrow_release(
        state_transaction: &StateTransaction<'_, '_>,
        escrow_id: &AssetId,
        destination_id: &AssetId,
        amount: &Quantity,
    ) -> Result<(), Error> {
        if escrow_id.definition() != destination_id.definition() {
            return Err(InstructionExecutionError::InvariantViolation(
                "SCCP escrow release must credit the escrowed asset".into(),
            ));
        }
        if amount.is_zero() {
            return Err(InstructionExecutionError::InvariantViolation(
                "asset transfer amount must be non-zero".into(),
            ));
        }
        let source_policy = NumericAssetTransferSourcePolicy::SccpEscrowRelease;
        ensure_global_asset_write_on_authoritative_route(
            state_transaction,
            escrow_id.definition(),
            "transfer",
        )?;
        let source_dataspace = transfer_source_dataspace_hint(state_transaction, escrow_id)?;
        let resolved_source = state_transaction
            .world
            .resolve_asset_id_for_scope_hint(escrow_id, source_dataspace)?;
        ensure_privacy_public_reserve_source_policy(
            state_transaction,
            &resolved_source,
            source_policy,
        )?;
        active_control_record(
            state_transaction,
            escrow_id.account(),
            escrow_id.definition(),
        )?;
        prepare_outbound_asset_transfer_control_update(state_transaction, escrow_id, amount)?;
        state_transaction.world.account(destination_id.account())?;
        let (source_id, destination_id) = resolve_numeric_asset_transfer_scope(
            state_transaction,
            escrow_id,
            destination_id,
            NumericAssetTransferScopePolicy::Ambient,
        )?;
        let spec = state_transaction
            .world
            .asset_definition(source_id.definition())?
            .spec();
        ensure_resolved_numeric_asset_transfer_policies(
            state_transaction,
            &source_id,
            &destination_id,
            amount,
            spec,
            source_policy,
        )?;
        prepare_retail_daily_usage_update(
            state_transaction,
            &source_id,
            &destination_id,
            amount,
            source_policy,
        )?;
        let delta = state_transaction
            .world
            .precheck_numeric_asset_transfer_delta_exact_with_control_policy(
                &source_id,
                &destination_id,
                amount,
                NumericAssetTransferControlPolicy::Enforce,
            )?;
        let source_after = if source_id == destination_id {
            &delta.to_balance_after
        } else {
            &delta.from_balance_after
        };
        crate::smartcontracts::isi::sorafs_moderation::ensure_moderation_bond_reserve_after_debit(
            state_transaction.world(),
            &source_id,
            source_after,
        )?;
        Ok(())
    }
    /// Consume one native AMX movement after independently rejoining exact canonical custody.
    /// The producer is the signed-root participant owner; generic escrow has no constructor.
    pub(crate) fn execute_verified_amx_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::sumeragi::amx::VerifiedAmxMovement,
    ) -> Result<(), Error> {
        use iroha_data_model::sumeragi_amx::{AmxOutcomeV1, AmxVoteV1};
        let (owner, slot, outcome) = authorization.into_parts();
        if !owner.belongs_to(
            state_transaction
                .pipeline_ivm_prepared_cache
                .execution_budget(),
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                "native AMX movement belongs to a foreign allocation pool".into(),
            ));
        }
        let record = owner
            .canonical()
            .and_then(|value| value.escrows.get(slot))
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "native AMX capability lost its exact original funded escrow slot".into(),
                )
            })?;
        let tx = record.tx;
        let effects_hash = iroha_data_model::sumeragi_amx::native_transfer_effects_hash(
            &record.leg,
        )
        .map_err(|error| {
            if let Some(resource) = crate::sumeragi::amx::classified_decode_refusal(&error) {
                state_transaction.arm_local_storage_refusal(
                    crate::state::StateStorageAdmissionError::AmxDecode(resource),
                );
            }
            InstructionExecutionError::InvariantViolation(error.to_string().into())
        })?;
        let participant = state_transaction
            .world
            .sumeragi_amx_participant()
            .canonical()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "native AMX movement has no genesis-installed participant".into(),
                )
            })?;
        if record.tx != tx
            || record.custody != participant.custody
            || record.leg.source.scope()
                != &AssetBalanceScope::Dataspace(participant.participant.dataspace)
            || record.effects_hash != effects_hash
            || record.settled.is_some()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "native AMX movement differs from its exact protected leg".into(),
            ));
        }
        let custody_id = AssetId::with_scope(
            record.leg.source.definition().clone(),
            record.custody.clone(),
            *record.leg.source.scope(),
        );
        let binding = canonical_numeric_movement_binding(&(tx, record.effects_hash, outcome))?;
        let (source_id, destination_id, authorization) = match outcome {
            None => {
                if participant.participant.entry(&tx).is_some()
                    || participant
                        .escrows
                        .binary_search_by_key(&tx, |record| record.tx)
                        .is_ok()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "native AMX funding repeats an original transaction".into(),
                    ));
                }
                (
                    record.leg.source.clone(),
                    custody_id,
                    NumericAssetMovementAuthorization::embedded_user(
                        record.leg.source.account(),
                        EmbeddedNumericAssetMovementPurpose::NativeAmx(binding),
                    ),
                )
            }
            Some(outcome) => {
                let original = participant
                    .escrows
                    .binary_search_by_key(&tx, |record| record.tx)
                    .ok()
                    .map(|slot| &participant.escrows[slot]);
                if original != Some(record)
                    || !participant.participant.entry(&tx).is_some_and(|entry| {
                        entry.settled.is_none() && entry.vote == AmxVoteV1::Yes(record.effects_hash)
                    })
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "native AMX settlement has no identical original unsettled Yes escrow"
                            .into(),
                    ));
                }
                let receiver = match outcome {
                    AmxOutcomeV1::Commit => &record.leg.destination,
                    AmxOutcomeV1::Abort => record.leg.source.account(),
                };
                let destination = AssetId::with_scope(
                    record.leg.source.definition().clone(),
                    receiver.clone(),
                    *record.leg.source.scope(),
                );
                (
                    custody_id,
                    destination,
                    NumericAssetMovementAuthorization::retained(
                        record.leg.source.account(),
                        RetainedNumericAssetMovementPurpose::NativeAmx(binding),
                    ),
                )
            }
        };
        PreparedNumericAssetMovement::prepare_with_scope(
            state_transaction,
            source_id,
            destination_id,
            record.leg.amount.clone(),
            authorization,
            NumericAssetTransferScopePolicy::ExplicitBilateral,
        )?
        .apply(state_transaction)
    }
    /// Consume one exact native-escrow movement capability.
    pub(in crate::smartcontracts::isi) fn execute_verified_native_escrow_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::escrow::VerifiedNativeEscrowMovement,
    ) -> Result<(), Error> {
        use crate::smartcontracts::isi::escrow::VerifiedNativeEscrowPurpose;
        let (purpose, source_id, destination_id, amount) = authorization.into_parts();
        let movement_authorization = match purpose {
            VerifiedNativeEscrowPurpose::Funding {
                escrow_id,
                authority,
            } => {
                let expected_custody =
                    crate::smartcontracts::isi::escrow::escrow_custody_account_id(
                        state_transaction.network_id(),
                        &escrow_id,
                        source_id.definition(),
                    );
                if source_id.account() != &authority
                    || destination_id.definition() != source_id.definition()
                    || destination_id.account() != &expected_custody
                    || state_transaction
                        .world
                        .asset_escrows
                        .get(&escrow_id)
                        .is_some()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "native escrow funding capability does not match its authority and deterministic custody"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    escrow_id,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                ))?;
                NumericAssetMovementAuthorization::embedded_user(
                    &authority,
                    EmbeddedNumericAssetMovementPurpose::NativeEscrow(binding),
                )
            }
            VerifiedNativeEscrowPurpose::Retained { escrow_id } => {
                let record = state_transaction
                    .world
                    .asset_escrows
                    .get(&escrow_id)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "native escrow release capability has no retained record".into(),
                        )
                    })?;
                let expected_source =
                    AssetId::new(record.asset_definition.clone(), record.custody.clone());
                let destination_is_party = destination_id.account() == &record.seller
                    || record
                        .buyer
                        .as_ref()
                        .is_some_and(|buyer| destination_id.account() == buyer);
                if source_id != expected_source
                    || destination_id.definition() != &record.asset_definition
                    || !destination_is_party
                    || amount > record.remaining_amount
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "native escrow release capability does not match its retained record"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    escrow_id,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                    record.remaining_amount.clone(),
                    record.status,
                ))?;
                NumericAssetMovementAuthorization::retained(
                    &record.seller,
                    RetainedNumericAssetMovementPurpose::NativeEscrow(binding),
                )
            }
            VerifiedNativeEscrowPurpose::CustodyPartition {
                parent_id,
                child_id,
            } => {
                let parent = state_transaction
                    .world
                    .asset_escrows
                    .get(&parent_id)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "native escrow partition capability has no retained parent".into(),
                        )
                    })?;
                let expected_source =
                    AssetId::new(parent.asset_definition.clone(), parent.custody.clone());
                let child_custody = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
                    state_transaction.network_id(),
                    &child_id,
                    &parent.asset_definition,
                );
                let expected_destination =
                    AssetId::new(parent.asset_definition.clone(), child_custody);
                if source_id != expected_source
                    || destination_id != expected_destination
                    || amount > parent.remaining_amount
                    || state_transaction
                        .world
                        .asset_escrows
                        .get(&child_id)
                        .is_some()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "native escrow partition capability does not match its retained parent and child custody"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    parent_id,
                    child_id,
                    source_id.clone(),
                    destination_id.clone(),
                    amount.clone(),
                    parent.remaining_amount.clone(),
                ))?;
                NumericAssetMovementAuthorization::retained(
                    &parent.seller,
                    RetainedNumericAssetMovementPurpose::NativeEscrow(binding),
                )
            }
        };
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            movement_authorization,
        )
    }
    /// Consume an exact multi-recipient native escrow settlement capability atomically.
    pub(in crate::smartcontracts::isi) fn execute_verified_native_escrow_batch(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::escrow::VerifiedNativeEscrowBatch,
    ) -> Result<(), Error> {
        let (escrow_id, authority, legs) = authorization.into_parts();
        let record = state_transaction
            .world
            .asset_escrows
            .get(&escrow_id)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "native escrow batch has no retained lock".into(),
                )
            })?;
        let expected_source = AssetId::new(record.asset_definition.clone(), record.custody.clone());
        let mut total = Quantity::zero();
        for (source, destination, amount) in &legs {
            if source != &expected_source
                || destination.definition() != &record.asset_definition
                || destination.account() == &record.custody
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "native escrow batch leg does not match retained custody".into(),
                ));
            }
            total = total.checked_add(amount).map_err(|_| MathError::Overflow)?;
        }
        if total > record.remaining_amount || record.release_authority.as_ref() != Some(&authority)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "native escrow batch exceeds its retained lock or has the wrong authority".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            escrow_id,
            authority.clone(),
            legs.clone(),
            record.remaining_amount.clone(),
            record.status,
        ))?;
        let movement_authorization = NumericAssetMovementAuthorization::retained(
            &authority,
            RetainedNumericAssetMovementPurpose::NativeEscrow(binding),
        );
        let applied = PreparedNumericAssetMovementBatch::prepare_with_authorization(
            state_transaction,
            &legs,
            movement_authorization,
        )?
        .apply(state_transaction)?;
        for movement in applied {
            #[allow(clippy::float_arithmetic)]
            #[cfg(feature = "telemetry")]
            state_transaction
                .telemetry
                .observe_tx_amount(movement.amount.as_numeric().clone().to_f64_lossy());
            emit_numeric_asset_transfer_events(
                state_transaction,
                movement.source_id,
                movement.destination_id,
                movement.amount,
            );
        }
        Ok(())
    }
    /// Consume one exact bond-vault movement selected by the bond kernel.
    ///
    /// The capability is re-checked against the stored bond record and
    /// entitlement before any balance is touched: funding moves exactly the
    /// recorded amount due from the signer into the deterministic vault, and a
    /// payment moves exactly one unclaimed entitlement's amount from the vault to
    /// its holder.
    pub(in crate::smartcontracts::isi) fn execute_verified_bond_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::bond::VerifiedBondMovement,
    ) -> Result<(), Error> {
        use crate::smartcontracts::isi::bond::VerifiedBondMovementPurpose;
        use iroha_data_model::bond::{BondCashflowStatus, BondEntitlementId};
        let (purpose, authority, bond, index, source_id, destination_id, amount) =
            authorization.into_parts();
        let mismatch = |what: &str| {
            InstructionExecutionError::InvariantViolation(
                format!("bond {what} capability does not match its retained record").into(),
            )
        };
        let record = state_transaction
            .world
            .bonds
            .get(&bond)
            .ok_or_else(|| mismatch("movement"))?;
        let cashflow = record.cashflow(index).ok_or_else(|| mismatch("movement"))?;
        let payment = &record.terms.payment_asset;
        let vault = record.vault.clone();
        if source_id.definition() != payment
            || destination_id.definition() != payment
            || source_id.scope() != &AssetBalanceScope::Global
            || destination_id.scope() != &AssetBalanceScope::Global
            || amount.is_zero()
        {
            return Err(mismatch("movement"));
        }
        let (tag, movement_authorization) = match purpose {
            VerifiedBondMovementPurpose::Funding => {
                let signer_may_fund =
                    authority == record.terms.paying_agent || authority == record.terms.issuer;
                if !signer_may_fund
                    || source_id.account() != &authority
                    || destination_id.account() != &vault
                    || cashflow.status != BondCashflowStatus::Recorded
                    || amount != cashflow.amount_due
                {
                    return Err(mismatch("funding"));
                }
                ("funding", None)
            }
            VerifiedBondMovementPurpose::Payment => {
                let holder = destination_id.account();
                let entitlement = state_transaction
                    .world
                    .bond_entitlements
                    .get(&BondEntitlementId::new(bond.clone(), index, holder.clone()));
                let remaining = cashflow
                    .funded
                    .checked_sub(&cashflow.paid)
                    .map_err(|_| mismatch("payment"))?;
                if source_id.account() != &vault
                    || !cashflow.is_claimable()
                    || entitlement.is_none_or(|entitlement| {
                        entitlement.claimed_at_ms.is_some() || entitlement.amount != amount
                    })
                    || (authority != *holder && authority != record.terms.paying_agent)
                    || amount > remaining
                {
                    return Err(mismatch("payment"));
                }
                ("payment", Some(()))
            }
        };
        let binding = canonical_numeric_movement_binding(&(
            tag,
            bond.clone(),
            index,
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
            cashflow.funded.clone(),
            cashflow.paid.clone(),
        ))?;
        let movement_authorization = match movement_authorization {
            None => NumericAssetMovementAuthorization::embedded_user(
                &authority,
                EmbeddedNumericAssetMovementPurpose::BondFunding(binding),
            ),
            Some(()) => NumericAssetMovementAuthorization::retained(
                &authority,
                RetainedNumericAssetMovementPurpose::BondVault(binding),
            ),
        };
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            movement_authorization,
        )
    }
    /// Consume one exact redemption-claim burn selected by the bond kernel.
    ///
    /// Burns exactly the units of one unclaimed redemption entitlement from its
    /// holder; this is the only supply change a registered bond admits.
    pub(in crate::smartcontracts::isi) fn execute_verified_bond_redemption_burn(
        state_transaction: &mut StateTransaction<'_, '_>,
        burn: crate::smartcontracts::isi::bond::VerifiedBondRedemptionBurn,
    ) -> Result<(), Error> {
        use iroha_data_model::bond::{BondCashflowKind, BondEntitlementId};
        let (authority, bond, index, holder, units) = burn.into_parts();
        let record = state_transaction.world.bonds.get(&bond).ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "bond redemption burn has no retained bond record".into(),
            )
        })?;
        let entitled = state_transaction
            .world
            .bond_entitlements
            .get(&BondEntitlementId::new(bond.clone(), index, holder.clone()))
            .is_some_and(|entitlement| {
                entitlement.units == units && entitlement.claimed_at_ms.is_none()
            });
        let matches_record = record.cashflow(index).is_some_and(|cashflow| {
            cashflow.terms.kind == BondCashflowKind::Redemption && cashflow.is_claimable()
        }) && entitled
            && (authority == holder || authority == record.terms.paying_agent)
            && !units.is_zero();
        if !matches_record {
            return Err(InstructionExecutionError::InvariantViolation(
                "bond redemption burn capability does not match its retained record".into(),
            ));
        }
        execute_checked_numeric_asset_burn(
            state_transaction,
            Some(&authority),
            AssetId::new(bond, holder),
            units,
            NumericAssetBurnSourcePolicy::BondRedemption,
            None,
        )
    }
    /// Burn exact units of the issuer's own global balance for `RetireBondTreasuryUnits`.
    pub(in crate::smartcontracts::isi) fn execute_verified_bond_treasury_retirement(
        state_transaction: &mut StateTransaction<'_, '_>,
        retirement: crate::smartcontracts::isi::bond::VerifiedBondTreasuryRetirement,
    ) -> Result<(), Error> {
        let (authority, bond, units) = retirement.into_parts();
        let record = state_transaction.world.bonds.get(&bond).ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "bond treasury retirement has no retained bond record".into(),
            )
        })?;
        let matches_record = authority == record.terms.issuer
            && crate::smartcontracts::isi::bond::recording_in_progress(record).is_none()
            && !units.is_zero();
        if !matches_record {
            return Err(InstructionExecutionError::InvariantViolation(
                "bond treasury retirement capability does not match its retained record".into(),
            ));
        }
        execute_checked_numeric_asset_burn(
            state_transaction,
            Some(&authority),
            AssetId::new(bond, authority.clone()),
            units,
            NumericAssetBurnSourcePolicy::BondTreasuryRetirement,
            None,
        )
    }
    /// Consume an exact game capability; only initial awards may defer before any transfer writes.
    pub(in crate::smartcontracts::isi) fn execute_verified_game_movement(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::game::VerifiedGameMovement,
    ) -> Result<bool, Error> {
        use crate::smartcontracts::isi::game::VerifiedGameMovementPurpose;
        use iroha_data_model::game::GamePhaseV1;
        let (session_id, authority, purpose, legs) = authorization.into_parts();
        let session = state_transaction
            .world
            .game_sessions
            .get(&session_id)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "session movement has no retained session".into(),
                )
            })?;
        let expected_custody = crate::smartcontracts::isi::game::game_custody_account_v1(
            state_transaction.network_id(),
            &session_id,
            &session.asset_definition,
        );
        if session.custody != expected_custody
            || legs.len() > iroha_data_model::game::GAME_MAX_PARTICIPANTS_V1
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "session custody or movement bounds invalid".into(),
            ));
        }
        let custody_asset = AssetId::new(session.asset_definition.clone(), expected_custody);
        if !matches!(&purpose, VerifiedGameMovementPurpose::Funding) {
            let resolved = state_transaction
                .world
                .resolve_asset_id_for_current_scope(&custody_asset)?;
            let balance = state_transaction
                .world
                .assets
                .get(&resolved)
                .map(|value| value.as_ref().clone())
                .unwrap_or_else(Quantity::zero);
            if balance != session.liability {
                return Err(InstructionExecutionError::InvariantViolation(
                    "session claims differ from exact retained custody".into(),
                ));
            }
        }
        let binding =
            canonical_numeric_movement_binding(&(session_id, session.revision, legs.clone()))?;
        let may_defer = matches!(&purpose, VerifiedGameMovementPurpose::Settlement);
        let movement = match purpose {
            VerifiedGameMovementPurpose::Funding => {
                if legs.as_slice()
                    != [(
                        AssetId::new(session.asset_definition.clone(), authority.clone()),
                        custody_asset,
                        session.stake.clone(),
                    )]
                    || session.phase != GamePhaseV1::Lobby
                    || session
                        .participants
                        .iter()
                        .any(|participant| participant.account == authority)
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "session funding differs from exact wallet-authorized seat".into(),
                    ));
                }
                let current = state_transaction
                    .world
                    .assets
                    .get(&AssetId::new(
                        session.asset_definition.clone(),
                        session.custody.clone(),
                    ))
                    .map(|value| value.as_ref().clone())
                    .unwrap_or_else(Quantity::zero);
                if current != session.liability {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "session funding reserve differs from its exact admitted liability".into(),
                    ));
                }
                NumericAssetMovementAuthorization::embedded_user(
                    &authority,
                    EmbeddedNumericAssetMovementPurpose::GameSession(binding),
                )
            }
            VerifiedGameMovementPurpose::Settlement => {
                if authority != session.custody
                    || matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled)
                    || !session.payout_claims.is_empty()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "session custody has already settled".into(),
                    ));
                }
                let mut total = Quantity::zero();
                for (source, destination, amount) in &legs {
                    if source != &custody_asset
                        || destination.definition() != &session.asset_definition
                        || !session
                            .participants
                            .iter()
                            .any(|participant| &participant.account == destination.account())
                    {
                        return Err(InstructionExecutionError::InvariantViolation(
                            "session payout differs from immutable roster".into(),
                        ));
                    }
                    total = total.checked_add(amount).map_err(|_| MathError::Overflow)?;
                }
                if total != session.liability {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "session payout must consume exact retained liability".into(),
                    ));
                }
                NumericAssetMovementAuthorization::retained(
                    &authority,
                    RetainedNumericAssetMovementPurpose::GameSession(binding),
                )
            }
            VerifiedGameMovementPurpose::Claim { slot } => {
                let claim = session
                    .payout_claims
                    .iter()
                    .find(|claim| claim.slot == slot)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "session has no matching payout claim".into(),
                        )
                    })?;
                let owner = &session
                    .participants
                    .get(usize::from(slot))
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "session claim owner is absent".into(),
                        )
                    })?
                    .account;
                let [(source, destination, amount)] = legs.as_slice() else {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "session claim requires one exact transfer".into(),
                    ));
                };
                if !matches!(session.phase, GamePhaseV1::Settled | GamePhaseV1::Cancelled)
                    || source != &custody_asset
                    || destination.definition() != &session.asset_definition
                    || destination.account() == &session.custody
                    || (destination.account() != owner && &authority != owner)
                    || amount.is_zero()
                    || amount > &claim.remaining
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "session claim exceeds its immutable owner authorization or remaining amount"
                            .into(),
                    ));
                }
                NumericAssetMovementAuthorization::retained(
                    &session.custody,
                    RetainedNumericAssetMovementPurpose::GameSession(binding),
                )
            }
        };
        // This purpose only admits existing destination accounts. Preparation
        // performs policy checks and checked balance arithmetic without account,
        // balance, control, event, or transcript writes. A failure can therefore
        // retain all exact backed claims instead of vetoing the proved result.
        let prepared = match PreparedNumericAssetMovementBatch::prepare_with_authorization(
            state_transaction,
            &legs,
            movement,
        ) {
            Ok(prepared) => prepared,
            Err(_) if may_defer => return Ok(false),
            Err(error) => return Err(error),
        };
        let applied = prepared.apply(state_transaction)?;
        for movement in applied {
            emit_numeric_asset_transfer_events(
                state_transaction,
                movement.source_id,
                movement.destination_id,
                movement.amount,
            );
        }
        Ok(true)
    }
    /// Consume an exact VPN funding, settlement, or refund capability atomically.
    pub(in crate::smartcontracts::isi) fn execute_verified_vpn_numeric_batch(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::vpn::VerifiedVpnNumericBatch,
    ) -> Result<(), Error> {
        use crate::smartcontracts::isi::vpn::VerifiedVpnNumericPurpose;
        let (purpose, legs) = authorization.into_parts();
        let movement_authorization = match purpose {
            VerifiedVpnNumericPurpose::Funding {
                lease_id,
                authority,
            } => {
                if legs.len() != 1 || state_transaction.world.vpn_leases.get(&lease_id).is_some() {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "VPN funding capability must contain one fresh lease leg".into(),
                    ));
                }
                let (source, destination, amount) = &legs[0];
                let expected_custody =
                    crate::smartcontracts::isi::vpn::vpn_lease_custody_account_id(
                        state_transaction.network_id(),
                        &lease_id,
                        source.definition(),
                    );
                if source.account() != &authority
                    || destination.definition() != source.definition()
                    || destination.account() != &expected_custody
                    || amount.is_zero()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "VPN funding capability does not match its authority and deterministic custody"
                            .into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    lease_id,
                    source.clone(),
                    destination.clone(),
                    amount.clone(),
                ))?;

                NumericAssetMovementAuthorization::embedded_user(
                    &authority,
                    EmbeddedNumericAssetMovementPurpose::VpnLease(binding),
                )
            }
            VerifiedVpnNumericPurpose::Settlement {
                lease_id,
                authority,
            } => {
                let record = state_transaction
                    .world
                    .vpn_leases
                    .get(&lease_id)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "VPN settlement capability has no retained lease".into(),
                        )
                    })?;
                let expected_source = AssetId::new(
                    record.asset_definition.clone(),
                    record.custody_account_id.clone(),
                );
                let mut total = Quantity::zero();
                for (source, destination, amount) in &legs {
                    let destination_is_party = destination.account() == &record.operator_account_id
                        || destination.account() == &record.client_account_id;
                    if source != &expected_source
                        || destination.definition() != &record.asset_definition
                        || !destination_is_party
                    {
                        return Err(InstructionExecutionError::InvariantViolation(
                            "VPN settlement leg does not match retained lease custody and parties"
                                .into(),
                        ));
                    }
                    total = total.checked_add(amount).map_err(|_| MathError::Overflow)?;
                }
                if authority != record.operator_account_id
                    || total != record.lease_fee
                    || record.status != iroha_data_model::soranet::vpn::VpnLeaseStatusV1::Active
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "VPN settlement capability does not match the active retained lease".into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    lease_id,
                    authority.clone(),
                    legs.clone(),
                    record.lease_fee.clone(),
                    record.status,
                ))?;

                NumericAssetMovementAuthorization::retained(
                    &authority,
                    RetainedNumericAssetMovementPurpose::VpnLease(binding),
                )
            }
            VerifiedVpnNumericPurpose::Refund {
                lease_id,
                authority,
            } => {
                let record = state_transaction
                    .world
                    .vpn_leases
                    .get(&lease_id)
                    .ok_or_else(|| {
                        InstructionExecutionError::InvariantViolation(
                            "VPN refund capability has no retained lease".into(),
                        )
                    })?;
                let expected_source = AssetId::new(
                    record.asset_definition.clone(),
                    record.custody_account_id.clone(),
                );
                let expected_destination = AssetId::new(
                    record.asset_definition.clone(),
                    record.client_account_id.clone(),
                );
                let exact_leg = legs.as_slice()
                    == [(
                        expected_source,
                        expected_destination,
                        record.lease_fee.clone(),
                    )];
                if !exact_leg
                    || record.status != iroha_data_model::soranet::vpn::VpnLeaseStatusV1::Active
                    || state_transaction.block_unix_timestamp_ms() < record.refund_available_at_ms()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "VPN refund capability does not match the expired retained lease".into(),
                    ));
                }
                let binding = canonical_numeric_movement_binding(&(
                    lease_id,
                    authority.clone(),
                    legs.clone(),
                    record.refund_available_at_ms(),
                ))?;

                NumericAssetMovementAuthorization::retained(
                    &authority,
                    RetainedNumericAssetMovementPurpose::VpnLease(binding),
                )
            }
        };
        let applied = PreparedNumericAssetMovementBatch::prepare_with_authorization(
            state_transaction,
            &legs,
            movement_authorization,
        )?
        .apply(state_transaction)?;
        for movement in applied {
            #[allow(clippy::float_arithmetic)]
            #[cfg(feature = "telemetry")]
            state_transaction
                .telemetry
                .observe_tx_amount(movement.amount.as_numeric().clone().to_f64_lossy());
            emit_numeric_asset_transfer_events(
                state_transaction,
                movement.source_id,
                movement.destination_id,
                movement.amount,
            );
        }
        Ok(())
    }
    /// Lock an exact user's governance voting bond.
    pub(crate) fn execute_governance_bond_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        referendum_id: &str,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        if source_id.account() != authority {
            return Err(InstructionExecutionError::InvariantViolation(
                "governance bond source does not match its exact authority".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            referendum_id.to_owned(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::GovernanceBond(binding),
            ),
        )
    }
    /// Lock an exact user's citizenship bond in configured custody.
    pub(crate) fn execute_citizenship_bond_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        owner: &AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let initial_genesis = crate::executor::is_initial_genesis_context(state_transaction);
        if (authority != owner && !initial_genesis)
            || source_id.account() != owner
            || source_id.definition() != &state_transaction.gov.citizenship_asset_id
            || destination_id.account() != &state_transaction.gov.citizenship_escrow_account
            || destination_id.definition() != &state_transaction.gov.citizenship_asset_id
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "citizenship bond movement does not match configured custody".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(owner.clone(), amount.clone()))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::CitizenshipBond {
                    source_authority: owner.clone(),
                    initial_genesis,
                    binding,
                },
            ),
        )
    }
    /// Fund one sponsor-owned fee vault from the sponsor's exact prefunded genesis balance.
    pub(crate) fn execute_initial_genesis_fee_sponsor_funding_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        program_id: &iroha_data_model::nexus::FeeSponsorProgramId,
        source_id: AssetId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let destination =
            crate::executor::root_fees::sponsor_vault_custody(state_transaction)?.clone();
        let destination_id = AssetId::new(source_id.definition().clone(), destination);
        if !crate::executor::is_initial_genesis_context(state_transaction)
            || source_id.account() != &program_id.sponsor
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "fee sponsor genesis funding requires the exact sponsor source during initial genesis"
                    .into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            program_id.clone(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                submitting_authority,
                EmbeddedNumericAssetMovementPurpose::InitialGenesisFeeSponsorFunding {
                    source_authority: program_id.sponsor.clone(),
                    binding,
                },
            ),
        )
    }
    enum PreparedTransferControl {
        NotRequired,
        Required(Option<AssetTransferControlRecord>),
    }
    struct PreparedNumericTransferPlan {
        retail_payment: bool,
        source_id: AssetId,
        destination_id: AssetId,
        source_policy: NumericAssetTransferSourcePolicy,
        event_source_id: AssetId,
        event_destination_id: AssetId,
        amount: Quantity,
        control_before: PreparedTransferControl,
        control_update: Option<AssetTransferControlRecord>,
        retail_usage_update: Option<PreparedRetailDailyUsageUpdate>,
        numeric_spec: NumericSpec,
        normalized_scale: u32,
        normalized_amount: Option<u64>,
        prechecked_delta: TransferDeltaTranscript,
    }
    struct AppliedNumericTransfer {
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        // Retain the applied value for exact prepared/applied parity assertions.
        #[cfg(test)]
        delta: TransferDeltaTranscript,
    }
    impl PreparedNumericTransferPlan {
        fn prepare_user(
            state_transaction: &mut StateTransaction<'_, '_>,
            authority: &AccountId,
            event_source_id: AssetId,
            event_destination_id: AssetId,
            amount: Quantity,
        ) -> Result<Self, Error> {
            Self::prepare(
                state_transaction,
                authority,
                event_source_id,
                event_destination_id,
                amount,
                NumericAssetTransferScopePolicy::Ambient,
                NumericAssetTransferAuthorityPolicy::UserSource,
                NumericAssetTransferSourcePolicy::User,
                NumericAssetTransferControlPolicy::Enforce,
                NumericAssetDestinationAdmissionPolicy::ImplicitReceive,
            )
        }
        fn prepare_explicit_bilateral(
            state_transaction: &mut StateTransaction<'_, '_>,
            authority: &AccountId,
            event_source_id: AssetId,
            event_destination_id: AssetId,
            amount: Quantity,
        ) -> Result<Self, Error> {
            Self::prepare(
                state_transaction,
                authority,
                event_source_id,
                event_destination_id,
                amount,
                NumericAssetTransferScopePolicy::ExplicitBilateral,
                NumericAssetTransferAuthorityPolicy::ProtocolAuthorized,
                NumericAssetTransferSourcePolicy::User,
                NumericAssetTransferControlPolicy::Enforce,
                NumericAssetDestinationAdmissionPolicy::ExistingAccount,
            )
        }
        fn prepare(
            state_transaction: &mut StateTransaction<'_, '_>,
            authority: &AccountId,
            event_source_id: AssetId,
            event_destination_id: AssetId,
            amount: Quantity,
            scope_policy: NumericAssetTransferScopePolicy,
            authority_policy: NumericAssetTransferAuthorityPolicy,
            source_policy: NumericAssetTransferSourcePolicy,
            control_policy: NumericAssetTransferControlPolicy,
            destination_admission: NumericAssetDestinationAdmissionPolicy,
        ) -> Result<Self, Error> {
            // Reject no-op transfers before account admission, control usage, transcripts,
            // balances, or events can be staged.
            if amount.is_zero() {
                return Err(InstructionExecutionError::InvariantViolation(
                    "asset transfer amount must be non-zero".into(),
                )
                .into());
            }
            // Every numeric movement path prepares here, so the book closing and
            // the redemption freeze of a registered bond cover all of them.
            crate::smartcontracts::isi::bond::ensure_bond_units_movable(
                state_transaction,
                &event_source_id,
                &event_destination_id,
                source_policy == NumericAssetTransferSourcePolicy::NativeEscrowCustody,
            )?;
            if scope_policy == NumericAssetTransferScopePolicy::Ambient {
                ensure_global_asset_write_on_authoritative_route(
                    state_transaction,
                    event_source_id.definition(),
                    "transfer",
                )?;
            }
            if authority_policy == NumericAssetTransferAuthorityPolicy::UserSource {
                let resolved_source_id = state_transaction
                    .world
                    .resolve_asset_id_for_current_scope(&event_source_id)?;
                ensure_user_numeric_asset_source_authority(
                    state_transaction,
                    authority,
                    &resolved_source_id,
                )?;
            }
            // A batch leg can be rejected without rolling back successful sibling legs.
            // Refuse protected sources before implicit destination admission can create an
            // account for a leg that will never move value.
            let source_dataspace = match scope_policy {
                NumericAssetTransferScopePolicy::Ambient => {
                    transfer_source_dataspace_hint(state_transaction, &event_source_id)?
                }
                NumericAssetTransferScopePolicy::ExplicitBilateral => {
                    match event_source_id.scope() {
                        AssetBalanceScope::Global => None,
                        AssetBalanceScope::Dataspace(dataspace) => Some(*dataspace),
                    }
                }
            };
            let resolved_source_id = state_transaction
                .world
                .resolve_asset_id_for_scope_hint(&event_source_id, source_dataspace)?;
            ensure_privacy_public_reserve_source_policy(
                state_transaction,
                &resolved_source_id,
                source_policy,
            )?;
            let (control_before, control_update) = match control_policy {
                NumericAssetTransferControlPolicy::Enforce => (
                    PreparedTransferControl::Required(active_control_record(
                        state_transaction,
                        event_source_id.account(),
                        event_source_id.definition(),
                    )?),
                    prepare_outbound_asset_transfer_control_update(
                        state_transaction,
                        &event_source_id,
                        &amount,
                    )?,
                ),
                NumericAssetTransferControlPolicy::OraclePenalty
                | NumericAssetTransferControlPolicy::OracleDisputeResolution
                | NumericAssetTransferControlPolicy::StakingUnbond
                | NumericAssetTransferControlPolicy::StakingSlash
                | NumericAssetTransferControlPolicy::ModerationChallengeSettlement
                | NumericAssetTransferControlPolicy::GovernanceSlash
                | NumericAssetTransferControlPolicy::GovernanceRestitution
                | NumericAssetTransferControlPolicy::GovernanceUnlock
                | NumericAssetTransferControlPolicy::CitizenshipRelease
                | NumericAssetTransferControlPolicy::BondVaultRelease => {
                    (PreparedTransferControl::NotRequired, None)
                }
            };
            match destination_admission {
                NumericAssetDestinationAdmissionPolicy::ImplicitReceive => {
                    let _created = ensure_receiving_account(
                        authority,
                        event_destination_id.account(),
                        Some((event_destination_id.definition(), &amount)),
                        state_transaction,
                    )?;
                }
                NumericAssetDestinationAdmissionPolicy::ExistingAccount => {
                    state_transaction
                        .world
                        .account(event_destination_id.account())?;
                }
            }
            let (source_id, destination_id) = ensure_numeric_asset_transfer_policies_with_scope(
                state_transaction,
                &event_source_id,
                &event_destination_id,
                &amount,
                source_policy,
                scope_policy,
            )?;
            crate::retail_fee::settle_balance(&mut state_transaction.world, &source_id)?;
            crate::retail_fee::settle_balance(&mut state_transaction.world, &destination_id)?;
            // The common transfer precheck below protects all additive reserves
            // against the final net balance, including an exact self-transfer.
            let retail_usage_update = prepare_retail_daily_usage_update(
                state_transaction,
                &source_id,
                &destination_id,
                &amount,
                source_policy,
            )?;
            let numeric_spec = state_transaction
                .numeric_spec_for(source_id.definition())
                .map_err(Error::from)?;
            debug_assert!(
                numeric_spec.check(amount.as_numeric()).is_ok(),
                "prepared numeric transfer amount must satisfy cached spec",
            );
            let normalized_scale = numeric_spec
                .scale()
                .unwrap_or_else(|| amount.as_numeric().scale());
            let normalized_amount =
                normalized_numeric_to_u64(amount.as_numeric(), normalized_scale);
            // Keep the typed control exception through the balance precheck so
            // mandatory debits cannot be vetoed by ordinary outbound availability.
            // Source custody, scope, usage, and privacy policies remain independent
            // gates above; this precheck always enforces precision and conservation.
            let prechecked_delta = state_transaction
                .world
                .precheck_numeric_asset_transfer_delta_exact_with_control_policy(
                    &source_id,
                    &destination_id,
                    &amount,
                    control_policy,
                )?;
            if !source_policy.is_moderation_challenge_settlement() {
                let source_balance_after = if source_id == destination_id {
                    &prechecked_delta.to_balance_after
                } else {
                    &prechecked_delta.from_balance_after
                };
                crate::smartcontracts::isi::sorafs_moderation::ensure_moderation_bond_reserve_after_debit(
                    state_transaction.world(),
                    &source_id,
                    source_balance_after,
                )?;
            }
            Ok(Self {
                source_id,
                destination_id,
                source_policy,
                event_source_id,
                event_destination_id,
                amount,
                control_before,
                control_update,
                retail_usage_update,
                numeric_spec,
                normalized_scale,
                normalized_amount,
                prechecked_delta,
                retail_payment: source_policy == NumericAssetTransferSourcePolicy::User,
            })
        }
        fn apply(
            self,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<AppliedNumericTransfer, Error> {
            self.ensure_current(state_transaction)?;
            debug_assert!(
                self.numeric_spec.check(self.amount.as_numeric()).is_ok(),
                "prepared numeric transfer amount must still satisfy cached spec",
            );
            debug_assert_eq!(
                self.normalized_amount,
                normalized_numeric_to_u64(self.amount.as_numeric(), self.normalized_scale),
                "prepared numeric transfer normalization must be stable",
            );
            if self.retail_payment {
                crate::retail_fee::record_payment(
                    state_transaction,
                    &self.source_id,
                    self.destination_id.account(),
                    &self.amount,
                )?;
            }
            state_transaction
                .world
                .apply_prechecked_numeric_asset_transfer_delta_exact(
                    &self.source_id,
                    &self.destination_id,
                    &self.amount,
                    &self.prechecked_delta,
                    self.source_policy,
                )?;
            if let Some(record) = self.control_update {
                update_control_record(state_transaction, self.source_id.account(), record)?;
            }
            if let Some(update) = self.retail_usage_update {
                retail_state::put_usage(&mut state_transaction.world, update.key, update.after)
                    .map_err(|reason| {
                        InstructionExecutionError::InvariantViolation(reason.into())
                    })?;
            }
            Ok(AppliedNumericTransfer {
                source_id: self.event_source_id,
                destination_id: self.event_destination_id,
                amount: self.amount,
                #[cfg(test)]
                delta: self.prechecked_delta,
            })
        }
        fn apply_after_batch_preflight(
            self,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<AppliedNumericTransfer, Error> {
            debug_assert!(
                self.control_update.is_none(),
                "batch control usage is persisted by the aggregate batch plan",
            );
            // Identity-wide usage is persisted once for the complete batch.
            debug_assert!(
                self.numeric_spec.check(self.amount.as_numeric()).is_ok(),
                "prepared numeric transfer amount must still satisfy cached spec",
            );
            debug_assert_eq!(
                self.normalized_amount,
                normalized_numeric_to_u64(self.amount.as_numeric(), self.normalized_scale),
                "prepared numeric transfer normalization must be stable",
            );
            if self.retail_payment {
                crate::retail_fee::record_payment(
                    state_transaction,
                    &self.source_id,
                    self.destination_id.account(),
                    &self.amount,
                )?;
            }
            state_transaction
                .world
                .apply_prechecked_numeric_asset_transfer_delta_exact(
                    &self.source_id,
                    &self.destination_id,
                    &self.amount,
                    &self.prechecked_delta,
                    self.source_policy,
                )?;
            Ok(AppliedNumericTransfer {
                source_id: self.event_source_id,
                destination_id: self.event_destination_id,
                amount: self.amount,
                #[cfg(test)]
                delta: self.prechecked_delta,
            })
        }
        fn ensure_current(
            &self,
            state_transaction: &StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let source_balance = state_transaction
                .world
                .assets
                .get(&self.source_id)
                .map(|value| value.as_ref().clone())
                .ok_or_else(|| FindError::Asset(self.source_id.clone().into()))?;
            if source_balance != self.prechecked_delta.from_balance_before {
                return Err(InstructionExecutionError::InvariantViolation(
                    format!(
                        "prepared numeric movement source balance changed before apply: {}",
                        self.source_id
                    )
                    .into(),
                ));
            }
            if self.source_id != self.destination_id {
                let destination_balance = state_transaction
                    .world
                    .assets
                    .get(&self.destination_id)
                    .map(|value| value.as_ref().clone())
                    .unwrap_or_else(Quantity::zero);
                if destination_balance != self.prechecked_delta.to_balance_before {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "prepared numeric movement destination balance changed before apply: {}",
                            self.destination_id
                        )
                        .into(),
                    ));
                }
            }
            if let PreparedTransferControl::Required(control_before) = &self.control_before {
                let control = active_control_record(
                    state_transaction,
                    self.source_id.account(),
                    self.source_id.definition(),
                )?;
                if &control != control_before {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "prepared numeric movement transfer controls changed before apply: {}",
                            self.source_id
                        )
                        .into(),
                    ));
                }
            }
            if prepare_retail_daily_usage_update(
                state_transaction,
                &self.source_id,
                &self.destination_id,
                &self.amount,
                self.source_policy,
            )? != self.retail_usage_update
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "prepared retail DAY policy, identity binding or usage changed before apply"
                        .into(),
                ));
            }
            Ok(())
        }
    }
    struct PreparedNumericAssetMovementBatch {
        plans: Vec<PreparedNumericTransferPlan>,
        initial_balances: BTreeMap<AssetId, Quantity>,
        control_updates: Vec<(
            AccountId,
            AssetDefinitionId,
            Option<AssetTransferControlRecord>,
            Option<AssetTransferControlRecord>,
        )>,
        retail_usage_updates: Vec<PreparedRetailDailyUsageUpdate>,
        authorization: NumericAssetMovementAuthorization,
    }
    impl PreparedNumericAssetMovementBatch {
        fn prepare_user(
            state_transaction: &mut StateTransaction<'_, '_>,
            authority: &AccountId,
            entries: &[(AssetId, AssetId, Quantity)],
        ) -> Result<Self, Error> {
            let mut plans = Vec::with_capacity(entries.len());
            for (source, destination, amount) in entries {
                plans.push(PreparedNumericTransferPlan::prepare_user(
                    state_transaction,
                    authority,
                    source.clone(),
                    destination.clone(),
                    amount.clone(),
                )?);
            }
            Self::aggregate(
                state_transaction,
                plans,
                NumericAssetMovementAuthorization::transaction_user(
                    authority,
                    "atomic asset transfer batch",
                ),
            )
        }
        fn prepare_with_authorization(
            state_transaction: &mut StateTransaction<'_, '_>,
            entries: &[(AssetId, AssetId, Quantity)],
            authorization: NumericAssetMovementAuthorization,
        ) -> Result<Self, Error> {
            let mut plans = Vec::with_capacity(entries.len());
            for (source, destination, amount) in entries {
                let resolved_source = state_transaction
                    .world
                    .resolve_asset_id_for_current_scope(source)?;
                let authority_policy =
                    authorization.authority_policy(state_transaction, &resolved_source)?;
                plans.push(PreparedNumericTransferPlan::prepare(
                    state_transaction,
                    &authorization.transcript_authority,
                    source.clone(),
                    destination.clone(),
                    amount.clone(),
                    NumericAssetTransferScopePolicy::Ambient,
                    authority_policy,
                    authorization.source_policy,
                    authorization.control_policy,
                    authorization.destination_admission,
                )?);
            }
            Self::aggregate(state_transaction, plans, authorization)
        }
        fn aggregate(
            state_transaction: &StateTransaction<'_, '_>,
            mut plans: Vec<PreparedNumericTransferPlan>,
            authorization: NumericAssetMovementAuthorization,
        ) -> Result<Self, Error> {
            for plan in &plans {
                authorization
                    .ensure_admits_bond_units(state_transaction, plan.source_id.definition())?;
            }
            let mut initial_balances = BTreeMap::<AssetId, Quantity>::new();
            for plan in &plans {
                for id in [&plan.source_id, &plan.destination_id] {
                    initial_balances.entry(id.clone()).or_insert_with(|| {
                        state_transaction
                            .world
                            .assets
                            .get(id)
                            .map(|value| value.as_ref().clone())
                            .unwrap_or_else(Quantity::zero)
                    });
                }
            }
            let mut virtual_balances = initial_balances.clone();
            for plan in &mut plans {
                let source_before = virtual_balances
                    .get(&plan.source_id)
                    .cloned()
                    .unwrap_or_else(Quantity::zero);
                let source_after = source_before
                    .checked_sub(&plan.amount)
                    .map_err(|_| MathError::NotEnoughQuantity)?;
                let (destination_before, destination_after) =
                    if plan.source_id == plan.destination_id {
                        (source_after.clone(), source_before.clone())
                    } else {
                        let destination_before = virtual_balances
                            .get(&plan.destination_id)
                            .cloned()
                            .unwrap_or_else(Quantity::zero);
                        let destination_after = destination_before
                            .checked_add(&plan.amount)
                            .map_err(|_| MathError::Overflow)?;
                        (destination_before, destination_after)
                    };
                assert_numeric_spec_with(source_before.as_numeric(), plan.numeric_spec)?;
                assert_numeric_spec_with(source_after.as_numeric(), plan.numeric_spec)?;
                assert_numeric_spec_with(destination_before.as_numeric(), plan.numeric_spec)?;
                assert_numeric_spec_with(destination_after.as_numeric(), plan.numeric_spec)?;
                state_transaction
                    .world
                    .ensure_numeric_asset_holding_limit(&plan.destination_id, &destination_after)?;
                if plan.source_id != plan.destination_id {
                    virtual_balances.insert(plan.source_id.clone(), source_after.clone());
                    virtual_balances.insert(plan.destination_id.clone(), destination_after.clone());
                }
                plan.prechecked_delta = TransferDeltaTranscript {
                    from_account: plan.source_id.account().clone(),
                    to_account: plan.destination_id.account().clone(),
                    asset_definition: plan.source_id.definition().clone(),
                    amount: plan.amount.clone(),
                    from_balance_before: source_before,
                    from_balance_after: source_after,
                    to_balance_before: destination_before,
                    to_balance_after: destination_after,
                    from_smt_witness: TransferSmtWitness::default(),
                    to_smt_witness: TransferSmtWitness::default(),
                };
            }
            if !authorization
                .source_policy
                .is_moderation_challenge_settlement()
            {
                let source_ids = plans
                    .iter()
                    .map(|plan| plan.source_id.clone())
                    .collect::<BTreeSet<_>>();
                for source_id in source_ids {
                    let balance_after = virtual_balances
                        .get(&source_id)
                        .cloned()
                        .unwrap_or_else(Quantity::zero);
                    crate::smartcontracts::isi::sorafs_moderation::ensure_moderation_bond_reserve_after_debit(
                        state_transaction.world(),
                        &source_id,
                        &balance_after,
                    )?;
                }
            }
            // Individual plans cannot independently spend the same free balance.
            // Check the complete ordered batch after all virtual debits and credits.
            for source_id in plans.iter().map(|plan| &plan.source_id) {
                if let Some(after) = virtual_balances.get(source_id) {
                    crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
                        state_transaction.world(),
                        source_id,
                        after,
                    )
                    .map_err(|error| {
                        state_transaction
                            .world
                            .attempt_error_to_instruction_error(error)
                    })?;
                }
            }
            let mut aggregate_outbound =
                BTreeMap::<(AccountId, AssetDefinitionId), (AssetId, Quantity)>::new();
            for plan in &plans {
                let key = (
                    plan.source_id.account().clone(),
                    plan.source_id.definition().clone(),
                );
                let entry = aggregate_outbound
                    .entry(key)
                    .or_insert_with(|| (plan.source_id.clone(), Quantity::zero()));
                entry.1 = entry
                    .1
                    .checked_add(&plan.amount)
                    .map_err(|_| MathError::Overflow)?;
            }
            let mut control_updates = Vec::with_capacity(aggregate_outbound.len());
            for ((account, definition), (source, amount)) in aggregate_outbound {
                let before = active_control_record(state_transaction, &account, &definition)?;
                let after = prepare_outbound_asset_transfer_control_update(
                    state_transaction,
                    &source,
                    &amount,
                )?;
                control_updates.push((account, definition, before, after));
            }
            let mut aggregate_retail =
                BTreeMap::<RetailDailyUsageKeyV1, (AssetId, Quantity)>::new();
            for plan in &plans {
                if let Some(update) = &plan.retail_usage_update {
                    let entry = aggregate_retail
                        .entry(update.key.clone())
                        .or_insert_with(|| (plan.source_id.clone(), Quantity::zero()));
                    entry.1 = entry
                        .1
                        .checked_add(&plan.amount)
                        .map_err(|_| MathError::Overflow)?;
                }
            }
            let mut retail_usage_updates = Vec::with_capacity(aggregate_retail.len());
            for (expected_key, (source, amount)) in aggregate_retail {
                let update = prepare_retail_daily_usage_update(
                    state_transaction,
                    &source,
                    &source,
                    &amount,
                    NumericAssetTransferSourcePolicy::User,
                )?
                .ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "retail DAY policy disappeared during batch preparation".into(),
                    )
                })?;
                if update.key != expected_key {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "retail identity changed during batch aggregation".into(),
                    ));
                }
                retail_usage_updates.push(update);
            }
            for plan in &mut plans {
                plan.control_before = PreparedTransferControl::NotRequired;
                plan.control_update = None;
            }
            Ok(Self {
                plans,
                initial_balances,
                control_updates,
                retail_usage_updates,
                authorization,
            })
        }
        fn apply(
            self,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<Vec<AppliedNumericTransfer>, Error> {
            let bindings = self
                .plans
                .iter()
                .map(|plan| {
                    (
                        plan.source_id.clone(),
                        plan.destination_id.clone(),
                        plan.amount.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let transcript_identity = self
                .authorization
                .resolve_transcript_identity(state_transaction, &bindings)?;
            for (id, expected) in &self.initial_balances {
                let actual = state_transaction
                    .world
                    .assets
                    .get(id)
                    .map(|value| value.as_ref().clone())
                    .unwrap_or_else(Quantity::zero);
                if &actual != expected {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!("atomic numeric movement balance changed before apply: {id}")
                            .into(),
                    ));
                }
            }
            for (account, definition, before, _) in &self.control_updates {
                if active_control_record(state_transaction, account, definition)? != *before {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "atomic numeric movement controls changed before apply: {account} {definition}"
                        )
                        .into(),
                    ));
                }
            }
            for plan in &self.plans {
                if prepare_retail_daily_usage_update(
                    state_transaction,
                    &plan.source_id,
                    &plan.destination_id,
                    &plan.amount,
                    plan.source_policy,
                )? != plan.retail_usage_update
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "atomic numeric movement retail DAY binding changed before apply".into(),
                    ));
                }
            }
            for update in &self.retail_usage_updates {
                if retail_state::usage_for_exact(state_transaction.world(), &update.key).map_err(
                    |reason| InstructionExecutionError::InvariantViolation(reason.into()),
                )? != update.before
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "atomic numeric movement retail DAY usage changed before apply".into(),
                    ));
                }
            }
            // Aggregation has replaced every delta with its exact ordered virtual balance
            // transition. Prepare one whole occurrence before applying the first batch leg.
            let deltas = self
                .plans
                .iter()
                .map(|plan| plan.prechecked_delta.clone())
                .collect();
            state_transaction.apply_with_prepared_transfer_transcripts(
                &self.authorization.transcript_authority,
                transcript_identity,
                deltas,
                |state_transaction| {
                    let legs = self
                        .plans
                        .iter()
                        .map(|plan| {
                            (
                                plan.source_id.clone(),
                                plan.destination_id.clone(),
                                plan.prechecked_delta.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    self.authorization.apply_with_quantity_candidate(
                        state_transaction,
                        transcript_identity,
                        &legs,
                        |state_transaction| {
                            let mut applied = Vec::with_capacity(self.plans.len());
                            for plan in self.plans {
                                applied.push(plan.apply_after_batch_preflight(state_transaction)?);
                            }
                            for (account, _, _, after) in self.control_updates {
                                if let Some(record) = after {
                                    update_control_record(state_transaction, &account, record)?;
                                }
                            }
                            for update in self.retail_usage_updates {
                                retail_state::put_usage(
                                    &mut state_transaction.world,
                                    update.key,
                                    update.after,
                                )
                                .map_err(|reason| {
                                    InstructionExecutionError::InvariantViolation(reason.into())
                                })?;
                            }
                            Ok(applied)
                        },
                    )
                },
            )
        }
    }
    /// Prepare one complete exact-consent batch without using incoming payments
    /// to fund its outgoing obligations. No receiver is implicitly registered.
    ///
    /// Conditional escrow funding legs (exact source bucket to the escrow's
    /// already created deterministic custody bucket) join the same prepared
    /// batch, prefunding budget and transcript as the signed movements.
    fn prepare_verified_settlement_numeric_batch(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::settlement::VerifiedSettlementNumericBatch,
    ) -> Result<PreparedNumericAssetMovementBatch, Error> {
        let (authority, movements, escrow_fundings) = authorization.into_parts();
        movements
            .validate()
            .map_err(|message| InstructionExecutionError::InvariantViolation(message.into()))?;
        let mut outbound = BTreeMap::<AssetId, Quantity>::new();
        let legs = movements
            .as_slice()
            .iter()
            .map(|movement| (&movement.source, &movement.destination, &movement.quantity))
            .chain(
                escrow_fundings
                    .iter()
                    .map(|(source, custody, amount)| (source, custody, amount)),
            );
        for (source, destination, quantity) in legs {
            for bucket in [source, destination] {
                validate_committed_public_balance_scope(
                    state_transaction,
                    bucket.definition(),
                    *bucket.scope(),
                    "in atomic settlement",
                )?;
            }
            let total = outbound
                .entry(source.clone())
                .or_insert_with(Quantity::zero);
            *total = total
                .checked_add(quantity)
                .map_err(|_| MathError::Overflow)?;
        }
        // This independent pre-debit budget is necessary: the general batch
        // aggregator uses ordered virtual balances and can otherwise count an
        // earlier incoming movement toward a later outgoing movement.
        for (source, amount) in outbound {
            let before = state_transaction
                .world
                .assets
                .get(&source)
                .map(|value| value.as_ref().clone())
                .ok_or_else(|| FindError::Asset(source.clone().into()))?;
            let after = before
                .checked_sub(&amount)
                .map_err(|_| MathError::NotEnoughQuantity)?;
            crate::smartcontracts::isi::sorafs_moderation::ensure_moderation_bond_reserve_after_debit(
                state_transaction.world(), &source, &after,
            )?;
            crate::smartcontracts::isi::staking::ensure_public_lane_reserves_after_debit(
                state_transaction.world(),
                &source,
                &after,
            )
            .map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?;
        }
        let mut plans = Vec::with_capacity(movements.as_slice().len() + escrow_fundings.len());
        for movement in movements.as_slice() {
            let plan = PreparedNumericTransferPlan::prepare_explicit_bilateral(
                state_transaction,
                &authority,
                movement.source.clone(),
                movement.destination.clone(),
                movement.quantity.clone(),
            )?;
            if plan.source_id != movement.source || plan.destination_id != movement.destination {
                return Err(InstructionExecutionError::InvariantViolation(
                    "atomic settlement must preserve both exact signed balance buckets".into(),
                ));
            }
            plans.push(plan);
        }
        for (source, custody, amount) in escrow_fundings {
            let plan = PreparedNumericTransferPlan::prepare_explicit_bilateral(
                state_transaction,
                &authority,
                source.clone(),
                custody.clone(),
                amount,
            )?;
            if plan.source_id != source || plan.destination_id != custody {
                return Err(InstructionExecutionError::InvariantViolation(
                    "atomic settlement escrow funding must preserve its exact source and custody buckets"
                        .into(),
                ));
            }
            plans.push(plan);
        }
        let batch = PreparedNumericAssetMovementBatch::aggregate(
            state_transaction,
            plans,
            NumericAssetMovementAuthorization {
                debit: NumericMovementDebitAuthorization::Protocol,
                transcript_authority: authority,
                transcript: NumericMovementTranscriptRequirement::TransactionRequired(
                    "atomic settlement",
                ),
                source_policy: NumericAssetTransferSourcePolicy::User,
                control_policy: NumericAssetTransferControlPolicy::Enforce,
                destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
            },
        )?;
        // Prove every composite control-store update is canonical before any
        // balance is touched. Apply revalidates the same retained records under
        // the exclusive transaction borrow; no late account creation is allowed.
        let mut stores = BTreeMap::<AccountId, AssetTransferControlStoreV1>::new();
        for (account, _, _, after) in &batch.control_updates {
            if let Some(record) = after {
                let store = match stores.entry(account.clone()) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                        load_asset_transfer_control_store(state_transaction, account)?,
                    ),
                };
                if record.is_empty() {
                    store.remove(&record.asset_definition_id);
                } else {
                    store.upsert(record.clone());
                }
                if !store.controls.is_empty() {
                    store.validate_canonical().map_err(|error| {
                        InstructionExecutionError::InvariantViolation(
                            format!("atomic settlement control update is not canonical: {error}")
                                .into(),
                        )
                    })?;
                    // The shared persistence owner uses Json::new. Prove its
                    // bounded encoding is accepted before any earlier payment
                    // can mutate state, including the combined record store.
                    Json::try_new(store.clone()).map_err(|error| {
                        InstructionExecutionError::InvariantViolation(
                            format!("atomic settlement control encoding failed: {error}").into(),
                        )
                    })?;
                }
            }
        }
        Ok(batch)
    }

    /// Consume complete current consent and validate all batch policies without mutation.
    pub(in crate::smartcontracts::isi) fn validate_verified_settlement_numeric_batch(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::settlement::VerifiedSettlementNumericBatch,
    ) -> Result<(), Error> {
        let _prepared =
            prepare_verified_settlement_numeric_batch(state_transaction, authorization)?;
        Ok(())
    }

    /// Apply one complete prefunded atomic settlement with one authenticated transcript.
    pub(in crate::smartcontracts::isi) fn execute_verified_settlement_numeric_batch(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::settlement::VerifiedSettlementNumericBatch,
    ) -> Result<(), Error> {
        let prepared = prepare_verified_settlement_numeric_batch(state_transaction, authorization)?;
        let applied = prepared.apply(state_transaction)?;
        for movement in applied {
            emit_numeric_asset_transfer_events(
                state_transaction,
                movement.source_id,
                movement.destination_id,
                movement.amount,
            );
        }
        Ok(())
    }

    struct PreparedNumericTransferPair {
        source: PreparedNumericTransferPlan,
        destination: PreparedNumericTransferPlan,
        quantity_authorization_context: Option<Hash>,
    }
    impl PreparedNumericTransferPair {
        /// Apply the ordered native FX pair and stage one occurrence after both legs succeed.
        fn apply_with_transcript(
            self,
            state_transaction: &mut StateTransaction<'_, '_>,
            authority: &AccountId,
            transcript_identity: Hash,
        ) -> Result<(AppliedNumericTransfer, AppliedNumericTransfer), Error> {
            let deltas = vec![
                self.source.prechecked_delta.clone(),
                self.destination.prechecked_delta.clone(),
            ];
            state_transaction.apply_with_prepared_transfer_transcripts(
                authority,
                transcript_identity,
                deltas,
                |state_transaction| {
                    let legs = [
                        (
                            self.source.source_id.clone(),
                            self.source.destination_id.clone(),
                            self.source.prechecked_delta.clone(),
                        ),
                        (
                            self.destination.source_id.clone(),
                            self.destination.destination_id.clone(),
                            self.destination.prechecked_delta.clone(),
                        ),
                    ];
                    let apply = |state_transaction: &mut StateTransaction<'_, '_>| {
                        let source = self.source.apply(state_transaction)?;
                        let destination = self.destination.apply(state_transaction)?;
                        Ok((source, destination))
                    };
                    match self.quantity_authorization_context {
                        Some(context) => state_transaction.apply_with_quantity_transfer_candidate(
                            authority,
                            transcript_identity,
                            context,
                            &legs,
                            apply,
                        ),
                        None => {
                            state_transaction.poison_quantity_candidate_owner();
                            apply(state_transaction)
                        }
                    }
                },
            )
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_authorized_numeric_asset_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        source_id: AssetId,
        source_destination_id: AssetId,
        source_amount: Quantity,
        destination_source_id: AssetId,
        destination_id: AssetId,
        destination_amount: Quantity,
    ) -> Result<PreparedNumericTransferPair, Error> {
        let source = PreparedNumericTransferPlan::prepare_explicit_bilateral(
            state_transaction,
            submitting_authority,
            source_id,
            source_destination_id,
            source_amount,
        )?;
        let destination = PreparedNumericTransferPlan::prepare_explicit_bilateral(
            state_transaction,
            submitting_authority,
            destination_source_id,
            destination_id,
            destination_amount,
        )?;
        if source.source_id.definition() == destination.source_id.definition() {
            return Err(InstructionExecutionError::InvariantViolation(
                "atomic bilateral transfer legs must use distinct asset definitions".into(),
            ));
        }
        Ok(PreparedNumericTransferPair {
            source,
            destination,
            quantity_authorization_context: None,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_native_fx_numeric_asset_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        source_id: AssetId,
        source_destination_id: AssetId,
        source_amount: Quantity,
        destination_source_id: AssetId,
        destination_id: AssetId,
        destination_amount: Quantity,
        policy: &iroha_data_model::isi::settlement::FxCorridorPolicy,
    ) -> Result<PreparedNumericTransferPair, Error> {
        if source_id.scope() != source_destination_id.scope()
            || destination_source_id.scope() != destination_id.scope()
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "native FX transfer legs must preserve one explicit dataspace scope per leg".into(),
            ));
        }
        if matches!(source_id.scope(), AssetBalanceScope::Global)
            || matches!(destination_source_id.scope(), AssetBalanceScope::Global)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "native FX transfer legs require explicit dataspace-scoped asset identifiers"
                    .into(),
            ));
        }
        let current_policy = crate::smartcontracts::isi::settlement::fx_policy(
            state_transaction,
            &policy.policy_id,
        )?;
        if current_policy != *policy {
            return Err(InstructionExecutionError::InvariantViolation(
                "native FX movement does not match the exact active corridor policy".into(),
            ));
        }
        let expected_escrow = iroha_data_model::isi::settlement::fx_corridor_escrow_account_id_v1(
            &state_transaction.network_id,
            &policy.corridor_id(),
            &policy.destination_asset_definition_id,
        );
        if source_id.account() != submitting_authority
            || source_destination_id.account() != &policy.owner
            || source_id.definition() != &policy.source_asset_definition_id
            || source_destination_id.definition() != &policy.source_asset_definition_id
            || source_id.scope() != &AssetBalanceScope::Dataspace(policy.source_dataspace)
            || destination_source_id.account() != &expected_escrow
            || destination_source_id.definition() != &policy.destination_asset_definition_id
            || destination_id.definition() != &policy.destination_asset_definition_id
            || destination_source_id.scope()
                != &AssetBalanceScope::Dataspace(policy.destination_dataspace)
            || destination_id.account() == &expected_escrow
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "native FX movement legs do not match the sealed owner/escrow corridor".into(),
            ));
        }
        ensure_user_numeric_asset_source_authority(
            state_transaction,
            submitting_authority,
            &source_id,
        )?;
        let source = PreparedNumericTransferPlan::prepare(
            state_transaction,
            submitting_authority,
            source_id,
            source_destination_id,
            source_amount,
            NumericAssetTransferScopePolicy::ExplicitBilateral,
            NumericAssetTransferAuthorityPolicy::ProtocolAuthorized,
            NumericAssetTransferSourcePolicy::User,
            NumericAssetTransferControlPolicy::Enforce,
            NumericAssetDestinationAdmissionPolicy::ExistingAccount,
        )?;
        let destination = PreparedNumericTransferPlan::prepare(
            state_transaction,
            submitting_authority,
            destination_source_id,
            destination_id,
            destination_amount,
            NumericAssetTransferScopePolicy::ExplicitBilateral,
            NumericAssetTransferAuthorityPolicy::ProtocolAuthorized,
            NumericAssetTransferSourcePolicy::FxEscrowRelease,
            NumericAssetTransferControlPolicy::Enforce,
            NumericAssetDestinationAdmissionPolicy::ExistingAccount,
        )?;
        let quantity_authorization_context =
            quantity_authorization::fx_context(&quantity_authorization::FxFrame {
                authority: submitting_authority,
                policy,
                legs: [
                    (&source.source_id, &source.destination_id, &source.amount),
                    (
                        &destination.source_id,
                        &destination.destination_id,
                        &destination.amount,
                    ),
                ],
            });
        Ok(PreparedNumericTransferPair {
            source,
            destination,
            quantity_authorization_context,
        })
    }
    /// Validate two explicitly authorized bilateral legs through the ordinary
    /// transfer policy and transfer-control pipeline without mutating state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_authorized_numeric_asset_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        first_source_id: AssetId,
        first_destination_id: AssetId,
        first_amount: Quantity,
        second_source_id: AssetId,
        second_destination_id: AssetId,
        second_amount: Quantity,
    ) -> Result<(), Error> {
        prepare_authorized_numeric_asset_pair(
            state_transaction,
            submitting_authority,
            first_source_id,
            first_destination_id,
            first_amount,
            second_source_id,
            second_destination_id,
            second_amount,
        )?;
        Ok(())
    }
    /// Apply two opaque-consent-authorized bilateral legs atomically.
    #[allow(clippy::too_many_arguments)]
    fn execute_verified_bilateral_numeric_asset_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        tag: &'static str,
        binding: Vec<u8>,
        first_source_id: AssetId,
        first_destination_id: AssetId,
        first_amount: Quantity,
        second_source_id: AssetId,
        second_destination_id: AssetId,
        second_amount: Quantity,
    ) -> Result<(), Error> {
        let prepared = prepare_authorized_numeric_asset_pair(
            state_transaction,
            submitting_authority,
            first_source_id,
            first_destination_id,
            first_amount,
            second_source_id,
            second_destination_id,
            second_amount,
        )?;
        let authorization =
            NumericAssetMovementAuthorization::bilateral(submitting_authority, tag, binding);
        let applied = PreparedNumericAssetMovementBatch::aggregate(
            state_transaction,
            vec![prepared.source, prepared.destination],
            authorization,
        )?
        .apply(state_transaction)?;
        for movement in applied {
            emit_numeric_asset_transfer_events(
                state_transaction,
                movement.source_id,
                movement.destination_id,
                movement.amount,
            );
        }
        Ok(())
    }
    /// Consume repo's one-shot exact bilateral-consent capability.
    pub(in crate::smartcontracts::isi) fn execute_verified_repo_numeric_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::repo::VerifiedRepoNumericPair,
    ) -> Result<(), Error> {
        let (authority, binding, [first, second]) = authorization.into_parts();
        execute_verified_bilateral_numeric_asset_pair(
            state_transaction,
            &authority,
            "repo-bilateral",
            binding,
            first.0,
            first.1,
            first.2,
            second.0,
            second.1,
            second.2,
        )
    }
    /// Consume settlement's one-shot exact bilateral-consent capability.
    pub(in crate::smartcontracts::isi) fn execute_verified_settlement_numeric_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::settlement::VerifiedSettlementNumericPair,
    ) -> Result<(), Error> {
        let (authority, binding, [first, second]) = authorization.into_parts();
        execute_verified_bilateral_numeric_asset_pair(
            state_transaction,
            &authority,
            "settlement-bilateral",
            binding,
            first.0,
            first.1,
            first.2,
            second.0,
            second.1,
            second.2,
        )
    }
    /// Validate both native FX legs through the ordinary transparent-transfer pipeline without
    /// mutating balances, controls, transcripts, or events.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_native_fx_numeric_asset_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        source_id: AssetId,
        source_destination_id: AssetId,
        source_amount: Quantity,
        destination_source_id: AssetId,
        destination_id: AssetId,
        destination_amount: Quantity,
        policy: &iroha_data_model::isi::settlement::FxCorridorPolicy,
    ) -> Result<(), Error> {
        prepare_native_fx_numeric_asset_pair(
            state_transaction,
            submitting_authority,
            source_id,
            source_destination_id,
            source_amount,
            destination_source_id,
            destination_id,
            destination_amount,
            policy,
        )?;
        Ok(())
    }
    /// Apply both legs of a native FX corridor through the ordinary transparent-transfer
    /// policy, transfer-control, transcript, and event pipeline.
    ///
    /// Both legs are fully prepared before either balance changes. The caller must supply
    /// explicit dataspace-scoped asset identifiers so cross-dataspace settlement cannot fall
    /// back to account or route inference.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_native_fx_numeric_asset_pair(
        state_transaction: &mut StateTransaction<'_, '_>,
        submitting_authority: &AccountId,
        source_id: AssetId,
        source_destination_id: AssetId,
        source_amount: Quantity,
        destination_source_id: AssetId,
        destination_id: AssetId,
        destination_amount: Quantity,
        policy: &iroha_data_model::isi::settlement::FxCorridorPolicy,
    ) -> Result<(), Error> {
        let transcript_identity =
            state_transaction.require_transfer_transcript_identity("native FX transfer")?;
        let prepared = prepare_native_fx_numeric_asset_pair(
            state_transaction,
            submitting_authority,
            source_id,
            source_destination_id,
            source_amount,
            destination_source_id,
            destination_id,
            destination_amount,
            policy,
        )?;
        // The policies require distinct asset definitions, so applying the first prechecked
        // delta cannot invalidate the second delta prepared from the same state snapshot.
        let (source, destination) = prepared.apply_with_transcript(
            state_transaction,
            submitting_authority,
            transcript_identity,
        )?;
        let source_amount = source.amount;
        let destination_amount = destination.amount;
        emit_numeric_asset_transfer_events(
            state_transaction,
            source.source_id,
            source.destination_id,
            source_amount,
        );
        emit_numeric_asset_transfer_events(
            state_transaction,
            destination.source_id,
            destination.destination_id,
            destination_amount,
        );
        Ok(())
    }
    /// Emit the canonical balance deltas and one transfer-specific event for a
    /// successful transparent account-to-account movement.
    ///
    /// Keeping the paired payload here prevents consumers from having to infer
    /// a transfer by correlating independent `Removed` and `Added` events.
    pub(crate) fn emit_numeric_asset_transfer_events(
        state_transaction: &mut StateTransaction<'_, '_>,
        source: AssetId,
        destination: AssetId,
        amount: Quantity,
    ) {
        let domain = state_transaction
            .world
            .asset_definition_domains
            .get(source.definition())
            .cloned();
        state_transaction.world.emit_events([
            DataEvent::asset(
                AssetEvent::Removed(AssetChanged {
                    asset: source.clone(),
                    amount: amount.clone(),
                }),
                domain.clone(),
            ),
            DataEvent::asset(
                AssetEvent::Added(AssetChanged {
                    asset: destination.clone(),
                    amount: amount.clone(),
                }),
                domain.clone(),
            ),
            DataEvent::asset(
                AssetEvent::Transferred(AssetTransferred {
                    source,
                    destination,
                    amount,
                }),
                domain,
            ),
        ]);
    }
    /// Validate policy gates for a transparent numeric asset balance movement.
    #[cfg(test)]
    fn ensure_numeric_asset_transfer_policies(
        state_transaction: &mut StateTransaction<'_, '_>,
        source_id: &AssetId,
        destination_id: &AssetId,
        amount: &Quantity,
        source_policy: NumericAssetTransferSourcePolicy,
    ) -> Result<(AssetId, AssetId), Error> {
        ensure_numeric_asset_transfer_policies_with_scope(
            state_transaction,
            source_id,
            destination_id,
            amount,
            source_policy,
            NumericAssetTransferScopePolicy::Ambient,
        )
    }
    fn ensure_privacy_public_reserve_source_policy(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
        source_policy: NumericAssetTransferSourcePolicy,
    ) -> Result<(), Error> {
        let reserve_owner = privacy_public_reserve_owner_v1(
            &state_transaction.world.privacy_commitments,
            source_id,
        )
        .map_err(|message| InstructionExecutionError::InvariantViolation(message.into()))?;
        ensure_privacy_public_reserve_source_policy_for_owner(reserve_owner, source_policy)
    }
    fn ensure_privacy_public_reserve_source_policy_for_owner(
        reserve_owner: Option<PrivacyPublicReserveOwnerV1>,
        source_policy: NumericAssetTransferSourcePolicy,
    ) -> Result<(), Error> {
        match (reserve_owner, source_policy) {
            (Some(actual), NumericAssetTransferSourcePolicy::PrivacyPoolBridge(expected))
                if actual == expected =>
            {
                Ok(())
            }
            (Some(_), _) => Err(InstructionExecutionError::InvariantViolation(
                "governed privacy public reserve requires its exact verified pool bridge".into(),
            )),
            (None, NumericAssetTransferSourcePolicy::PrivacyPoolBridge(_)) => {
                Err(InstructionExecutionError::InvariantViolation(
                    "verified privacy pool bridge source is not governed reserve custody".into(),
                ))
            }
            (None, _) => Ok(()),
        }
    }
    fn ensure_numeric_asset_transfer_policies_with_scope(
        state_transaction: &mut StateTransaction<'_, '_>,
        source_id: &AssetId,
        destination_id: &AssetId,
        amount: &Quantity,
        source_policy: NumericAssetTransferSourcePolicy,
        scope_policy: NumericAssetTransferScopePolicy,
    ) -> Result<(AssetId, AssetId), Error> {
        let (source_id, destination_id) = resolve_numeric_asset_transfer_scope(
            state_transaction,
            source_id,
            destination_id,
            scope_policy,
        )?;
        let spec = state_transaction
            .numeric_spec_for(source_id.definition())
            .map_err(Error::from)?;
        ensure_resolved_numeric_asset_transfer_policies(
            state_transaction,
            &source_id,
            &destination_id,
            amount,
            spec,
            source_policy,
        )?;
        Ok((source_id, destination_id))
    }
    /// Resolve the balance scopes of a numeric movement under `scope_policy` without
    /// mutating state.
    fn resolve_numeric_asset_transfer_scope(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
        destination_id: &AssetId,
        scope_policy: NumericAssetTransferScopePolicy,
    ) -> Result<(AssetId, AssetId), Error> {
        Ok(match scope_policy {
            NumericAssetTransferScopePolicy::Ambient => {
                ensure_global_asset_write_on_authoritative_route(
                    state_transaction,
                    source_id.definition(),
                    "transfer",
                )?;
                let source_dataspace =
                    transfer_source_dataspace_hint(state_transaction, source_id)?;
                let source_id = state_transaction
                    .world
                    .resolve_asset_id_for_scope_hint(source_id, source_dataspace)?;
                let destination_dataspace = match source_id.scope() {
                    iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace)
                        if *dataspace == DataSpaceId::UNIVERSAL =>
                    {
                        Some(DataSpaceId::UNIVERSAL)
                    }
                    iroha_data_model::asset::AssetBalanceScope::Dataspace(dataspace) => {
                        let hint =
                            transfer_destination_dataspace_hint(state_transaction, destination_id)?;
                        if matches!(
                            destination_id.scope(),
                            iroha_data_model::asset::AssetBalanceScope::Dataspace(_)
                        ) || hint.is_some_and(|hint| hint != DataSpaceId::UNIVERSAL)
                        {
                            hint
                        } else {
                            Some(*dataspace)
                        }
                    }
                    _ => transfer_destination_dataspace_hint(state_transaction, destination_id)?,
                };
                let destination_id = state_transaction
                    .world
                    .resolve_asset_id_for_scope_hint(destination_id, destination_dataspace)?;
                (source_id, destination_id)
            }
            NumericAssetTransferScopePolicy::ExplicitBilateral => {
                if source_id.scope() != destination_id.scope() {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "explicit bilateral transfer must preserve one exact balance scope".into(),
                    ));
                }
                validate_committed_public_balance_scope(
                    state_transaction,
                    source_id.definition(),
                    *source_id.scope(),
                    "explicit bilateral transfer",
                )?;
                let definition = state_transaction
                    .world
                    .asset_definition(source_id.definition())
                    .map_err(Error::from)?;
                let explicit_dataspace = match definition.balance_scope_policy() {
                    AssetBalancePolicy::Global => None,
                    AssetBalancePolicy::DataspaceRestricted => {
                        let (
                            AssetBalanceScope::Dataspace(source_dataspace),
                            AssetBalanceScope::Dataspace(destination_dataspace),
                        ) = (source_id.scope(), destination_id.scope())
                        else {
                            return Err(InstructionExecutionError::InvariantViolation(
                                "bilateral settlement requires explicit dataspace scopes for restricted assets"
                                    .into(),
                            ));
                        };
                        if source_dataspace != destination_dataspace {
                            return Err(InstructionExecutionError::InvariantViolation(
                                "each bilateral settlement leg must preserve one exact balance scope"
                                    .into(),
                            ));
                        }
                        Some(*source_dataspace)
                    }
                };
                let source_id = state_transaction
                    .world
                    .resolve_asset_id_for_scope_hint(source_id, explicit_dataspace)?;
                let destination_id = state_transaction
                    .world
                    .resolve_asset_id_for_scope_hint(destination_id, explicit_dataspace)?;
                (source_id, destination_id)
            }
        })
    }
    /// Check every definition, custody, usage and privacy policy of a numeric movement between
    /// the resolved balances `source_id` and `destination_id` under `source_policy`, given the
    /// definition's numeric `spec`, without mutating state. Every movement path and the SCCP
    /// release precheck ([`precheck_sccp_escrow_release`]) share this gate.
    fn ensure_resolved_numeric_asset_transfer_policies(
        state_transaction: &StateTransaction<'_, '_>,
        source_id: &AssetId,
        destination_id: &AssetId,
        amount: &Quantity,
        spec: NumericSpec,
        source_policy: NumericAssetTransferSourcePolicy,
    ) -> Result<(), Error> {
        if source_id.definition() != destination_id.definition() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "asset transfer source definition {} does not match destination definition {}",
                    source_id.definition(),
                    destination_id.definition()
                )
                .into(),
            ));
        }
        ensure_privacy_public_reserve_source_policy(state_transaction, source_id, source_policy)?;
        if state_transaction
            .world
            .game_custody_by_account
            .get(destination_id.account())
            .is_some()
            && source_policy != NumericAssetTransferSourcePolicy::GameSessionFunding
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "native game custody accepts only exact native entry funding".into(),
            ));
        }
        assert_numeric_spec_with(amount.as_numeric(), spec)?;
        if source_policy != NumericAssetTransferSourcePolicy::KagemushaReserveCustody {
            ensure_not_kagemusha_reserve_source(state_transaction.world(), source_id)?;
        }
        // Exact retained staking-slash and moderation-settlement capabilities
        // are finality-owned protocol custody. User transfer availability,
        // holding, issuer-usage, privacy-mode, and unrelated custody controls
        // cannot veto them after their source and sink have been bound to the
        // retained protocol record. Definition, balance scope, and amount
        // precision were still validated above.
        if source_policy.uses_protocol_custody_precheck() {
            return Ok(());
        }
        let source_subject = (
            source_id.account(),
            asset_id_dataspace_hint(state_transaction, source_id),
        );
        let destination_subject = (
            destination_id.account(),
            asset_id_dataspace_hint(state_transaction, destination_id),
        );
        // A key-less bond vault is protocol custody: the payment asset's transparency
        // and usage policies bind the funding party and the paid holder, never the
        // vault itself, so they cannot trap funded payments in it.
        match source_policy {
            NumericAssetTransferSourcePolicy::BondVaultCustody => {
                ensure_usage_policy_for_accounts(
                    state_transaction,
                    source_id.definition(),
                    [destination_subject],
                    Some(amount),
                )?;
            }
            NumericAssetTransferSourcePolicy::BondVaultFunding => {
                ensure_transparent_allowed(
                    state_transaction,
                    source_id.definition(),
                    "transparent transfer not permitted by policy",
                )?;
                ensure_usage_policy_for_accounts(
                    state_transaction,
                    source_id.definition(),
                    [source_subject],
                    Some(amount),
                )?;
            }
            _ => {
                ensure_transparent_allowed(
                    state_transaction,
                    source_id.definition(),
                    "transparent transfer not permitted by policy",
                )?;
                ensure_usage_policy_for_accounts(
                    state_transaction,
                    source_id.definition(),
                    [source_subject, destination_subject],
                    Some(amount),
                )?;
            }
        }
        if source_policy != NumericAssetTransferSourcePolicy::SorafsReserveCustody {
            ensure_not_sorafs_reserve_custody_source(state_transaction, source_id)?;
        }
        if source_policy != NumericAssetTransferSourcePolicy::SccpEscrowRelease {
            ensure_not_sccp_escrow_source(state_transaction, source_id)?;
        }
        if source_policy != NumericAssetTransferSourcePolicy::SccpEscrowLock {
            ensure_not_sccp_escrow_destination(state_transaction, destination_id)?;
        }
        if source_policy != NumericAssetTransferSourcePolicy::FxEscrowRelease {
            ensure_not_fx_corridor_escrow_source(state_transaction, source_id)?;
        }
        if source_policy != NumericAssetTransferSourcePolicy::FxEscrowDeposit {
            ensure_not_fx_corridor_escrow_destination(state_transaction, destination_id)?;
        }
        if source_policy != NumericAssetTransferSourcePolicy::BondVaultFunding {
            ensure_not_bond_vault_destination(state_transaction, destination_id)?;
        }
        match source_policy {
            NumericAssetTransferSourcePolicy::User
            | NumericAssetTransferSourcePolicy::RetailMonetary(_)
            | NumericAssetTransferSourcePolicy::PrivacyPoolBridge(_)
            | NumericAssetTransferSourcePolicy::GameSessionFunding => {
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::FxEscrowDeposit => {
                ensure_not_native_escrow_source(state_transaction, source_id)?;
                if !is_fx_corridor_escrow_asset(state_transaction, destination_id)? {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "FX corridor escrow deposit destination is not governed protocol custody"
                            .into(),
                    )
                    .into());
                }
            }
            NumericAssetTransferSourcePolicy::BondVaultFunding => {
                if !crate::smartcontracts::isi::bond::is_bond_vault_asset(
                    state_transaction.world(),
                    destination_id,
                ) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "bond funding destination is not a registered bond vault".into(),
                    ));
                }
                ensure_not_native_escrow_source(state_transaction, &source_id)?;
            }
            NumericAssetTransferSourcePolicy::BondVaultCustody => {
                if !crate::smartcontracts::isi::bond::is_bond_vault_asset(
                    state_transaction.world(),
                    source_id,
                ) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "bond vault payment source is not a registered bond vault".into(),
                    ));
                }
                if crate::smartcontracts::isi::escrow::is_native_escrow_custody_asset(
                    state_transaction,
                    source_id,
                )? {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "bond vault payment source overlaps native escrow custody".into(),
                    ));
                }
            }
            NumericAssetTransferSourcePolicy::NativeEscrowCustody => {
                if !crate::smartcontracts::isi::escrow::is_native_escrow_custody_asset(
                    state_transaction,
                    source_id,
                )? {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "native escrow settlement source is not a recorded custody asset".into(),
                    ));
                }
            }
            NumericAssetTransferSourcePolicy::KagemushaReserveCustody => {
                if crate::kagemusha_wallet_v1::custody::reserve_registration(
                    state_transaction.world(),
                    source_id,
                )
                .map_err(kagemusha_custody_error)?
                .is_none()
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "KAGEMUSHA payout source is not registered custody".into(),
                    ));
                }
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::SorafsReserveCustody => {
                if !crate::smartcontracts::isi::sorafs_reserve::is_reserve_custody_asset(
                    state_transaction.world(),
                    source_id,
                )? {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "SoraFS reserve withdrawal source is not active protocol custody".into(),
                    ));
                }
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::FxEscrowRelease => {
                if !is_fx_corridor_escrow_asset(state_transaction, source_id)? {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "FX corridor escrow release source is not governed protocol custody".into(),
                    )
                    .into());
                }
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::FeeSponsorCustody => {
                if source_id.account()
                    != crate::executor::root_fees::sponsor_vault_custody(state_transaction)?
                {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "fee sponsor custody transfer source does not match configured custody"
                            .into(),
                    )
                    .into());
                }
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::OracleReward
            | NumericAssetTransferSourcePolicy::OraclePenalty
            | NumericAssetTransferSourcePolicy::OracleDisputeResolution
            | NumericAssetTransferSourcePolicy::SocialReward
            | NumericAssetTransferSourcePolicy::SocialEscrow
            | NumericAssetTransferSourcePolicy::StakingUnbond
            | NumericAssetTransferSourcePolicy::StakingSlash
            | NumericAssetTransferSourcePolicy::ModerationChallengeRefund
            | NumericAssetTransferSourcePolicy::ModerationChallengeSlash
            | NumericAssetTransferSourcePolicy::GovernanceSlash
            | NumericAssetTransferSourcePolicy::GovernanceRestitution
            | NumericAssetTransferSourcePolicy::GovernanceUnlock
            | NumericAssetTransferSourcePolicy::CitizenshipRelease => {
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::SccpEscrowLock => {
                if !is_sccp_escrow_account(state_transaction, destination_id.account()) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "SCCP escrow lock destination is not a registered route escrow".into(),
                    ));
                }
                ensure_not_native_escrow_source(state_transaction, source_id)?;
            }
            NumericAssetTransferSourcePolicy::SccpEscrowRelease => {
                if !is_sccp_escrow_account(state_transaction, source_id.account()) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "SCCP escrow release source is not a registered route escrow".into(),
                    ));
                }
            }
        }
        Ok(())
    }
    /// Consume one exact fee-sponsor charge capability produced after sponsor debit admission.
    pub(crate) fn execute_verified_fee_sponsor_charge(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::executor::VerifiedFeeSponsorCharge,
    ) -> Result<(), Error> {
        let (
            submitting_authority,
            program_id,
            kind,
            source_id,
            destination,
            amount,
            quantity_source,
        ) = authorization.into_parts();
        if source_id.account()
            != crate::executor::root_fees::sponsor_vault_custody(state_transaction)?
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "verified fee sponsor charge source does not match configured custody".into(),
            ));
        }
        let binding = canonical_numeric_movement_binding(&(
            program_id,
            kind,
            source_id.clone(),
            destination.clone(),
            amount.clone(),
            quantity_source,
        ))?;
        match (kind, destination) {
            (iroha_data_model::transaction::FeeChargeKind::PipelineGas, Some(destination)) => {
                let destination_id = AssetId::with_scope(
                    source_id.definition().clone(),
                    destination,
                    source_id.scope().clone(),
                );
                execute_numeric_asset_movement(
                    state_transaction,
                    source_id,
                    destination_id,
                    amount,
                    NumericAssetMovementAuthorization::retained(
                        &submitting_authority,
                        RetainedNumericAssetMovementPurpose::FeeSponsor(binding),
                    ),
                )
            }
            (iroha_data_model::transaction::FeeChargeKind::Nexus, None) => {
                execute_checked_numeric_asset_burn(
                    state_transaction,
                    None,
                    source_id,
                    amount,
                    NumericAssetBurnSourcePolicy::FeeSponsorCustody,
                    quantity_source.map(|(execution_entry, _, _)| FeeSponsorBurnQuantityOwner {
                        authority: submitting_authority,
                        execution_entry,
                        binding,
                    }),
                )
            }
            _ => Err(InstructionExecutionError::InvariantViolation(
                "verified fee sponsor charge kind does not match transfer/burn destination".into(),
            )),
        }
    }
    /// Consume one exact, permission-checked fee-sponsor vault withdrawal.
    pub(in crate::smartcontracts::isi) fn execute_verified_fee_sponsor_vault_withdrawal(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::smartcontracts::isi::world::isi::VerifiedFeeSponsorVaultWithdrawal,
    ) -> Result<(), Error> {
        let (authority, program_id, source_id, destination, amount) = authorization.into_parts();
        let key = iroha_data_model::nexus::FeeSponsorVaultKey {
            program_id: program_id.clone(),
            asset_definition_id: source_id.definition().clone(),
        };
        let vault = state_transaction
            .world
            .fee_sponsor_vaults
            .get(&key)
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    "fee sponsor withdrawal has no retained vault".into(),
                )
            })?;
        if source_id.account()
            != crate::executor::root_fees::sponsor_vault_custody(state_transaction)?
            || amount > vault.balance
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "fee sponsor withdrawal does not match retained vault custody and balance".into(),
            ));
        }
        let destination_id = AssetId::with_scope(
            source_id.definition().clone(),
            destination,
            source_id.scope().clone(),
        );
        let binding = canonical_numeric_movement_binding(&(
            program_id,
            authority.clone(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
            vault.balance.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                &authority,
                RetainedNumericAssetMovementPurpose::FeeSponsor(binding),
            ),
        )
    }
    /// Closed original teardown arguments; these are borrowed observations, not
    /// caller-created permission or a substitute for the signed execution entry.
    #[derive(Clone, Copy)]
    pub(in crate::smartcontracts::isi) enum QuantityRetirementScope<'a> {
        /// The original Unregister<AssetDefinition> argument.
        Definition(&'a AssetDefinitionId),
        /// The original Unregister<Domain> argument and its authoritative membership.
        Domain(&'a iroha_model_base::domain::DomainId),
    }

    /// Original teardown invocation retained before its actual balance enumeration.
    pub(in crate::smartcontracts::isi) struct QuantityRetirementOwner<'a> {
        authority: &'a AccountId,
        scope: QuantityRetirementScope<'a>,
        invocation:
            Result<crate::state::QuantityRetirementInvocation, crate::state::QuantityCaptureIssue>,
        lifecycles: Result<
            iroha_allocation::ChargedBuffer<(
                AssetDefinitionId,
                iroha_data_model::nexus::AxtAssetIncarnationV1,
            )>,
            crate::state::QuantityCaptureIssue,
        >,
    }

    impl<'a> QuantityRetirementOwner<'a> {
        /// Observe the already authorized native instruction. Failure affects only
        /// capture; it never changes the original business operation or error order.
        #[expect(
            single_use_lifetimes,
            reason = "Rust 1.93 requires a named lifetime for reference items in impl ExactSizeIterator bounds"
        )]
        pub(in crate::smartcontracts::isi) fn retain<'ids>(
            state: &StateTransaction<'_, '_>,
            authority: &'a AccountId,
            scope: QuantityRetirementScope<'a>,
            definitions: impl ExactSizeIterator<Item = &'ids AssetDefinitionId>,
        ) -> Self {
            let invocation = state.retain_quantity_retirement_invocation();
            let lifecycles = (|| {
                use crate::state::QuantityCaptureIssue;
                invocation.as_ref().map_err(Clone::clone)?;
                let mut retained =
                    state.reserve_quantity_retirement_lifecycles(definitions.len())?;
                for id in definitions {
                    let scope_matches = match scope {
                        QuantityRetirementScope::Definition(expected) => expected == id,
                        QuantityRetirementScope::Domain(domain) => {
                            state.world.asset_definition_domains.get(id) == Some(domain)
                        }
                    };
                    if !scope_matches
                        || state.world.asset_definitions.get(id).is_none()
                        || retained
                            .as_slice()
                            .last()
                            .is_some_and(|(previous, _)| previous >= id)
                    {
                        return Err(QuantityCaptureIssue::InvalidFacts);
                    }
                    let incarnation = state
                        .world
                        .axt_asset_incarnations
                        .get(id)
                        .copied()
                        .filter(|value| value.validate().is_ok())
                        .ok_or(QuantityCaptureIssue::MissingIncarnation)?;
                    retained.push_reserved((id.clone(), incarnation));
                }
                Ok(retained)
            })();
            Self {
                authority,
                scope,
                invocation,
                lifecycles,
            }
        }

        fn context(
            &self,
            state: &StateTransaction<'_, '_>,
            id: &AssetDefinitionId,
            balance: Option<(&AssetId, &Quantity)>,
        ) -> Result<(Hash, Hash), crate::state::QuantityCaptureIssue> {
            use crate::state::QuantityCaptureIssue;
            let hash = state.validate_quantity_retirement_invocation(
                self.invocation.as_ref().map_err(Clone::clone)?,
            )?;
            let (purpose, domain) = match self.scope {
                QuantityRetirementScope::Definition(expected) if expected == id => {
                    ("definition-unregister", None)
                }
                QuantityRetirementScope::Domain(domain)
                    if state.world.asset_definition_domains.get(id) == Some(domain) =>
                {
                    ("domain-unregister", Some(domain))
                }
                _ => return Err(QuantityCaptureIssue::InvalidFacts),
            };
            let lifecycles = self.lifecycles.as_ref().map_err(Clone::clone)?.as_slice();
            let position = lifecycles
                .binary_search_by(|(definition, _)| definition.cmp(id))
                .map_err(|_| QuantityCaptureIssue::MissingIncarnation)?;
            let incarnation = &lifecycles[position].1;
            if state.world.axt_asset_incarnations.get(id) != Some(incarnation) {
                return Err(QuantityCaptureIssue::MissingIncarnation);
            }
            let context = quantity_authorization::retirement_context(
                purpose,
                self.authority,
                id,
                incarnation,
                domain,
                balance,
            )
            .ok_or(QuantityCaptureIssue::Capacity)?;
            Ok((hash, context))
        }

        /// Preserve the original supply-before-balance removal and exact selected key.
        pub(in crate::smartcontracts::isi) fn remove_asset(
            &self,
            state: &mut StateTransaction<'_, '_>,
            id: &AssetId,
        ) -> Result<Option<iroha_data_model::asset::AssetValue>, Error> {
            remove_asset_with_quantity_candidate(state, self.authority, id, Some(self))
        }

        /// Consume the retained original lifecycle around the actual World erasure.
        pub(in crate::smartcontracts::isi) fn retire_definition(
            &self,
            state: &mut StateTransaction<'_, '_>,
            id: &AssetDefinitionId,
        ) -> Result<Option<iroha_data_model::asset::AssetDefinition>, Error> {
            let prepared = self.context(state, id, None).and_then(|(hash, context)| {
                state.prepare_quantity_retirement_candidate(self.authority, hash, context, id)
            });
            state.apply_with_quantity_candidate(prepared, |state| {
                state
                    .retire_direct_asset_definition_home(id)
                    .map_err(|error| {
                        InstructionExecutionError::InvariantViolation(
                            format!("direct asset home retirement failed: {error}").into(),
                        )
                    })?;
                Ok(state.world.remove_asset_definition_entry(id))
            })
        }
    }

    /// Observe only the account-unregistration owner's existing full-balance removal.
    /// Lifecycle checks and execution authorization remain with that original caller;
    /// the bounded frame records its purpose and does not grant a new capability.
    pub(in crate::smartcontracts::isi) fn remove_account_asset_with_quantity_candidate(
        state: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        asset_id: &AssetId,
    ) -> Result<Option<iroha_data_model::asset::AssetValue>, Error> {
        remove_asset_with_quantity_candidate(state, authority, asset_id, None)
    }

    fn remove_asset_with_quantity_candidate(
        state: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        asset_id: &AssetId,
        retirement: Option<&QuantityRetirementOwner<'_>>,
    ) -> Result<Option<iroha_data_model::asset::AssetValue>, Error> {
        let Some(value) = state.world.assets.get(asset_id).cloned() else {
            state.world.asset_metadata.remove(asset_id.clone());
            return Ok(None);
        };
        // Preserve the original removal's business-owned amount and checked total.
        let amount = value.clone().into_inner();
        let supply_after =
            state
                .world
                .precheck_asset_total_amount_change(asset_id.definition(), &amount, false);
        let binding = if let Some(owner) = retirement {
            owner.context(state, asset_id.definition(), Some((asset_id, &amount)))
        } else {
            let context =
                quantity_authorization::supply_context(&quantity_authorization::SupplyFrame {
                    mint: false,
                    purpose: "account-unregister-burn",
                    binding: quantity_authorization::SupplyBinding::Bytes(&[]),
                    authority,
                    id: asset_id,
                    amount: &amount,
                });
            state
                .tx_call_hash
                .zip(context)
                .ok_or(crate::state::QuantityCaptureIssue::UnsupportedOwner)
        };
        let prepared = match (binding, &supply_after) {
            (Ok((entry_hash, context)), Ok(after)) => state.prepare_quantity_removal_candidate(
                authority, entry_hash, context, asset_id, &amount, after,
            ),
            (_, Err(_)) => Err(crate::state::QuantityCaptureIssue::InvalidFacts),
            (Err(issue), _) => Err(issue),
        };
        state.apply_with_quantity_candidate(prepared, |state| {
            // Preserve each original teardown owner's supply-before-balance order.
            state.world.apply_prechecked_asset_total_amount_change(
                asset_id.definition(),
                &amount,
                supply_after?,
                false,
            );
            Ok(state.world.remove_asset_and_metadata(asset_id))
        })
    }

    /// TODO: admit retained retail-policy binding, initial closure capture and original
    /// arithmetic scratch before claiming complete physical capture coverage.
    /// Original business preparation: no capture-only quantity calculation is retained.
    /// The total result stays deferred so an existing error still follows the balance write.
    struct PreparedNumericSupplyChange {
        id: AssetId,
        balance_after: Quantity,
        supply_after: Result<Quantity, Error>,
        mint: bool,
    }

    impl PreparedNumericSupplyChange {
        fn prepare(
            state: &mut StateTransaction<'_, '_>,
            id: &AssetId,
            amount: &Quantity,
            mint: bool,
        ) -> Result<Self, Error> {
            let (id, balance_after) = if mint {
                state.world.precheck_numeric_asset_credit(id, amount)?
            } else {
                state
                    .world
                    .precheck_numeric_asset_debit(&state.network_id, id, amount)?
            };
            let supply_after =
                state
                    .world
                    .precheck_asset_total_amount_change(id.definition(), amount, mint);
            Ok(Self {
                id,
                balance_after,
                supply_after,
                mint,
            })
        }

        fn apply_balance(
            self,
            world: &mut WorldTransaction<'_, '_>,
        ) -> Result<PreparedNumericSupplyTotal, Error> {
            if self.mint {
                world.apply_prechecked_numeric_asset_credit_exact(&self.id, self.balance_after)?;
            } else {
                world.apply_prechecked_numeric_asset_debit_exact(&self.id, self.balance_after)?;
            }
            Ok(PreparedNumericSupplyTotal {
                definition: self.id.definition().clone(),
                after: self.supply_after,
                mint: self.mint,
            })
        }
    }

    /// The original aggregate result moves to the second physical write in program order.
    struct PreparedNumericSupplyTotal {
        definition: AssetDefinitionId,
        after: Result<Quantity, Error>,
        mint: bool,
    }
    impl PreparedNumericSupplyTotal {
        fn apply(
            self,
            world: &mut WorldTransaction<'_, '_>,
            amount: &Quantity,
        ) -> Result<(), Error> {
            let after = self.after?;
            world.apply_prechecked_asset_total_amount_change(
                &self.definition,
                amount,
                after,
                self.mint,
            );
            Ok(())
        }
    }

    /// Observe supply only under the exact existing invocation; unsupported direct
    /// protocol supply keeps business semantics and poisons this candidate export.
    fn apply_with_supply_quantity_candidate<T>(
        state: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        id: &AssetId,
        amount: &Quantity,
        mint: bool,
        purpose: (&str, Option<quantity_authorization::SupplyBinding<'_>>),
        apply: impl FnOnce(
            &mut StateTransaction<'_, '_>,
            PreparedNumericSupplyChange,
        ) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let context = purpose.1.and_then(|binding| {
            quantity_authorization::supply_context(&quantity_authorization::SupplyFrame {
                mint,
                purpose: purpose.0,
                binding,
                authority,
                id,
                amount,
            })
        });
        let original = PreparedNumericSupplyChange::prepare(state, id, amount, mint);
        let prepared = match (state.tx_call_hash, context, &original) {
            (Some(entry_hash), Some(context), Ok(original)) => match &original.supply_after {
                Ok(supply_after) => state.prepare_quantity_supply_candidate(
                    authority,
                    entry_hash,
                    context,
                    &original.id,
                    amount,
                    mint,
                    &original.balance_after,
                    supply_after,
                ),
                Err(_) => Err(crate::state::QuantityCaptureIssue::InvalidFacts),
            },
            (_, _, Err(_)) => Err(crate::state::QuantityCaptureIssue::InvalidFacts),
            _ => Err(crate::state::QuantityCaptureIssue::UnsupportedOwner),
        };
        state.apply_with_quantity_candidate(prepared, |state| apply(state, original?))
    }
    impl Execute for Mint<Quantity, Asset> {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let quantity = self.object().clone();
            if quantity.is_zero() {
                return Err(InstructionExecutionError::InvariantViolation(
                    "asset mint amount must be non-zero".into(),
                )
                .into());
            }
            let asset_id = self.destination().clone();
            ensure_global_asset_write_on_authoritative_route(
                state_transaction,
                asset_id.definition(),
                "mint",
            )?;
            crate::smartcontracts::isi::bond::ensure_bond_supply_unlocked(
                state_transaction.world(),
                asset_id.definition(),
            )?;
            let resolved_asset_id = state_transaction
                .world
                .resolve_asset_id_for_current_scope(&asset_id)?;
            reject_uncovered_retail_asset_mutation(state_transaction, &resolved_asset_id, "mint")?;
            if state_transaction
                .world
                .game_custody_by_account
                .get(resolved_asset_id.account())
                .is_some()
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "native game custody accepts only exact native entry funding".into(),
                ));
            }
            ensure_not_fx_corridor_escrow_destination(state_transaction, &resolved_asset_id)?;
            ensure_not_sccp_escrow_destination(state_transaction, &resolved_asset_id)?;
            ensure_not_bond_vault_destination(state_transaction, &resolved_asset_id)?;
            let _created = ensure_receiving_account(
                authority,
                asset_id.account(),
                Some((asset_id.definition(), &quantity)),
                state_transaction,
            )?;
            let spec = state_transaction
                .numeric_spec_for(asset_id.definition())
                .map_err(Error::from)?;
            assert_numeric_spec_with(quantity.as_numeric(), spec)?;
            ensure_transparent_allowed(
                state_transaction,
                asset_id.definition(),
                "transparent mint not permitted by policy",
            )?;
            ensure_usage_policy_for_accounts(
                state_transaction,
                asset_id.definition(),
                [(
                    resolved_asset_id.account(),
                    asset_id_dataspace_hint(state_transaction, &resolved_asset_id),
                )],
                Some(&quantity),
            )?;
            let flipped = assert_can_mint_cached(state_transaction, asset_id.definition())?;
            let captured_quantity = quantity.clone();
            apply_with_supply_quantity_candidate(
                state_transaction,
                authority,
                &resolved_asset_id,
                &captured_quantity,
                true,
                (
                    "ordinary-mint",
                    Some(quantity_authorization::SupplyBinding::Bytes(&[])),
                ),
                |state_transaction, original| {
                    // Deposit into destination asset balance, creating if needed
                    #[cfg(feature = "telemetry")]
                    let amount_f64 = quantity.as_numeric().clone().to_f64_lossy();
                    let total = original.apply_balance(&mut state_transaction.world)?;
                    #[allow(clippy::float_arithmetic)]
                    {
                        #[cfg(feature = "telemetry")]
                        state_transaction.telemetry.observe_tx_amount(amount_f64);
                        total.apply(&mut state_transaction.world, &quantity)?;
                    }
                    state_transaction
                        .world
                        .emit_asset_event(AssetEvent::Added(AssetChanged {
                            asset: asset_id.clone(),
                            amount: quantity.clone(),
                        }));
                    if flipped {
                        state_transaction.world.emit_asset_definition_event(
                            AssetDefinitionEvent::MintabilityChangedDetailed(
                                AssetDefinitionMintabilityChanged {
                                    asset_definition: asset_id.definition().clone(),
                                    minted_amount: quantity,
                                    authority: authority.clone(),
                                },
                            ),
                        );
                    }
                    Ok(())
                },
            )
        }
    }
    impl Execute for Burn<Quantity, Asset> {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.destination().clone();
            ensure_global_asset_write_on_authoritative_route(
                state_transaction,
                asset_id.definition(),
                "burn",
            )?;
            crate::smartcontracts::isi::bond::ensure_bond_supply_unlocked(
                state_transaction.world(),
                asset_id.definition(),
            )?;
            let resolved_asset_id = state_transaction
                .world
                .resolve_asset_id_for_current_scope(&asset_id)?;
            reject_uncovered_retail_asset_mutation(state_transaction, &resolved_asset_id, "burn")?;
            let quantity = self.object().clone();
            crate::validation_fee_rewards::ensure_reward_custody_debit(
                state_transaction,
                &resolved_asset_id,
                &quantity,
            )?;
            let spec = state_transaction
                .numeric_spec_for(asset_id.definition())
                .map_err(Error::from)?;
            assert_numeric_spec_with(quantity.as_numeric(), spec)?;
            ensure_usage_policy_for_accounts(
                state_transaction,
                asset_id.definition(),
                [(
                    resolved_asset_id.account(),
                    asset_id_dataspace_hint(state_transaction, &resolved_asset_id),
                )],
                Some(&quantity),
            )?;
            ensure_not_native_escrow_source(state_transaction, &resolved_asset_id)?;
            ensure_not_fx_corridor_escrow_source(state_transaction, &resolved_asset_id)?;
            ensure_not_sorafs_reserve_custody_source(state_transaction, &resolved_asset_id)?;
            ensure_not_kagemusha_reserve_source(state_transaction.world(), &resolved_asset_id)?;
            ensure_not_sccp_escrow_source(state_transaction, &resolved_asset_id)?;
            let captured_quantity = quantity.clone();
            apply_with_supply_quantity_candidate(
                state_transaction,
                authority,
                &resolved_asset_id,
                &captured_quantity,
                false,
                (
                    "ordinary-burn",
                    Some(quantity_authorization::SupplyBinding::Bytes(&[])),
                ),
                |state_transaction, original| {
                    // Withdraw from source asset balance and remove if it reaches zero
                    let total = original.apply_balance(&mut state_transaction.world)?;
                    #[allow(clippy::float_arithmetic)]
                    {
                        #[cfg(feature = "telemetry")]
                        state_transaction
                            .telemetry
                            .observe_tx_amount(quantity.as_numeric().clone().to_f64_lossy());
                        total.apply(&mut state_transaction.world, &quantity)?;
                    }
                    state_transaction
                        .world
                        .emit_asset_event(AssetEvent::Removed(AssetChanged {
                            asset: asset_id.clone(),
                            amount: quantity,
                        }));
                    Ok(())
                },
            )
        }
    }
    fn exact_retail_reserve_policy(
        state_transaction: &StateTransaction<'_, '_>,
        authority: &AccountId,
        asset_id: &AssetId,
    ) -> Result<RetailDailyLimitPolicyV1, Error> {
        let AssetBalanceScope::Dataspace(dataspace) = asset_id.scope() else {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail monetary reserve requires an exact physical balance scope".into(),
            ));
        };
        let policy = retail_state::policy_for_exact(
            state_transaction.world(),
            asset_id.definition(),
            *dataspace,
        )
        .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?
        .ok_or_else(|| {
            InstructionExecutionError::InvariantViolation(
                "retail monetary reserve has no exact activated policy".into(),
            )
        })?;
        retail_state::activation_for_exact(state_transaction.world(), &policy)
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
        if &policy.monetary_issuer_account != authority
            || &policy.reserve_account != asset_id.account()
            || state_transaction.current_dataspace_id != Some(*dataspace)
            || state_transaction.world.current_dataspace_id != Some(*dataspace)
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail monetary supply requires its exact issuer, reserve and physical lane"
                    .into(),
            ));
        }
        Ok(policy)
    }

    /// Supply creation is available only to the owner-installed monetary issuer
    /// and only into the owner-installed reserve, never through generic Mint.
    pub(crate) fn execute_retail_reserve_mint(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        asset_id: AssetId,
        quantity: Quantity,
    ) -> Result<(), Error> {
        if quantity.is_zero() {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail monetary mint amount must be positive".into(),
            ));
        }
        let authorized_policy =
            exact_retail_reserve_policy(state_transaction, authority, &asset_id)?;
        ensure_global_asset_write_on_authoritative_route(
            state_transaction,
            asset_id.definition(),
            "retail monetary mint",
        )?;
        crate::smartcontracts::isi::bond::ensure_bond_supply_unlocked(
            state_transaction.world(),
            asset_id.definition(),
        )?;
        let resolved = state_transaction
            .world
            .resolve_asset_id_for_current_scope(&asset_id)?;
        if resolved != asset_id {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail monetary mint resolved a different reserve balance".into(),
            ));
        }
        state_transaction.world.account(asset_id.account())?;
        ensure_not_fx_corridor_escrow_destination(state_transaction, &asset_id)?;
        ensure_not_sccp_escrow_destination(state_transaction, &asset_id)?;
        ensure_not_bond_vault_destination(state_transaction, &asset_id)?;
        let spec = state_transaction
            .numeric_spec_for(asset_id.definition())
            .map_err(Error::from)?;
        assert_numeric_spec_with(quantity.as_numeric(), spec)?;
        ensure_transparent_allowed(
            state_transaction,
            asset_id.definition(),
            "transparent retail monetary mint not permitted by policy",
        )?;
        ensure_usage_policy_for_accounts(
            state_transaction,
            asset_id.definition(),
            [(
                asset_id.account(),
                asset_id_dataspace_hint(state_transaction, &asset_id),
            )],
            Some(&quantity),
        )?;
        let flipped = assert_can_mint_cached(state_transaction, asset_id.definition())?;
        let captured_quantity = quantity.clone();
        let captured_id = asset_id.clone();
        apply_with_supply_quantity_candidate(
            state_transaction,
            authority,
            &captured_id,
            &captured_quantity,
            true,
            (
                "retail-reserve-mint",
                Some(quantity_authorization::SupplyBinding::RetailPolicy(
                    &authorized_policy,
                )),
            ),
            |state_transaction, original| {
                original
                    .apply_balance(&mut state_transaction.world)?
                    .apply(&mut state_transaction.world, &quantity)?;
                state_transaction
                    .world
                    .emit_asset_event(AssetEvent::Added(AssetChanged {
                        asset: asset_id.clone(),
                        amount: quantity.clone(),
                    }));
                if flipped {
                    state_transaction.world.emit_asset_definition_event(
                        AssetDefinitionEvent::MintabilityChangedDetailed(
                            AssetDefinitionMintabilityChanged {
                                asset_definition: asset_id.definition().clone(),
                                minted_amount: quantity,
                                authority: authority.clone(),
                            },
                        ),
                    );
                }
                Ok(())
            },
        )
    }

    /// Supply retirement is available only to the owner-installed monetary
    /// issuer and only from the installed reserve after the activation DAY.
    pub(crate) fn execute_retail_reserve_burn(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        asset_id: AssetId,
        quantity: Quantity,
    ) -> Result<(), Error> {
        if quantity.is_zero() {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail monetary burn amount must be positive".into(),
            ));
        }
        let authorized_policy =
            exact_retail_reserve_policy(state_transaction, authority, &asset_id)?;
        installed_retail_policy_for_source(state_transaction, &asset_id)?;
        ensure_global_asset_write_on_authoritative_route(
            state_transaction,
            asset_id.definition(),
            "retail monetary burn",
        )?;
        crate::smartcontracts::isi::bond::ensure_bond_supply_unlocked(
            state_transaction.world(),
            asset_id.definition(),
        )?;
        let resolved = state_transaction
            .world
            .resolve_asset_id_for_current_scope(&asset_id)?;
        if resolved != asset_id {
            return Err(InstructionExecutionError::InvariantViolation(
                "retail monetary burn resolved a different reserve balance".into(),
            ));
        }
        let spec = state_transaction
            .numeric_spec_for(asset_id.definition())
            .map_err(Error::from)?;
        assert_numeric_spec_with(quantity.as_numeric(), spec)?;
        ensure_transparent_allowed(
            state_transaction,
            asset_id.definition(),
            "transparent retail monetary burn not permitted by policy",
        )?;
        ensure_usage_policy_for_accounts(
            state_transaction,
            asset_id.definition(),
            [(
                asset_id.account(),
                asset_id_dataspace_hint(state_transaction, &asset_id),
            )],
            Some(&quantity),
        )?;
        ensure_not_native_escrow_source(state_transaction, &asset_id)?;
        ensure_not_fx_corridor_escrow_source(state_transaction, &asset_id)?;
        ensure_not_sorafs_reserve_custody_source(state_transaction, &asset_id)?;
        ensure_not_kagemusha_reserve_source(state_transaction.world(), &asset_id)?;
        ensure_not_sccp_escrow_source(state_transaction, &asset_id)?;
        let captured_quantity = quantity.clone();
        let captured_id = asset_id.clone();
        apply_with_supply_quantity_candidate(
            state_transaction,
            authority,
            &captured_id,
            &captured_quantity,
            false,
            (
                "retail-reserve-burn",
                Some(quantity_authorization::SupplyBinding::RetailPolicy(
                    &authorized_policy,
                )),
            ),
            |state_transaction, original| {
                original
                    .apply_balance(&mut state_transaction.world)?
                    .apply(&mut state_transaction.world, &quantity)?;
                state_transaction
                    .world
                    .emit_asset_event(AssetEvent::Removed(AssetChanged {
                        asset: asset_id,
                        amount: quantity,
                    }));
                Ok(())
            },
        )
    }
    impl Execute for Transfer<Asset, Quantity, Account> {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            execute_user_numeric_asset_transfer(
                state_transaction,
                authority,
                self.source().clone(),
                self.destination().clone(),
                self.object().clone(),
            )
        }
    }
    /// Apply a user-authorized transparent numeric asset transfer.
    pub(crate) fn execute_user_numeric_asset_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: AssetId,
        destination: AccountId,
        amount: Quantity,
    ) -> Result<(), Error> {
        let destination_id = AssetId::new(source_id.definition().clone(), destination);
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::transaction_user(authority, "asset transfer"),
        )
    }
    /// Execute the one exact reserve/retail direction admitted by the native
    /// retail monetary instruction through the shared checked movement kernel.
    pub(crate) fn execute_retail_monetary_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        purpose: RetailMonetaryPurposeV1,
    ) -> Result<(), Error> {
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retail_monetary(authority, purpose),
        )
    }
    /// Consume one exact SNS renewal charge capability produced by the maintenance sweep.
    pub(crate) fn execute_verified_sns_auto_renewal_charge(
        state_transaction: &mut StateTransaction<'_, '_>,
        authorization: crate::sns::VerifiedSnsAutoRenewalCharge,
    ) -> Result<(), Error> {
        let (
            permit,
            selector,
            owner,
            current_expiry_ms,
            target_expiry_ms,
            source_id,
            destination,
            amount,
        ) = authorization.into_parts();
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let record =
            crate::sns::get_name_record_by_selector(&state_transaction.world, &selector, now_ms)
                .map_err(|error| {
                    if error.deferral().is_some() {
                        return error.retain_in_instruction(state_transaction);
                    }
                    InstructionExecutionError::InvariantViolation(
                        format!("verified SNS renewal record is no longer valid: {error}").into(),
                    )
                })?;
        let quote = crate::sns::quote_resolved_name_renewal(
            &state_transaction.world,
            selector.clone(),
            current_expiry_ms,
            target_expiry_ms,
            now_ms,
        )
        .map_err(|error| {
            if error.deferral().is_some() {
                return error.retain_in_instruction(state_transaction);
            }
            InstructionExecutionError::InvariantViolation(
                format!("verified SNS renewal quote is no longer valid: {error}").into(),
            )
        })?;
        if record.owner != owner
            || record.expires_at_ms != current_expiry_ms
            || source_id.account() != &owner
            || source_id.definition() != &quote.payment_asset_definition_id
            || destination != quote.collector_account
            || amount != quote.charge_amount
            || quote.expires_at_ms != target_expiry_ms
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "verified SNS renewal charge does not match live record and quote state".into(),
            ));
        }
        let destination_id = AssetId::new(source_id.definition().clone(), destination);
        let binding = canonical_numeric_movement_binding(&(
            permit
                .binding()
                .map_err(|error| InstructionExecutionError::InvariantViolation(error.into()))?,
            selector,
            owner.clone(),
            current_expiry_ms,
            target_expiry_ms,
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        let authorization = NumericAssetMovementAuthorization::embedded_user(
            &owner,
            EmbeddedNumericAssetMovementPurpose::SnsAutoRenewal(binding),
        );
        let identity = authorization.resolve_transcript_identity(
            state_transaction,
            &[(source_id.clone(), destination_id.clone(), amount.clone())],
        )?;
        state_transaction
            .authorize_sns_native_source(permit, identity)
            .map_err(|error| error.retain_in_instruction(state_transaction))?;
        // A free quote or payment to the same canonical balance renews the lease
        // without inventing a numeric movement, transcript or unapplied source E.
        if amount.is_zero() || source_id == destination_id {
            return Ok(());
        }
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            authorization,
        )
    }
    fn resolve_fx_corridor_escrow_binding(
        state_transaction: &StateTransaction<'_, '_>,
        policy: &iroha_data_model::isi::settlement::FxCorridorPolicy,
    ) -> Result<(AccountId, AssetId), Error> {
        let current = crate::smartcontracts::isi::settlement::fx_policy(
            state_transaction,
            &policy.policy_id,
        )?;
        if current != *policy {
            return Err(InstructionExecutionError::InvariantViolation(
                "FX escrow movement does not match the exact active corridor policy".into(),
            ));
        }
        let escrow = iroha_data_model::isi::settlement::fx_corridor_escrow_account_id_v1(
            &state_transaction.network_id,
            &policy.corridor_id(),
            &policy.destination_asset_definition_id,
        );
        state_transaction.world.account(&escrow)?;
        let escrow_asset = AssetId::with_scope(
            policy.destination_asset_definition_id.clone(),
            escrow,
            AssetBalanceScope::Dataspace(policy.destination_dataspace),
        );
        Ok((policy.owner.clone(), escrow_asset))
    }
    /// Fund an exact FX reserve from its immutable owner through a typed movement corridor.
    pub(crate) fn execute_fx_corridor_owner_funding(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        policy: &iroha_data_model::isi::settlement::FxCorridorPolicy,
        amount: Quantity,
    ) -> Result<(), Error> {
        let (owner, destination_id) =
            resolve_fx_corridor_escrow_binding(state_transaction, policy)?;
        if authority != &owner {
            return Err(InstructionExecutionError::InvariantViolation(
                "only the exact FX corridor owner may fund its protocol escrow".into(),
            ));
        }
        let source_id = AssetId::with_scope(
            policy.destination_asset_definition_id.clone(),
            owner,
            AssetBalanceScope::Dataspace(policy.destination_dataspace),
        );
        let binding = canonical_numeric_movement_binding(&(
            policy.policy_id.clone(),
            policy.revision,
            policy.corridor_id(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::embedded_user(
                authority,
                EmbeddedNumericAssetMovementPurpose::FxCorridorEscrowDeposit(binding),
            ),
        )
    }
    /// Refund an inactive FX reserve only to its immutable owner.
    pub(crate) fn execute_fx_corridor_owner_refund(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        policy: &iroha_data_model::isi::settlement::FxCorridorPolicy,
        amount: Quantity,
    ) -> Result<(), Error> {
        let (owner, source_id) = resolve_fx_corridor_escrow_binding(state_transaction, policy)?;
        if authority != &owner || policy.enabled {
            return Err(InstructionExecutionError::InvariantViolation(
                "FX corridor refund requires its exact owner and an inactive policy".into(),
            ));
        }
        let destination_id = AssetId::with_scope(
            policy.destination_asset_definition_id.clone(),
            owner,
            AssetBalanceScope::Dataspace(policy.destination_dataspace),
        );
        let binding = canonical_numeric_movement_binding(&(
            policy.policy_id.clone(),
            policy.revision,
            policy.corridor_id(),
            source_id.clone(),
            destination_id.clone(),
            amount.clone(),
        ))?;
        execute_numeric_asset_movement(
            state_transaction,
            source_id,
            destination_id,
            amount,
            NumericAssetMovementAuthorization::retained(
                authority,
                RetainedNumericAssetMovementPurpose::FxCorridorEscrowRefund(binding),
            ),
        )
    }
    #[cfg(test)]
    /// Exercise the reference numeric-transfer batch path in delta regression tests.
    ///
    /// Returns `Ok(false)` when the transfer needs the full per-transaction merge path.
    pub(crate) fn execute_batch_merge_eligible_user_numeric_asset_transfer(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        source_id: AssetId,
        destination: AccountId,
        amount: Quantity,
    ) -> Result<bool, Error> {
        if state_transaction.world.account(&destination).is_err() {
            return Ok(false);
        }
        let destination_id = AssetId::new(source_id.definition().clone(), destination);
        let plan = PreparedNumericTransferPlan::prepare_user(
            state_transaction,
            authority,
            source_id,
            destination_id,
            amount,
        )?;
        if plan.control_update.is_some() {
            return Ok(false);
        }
        let transcript_identity = state_transaction
            .require_transfer_transcript_identity("FastPQ transfer transcript recording")?;
        let applied = state_transaction.apply_with_prepared_transfer_transcripts(
            authority,
            transcript_identity,
            vec![plan.prechecked_delta.clone()],
            |state_transaction| {
                let legs = [(
                    plan.source_id.clone(),
                    plan.destination_id.clone(),
                    plan.prechecked_delta.clone(),
                )];
                NumericAssetMovementAuthorization::transaction_user(authority, "asset transfer")
                    .apply_with_quantity_candidate(
                        state_transaction,
                        transcript_identity,
                        &legs,
                        |state_transaction| plan.apply(state_transaction),
                    )
            },
        )?;
        #[allow(clippy::float_arithmetic)]
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .observe_tx_amount(applied.amount.as_numeric().clone().to_f64_lossy());
        let amount = applied.amount;
        emit_numeric_asset_transfer_events(
            state_transaction,
            applied.source_id,
            applied.destination_id,
            amount,
        );
        Ok(true)
    }
    impl Execute for SetAssetTransferAvailability {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_asset_transfer_control_authority(
                state_transaction,
                authority,
                &self.account_id,
                &self.asset_definition_id,
                TransferControlCapability::Availability,
            )?;
            state_transaction.world.account(&self.account_id)?;
            if let Err(error) = validate_asset_transfer_availability_reason(self.reason.as_deref())
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    error.to_string().into(),
                )
                .into());
            }
            let now_ms = state_transaction.block_unix_timestamp_ms();
            let mut record = active_control_record(
                state_transaction,
                &self.account_id,
                &self.asset_definition_id,
            )?
            .unwrap_or_else(|| AssetTransferControlRecord::new(self.asset_definition_id.clone()));
            if record.availability_revision != self.expected_revision {
                return Err(InstructionExecutionError::AssetTransferAdmission(
                    AssetTransferAdmissionError::AvailabilityRevisionMismatch(
                        format!(
                            "expected {}, current {} for account {} on asset definition {}",
                            self.expected_revision,
                            record.availability_revision,
                            self.account_id,
                            self.asset_definition_id
                        )
                        .into(),
                    ),
                )
                .into());
            }
            if record.incoming_availability == self.incoming
                && record.outgoing_availability == self.outgoing
            {
                return Err(InstructionExecutionError::InvariantViolation(
                    "asset-transfer availability update must change at least one direction".into(),
                )
                .into());
            }
            record.availability_revision =
                record.availability_revision.checked_add(1).ok_or_else(|| {
                    InstructionExecutionError::InvariantViolation(
                        "asset-transfer availability revision overflow".into(),
                    )
                })?;
            record.incoming_availability = self.incoming;
            record.outgoing_availability = self.outgoing;
            record.availability_reason = self.reason;
            record.updated_at_ms = Some(now_ms);
            update_control_record(state_transaction, &self.account_id, record)
        }
    }
    impl Execute for SetAssetTransferBlacklist {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_asset_transfer_control_authority(
                state_transaction,
                authority,
                &self.account_id,
                &self.asset_definition_id,
                TransferControlCapability::OwnerOnly,
            )?;
            state_transaction.world.account(&self.account_id)?;
            let now_ms = state_transaction.block_unix_timestamp_ms();
            let mut record = active_control_record(
                state_transaction,
                &self.account_id,
                &self.asset_definition_id,
            )?
            .unwrap_or_else(|| AssetTransferControlRecord::new(self.asset_definition_id.clone()));
            record.blacklisted = self.blacklisted;
            record.updated_at_ms = Some(now_ms);
            update_control_record(state_transaction, &self.account_id, record)
        }
    }
    impl Execute for SetAssetTransferControl {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            if self.limits.len() != 1 || self.limits[0].window != AssetTransferControlWindow::Day {
                let asset_definition = state_transaction
                    .world
                    .asset_definition(&self.asset_definition_id)?;
                let owner = asset_definition.owned_by();
                if owner != authority {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "delegated daily-limit permission accepts exactly one DAY limit"
                            .to_owned()
                            .into(),
                    ));
                }
            }
            ensure_asset_transfer_control_authority(
                state_transaction,
                authority,
                &self.account_id,
                &self.asset_definition_id,
                TransferControlCapability::DailyLimit,
            )?;
            state_transaction.world.account(&self.account_id)?;
            let now_ms = state_transaction.block_unix_timestamp_ms();
            let mut record = active_control_record(
                state_transaction,
                &self.account_id,
                &self.asset_definition_id,
            )?
            .unwrap_or_else(|| AssetTransferControlRecord::new(self.asset_definition_id.clone()));
            let next_limits = canonicalize_asset_transfer_limits(self.limits)?;
            let active_windows = next_limits
                .iter()
                .map(|limit| limit.window)
                .collect::<BTreeSet<_>>();
            record.limits = next_limits;
            record
                .usages
                .retain(|usage| active_windows.contains(&usage.window));
            record.updated_at_ms = Some(now_ms);
            update_control_record(state_transaction, &self.account_id, record)
        }
    }
    impl Execute for SetAssetHoldingLimit {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_asset_transfer_control_authority(
                state_transaction,
                authority,
                &self.account_id,
                &self.asset_definition_id,
                TransferControlCapability::HoldingLimit,
            )?;
            state_transaction.world.account(&self.account_id)?;
            let spec = state_transaction
                .numeric_spec_for(&self.asset_definition_id)
                .map_err(Error::from)?;
            if let Some(limit) = self.holding_limit.as_ref() {
                assert_numeric_spec_with(limit.as_numeric(), spec)?;
            }
            let now_ms = state_transaction.block_unix_timestamp_ms();
            let mut record = active_control_record(
                state_transaction,
                &self.account_id,
                &self.asset_definition_id,
            )?
            .unwrap_or_else(|| AssetTransferControlRecord::new(self.asset_definition_id.clone()));
            record.holding_limit = self.holding_limit;
            record.updated_at_ms = Some(now_ms);
            update_control_record(state_transaction, &self.account_id, record)
        }
    }
    impl Execute for TransferAssetBatch {
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            if self.entries().is_empty() {
                return Err(InstructionExecutionError::InvariantViolation(
                    "transfer asset batch requires at least one entry".into(),
                ));
            }
            if self.mode() == &BatchMode::Independent
                && crate::validation_fee::active_policy(state_transaction)
                    .map_err(|e| Error::InvariantViolation(e.to_string().into()))?
                    .is_some_and(|policy| {
                        self.entries()
                            .iter()
                            .any(|entry| entry.asset_definition() == &policy.ds_asset_id)
                    })
            {
                return Err(Error::InvariantViolation(
                    "governed SBD payment batches require atomic settlement".into(),
                ));
            }
            let mut leg_ids = BTreeSet::new();
            for entry in self.entries() {
                if entry.leg_id().trim().is_empty() || entry.leg_id().trim() != entry.leg_id() {
                    return Err(InstructionExecutionError::InvariantViolation(
                        "transfer asset batch leg_id must be non-empty and unpadded".into(),
                    ));
                }
                if !leg_ids.insert(entry.leg_id()) {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "transfer asset batch contains duplicate leg_id `{}`",
                            entry.leg_id()
                        )
                        .into(),
                    ));
                }
                if entry.amount().is_zero() {
                    return Err(InstructionExecutionError::InvariantViolation(
                        format!(
                            "transfer asset batch leg `{}` amount must be non-zero",
                            entry.leg_id()
                        )
                        .into(),
                    ));
                }
            }
            if self.mode() == &BatchMode::Atomic {
                let entries = self
                    .entries()
                    .iter()
                    .map(|entry| {
                        (
                            AssetId::new(entry.asset_definition().clone(), entry.from().clone()),
                            AssetId::new(entry.asset_definition().clone(), entry.to().clone()),
                            entry.amount().clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                let applied = PreparedNumericAssetMovementBatch::prepare_user(
                    state_transaction,
                    authority,
                    &entries,
                )?
                .apply(state_transaction)?;
                for (index, (entry, movement)) in self.entries().iter().zip(applied).enumerate() {
                    #[allow(clippy::float_arithmetic)]
                    #[cfg(feature = "telemetry")]
                    state_transaction
                        .telemetry
                        .observe_tx_amount(movement.amount.as_numeric().clone().to_f64_lossy());
                    emit_numeric_asset_transfer_events(
                        state_transaction,
                        movement.source_id,
                        movement.destination_id,
                        movement.amount,
                    );
                    let outcome = AssetBatchTransferOutcome {
                        leg_index: u32::try_from(index).map_err(|_| {
                            InstructionExecutionError::InvariantViolation(
                                "transfer asset batch contains too many legs".into(),
                            )
                        })?,
                        leg_id: entry.leg_id().clone(),
                        asset: entries[index].0.clone(),
                        destination: entry.to().clone(),
                        amount: entry.amount().clone(),
                        status: AssetBatchTransferLegStatus::Applied,
                    };
                    state_transaction.record_batch_transfer_outcome(outcome.clone());
                    state_transaction
                        .world
                        .emit_asset_event(AssetEvent::BatchTransferOutcome(outcome));
                }
                return Ok(());
            }
            let batch_hash = state_transaction
                .require_transfer_transcript_identity("independent asset transfer batch")?;
            state_transaction.apply_with_incremental_transfer_transcripts(
                authority,
                batch_hash,
                self.entries().len(),
                |state_transaction, prepare_delta| {
                    for (index, entry) in self.entries().iter().enumerate() {
                        let source_id =
                            AssetId::new(entry.asset_definition().clone(), entry.from().clone());
                        let destination_id =
                            AssetId::new(entry.asset_definition().clone(), entry.to().clone());
                        let amount = entry.amount().clone();
                        let plan = (|| -> Result<PreparedNumericTransferPlan, Error> {
                            if self.mode() == &BatchMode::Independent {
                                // Independent settlement captures participant and asset
                                // admission as a leg-local outcome. Requiring both
                                // accounts up front also ensures a failed leg cannot
                                // stage implicit-account creation or its fee before the
                                // failure is isolated.
                                state_transaction.world.account(entry.from())?;
                                state_transaction.world.account(entry.to())?;
                                state_transaction
                                    .world
                                    .asset_definition(entry.asset_definition())?;
                            }
                            PreparedNumericTransferPlan::prepare_user(
                                state_transaction,
                                authority,
                                source_id.clone(),
                                destination_id,
                                amount.clone(),
                            )
                        })();
                        let plan = match plan {
                            Ok(plan) => plan,
                            Err(error) if self.mode() == &BatchMode::Independent => {
                                let message = error.to_string();
                                let code = batch_transfer_rejection_code(&error);
                                let outcome = AssetBatchTransferOutcome {
                                    leg_index: u32::try_from(index).map_err(|_| {
                                        InstructionExecutionError::InvariantViolation(
                                            "transfer asset batch contains too many legs".into(),
                                        )
                                    })?,
                                    leg_id: entry.leg_id().clone(),
                                    asset: source_id,
                                    destination: entry.to().clone(),
                                    amount,
                                    status: AssetBatchTransferLegStatus::Rejected(
                                        AssetBatchTransferRejection { code, message },
                                    ),
                                };
                                state_transaction.record_batch_transfer_outcome(outcome.clone());
                                state_transaction
                                    .world
                                    .emit_asset_event(AssetEvent::BatchTransferOutcome(outcome));
                                continue;
                            }
                            Err(error) => return Err(error),
                        };
                        prepare_delta(state_transaction, plan.prechecked_delta.clone())?;
                        let legs = [(
                            plan.source_id.clone(),
                            plan.destination_id.clone(),
                            plan.prechecked_delta.clone(),
                        )];
                        let applied = NumericAssetMovementAuthorization::transaction_user(
                            authority,
                            "independent asset transfer batch",
                        )
                        .apply_with_quantity_candidate(
                            state_transaction,
                            batch_hash,
                            &legs,
                            |state_transaction| plan.apply(state_transaction),
                        )?;
                        #[allow(clippy::float_arithmetic)]
                        #[cfg(feature = "telemetry")]
                        state_transaction
                            .telemetry
                            .observe_tx_amount(applied.amount.as_numeric().clone().to_f64_lossy());
                        let amount = applied.amount;
                        emit_numeric_asset_transfer_events(
                            state_transaction,
                            applied.source_id,
                            applied.destination_id,
                            amount,
                        );
                        let outcome = AssetBatchTransferOutcome {
                            leg_index: u32::try_from(index).map_err(|_| {
                                InstructionExecutionError::InvariantViolation(
                                    "transfer asset batch contains too many legs".into(),
                                )
                            })?,
                            leg_id: entry.leg_id().clone(),
                            asset: source_id,
                            destination: entry.to().clone(),
                            amount: entry.amount().clone(),
                            status: AssetBatchTransferLegStatus::Applied,
                        };
                        state_transaction.record_batch_transfer_outcome(outcome.clone());
                        state_transaction
                            .world
                            .emit_asset_event(AssetEvent::BatchTransferOutcome(outcome));
                    }
                    Ok(())
                },
            )
        }
    }
    fn batch_transfer_rejection_code(
        error: &InstructionExecutionError,
    ) -> AssetBatchTransferRejectionCode {
        match error {
            InstructionExecutionError::Math(MathError::NotEnoughQuantity) => {
                AssetBatchTransferRejectionCode::InsufficientFunds
            }
            InstructionExecutionError::AssetTransferAdmission(admission) => match admission {
                AssetTransferAdmissionError::HoldingLimitExceeded(_) => {
                    AssetBatchTransferRejectionCode::HoldingLimitExceeded
                }
                AssetTransferAdmissionError::IncomingDisabled(_) => {
                    AssetBatchTransferRejectionCode::IncomingDisabled
                }
                AssetTransferAdmissionError::OutgoingDisabled(_) => {
                    AssetBatchTransferRejectionCode::OutgoingDisabled
                }
                AssetTransferAdmissionError::AvailabilityRevisionMismatch(_) => {
                    AssetBatchTransferRejectionCode::PolicyRejected
                }
                AssetTransferAdmissionError::Blacklisted(_) => {
                    AssetBatchTransferRejectionCode::Blacklisted
                }
                AssetTransferAdmissionError::PolicyRejected(_) => {
                    AssetBatchTransferRejectionCode::PolicyRejected
                }
            },
            _ => AssetBatchTransferRejectionCode::PolicyRejected,
        }
    }
    impl Execute for SetAssetKeyValue {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let SetAssetKeyValue { asset, key, value } = self;
            crate::smartcontracts::limits::enforce_json_size(
                state_transaction,
                &value,
                "max_metadata_value_bytes",
                crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
            )?;
            state_transaction
                .world
                .asset_metadata_mut_or_default(&asset)
                .map_err(Error::from)?
                .insert(key.clone(), value.clone());
            state_transaction
                .world
                .emit_asset_event(AssetEvent::MetadataInserted(MetadataChanged {
                    target: asset,
                    key,
                    value,
                }));
            Ok(())
        }
    }
    impl Execute for RemoveAssetKeyValue {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let RemoveAssetKeyValue { asset, key } = self;
            let removed = state_transaction
                .world
                .remove_asset_metadata_key(&asset, &key)
                .map_err(Error::from)?;
            state_transaction
                .world
                .emit_asset_event(AssetEvent::MetadataRemoved(MetadataChanged {
                    target: asset,
                    key,
                    value: removed,
                }));
            Ok(())
        }
    }
    /// Check and consume mintability through the transaction-local cache.
    fn assert_can_mint_cached(
        state_transaction: &mut StateTransaction<'_, '_>,
        def_id: &AssetDefinitionId,
    ) -> Result<bool, Error> {
        let mintable = state_transaction
            .mintable_for(def_id)
            .map_err(Error::from)?;
        match mintable {
            Mintable::Infinitely => Ok(false),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once | Mintable::Limited(_) => {
                let mut def_mut = state_transaction
                    .world
                    .asset_definition_metadata_mut(def_id)?;
                let flipped = def_mut.consume_mintability().map_err(Error::Mintability)?;
                let updated = def_mut.mintable();
                state_transaction
                    .mintable_cache
                    .insert(def_id.clone(), updated);
                if let Some((ref id, _)) = state_transaction.last_mintable
                    && id == def_id
                {
                    state_transaction.last_mintable = Some((id.clone(), updated));
                }
                Ok(flipped)
            }
        }
    }
    #[cfg(test)]
    mod prepared_source_additional_owner_tests {
        use super::*;
        use iroha_model_base::domain::DomainId;
        include!("asset/prepared_source_additional_owner_tests.rs");
        #[test]
        fn quantity_preimage_measurement_refuses_before_frame_allocation() {
            let value = vec![7_u8; 1024];
            let measured = u64::try_from(norito::canonical_frame_len(&value).unwrap()).unwrap();
            let mut exact = measured + 8;
            assert_eq!(
                bounded_quantity_frame(&value, &mut exact).unwrap(),
                norito::encode_canonical(&value).unwrap()
            );
            assert_eq!(exact, 0);
            let mut short = measured + 7;
            assert!(bounded_quantity_frame(&value, &mut short).is_none());
            assert_eq!(short, measured + 7);
        }
        #[test]
        fn quantity_context_retains_protocol_purpose_inside_same_transaction() {
            let (state, definition, source) = build_asset_transfer_control_test_state(10);
            let destination = AssetId::new(definition, BOB_ID.clone());
            let legs = [(source, destination, Quantity::from(3_u32))];
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut transaction = block.transaction();
            transaction.tx_call_hash = Some(Hash::new(b"same authenticated invocation"));
            let first = NumericAssetMovementAuthorization::retained(
                &ALICE_ID,
                RetainedNumericAssetMovementPurpose::GovernanceSlash(vec![1]),
            );
            let second = NumericAssetMovementAuthorization::retained(
                &ALICE_ID,
                RetainedNumericAssetMovementPurpose::GovernanceSlash(vec![2]),
            );
            let other = NumericAssetMovementAuthorization::retained(
                &ALICE_ID,
                RetainedNumericAssetMovementPurpose::GovernanceRestitution(vec![1]),
            );
            assert_eq!(
                first
                    .resolve_transcript_identity(&transaction, &legs)
                    .unwrap(),
                second
                    .resolve_transcript_identity(&transaction, &legs)
                    .unwrap()
            );
            assert_ne!(
                first.quantity_authorization_context(&legs, u64::MAX),
                second.quantity_authorization_context(&legs, u64::MAX)
            );
            assert_ne!(
                first.quantity_authorization_context(&legs, u64::MAX),
                other.quantity_authorization_context(&legs, u64::MAX)
            );
            assert!(
                first
                    .quantity_authorization_context(&legs, u64::MAX)
                    .is_some()
            );
        }
        #[test]
        fn quantity_context_binds_scope_amount_and_debit_authority() {
            let (_state, definition, source) = build_asset_transfer_control_test_state(10);
            let destination = AssetId::new(definition.clone(), BOB_ID.clone());
            let legs = [(source.clone(), destination.clone(), Quantity::from(3_u32))];
            let authorization =
                NumericAssetMovementAuthorization::transaction_user(&ALICE_ID, "asset transfer");
            let original = authorization
                .quantity_authorization_context(&legs, u64::MAX)
                .unwrap();
            let scoped = [(
                AssetId::with_scope(
                    definition,
                    ALICE_ID.clone(),
                    iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
                ),
                destination.clone(),
                Quantity::from(3_u32),
            )];
            assert_ne!(
                Some(original),
                authorization.quantity_authorization_context(&scoped, u64::MAX)
            );
            assert_ne!(
                Some(original),
                authorization.quantity_authorization_context(
                    &[(source, destination, Quantity::from(4_u32))],
                    u64::MAX
                )
            );
            let different =
                NumericAssetMovementAuthorization::transaction_user(&BOB_ID, "asset transfer");
            assert_ne!(
                Some(original),
                different.quantity_authorization_context(&legs, u64::MAX)
            );
        }
        #[test]
        fn prepared_transfer_rechecks_public_lane_reserves_before_consumption() {
            let (state, definition_id, source) = build_asset_transfer_control_test_state(100);
            let destination = AssetId::new(definition_id, BOB_ID.clone());
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut transaction = block.transaction();
            let delta = transaction
                .world
                .precheck_numeric_asset_transfer_delta_exact(
                    &source,
                    &destination,
                    &Quantity::from(50_u64),
                )
                .unwrap();
            transaction
                .world
                .public_lane_stake_reserves
                .insert(source.clone(), Quantity::from(60_u64));
            assert!(
                transaction
                    .world
                    .apply_prechecked_numeric_asset_transfer_delta_exact(
                        &source,
                        &destination,
                        &delta.amount,
                        &delta,
                        NumericAssetTransferSourcePolicy::User,
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("reserved public-lane")
            );
            assert_eq!(
                transaction.world.assets.get(&source).unwrap().as_ref(),
                &Quantity::from(100_u64)
            );
            assert!(transaction.world.assets.get(&destination).is_none());
            transaction
                .world
                .public_lane_stake_reserves
                .insert(source.clone(), Quantity::from(50_u64));
            transaction
                .world
                .apply_prechecked_numeric_asset_transfer_delta_exact(
                    &source,
                    &destination,
                    &delta.amount,
                    &delta,
                    NumericAssetTransferSourcePolicy::User,
                )
                .unwrap();
            assert_eq!(
                transaction.world.assets.get(&source).unwrap().as_ref(),
                &Quantity::from(50_u64)
            );
            assert_eq!(
                transaction.world.assets.get(&destination).unwrap().as_ref(),
                &Quantity::from(50_u64)
            );
        }
        #[test]
        fn oracle_movement_frames_bind_owner_and_replay_context() {
            use iroha_data_model::oracle::{
                FeedConfigVersion, FeedId, OracleDisputeId, OraclePenaltyKind,
            };
            type Reward = (FeedId, FeedConfigVersion, u64, Hash, AccountId, Quantity);
            type Penalty = (
                FeedId,
                FeedConfigVersion,
                u64,
                Hash,
                AccountId,
                OraclePenaltyKind,
                Quantity,
            );
            let (state, definition, source) = build_asset_transfer_control_test_state(10);
            let destination = AssetId::new(definition, BOB_ID.clone());
            let legs = vec![(source.clone(), destination.clone(), Quantity::from(3_u32))];
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let stx = block.transaction();
            assert!(stx.tx_call_hash.is_none());
            let dispute_binding = canonical_numeric_movement_binding(&OracleDisputeId(7)).unwrap();
            assert_eq!(
                norito::decode_canonical::<OracleDisputeId>(&dispute_binding).unwrap(),
                OracleDisputeId(7)
            );
            let dispute_identity = |binding| {
                NumericAssetMovementAuthorization::embedded_user(
                    &ALICE_ID,
                    EmbeddedNumericAssetMovementPurpose::OracleDisputeBond(binding),
                )
                .resolve_transcript_identity(&stx, &legs)
                .unwrap()
            };
            let identity = dispute_identity(dispute_binding.clone());
            assert_eq!(
                identity,
                dispute_identity(canonical_numeric_movement_binding(&OracleDisputeId(7)).unwrap())
            );
            assert_ne!(
                identity,
                dispute_identity(canonical_numeric_movement_binding(&OracleDisputeId(8)).unwrap())
            );
            // An integer binding cannot replay the dispute-owned frame.
            let integer_binding = canonical_numeric_movement_binding(&7_u64).unwrap();
            assert!(matches!(
                norito::decode_canonical::<OracleDisputeId>(&integer_binding),
                Err(norito::Error::SchemaMismatch)
            ));
            assert_ne!(identity, dispute_identity(integer_binding));
            let reward: Reward = (
                FeedId("price_xor_usd".parse().unwrap()),
                FeedConfigVersion(1),
                11,
                Hash::new(b"oracle-request"),
                ALICE_ID.clone(),
                Quantity::from(3_u32),
            );
            let reward_binding = canonical_numeric_movement_binding(&reward).unwrap();
            assert_eq!(
                norito::decode_canonical::<Reward>(&reward_binding).unwrap(),
                reward
            );
            let reward_identity = |binding| {
                NumericAssetMovementAuthorization::retained(
                    &ALICE_ID,
                    RetainedNumericAssetMovementPurpose::OracleReward(binding),
                )
                .resolve_transcript_identity(&stx, &legs)
                .unwrap()
            };
            let reward_hash = reward_identity(reward_binding.clone());
            let mut later_config = reward.clone();
            later_config.1 = FeedConfigVersion(2);
            assert_ne!(
                reward_hash,
                reward_identity(canonical_numeric_movement_binding(&later_config).unwrap())
            );
            let mut later_slot = reward.clone();
            later_slot.2 += 1;
            assert_ne!(
                reward_hash,
                reward_identity(canonical_numeric_movement_binding(&later_slot).unwrap())
            );
            let penalty: Penalty = (
                reward.0,
                reward.1,
                reward.2,
                reward.3,
                reward.4,
                OraclePenaltyKind::Outlier,
                reward.5,
            );
            let penalty_binding = canonical_numeric_movement_binding(&penalty).unwrap();
            assert_eq!(
                norito::decode_canonical::<Penalty>(&penalty_binding).unwrap(),
                penalty
            );
            assert!(matches!(
                norito::decode_canonical::<Reward>(&penalty_binding),
                Err(norito::Error::SchemaMismatch)
            ));
            let penalty_hash = NumericAssetMovementAuthorization::retained(
                &ALICE_ID,
                RetainedNumericAssetMovementPurpose::OraclePenalty(reward_binding),
            )
            .resolve_transcript_identity(&stx, &legs)
            .unwrap();
            assert_ne!(
                reward_hash, penalty_hash,
                "purpose tag separates otherwise equal binding bytes"
            );
            let resolution = (
                OracleDisputeId(7),
                source,
                destination,
                Quantity::from(3_u32),
            );
            let resolution_binding = canonical_numeric_movement_binding(&resolution).unwrap();
            assert_eq!(
                norito::decode_canonical::<(OracleDisputeId, AssetId, AssetId, Quantity)>(
                    &resolution_binding
                )
                .unwrap(),
                resolution
            );
            assert!(
                norito::decode_canonical::<Penalty>(&penalty_binding[..penalty_binding.len() - 1])
                    .is_err()
            );
            assert!(
                norito::decode_canonical::<(OracleDisputeId, AssetId, AssetId, Quantity)>(
                    &resolution_binding[..resolution_binding.len() - 1]
                )
                .is_err()
            );
        }
    }
}
/// Asset-related query implementations.
pub mod query {
    #[cfg(test)]
    use super::isi::execute_user_numeric_asset_transfer;
    use super::*;
    use crate::smartcontracts::isi::query::json_predicate::{
        parse_domain_predicate_value, predicate_matches_with_aliases,
    };
    use crate::{
        smartcontracts::{ValidQuery, ValidSingularQuery},
        state::StateReadOnly,
    };
    use eyre::Result;
    use iroha_data_model::{
        asset::{Asset, AssetDefinition, AssetEntry},
        query::{
            asset::{FindAssetById, FindAssetDefinitionById},
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::QueryExecutionFail as Error,
            json::PredicateJson,
        },
    };
    use iroha_model_base::domain::DomainId;
    use norito::json::Value;
    use std::{collections::BTreeSet, sync::Arc};
    #[derive(Debug, Default, Clone)]
    struct AssetPredicateView {
        ids: BTreeSet<AssetId>,
        subjects: BTreeSet<AccountId>,
        definitions: BTreeSet<AssetDefinitionId>,
        domains: BTreeSet<DomainId>,
    }
    impl AssetPredicateView {
        fn from_predicate(predicate: &CompoundPredicate<Asset>) -> Self {
            let mut view = Self::default();
            let Some(raw) = predicate.json_payload() else {
                return view;
            };
            let Some(parsed) =
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution(raw)
            else {
                return view;
            };
            view.ingest_predicate(parsed);
            view
        }
        fn ingest_predicate(&mut self, predicate: PredicateJson) {
            for condition in predicate.equals {
                self.push_field_value(&condition.field, &condition.value);
            }
            for membership in predicate.r#in {
                for value in membership.values {
                    self.push_field_value(&membership.field, &value);
                }
            }
        }
        fn push_field_value(&mut self, field: &str, value: &Value) {
            let Some(raw) = Self::value_as_str(value) else {
                return;
            };
            match field {
                "account" | "account_id" | "owner" | "id.account" => {
                    if let Ok(account_id) = AccountId::parse_encoded(raw) {
                        self.subjects.insert(account_id.subject_id());
                    }
                }
                "definition"
                | "asset_definition"
                | "asset_definition_id"
                | "definition_id"
                | "id.definition" => {
                    if let Ok(definition_id) = raw.parse() {
                        self.definitions.insert(definition_id);
                    }
                }
                "domain" | "definition.domain" | "id.definition.domain" => {
                    if let Some(domain_id) = parse_domain_predicate_value(raw) {
                        self.domains.insert(domain_id);
                    }
                }
                "id" => {
                    if let Ok(asset_id) = raw.parse::<AssetId>() {
                        self.subjects.insert(asset_id.account().subject_id());
                        self.definitions.insert(asset_id.definition().clone());
                        self.ids.insert(asset_id);
                    }
                }
                _ => {}
            }
        }
        fn value_as_str(value: &Value) -> Option<&str> {
            if let Value::String(raw) = value {
                Some(raw.as_str())
            } else {
                None
            }
        }
        fn plan(&self) -> AssetQueryPlan {
            let mut ids: Vec<_> = self.ids.iter().cloned().collect();
            ids.sort();
            let mut subjects: Vec<_> = self.subjects.iter().cloned().collect();
            subjects.sort();
            let mut definitions: Vec<_> = self.definitions.iter().cloned().collect();
            definitions.sort();
            let mut domains: Vec<_> = self.domains.iter().cloned().collect();
            domains.sort();
            if !ids.is_empty() {
                return AssetQueryPlan::Ids(ids);
            }
            if !self.subjects.is_empty() {
                return AssetQueryPlan::Subjects {
                    subjects,
                    domains: (!domains.is_empty()).then_some(domains),
                    definitions: (!definitions.is_empty()).then_some(definitions),
                };
            }
            if !domains.is_empty() && !definitions.is_empty() {
                return AssetQueryPlan::Domains {
                    domains,
                    definitions: Some(definitions),
                };
            }
            if !domains.is_empty() {
                return AssetQueryPlan::Domains {
                    domains,
                    definitions: None,
                };
            }
            if !definitions.is_empty() {
                return AssetQueryPlan::Definitions(definitions);
            }
            AssetQueryPlan::Full
        }
        fn matches(&self, world: &impl WorldReadOnly, asset: &Asset) -> bool {
            if !self.ids.is_empty() && !self.ids.contains(asset.id()) {
                return false;
            }
            if !self.subjects.is_empty()
                && !self.subjects.contains(&asset.id().account().subject_id())
            {
                return false;
            }
            if !self.definitions.is_empty() && !self.definitions.contains(asset.id().definition()) {
                return false;
            }
            if !self.domains.is_empty()
                && !asset_definition_domain(world, asset.id().definition())
                    .is_some_and(|domain| self.domains.contains(&domain))
            {
                return false;
            }
            true
        }
    }
    #[derive(Debug, Default, Clone)]
    struct AssetDefinitionPredicateView {
        ids: BTreeSet<AssetDefinitionId>,
        owners: BTreeSet<AccountId>,
        domains: BTreeSet<DomainId>,
    }
    impl AssetDefinitionPredicateView {
        fn from_predicate(predicate: &CompoundPredicate<AssetDefinition>) -> Self {
            let mut view = Self::default();
            let Some(raw) = predicate.json_payload() else {
                return view;
            };
            let Some(parsed) =
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution(raw)
            else {
                return view;
            };
            view.ingest_predicate(parsed);
            view
        }
        fn ingest_predicate(&mut self, predicate: PredicateJson) {
            for condition in predicate.equals {
                self.push_field_value(&condition.field, &condition.value);
            }
            for membership in predicate.r#in {
                for value in membership.values {
                    self.push_field_value(&membership.field, &value);
                }
            }
        }
        fn push_field_value(&mut self, field: &str, value: &Value) {
            let Some(raw) = AssetPredicateView::value_as_str(value) else {
                return;
            };
            match field {
                "id"
                | "definition"
                | "asset_definition"
                | "asset_definition_id"
                | "definition_id" => {
                    if let Ok(definition_id) = raw.parse::<AssetDefinitionId>() {
                        self.ids.insert(definition_id);
                    }
                }
                "owner" | "owned_by" | "account" | "account_id" => {
                    if let Ok(account_id) = AccountId::parse_encoded(raw) {
                        self.owners.insert(account_id.subject_id());
                    }
                }
                "domain" | "id.domain" => {
                    if let Some(domain_id) = parse_domain_predicate_value(raw) {
                        self.domains.insert(domain_id);
                    }
                }
                _ => {}
            }
        }
        fn plan(&self) -> AssetDefinitionQueryPlan {
            let mut ids: Vec<_> = self.ids.iter().cloned().collect();
            ids.sort();
            let mut owners: Vec<_> = self.owners.iter().cloned().collect();
            owners.sort();
            let mut domains: Vec<_> = self.domains.iter().cloned().collect();
            domains.sort();
            if !ids.is_empty() {
                return AssetDefinitionQueryPlan::Ids(ids);
            }
            if !owners.is_empty() {
                return AssetDefinitionQueryPlan::Owners {
                    owners,
                    domains: (!domains.is_empty()).then_some(domains),
                };
            }
            if !domains.is_empty() {
                return AssetDefinitionQueryPlan::Domains(domains);
            }
            AssetDefinitionQueryPlan::Full
        }
    }
    #[derive(Debug)]
    enum AssetDefinitionQueryPlan {
        Ids(Vec<AssetDefinitionId>),
        Owners {
            owners: Vec<AccountId>,
            domains: Option<Vec<DomainId>>,
        },
        Domains(Vec<DomainId>),
        Full,
    }
    fn asset_definition_domain(
        world: &impl WorldReadOnly,
        definition_id: &AssetDefinitionId,
    ) -> Option<DomainId> {
        world.asset_definition_domains().get(definition_id).cloned()
    }
    fn asset_alias_values(world: &impl WorldReadOnly, asset: &Asset, field: &str) -> Vec<String> {
        match field {
            "id" => vec![asset.id().to_string()],
            "account" | "account_id" | "owner" | "id.account" => {
                vec![asset.id().account().to_string()]
            }
            "definition"
            | "asset_definition"
            | "asset_definition_id"
            | "definition_id"
            | "id.definition" => vec![asset.id().definition().to_string()],
            "domain" | "definition.domain" | "id.definition.domain" => {
                asset_definition_domain(world, asset.id().definition())
                    .map(|domain| {
                        let canonical = domain.to_string();
                        let shorthand = domain.name().to_string();
                        if canonical == shorthand {
                            vec![canonical]
                        } else {
                            vec![canonical, shorthand]
                        }
                    })
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    }
    enum AssetSimplePath {
        Definitions(Vec<AssetDefinitionId>),
        Domains(Vec<DomainId>),
        Ids(Vec<AssetId>),
    }
    fn parse_asset_simple_values(field: &str, values: &[Value]) -> Option<AssetSimplePath> {
        match field {
            "account" | "account_id" | "owner" | "id.account" => None,
            "definition"
            | "asset_definition"
            | "asset_definition_id"
            | "definition_id"
            | "id.definition" => {
                let definitions = values
                    .iter()
                    .filter_map(|value| {
                        let Value::String(raw) = value else {
                            return None;
                        };
                        AssetDefinitionId::parse_address_literal(raw).ok()
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                Some(AssetSimplePath::Definitions(definitions))
            }
            "domain" | "definition.domain" | "id.definition.domain" => {
                let domains = values
                    .iter()
                    .filter_map(|value| {
                        let Value::String(raw) = value else {
                            return None;
                        };
                        parse_domain_predicate_value(raw)
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                Some(AssetSimplePath::Domains(domains))
            }
            "id" => {
                let ids = values
                    .iter()
                    .filter_map(|value| {
                        let Value::String(raw) = value else {
                            return None;
                        };
                        raw.parse::<AssetId>().ok()
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                Some(AssetSimplePath::Ids(ids))
            }
            _ => None,
        }
    }
    fn asset_predicate_simple_path(predicate: &PredicateJson) -> Option<AssetSimplePath> {
        if !predicate.exists.is_empty() {
            return None;
        }
        if predicate.r#in.is_empty() && predicate.equals.len() == 1 {
            let cond = &predicate.equals[0];
            return parse_asset_simple_values(&cond.field, std::slice::from_ref(&cond.value));
        }
        if predicate.equals.is_empty() && predicate.r#in.len() == 1 {
            let cond = &predicate.r#in[0];
            return parse_asset_simple_values(&cond.field, &cond.values);
        }
        None
    }
    fn selected_asset_count_for_definitions(
        world: &impl WorldReadOnly,
        definitions: &BTreeSet<AssetDefinitionId>,
    ) -> usize {
        definitions
            .iter()
            .map(|definition| {
                world
                    .asset_definition_assets()
                    .get(definition)
                    .map_or(0, BTreeSet::len)
            })
            .sum()
    }
    fn selected_asset_count_for_domains(
        world: &impl WorldReadOnly,
        domains: &BTreeSet<DomainId>,
    ) -> usize {
        domains
            .iter()
            .flat_map(|domain| {
                world
                    .domain_asset_definitions()
                    .get(domain)
                    .into_iter()
                    .flat_map(BTreeSet::iter)
            })
            .map(|definition| {
                world
                    .asset_definition_assets()
                    .get(definition)
                    .map_or(0, BTreeSet::len)
            })
            .sum()
    }
    fn should_scan_assets_directly(
        world: &impl WorldReadOnly,
        selected_asset_count: usize,
    ) -> bool {
        let total_assets = world.assets().len();
        total_assets != 0 && selected_asset_count.saturating_mul(8) >= total_assets
    }
    fn predicate_matches_asset(
        world: &impl WorldReadOnly,
        predicate: &PredicateJson,
        asset: &Asset,
    ) -> bool {
        predicate_matches_with_aliases(predicate, asset, |asset, field| {
            asset_alias_values(world, asset, field)
        })
    }
    fn asset_definition_alias_values(
        world: &impl WorldReadOnly,
        asset_definition: &AssetDefinition,
        field: &str,
    ) -> Vec<String> {
        match field {
            "id" | "definition" | "asset_definition" | "asset_definition_id" | "definition_id" => {
                vec![asset_definition.id().to_string()]
            }
            "owner" | "owned_by" | "account" | "account_id" => {
                vec![asset_definition.owned_by().to_string()]
            }
            "domain" | "id.domain" => asset_definition_domain(world, asset_definition.id())
                .map(|domain| {
                    let canonical = domain.to_string();
                    let shorthand = domain.name().to_string();
                    if canonical == shorthand {
                        vec![canonical]
                    } else {
                        vec![canonical, shorthand]
                    }
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
    fn predicate_matches_asset_definition(
        world: &impl WorldReadOnly,
        predicate: &PredicateJson,
        asset_definition: &AssetDefinition,
    ) -> bool {
        predicate_matches_with_aliases(predicate, asset_definition, |asset_definition, field| {
            asset_definition_alias_values(world, asset_definition, field)
        })
    }
    #[derive(Debug)]
    enum AssetQueryPlan {
        Ids(Vec<AssetId>),
        Subjects {
            subjects: Vec<AccountId>,
            domains: Option<Vec<DomainId>>,
            definitions: Option<Vec<AssetDefinitionId>>,
        },
        Domains {
            domains: Vec<DomainId>,
            definitions: Option<Vec<AssetDefinitionId>>,
        },
        Definitions(Vec<AssetDefinitionId>),
        Full,
    }
    fn collect_projected_asset_balances(
        iter: impl Iterator<Item = Asset>,
        world: &impl WorldReadOnly,
        now_ms: u64,
    ) -> Result<Vec<Asset>, crate::execution_attempt::ExecutionAttemptError<Error>> {
        use crate::execution_attempt::{ExecutionAttemptError, norito_decode_attempt_error};
        let mut assets = Vec::new();
        for mut asset in iter {
            if let Some(value) = crate::retail_fee::projected_balance(world, &asset.id, now_ms)
                .map_err(|error| error.map_rejection(Error::Conversion))?
            {
                asset.value = value;
            }
            if assets.len() == assets.capacity() {
                let additional = assets.capacity().max(4);
                let bytes = additional
                    .checked_mul(std::mem::size_of::<Asset>())
                    .ok_or_else(|| {
                        ExecutionAttemptError::Deferred(
                            iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                        )
                    })?;
                norito::core::reserve_decode_allocation(bytes).map_err(|error| {
                    norito_decode_attempt_error(error, |error| Error::Conversion(error.to_string()))
                })?;
                assets.try_reserve_exact(additional).map_err(|_| {
                    ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                    )
                })?;
            }
            assets.push(asset);
        }
        Ok(assets)
    }
    fn project_asset_balances<'a>(
        iter: Box<dyn Iterator<Item = Asset> + 'a>,
        world: &impl WorldReadOnly,
        now_ms: u64,
    ) -> Result<
        Box<dyn Iterator<Item = Asset> + 'a>,
        crate::execution_attempt::ExecutionAttemptError<Error>,
    > {
        Ok(Box::new(
            collect_projected_asset_balances(iter, world, now_ms)?.into_iter(),
        ))
    }
    impl ValidQuery<crate::execution_attempt::ExecutionAttemptError<Error>> for FindAssets {
        #[metrics(+"find_assets")]
        fn execute(
            self,
            filter: CompoundPredicate<Asset>,
            state_ro: &impl StateReadOnly,
        ) -> Result<
            impl Iterator<Item = Asset>,
            crate::execution_attempt::ExecutionAttemptError<Error>,
        > {
            fn entry_to_asset(entry: AssetEntry<'_>) -> Asset {
                Asset {
                    id: entry.id().clone(),
                    value: entry.value().clone().into_inner(),
                }
            }
            let world = state_ro.world();
            let filter_payload = filter.json_payload();
            if filter_payload.is_none() {
                let iter: Box<dyn Iterator<Item = Asset> + '_> =
                    Box::new(world.assets_iter().map(entry_to_asset));
                return project_asset_balances(iter, world, state_ro.query_ledger_time_ms());
            }
            let predicate_view = AssetPredicateView::from_predicate(&filter);
            let predicate_json = filter_payload.and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let plan = predicate_view.plan();
            let simple_path = predicate_json
                .as_ref()
                .and_then(asset_predicate_simple_path);
            if let Some(path) = simple_path {
                let iter: Box<dyn Iterator<Item = Asset> + '_> = match path {
                    AssetSimplePath::Definitions(definitions) => {
                        let definitions = definitions.into_iter().collect::<BTreeSet<_>>();
                        if should_scan_assets_directly(
                            world,
                            selected_asset_count_for_definitions(world, &definitions),
                        ) {
                            Box::new(
                                world
                                    .assets_iter()
                                    .filter(move |entry| {
                                        definitions.contains(entry.id().definition())
                                    })
                                    .map(entry_to_asset),
                            )
                        } else {
                            Box::new(
                                world
                                    .asset_entries_by_definition_ids_iter(definitions)
                                    .map(entry_to_asset),
                            )
                        }
                    }
                    AssetSimplePath::Domains(domains) => {
                        let domains = domains.into_iter().collect::<BTreeSet<_>>();
                        if should_scan_assets_directly(
                            world,
                            selected_asset_count_for_domains(world, &domains),
                        ) {
                            Box::new(
                                world
                                    .assets_iter()
                                    .filter(move |entry| {
                                        asset_definition_domain(world, entry.id().definition())
                                            .is_some_and(|domain| domains.contains(&domain))
                                    })
                                    .map(entry_to_asset),
                            )
                        } else {
                            let mut definitions = BTreeSet::<AssetDefinitionId>::new();
                            for domain in &domains {
                                definitions.extend(
                                    world
                                        .domain_asset_definitions()
                                        .get(domain)
                                        .into_iter()
                                        .flat_map(BTreeSet::iter)
                                        .cloned(),
                                );
                            }
                            Box::new(
                                world
                                    .asset_entries_by_definition_ids_iter(definitions)
                                    .map(entry_to_asset),
                            )
                        }
                    }
                    AssetSimplePath::Ids(asset_ids) => Box::new(
                        world
                            .asset_entries_by_ids_iter(asset_ids)
                            .map(entry_to_asset),
                    ),
                };
                return project_asset_balances(iter, world, state_ro.query_ledger_time_ms());
            }
            let iter: Box<dyn Iterator<Item = Asset> + '_> = match plan {
                AssetQueryPlan::Ids(asset_ids) => Box::new(
                    world
                        .asset_entries_by_ids_iter(asset_ids)
                        .map(entry_to_asset),
                ),
                AssetQueryPlan::Subjects {
                    subjects,
                    domains,
                    definitions,
                } => {
                    let subjects = subjects
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    let domains = domains
                        .map(|domains| Arc::new(domains.into_iter().collect::<BTreeSet<_>>()));
                    let definitions = definitions.map(|definitions| {
                        Arc::new(definitions.into_iter().collect::<BTreeSet<_>>())
                    });
                    if let Some(definitions) = definitions {
                        let definitions = if let Some(domains) = domains.as_ref() {
                            Arc::new(
                                definitions
                                    .iter()
                                    .filter(|definition| {
                                        asset_definition_domain(world, definition)
                                            .is_some_and(|domain| domains.contains(&domain))
                                    })
                                    .cloned()
                                    .collect::<BTreeSet<_>>(),
                            )
                        } else {
                            definitions
                        };
                        Box::new(subjects.into_iter().flat_map(move |subject| {
                            let mut asset_ids = Vec::new();
                            for definition in definitions.iter() {
                                asset_ids.extend(
                                    world
                                        .assets_in_account_by_definition_iter(&subject, definition)
                                        .map(|entry| entry.id().clone()),
                                );
                            }
                            world
                                .asset_entries_by_ids_iter(asset_ids)
                                .map(entry_to_asset)
                        }))
                    } else {
                        Box::new(subjects.into_iter().flat_map(move |subject| {
                            let domains = domains.clone();
                            let asset_ids = world
                                .assets_in_account_iter(&subject)
                                .filter(move |entry| {
                                    domains.as_ref().is_none_or(|domains| {
                                        asset_definition_domain(world, entry.id().definition())
                                            .is_some_and(|domain| domains.contains(&domain))
                                    })
                                })
                                .map(|entry| entry.id().clone())
                                .collect::<Vec<_>>();
                            world
                                .asset_entries_by_ids_iter(asset_ids)
                                .map(entry_to_asset)
                        }))
                    }
                }
                AssetQueryPlan::Domains {
                    domains,
                    definitions,
                } => {
                    let domains: BTreeSet<_> = domains.into_iter().collect();
                    let definitions: BTreeSet<_> = match definitions {
                        Some(definitions) => definitions
                            .into_iter()
                            .filter(|definition| {
                                asset_definition_domain(world, definition)
                                    .is_some_and(|domain| domains.contains(&domain))
                            })
                            .collect(),
                        None => {
                            let mut definitions = BTreeSet::<AssetDefinitionId>::new();
                            for domain in &domains {
                                definitions.extend(
                                    world
                                        .domain_asset_definitions()
                                        .get(domain)
                                        .into_iter()
                                        .flat_map(BTreeSet::iter)
                                        .cloned(),
                                );
                            }
                            definitions
                        }
                    };
                    Box::new(
                        world
                            .asset_entries_by_definition_ids_iter(definitions)
                            .map(entry_to_asset),
                    )
                }
                AssetQueryPlan::Definitions(definitions) => {
                    let definitions: BTreeSet<_> = definitions.into_iter().collect();
                    Box::new(
                        world
                            .asset_entries_by_definition_ids_iter(definitions)
                            .map(entry_to_asset),
                    )
                }
                AssetQueryPlan::Full => Box::new(world.assets_iter().map(entry_to_asset)),
            };
            let assets =
                collect_projected_asset_balances(iter, world, state_ro.query_ledger_time_ms())?;
            let iter: Box<dyn Iterator<Item = Asset> + '_> =
                Box::new(assets.into_iter().filter(move |asset| {
                    if !predicate_view.matches(world, asset) {
                        return false;
                    }
                    if let Some(predicate) = predicate_json.as_ref() {
                        return predicate_matches_asset(world, predicate, asset);
                    }
                    filter.applies(asset)
                }));
            Ok(iter)
        }
    }
    impl ValidQuery<crate::execution_attempt::ExecutionAttemptError<Error>> for FindAssetsByAccountId {
        #[metrics(+"find_assets_by_account_id")]
        fn execute(
            self,
            filter: CompoundPredicate<Asset>,
            state_ro: &impl StateReadOnly,
        ) -> Result<
            impl Iterator<Item = Asset>,
            crate::execution_attempt::ExecutionAttemptError<Error>,
        > {
            fn entry_to_asset(entry: AssetEntry<'_>) -> Asset {
                Asset {
                    id: entry.id().clone(),
                    value: entry.value().clone().into_inner(),
                }
            }
            let account_id = self.account_id().clone();
            let world = state_ro.world();
            world.account(&account_id).map_err(Error::Find)?;
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let assets = collect_projected_asset_balances(
                world
                    .assets_in_account_iter(&account_id)
                    .map(entry_to_asset),
                world,
                state_ro.query_ledger_time_ms(),
            )?;
            Ok(assets.into_iter().filter(move |asset| {
                predicate_json.as_ref().map_or_else(
                    || filter.applies(asset),
                    |predicate| predicate_matches_asset(world, predicate, asset),
                )
            }))
        }
    }
    impl ValidSingularQuery<crate::execution_attempt::ExecutionAttemptError<Error>> for FindAssetById {
        #[metrics(+"find_asset_by_id")]
        fn execute(
            &self,
            state_ro: &impl StateReadOnly,
        ) -> Result<Asset, crate::execution_attempt::ExecutionAttemptError<Error>> {
            let entry = state_ro.world().asset(self.asset_id())?;
            if let Some(value) = crate::retail_fee::projected_balance(
                state_ro.world(),
                entry.id(),
                state_ro.query_ledger_time_ms(),
            )
            .map_err(|error| error.map_rejection(Error::Conversion))?
            {
                return Ok(Asset {
                    id: entry.id().clone(),
                    value,
                });
            }
            crate::smartcontracts::isi::query::own_singular_query_struct::<Asset, 2>(
                [entry.id(), entry.value().as_ref()],
                || Asset {
                    id: entry.id().clone(),
                    value: entry.value().clone().into_inner(),
                },
            )
            .map_err(Into::into)
        }
    }
    impl ValidSingularQuery for FindAssetDefinitionById {
        #[metrics(+"find_asset_definition_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<AssetDefinition, Error> {
            let world = state_ro.world();
            let definition = world
                .asset_definitions()
                .get(self.asset_definition_id())
                .ok_or_else(|| FindError::AssetDefinition(self.asset_definition_id().clone()))?;
            let alias = crate::smartcontracts::isi::query::BorrowedSingularOption::new(
                world
                    .asset_definition_alias_bindings()
                    .get(self.asset_definition_id())
                    .map(|binding| &binding.alias),
            );
            crate::smartcontracts::isi::query::own_singular_query_struct::<AssetDefinition, 13>(
                [
                    &definition.id,
                    &definition.name,
                    &definition.description,
                    &alias,
                    &definition.spec,
                    &definition.mintable,
                    &definition.logo,
                    &definition.metadata,
                    &definition.balance_scope_policy,
                    &definition.owning_domain,
                    &definition.owned_by,
                    &definition.total_quantity,
                    &definition.confidential_policy,
                ],
                || {
                    let mut owned = definition.clone();
                    owned.alias = world
                        .asset_definition_alias_bindings()
                        .get(self.asset_definition_id())
                        .map(|binding| binding.alias.clone());
                    owned
                },
            )
        }
    }
    impl ValidQuery for FindAssetDefinitions {
        #[metrics(+"find_asset_definitions")]
        fn execute(
            self,
            filter: CompoundPredicate<AssetDefinition>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = AssetDefinition>, Error> {
            let world = state_ro.world();
            let predicate_view = AssetDefinitionPredicateView::from_predicate(&filter);
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let iter: Box<dyn Iterator<Item = AssetDefinition> + '_> = match predicate_view.plan() {
                AssetDefinitionQueryPlan::Ids(ids) => Box::new(
                    ids.into_iter()
                        .filter_map(move |id| world.asset_definition(&id).ok()),
                ),
                AssetDefinitionQueryPlan::Owners { owners, domains } => {
                    let domains =
                        domains.map(|domains| domains.into_iter().collect::<BTreeSet<_>>());
                    Box::new(owners.into_iter().flat_map(move |owner| {
                        let domains = domains.clone();
                        world
                            .asset_definitions_by_owner()
                            .get(&owner)
                            .into_iter()
                            .flat_map(BTreeSet::iter)
                            .filter(move |definition_id| {
                                domains.as_ref().is_none_or(|domains| {
                                    asset_definition_domain(world, definition_id)
                                        .is_some_and(|domain| domains.contains(&domain))
                                })
                            })
                            .filter_map(|definition_id| world.asset_definition(definition_id).ok())
                            .collect::<Vec<_>>()
                    }))
                }
                AssetDefinitionQueryPlan::Domains(domains) => {
                    Box::new(domains.into_iter().flat_map(move |domain| {
                        world
                            .domain_asset_definitions()
                            .get(&domain)
                            .into_iter()
                            .flat_map(BTreeSet::iter)
                            .filter_map(|definition_id| world.asset_definition(definition_id).ok())
                            .collect::<Vec<_>>()
                    }))
                }
                AssetDefinitionQueryPlan::Full => Box::new(
                    world
                        .asset_definitions()
                        .iter()
                        .filter_map(|(id, _)| world.asset_definition(id).ok()),
                ),
            };
            Ok(iter.filter(move |asset_definition| {
                if let Some(predicate) = predicate_json.as_ref() {
                    predicate_matches_asset_definition(world, predicate, asset_definition)
                } else {
                    filter.applies(asset_definition)
                }
            }))
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            smartcontracts::ValidQuery,
            state::{State, StateTransaction, World},
        };
        use iroha_crypto::{Algorithm, Hash, KeyPair};
        use iroha_data_model::account::{
            NewAccount,
            rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
        };
        use iroha_data_model::asset::{
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, ASSET_TRANSFER_CONTROL_METADATA_KEY,
            AssetIssuerUsagePolicyV1, AssetSubjectBindingV1, AssetTransferControlRecord,
            AssetTransferControlStoreV1, AssetTransferControlWindow, AssetTransferLimit,
            DOMAIN_ASSET_USAGE_POLICY_METADATA_KEY, DomainAssetUsagePolicyV1,
        };
        use iroha_data_model::isi::{
            error::InstructionEvaluationError,
            transfer::{TransferAssetBatch, TransferAssetBatchEntry},
        };
        use iroha_data_model::nexus::{
            Allowance, AllowanceWindow, AssetPermissionManifest, CapabilityScope, ManifestEffect,
            ManifestEntry,
        };
        use iroha_data_model::query::json::{EqualsCondition, PredicateJson};
        use iroha_model_base::metadata::Metadata;
        use iroha_model_base::topology::DataSpaceId;
        use iroha_primitives::{json::Json, numeric::Numeric};
        use iroha_test_samples::{ALICE_ID, BOB_ID};
        use nonzero_ext::nonzero;
        use norito::json::Value;
        use std::collections::{BTreeMap, BTreeSet};
        fn build_account_in_domain(account_id: &AccountId, _domain_id: &DomainId) -> Account {
            Account::new(account_id.clone()).build(account_id)
        }
        fn build_numeric_asset_definition(
            asset_definition_id: &AssetDefinitionId,
            name: &str,
            owner: &AccountId,
        ) -> AssetDefinition {
            AssetDefinition::numeric(
                asset_definition_id.clone(),
                name.to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(owner)
        }
        fn build_restricted_rose_definition(
            asset_definition_id: &AssetDefinitionId,
            domain_id: &DomainId,
        ) -> AssetDefinition {
            AssetDefinition::numeric(
                asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id.clone()),
            )
            .build(&ALICE_ID)
        }
        fn wonderland_domain_id() -> DomainId {
            DomainId::try_new("wonderland", "universal").expect("domain id")
        }
        fn wonderland_asset_definition_id(name: &str) -> AssetDefinitionId {
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                name.parse().unwrap(),
            )
        }
        fn asset_route_test_state(world: World) -> State {
            State::new(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            )
        }
        fn seed_test_call_hash(state_transaction: &mut StateTransaction<'_, '_>, byte: u8) {
            state_transaction.tx_call_hash = Some(Hash::prehashed([byte; Hash::LENGTH]));
        }
        #[test]
        fn fee_asset_projection_buffer_preserves_original_decode_refusal_and_retries_same_data() {
            let state = asset_route_test_state(World::default());
            let view = state.view();
            let original = vec![Asset::new(
                AssetId::new(wonderland_asset_definition_id("rose"), ALICE_ID.clone()),
                "7".parse::<iroha_primitives::numeric::Quantity>().unwrap(),
            )];
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
            let error = norito::with_decode_limits_scope(limits, || {
                collect_projected_asset_balances(original.clone().into_iter(), view.world(), 0)
            })
            .unwrap_err();
            assert!(matches!(
                error,
                crate::execution_attempt::ExecutionAttemptError::Deferred(_)
            ));
            let retry =
                collect_projected_asset_balances(original.clone().into_iter(), view.world(), 0)
                    .unwrap();
            assert_eq!(retry, original);
        }

        #[test]
        fn genesis_transfer_control_rejects_missing_asset_definition() {
            let account = build_account_in_domain(&ALICE_ID, &wonderland_domain_id());
            let world = World::with([], [account], []);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut state_transaction = block.transaction();
            let missing = wonderland_asset_definition_id("missing");
            let error = SetAssetTransferBlacklist::new(ALICE_ID.clone(), missing.clone(), true)
                .execute(&ALICE_ID, &mut state_transaction)
                .expect_err("genesis must not create transfer controls for a missing definition");
            assert!(
                matches!(error, InstructionExecutionError::Find(FindError::AssetDefinition(ref id)) if *id == missing),
                "unexpected missing-definition rejection: {error:?}"
            );
            assert!(
                state_transaction
                    .world
                    .account(&ALICE_ID)
                    .expect("account remains")
                    .metadata()
                    .get(ASSET_TRANSFER_CONTROL_METADATA_KEY)
                    .is_none()
            );
        }
        #[test]
        fn duplicate_transfer_control_store_fails_closed_without_mutation() {
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let asset_definition_id = wonderland_asset_definition_id("rose");
            let asset_definition =
                build_numeric_asset_definition(&asset_definition_id, "rose", &ALICE_ID);
            let mut record = AssetTransferControlRecord::new(asset_definition_id.clone());
            record.blacklisted = true;
            let store = AssetTransferControlStoreV1 {
                controls: vec![record.clone(), record],
            };
            let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
                .parse()
                .expect("asset transfer-control metadata key");
            let mut metadata = Metadata::default();
            metadata.insert(metadata_key.clone(), Json::new(store));
            let account = Account::new(ALICE_ID.clone())
                .with_metadata(metadata)
                .build(&ALICE_ID);
            let world = World::with([domain], [account], [asset_definition]);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut state_transaction = block.transaction();
            let before = state_transaction
                .world
                .account(&ALICE_ID)
                .expect("account exists")
                .metadata()
                .get(&metadata_key)
                .cloned();
            let error =
                SetAssetTransferBlacklist::new(ALICE_ID.clone(), asset_definition_id, false)
                    .execute(&ALICE_ID, &mut state_transaction)
                    .expect_err("duplicate first-match transfer-control state must fail closed");
            assert!(
                error.to_string().contains("unique, strictly ordered"),
                "unexpected duplicate-store rejection: {error}"
            );
            assert_eq!(
                state_transaction
                    .world
                    .account(&ALICE_ID)
                    .expect("account remains")
                    .metadata()
                    .get(&metadata_key)
                    .cloned(),
                before,
                "failed validation must not rewrite ambiguous transfer-control state"
            );
        }
        fn collect_rust_sources(
            directory: &std::path::Path,
            sources: &mut Vec<std::path::PathBuf>,
        ) {
            for entry in std::fs::read_dir(directory).expect("read source directory") {
                let path = entry.expect("read source entry").path();
                if path.is_dir() {
                    collect_rust_sources(&path, sources);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    sources.push(path);
                }
            }
        }
        include!("asset/core_numeric_mutation_tests.rs");
        include!("asset/retail_daily_limit_tests.rs");
        include!("asset/privacy_public_reserve_tests.rs");
        mod privacy_economic_invariant_tests {
            include!("asset/privacy_economic_invariant_tests.rs");
        }
        mod prepared_independent_occurrence_tests {
            include!("asset/prepared_independent_occurrence_tests.rs");
        }
        include!("asset/global_scope_rejection_tests.rs");
        #[test]
        fn transfer_global_asset_rejects_explicit_dataspace_scope_on_universal_route() {
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("xor");
            let asset_def = build_numeric_asset_definition(&asset_def_id, "xor", &ALICE_ID);
            let world = World::with([domain], [alice_account, bob_account], [asset_def]);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let scoped_source_id = AssetId::with_scope(
                asset_def_id,
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            );
            let err = Transfer::asset_quantity(scoped_source_id, 1_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("global assets must reject explicit dataspace-scoped ids");
            match err {
                InstructionExecutionError::InvariantViolation(message) => {
                    assert!(
                        message.contains("global assets cannot be addressed with dataspace scope"),
                        "unexpected invariant message: {message}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
        #[test]
        fn transfer_global_asset_rejects_non_authoritative_dataspace_route() {
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("xor");
            let asset_def = build_numeric_asset_definition(&asset_def_id, "xor", &ALICE_ID);
            let source_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            let private_dataspace = DataSpaceId::new(7);
            stx.current_dataspace_id = Some(private_dataspace);
            stx.world.current_dataspace_id = Some(private_dataspace);
            let err = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("global asset transfer must use the authoritative route");
            match err {
                InstructionExecutionError::InvariantViolation(message) => {
                    assert!(
                        message.contains("authoritative dataspace"),
                        "unexpected invariant message: {message}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
            let destination_asset_id = AssetId::new(asset_def_id, BOB_ID.clone());
            assert_eq!(
                asset_balance_or_zero(&stx, &source_asset_id),
                Quantity::from(10_u32)
            );
            assert_eq!(
                asset_balance_or_zero(&stx, &destination_asset_id),
                Quantity::zero()
            );
        }
        #[test]
        fn transfer_global_asset_rejects_before_implicit_receiver_creation_on_private_route() {
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("xor");
            let asset_def = build_numeric_asset_definition(&asset_def_id, "xor", &ALICE_ID);
            let source_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let world =
                World::with_assets([domain], [alice_account], [asset_def], [source_asset], []);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            let private_dataspace = DataSpaceId::new(7);
            stx.current_dataspace_id = Some(private_dataspace);
            stx.world.current_dataspace_id = Some(private_dataspace);
            let err = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("route rejection must happen before implicit receiver admission");
            match err {
                InstructionExecutionError::InvariantViolation(message) => {
                    assert!(
                        message.contains("authoritative dataspace"),
                        "unexpected invariant message: {message}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
            let destination_asset_id = AssetId::new(asset_def_id, BOB_ID.clone());
            assert!(
                stx.world.account(&BOB_ID).is_err(),
                "rejected transfer must not implicitly create the receiver account"
            );
            assert_eq!(
                asset_balance_or_zero(&stx, &source_asset_id),
                Quantity::from(10_u32)
            );
            assert_eq!(
                asset_balance_or_zero(&stx, &destination_asset_id),
                Quantity::zero()
            );
        }
        #[test]
        fn burn_global_asset_rejects_non_authoritative_dataspace_route() {
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let account = build_account_in_domain(&ALICE_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("xor");
            let asset_def = build_numeric_asset_definition(&asset_def_id, "xor", &ALICE_ID);
            let source_asset_id = AssetId::new(asset_def_id, ALICE_ID.clone());
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let world = World::with_assets([domain], [account], [asset_def], [source_asset], []);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            let private_dataspace = DataSpaceId::new(7);
            stx.current_dataspace_id = Some(private_dataspace);
            stx.world.current_dataspace_id = Some(private_dataspace);
            let err = Burn::asset_quantity(1_u32, source_asset_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("global asset burn must use the authoritative route");
            match err {
                InstructionExecutionError::InvariantViolation(message) => {
                    assert!(
                        message.contains("authoritative dataspace"),
                        "unexpected invariant message: {message}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
            assert_eq!(
                asset_balance_or_zero(&stx, &source_asset_id),
                Quantity::from(10_u32)
            );
        }
        #[test]
        fn mint_global_asset_allows_universal_amx_route_for_non_universal_home() {
            let home_dataspace = DataSpaceId::new(7);
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let account = build_account_in_domain(&ALICE_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("xor");
            let asset_def = build_numeric_asset_definition(&asset_def_id, "xor", &ALICE_ID);
            let mut world = World::with([domain], [account], [asset_def]);
            let alias: iroha_data_model::asset::AssetDefinitionAlias =
                "xor#paynet".parse().expect("asset alias");
            world
                .asset_definition_aliases
                .insert(alias.clone(), asset_def_id.clone());
            world.asset_definition_alias_bindings.insert(
                asset_def_id.clone(),
                crate::state::AssetDefinitionAliasBindingRecord {
                    alias,
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 0,
                },
            );
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            block.nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
                iroha_data_model::nexus::DataSpaceMetadata::default(),
                iroha_data_model::nexus::DataSpaceMetadata {
                    id: home_dataspace,
                    alias: "paynet".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("dataspace catalog");
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let mint_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
            Mint::asset_quantity(5_u32, mint_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("universal AMX coordinator can mutate non-universal global asset home");
            assert_eq!(
                stx.world
                    .asset(&mint_id)
                    .expect("minted global asset")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(5_u32)
            );
        }
        #[test]
        fn transfer_restricted_asset_rejects_cross_dataspace_scope() {
            let domain_id = wonderland_domain_id();
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset = Asset::new(
                AssetId::with_scope(
                    asset_def_id.clone(),
                    ALICE_ID.clone(),
                    iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
                ),
                Quantity::from(10_u32),
            );
            let world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(DataSpaceId::new(8));
            stx.world.current_dataspace_id = Some(DataSpaceId::new(8));
            let source = AssetId::with_scope(
                asset_def_id,
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            );
            let err = Transfer::asset_quantity(source, 1_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("cross-dataspace transfer must be rejected");
            assert!(
                matches!(err, InstructionExecutionError::InvariantViolation(_)),
                "unexpected error: {err:?}"
            );
        }
        #[test]
        fn transfer_restricted_asset_rejects_destination_binding_outside_non_universal_route() {
            let domain_id = wonderland_domain_id();
            let source_dataspace = DataSpaceId::new(7);
            let destination_dataspace = DataSpaceId::new(8);
            let uaid_bob = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::bob-non-universal-cross-credit"),
            );
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = NewAccount::new(BOB_ID.clone())
                .with_uaid(Some(uaid_bob))
                .build(&BOB_ID);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let mut world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            world.uaid_accounts.insert(uaid_bob, BOB_ID.clone());
            let mut bob_bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
            bob_bindings.bind_account(destination_dataspace, BOB_ID.clone());
            let mut state = asset_route_test_state(world);
            state.world.uaid_dataspaces.insert(uaid_bob, bob_bindings);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            block.admit_fastpq_source_for_testing(Hash::prehashed([0xB6; Hash::LENGTH]));
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(source_dataspace);
            stx.world.current_dataspace_id = Some(source_dataspace);
            seed_test_call_hash(&mut stx, 0xB6);
            let err = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("non-universal route must not credit another dataspace binding");
            match err {
                InstructionExecutionError::InvariantViolation(message) => assert!(
                    message.contains("destination account scope must match"),
                    "{message}"
                ),
                other => panic!("unexpected error: {other:?}"),
            }
            assert_eq!(
                stx.world
                    .asset(&source_asset_id)
                    .expect("source balance must remain untouched")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(10_u32)
            );
            let destination_asset_id = AssetId::with_scope(
                asset_def_id,
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(destination_dataspace),
            );
            assert!(
                stx.world.asset(&destination_asset_id).is_err(),
                "non-universal rejection must not materialize the cross-dataspace destination"
            );
        }
        #[test]
        fn transfer_batch_rejects_destination_binding_outside_non_universal_route() {
            let domain_id = wonderland_domain_id();
            let source_dataspace = DataSpaceId::new(7);
            let destination_dataspace = DataSpaceId::new(8);
            let uaid_bob = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::bob-batch-non-universal-cross-credit"),
            );
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = NewAccount::new(BOB_ID.clone())
                .with_uaid(Some(uaid_bob))
                .build(&BOB_ID);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let mut world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            world.uaid_accounts.insert(uaid_bob, BOB_ID.clone());
            let mut bob_bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
            bob_bindings.bind_account(destination_dataspace, BOB_ID.clone());
            let mut state = asset_route_test_state(world);
            state.world.uaid_dataspaces.insert(uaid_bob, bob_bindings);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            block.admit_fastpq_source_for_testing(Hash::prehashed([0xB7; Hash::LENGTH]));
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(source_dataspace);
            stx.world.current_dataspace_id = Some(source_dataspace);
            seed_test_call_hash(&mut stx, 0xB7);
            let batch = TransferAssetBatch::new(vec![TransferAssetBatchEntry::new(
                ALICE_ID.clone(),
                BOB_ID.clone(),
                asset_def_id.clone(),
                1_u32,
            )]);
            let err = batch
                .execute(&ALICE_ID, &mut stx)
                .expect_err("batch route must not credit another dataspace binding");
            match err {
                InstructionExecutionError::InvariantViolation(message) => assert!(
                    message.contains("destination account scope must match"),
                    "{message}"
                ),
                other => panic!("unexpected error: {other:?}"),
            }
            assert_eq!(
                stx.world
                    .asset(&source_asset_id)
                    .expect("source balance must remain untouched")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(10_u32)
            );
            let destination_asset_id = AssetId::with_scope(
                asset_def_id,
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(destination_dataspace),
            );
            assert!(
                stx.world.asset(&destination_asset_id).is_err(),
                "batch rejection must not materialize the cross-dataspace destination"
            );
        }
        include!("asset/transfer_batch_tests.rs");
        #[test]
        fn transfer_policy_rejects_explicit_destination_scope_outside_non_universal_route() {
            let domain_id = wonderland_domain_id();
            let source_dataspace = DataSpaceId::new(7);
            let destination_dataspace = DataSpaceId::new(8);
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(source_dataspace);
            stx.world.current_dataspace_id = Some(source_dataspace);
            let destination_asset_id = AssetId::with_scope(
                asset_def_id,
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(destination_dataspace),
            );
            let err = super::super::isi::validate_user_numeric_asset_transfer_policies_for_test(
                &mut stx,
                &source_asset_id,
                &destination_asset_id,
                &Quantity::one(),
            )
            .expect_err("explicit destination scope outside non-universal route must reject");
            match err {
                InstructionExecutionError::InvariantViolation(message) => assert!(
                    message.contains("destination asset scope must match"),
                    "{message}"
                ),
                other => panic!("unexpected error: {other:?}"),
            }
            assert_eq!(
                asset_balance_or_zero(&stx, &source_asset_id),
                Quantity::from(10_u32)
            );
            assert_eq!(
                asset_balance_or_zero(&stx, &destination_asset_id),
                Quantity::zero()
            );
        }
        #[test]
        fn transfer_restricted_asset_uses_destination_dataspace_binding_and_policy() {
            let domain_id = wonderland_domain_id();
            let source_dataspace = DataSpaceId::new(7);
            let destination_dataspace = DataSpaceId::new(11);
            let uaid_alice = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::alice-destination-scope"),
            );
            let uaid_bob = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::bob-destination-scope"),
            );
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = NewAccount::new(ALICE_ID.clone())
                .with_uaid(Some(uaid_alice))
                .build(&ALICE_ID);
            let bob_account = NewAccount::new(BOB_ID.clone())
                .with_uaid(Some(uaid_bob))
                .build(&BOB_ID);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let mut asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let issuer_policy = AssetIssuerUsagePolicyV1 {
                require_subject_binding: true,
                subject_bindings: BTreeMap::from([
                    (
                        ALICE_ID.clone(),
                        AssetSubjectBindingV1 {
                            allowed_domains: BTreeSet::new(),
                            allowed_dataspaces: BTreeSet::from([source_dataspace]),
                        },
                    ),
                    (
                        BOB_ID.clone(),
                        AssetSubjectBindingV1 {
                            allowed_domains: BTreeSet::new(),
                            allowed_dataspaces: BTreeSet::from([destination_dataspace]),
                        },
                    ),
                ]),
            };
            asset_def.metadata_mut().insert(
                ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
                    .parse()
                    .expect("metadata key"),
                Json::new(issuer_policy),
            );
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let mut world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            world.uaid_accounts.insert(uaid_alice, ALICE_ID.clone());
            world.uaid_accounts.insert(uaid_bob, BOB_ID.clone());
            let mut alice_bindings =
                crate::nexus::space_directory::UaidDataspaceBindings::default();
            alice_bindings.bind_account(source_dataspace, ALICE_ID.clone());
            world.uaid_dataspaces.insert(uaid_alice, alice_bindings);
            let mut bob_bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
            bob_bindings.bind_account(destination_dataspace, BOB_ID.clone());
            world.uaid_dataspaces.insert(uaid_bob, bob_bindings);
            let mut alice_manifest_record =
                crate::nexus::space_directory::SpaceDirectoryManifestRecord::new(
                    AssetPermissionManifest {
                        version: iroha_data_model::nexus::ManifestVersion::default(),
                        uaid: uaid_alice,
                        dataspace: source_dataspace,
                        issued_ms: 1,
                        activation_epoch: 0,
                        expiry_epoch: None,
                        entries: vec![ManifestEntry {
                            scope: CapabilityScope {
                                dataspace: Some(source_dataspace),
                                program: None,
                                method: None,
                                asset: Some(asset_def_id.clone()),
                                role: None,
                            },
                            effect: ManifestEffect::Allow(Allowance {
                                max_amount: None,
                                window: AllowanceWindow::PerDay,
                            }),
                            notes: None,
                        }],
                    },
                );
            alice_manifest_record.lifecycle.mark_activated(0);
            let mut bob_manifest_record =
                crate::nexus::space_directory::SpaceDirectoryManifestRecord::new(
                    AssetPermissionManifest {
                        version: iroha_data_model::nexus::ManifestVersion::default(),
                        uaid: uaid_bob,
                        dataspace: destination_dataspace,
                        issued_ms: 1,
                        activation_epoch: 0,
                        expiry_epoch: None,
                        entries: vec![ManifestEntry {
                            scope: CapabilityScope {
                                dataspace: Some(destination_dataspace),
                                program: None,
                                method: None,
                                asset: Some(asset_def_id.clone()),
                                role: None,
                            },
                            effect: ManifestEffect::Allow(Allowance {
                                max_amount: None,
                                window: AllowanceWindow::PerDay,
                            }),
                            notes: None,
                        }],
                    },
                );
            bob_manifest_record.lifecycle.mark_activated(0);
            let mut alice_set = crate::nexus::space_directory::SpaceDirectoryManifestSet::default();
            alice_set.upsert(alice_manifest_record);
            let mut bob_set = crate::nexus::space_directory::SpaceDirectoryManifestSet::default();
            bob_set.upsert(bob_manifest_record);
            world
                .space_directory_manifests
                .insert(uaid_alice, alice_set);
            world.space_directory_manifests.insert(uaid_bob, bob_set);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            block.admit_fastpq_source_for_testing(Hash::prehashed([0xB3; Hash::LENGTH]));
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            seed_test_call_hash(&mut stx, 0xB3);
            Transfer::asset_quantity(
                AssetId::new(asset_def_id.clone(), ALICE_ID.clone()),
                1_u32,
                BOB_ID.clone(),
            )
            .execute(&ALICE_ID, &mut stx)
            .expect("transfer should resolve the recipient into its bound dataspace");
            let destination_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(destination_dataspace),
            );
            assert_eq!(
                stx.world
                    .asset(&destination_asset_id)
                    .expect("destination asset created in bound dataspace")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(1_u32)
            );
            let wrong_scope_destination = AssetId::with_scope(
                asset_def_id.clone(),
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
            );
            assert!(
                stx.world.asset(&wrong_scope_destination).is_err(),
                "destination balance must not be materialized in the source dataspace"
            );
            assert_eq!(
                stx.world
                    .asset(&source_asset_id)
                    .expect("source balance still exists")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(9_u32)
            );
        }
        #[test]
        fn transfer_restricted_asset_requires_definition_home_route_and_bucket() {
            let home_dataspace = DataSpaceId::new(7);
            let domain_id = DomainId::try_new("wonderland", "paynet").expect("home domain");
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(home_dataspace),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let mut world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            let alias: iroha_data_model::asset::AssetDefinitionAlias =
                "rose#paynet".parse().expect("asset alias");
            world
                .asset_definition_aliases
                .insert(alias.clone(), asset_def_id.clone());
            world.asset_definition_alias_bindings.insert(
                asset_def_id.clone(),
                crate::state::AssetDefinitionAliasBindingRecord {
                    alias,
                    lease_expiry_ms: None,
                    grace_until_ms: None,
                    bound_at_ms: 0,
                },
            );
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let catalog = DataSpaceCatalog::new(vec![
                iroha_data_model::nexus::DataSpaceMetadata::default(),
                iroha_data_model::nexus::DataSpaceMetadata {
                    id: home_dataspace,
                    alias: "paynet".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .expect("dataspace catalog");
            block.nexus.dataspace_catalog = catalog.clone();
            block.admit_fastpq_source_for_testing(Hash::prehashed([0xB9; Hash::LENGTH]));
            let mut stx = block.transaction();
            stx.nexus.dataspace_catalog = catalog.clone();
            stx.world.dataspace_catalog = catalog;
            stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            seed_test_call_hash(&mut stx, 0xB9);
            Transfer::asset_quantity(
                AssetId::new(asset_def_id.clone(), ALICE_ID.clone()),
                3_u32,
                BOB_ID.clone(),
            )
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a confined asset cannot transfer through the universal route");
            assert_eq!(
                stx.world.asset(&source_asset_id).unwrap().value().as_ref(),
                &Quantity::from(10_u32),
            );
            stx.current_dataspace_id = Some(home_dataspace);
            stx.world.current_dataspace_id = Some(home_dataspace);
            Transfer::asset_quantity(
                AssetId::new(asset_def_id.clone(), ALICE_ID.clone()),
                3_u32,
                BOB_ID.clone(),
            )
            .execute(&ALICE_ID, &mut stx)
            .expect("bare restricted transfer succeeds on its definition home route");
            let destination_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(home_dataspace),
            );
            assert_eq!(
                stx.world
                    .asset(&destination_asset_id)
                    .expect("destination asset created in definition home dataspace")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(3_u32)
            );
            assert_eq!(
                stx.world
                    .asset(&source_asset_id)
                    .expect("source balance still exists")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(7_u32)
            );
            let universal_destination_asset_id = AssetId::with_scope(
                asset_def_id,
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL),
            );
            assert!(
                stx.world.asset(&universal_destination_asset_id).is_err(),
                "bare restricted transfer must not fall back to universal dataspace"
            );
        }
        #[test]
        fn transfer_restricted_asset_preserves_explicit_universal_source_scope() {
            let domain_id = wonderland_domain_id();
            let destination_dataspace = DataSpaceId::new(11);
            let uaid_bob = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::bob-explicit-universal-scope"),
            );
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
            let bob_account = NewAccount::new(BOB_ID.clone())
                .with_uaid(Some(uaid_bob))
                .build(&BOB_ID);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let mut world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            world.uaid_accounts.insert(uaid_bob, BOB_ID.clone());
            let mut bob_bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
            bob_bindings.bind_account(destination_dataspace, BOB_ID.clone());
            world.uaid_dataspaces.insert(uaid_bob, bob_bindings);
            let state = asset_route_test_state(world);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            block.admit_fastpq_source_for_testing(Hash::prehashed([0xB8; Hash::LENGTH]));
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            seed_test_call_hash(&mut stx, 0xB8);
            Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("explicit universal source scope should credit universal destination");
            let universal_destination_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL),
            );
            assert_eq!(
                stx.world
                    .asset(&universal_destination_asset_id)
                    .expect("destination asset created in universal dataspace")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(1_u32)
            );
            let bound_destination_asset_id = AssetId::with_scope(
                asset_def_id,
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(destination_dataspace),
            );
            assert!(
                stx.world.asset(&bound_destination_asset_id).is_err(),
                "explicit universal source scope must not re-bucket into recipient binding"
            );
            assert_eq!(
                stx.world
                    .asset(&source_asset_id)
                    .expect("source balance still exists")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(9_u32)
            );
        }
        #[test]
        fn transfer_restricted_asset_rejects_ambiguous_destination_dataspace_binding() {
            let domain_id = wonderland_domain_id();
            let source_dataspace = DataSpaceId::new(7);
            let first_destination_dataspace = DataSpaceId::new(11);
            let second_destination_dataspace = DataSpaceId::new(12);
            let uaid_alice = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::alice-ambiguous-destination"),
            );
            let uaid_bob = iroha_data_model::nexus::UniversalAccountId::from_hash(
                iroha_crypto::Hash::new(b"uaid::bob-ambiguous-destination"),
            );
            let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
            let alice_account = NewAccount::new(ALICE_ID.clone())
                .with_uaid(Some(uaid_alice))
                .build(&ALICE_ID);
            let bob_account = NewAccount::new(BOB_ID.clone())
                .with_uaid(Some(uaid_bob))
                .build(&BOB_ID);
            let asset_def_id = wonderland_asset_definition_id("rose");
            let asset_def = build_restricted_rose_definition(&asset_def_id, &domain_id);
            let source_asset_id = AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
            );
            let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(10_u32));
            let mut world = World::with_assets(
                [domain],
                [alice_account, bob_account],
                [asset_def],
                [source_asset],
                [],
            );
            world.uaid_accounts.insert(uaid_alice, ALICE_ID.clone());
            world.uaid_accounts.insert(uaid_bob, BOB_ID.clone());
            let mut alice_bindings =
                crate::nexus::space_directory::UaidDataspaceBindings::default();
            alice_bindings.bind_account(source_dataspace, ALICE_ID.clone());
            let mut bob_bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
            bob_bindings.bind_account(first_destination_dataspace, BOB_ID.clone());
            bob_bindings.bind_account(second_destination_dataspace, BOB_ID.clone());
            let mut state = asset_route_test_state(world);
            state
                .world
                .uaid_dataspaces
                .insert(uaid_alice, alice_bindings);
            state.world.uaid_dataspaces.insert(uaid_bob, bob_bindings);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            block.admit_fastpq_source_for_testing(Hash::prehashed([0xB4; Hash::LENGTH]));
            let mut stx = block.transaction();
            stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            seed_test_call_hash(&mut stx, 0xB4);
            assert_eq!(
                stx.world
                    .account(&BOB_ID)
                    .expect("bob exists")
                    .as_ref()
                    .uaid(),
                Some(&uaid_bob),
                "fixture must preserve Bob's UAID"
            );
            assert!(
                stx.world.uaid_dataspaces.get(&uaid_bob).is_some(),
                "fixture must preserve Bob's UAID dataspace bindings"
            );
            let err = Transfer::asset_quantity(
                AssetId::with_scope(
                    asset_def_id,
                    ALICE_ID.clone(),
                    iroha_data_model::asset::AssetBalanceScope::Dataspace(source_dataspace),
                ),
                1_u32,
                BOB_ID.clone(),
            )
            .execute(&ALICE_ID, &mut stx)
            .expect_err("ambiguous destination binding must not pick a dataspace");
            match err {
                InstructionExecutionError::InvariantViolation(message) => assert!(
                    message.contains("bound to multiple dataspaces"),
                    "{message}"
                ),
                other => panic!("unexpected error: {other:?}"),
            }
            assert_eq!(
                stx.world
                    .asset(&source_asset_id)
                    .expect("source balance must remain untouched")
                    .value()
                    .clone()
                    .into_inner(),
                Quantity::from(10_u32)
            );
        }
        include!("asset/ambiguous_source_dataspace_tests.rs");
        include!("asset_tail_policy_tests.rs");
    }
}
