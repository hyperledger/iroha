//! FI-authenticated references, exact owner consent and sealed native off-ramps.

use super::*;
use crate::{
    executor::ContractRuntimeExecutionContext,
    state::{asset_fi, asset_uid},
};
use iroha_data_model::isi::asset_fi::{
    SetAssetFiLinkAttestationV1, SetAssetFiLinkV1, SetAssetFiV1, TransferToLinkedFiV1,
};
use iroha_primitives::numeric::Quantity;

fn next_revision(previous: Option<u64>, actual: u64) -> Result<(), Error> {
    if previous.map_or(Some(1), |value| value.checked_add(1)) != Some(actual) {
        return Err(asset_fi::reject(
            "native FI revision must advance exactly once",
        ));
    }
    Ok(())
}

impl Execute for SetAssetFiV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let value = self.fi;
        let definition = tx.world.asset_definition(&value.asset_definition_id)?;
        if definition.owned_by() != authority
            || definition.balance_scope_policy()
                != iroha_data_model::asset::AssetBalancePolicy::Global
        {
            return Err(asset_fi::reject(
                "FI eligibility requires the exact Global asset owner",
            ));
        }
        tx.world.account(&value.fi_account_id)?;
        if asset_uid::binding(tx.world(), &value.asset_definition_id, &value.fi_account_id)?
            .is_some()
            || crate::state::asset_uid_enrollment::system(
                tx.world(),
                &value.asset_definition_id,
                &value.fi_account_id,
            )?
            .is_some()
            || tx
                .world
                .asset_escrows
                .iter()
                .any(|(_, record)| record.custody == value.fi_account_id)
        {
            return Err(asset_fi::reject(
                "FI enrollment cannot overlap retail, system or native custody",
            ));
        }
        let old = asset_fi::fi(tx.world(), &value.asset_definition_id, &value.fi_account_id)?;
        next_revision(old.map(|old| old.revision), value.revision)?;
        let bytes = asset_uid::encode(&value)?;
        tx.world.smart_contract_state.insert(
            asset_fi::fi_key(&value.asset_definition_id, &value.fi_account_id),
            bytes,
        );
        Ok(())
    }
}

impl Execute for SetAssetFiLinkAttestationV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let value = self.attestation;
        if &value.fi_account_id != authority
            || value.account_id == value.fi_account_id
            || value.reference_digest == [0; 32]
        {
            return Err(asset_fi::reject(
                "opaque bank reference requires its exact FI authority",
            ));
        }
        let fi = asset_fi::fi(tx.world(), &value.asset_definition_id, &value.fi_account_id)?
            .ok_or_else(|| asset_fi::reject("FI is not registered for this asset"))?;
        if value.enabled && !fi.enabled {
            return Err(asset_fi::reject(
                "revoked FI cannot authenticate new references",
            ));
        }
        tx.world.account(&value.account_id)?;
        let old = asset_fi::attestation(
            tx.world(),
            &value.asset_definition_id,
            &value.account_id,
            &value.fi_account_id,
            &value.reference_digest,
        )?;
        next_revision(old.map(|old| old.revision), value.revision)?;
        let bytes = asset_uid::encode(&value)?;
        tx.world.smart_contract_state.insert(
            asset_fi::attestation_key(
                &value.asset_definition_id,
                &value.account_id,
                &value.fi_account_id,
                &value.reference_digest,
            ),
            bytes,
        );
        Ok(())
    }
}

impl Execute for SetAssetFiLinkV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let value = self.link;
        asset_fi::validate_link_shape(&value)?;
        if &value.account_id != authority {
            return Err(asset_fi::reject(
                "only the exact wallet owner may approve FI capabilities",
            ));
        }
        let policy =
            asset_uid::member_policy(tx.world(), &value.asset_definition_id, &value.account_id)?
                .ok_or_else(|| asset_fi::reject("FI link requires a bound UID policy"))?;
        if policy.revision != self.expected_policy_revision {
            return Err(asset_fi::reject(
                "UID policy changed since owner FI-link approval",
            ));
        }
        let old = asset_fi::link(tx.world(), &value.asset_definition_id, &value.account_id)?;
        next_revision(old.map(|old| old.revision), value.revision)?;
        let fi = asset_fi::fi(tx.world(), &value.asset_definition_id, &value.fi_account_id)?
            .ok_or_else(|| asset_fi::reject("FI is not registered for this asset"))?;
        let attestation = asset_fi::attestation(
            tx.world(),
            &value.asset_definition_id,
            &value.account_id,
            &value.fi_account_id,
            &value.reference_digest,
        )?
        .ok_or_else(|| asset_fi::reject("FI has not authenticated the exact opaque reference"))?;
        if value.enabled
            && (!fi.enabled
                || fi.revision != value.fi_revision
                || !attestation.enabled
                || attestation.revision != value.attestation_revision)
        {
            return Err(asset_fi::reject(
                "owner approval refers to a revoked or changed FI reference",
            ));
        }
        if let Some(controller) = &value.controller {
            if !tx.world.contract_instances.contains_key(controller)
                || tx
                    .world
                    .contract_subject_addresses
                    .get(&controller.subject_id())
                    != Some(controller)
            {
                return Err(asset_fi::reject(
                    "owner FI link requires an existing exact contract instance",
                ));
            }
        }
        let bytes = asset_uid::encode(&value)?;
        tx.world.smart_contract_state.insert(
            asset_fi::link_key(&value.asset_definition_id, &value.account_id),
            bytes,
        );
        Ok(())
    }
}

/// Non-cloneable source-owned capability consumed immediately by the movement kernel.
pub(crate) struct VerifiedLinkedFiTransfer {
    authority: AccountId,
    source: AssetId,
    destination: AssetId,
    amount: Quantity,
    binding: Vec<u8>,
}

impl VerifiedLinkedFiTransfer {
    pub(crate) fn into_parts(self) -> (AccountId, AssetId, AssetId, Quantity, Vec<u8>) {
        (
            self.authority,
            self.source,
            self.destination,
            self.amount,
            self.binding,
        )
    }
}

fn execute_transfer(
    instruction: TransferToLinkedFiV1,
    authority: &AccountId,
    tx: &mut StateTransaction<'_, '_>,
    context: Option<&ContractRuntimeExecutionContext>,
) -> Result<(), Error> {
    let link = asset_fi::active_link(
        tx.world(),
        &instruction.asset_definition_id,
        &instruction.account_id,
        instruction.expected_link_revision,
    )?;
    let policy = asset_uid::member_policy(
        tx.world(),
        &instruction.asset_definition_id,
        &instruction.account_id,
    )?
    .ok_or_else(|| asset_fi::reject("FI transfer requires a bound UID policy"))?;
    if policy.revision != instruction.expected_policy_revision {
        return Err(asset_fi::reject(
            "UID policy changed since FI transfer approval",
        ));
    }
    if authority != &instruction.account_id {
        let context = context.ok_or_else(|| {
            asset_fi::reject(
                "FI waterfall requires its authenticated owner-approved contract frame",
            )
        })?;
        if !link.waterfall
            || link.controller.as_ref() != Some(&context.contract_address)
            || !crate::executor::valid_contract_runtime_subject(
                tx.world(),
                authority,
                Some(context),
            )
        {
            return Err(asset_fi::reject(
                "FI waterfall requires the exact current owner-approved controller",
            ));
        }
        let cap = policy.holding_limit.as_ref().ok_or_else(|| {
            asset_fi::reject("unlimited holdings have no automatic waterfall excess")
        })?;
        let holdings = asset_uid::holdings(tx.world(), &policy, &BTreeMap::new())?;
        let excess = if holdings > *cap {
            holdings
                .checked_sub(cap)
                .map_err(|_| asset_fi::reject("invalid waterfall excess"))?
        } else {
            Quantity::zero()
        };
        if instruction.amount > excess {
            return Err(asset_fi::reject(
                "controller FI transfer exceeds current beneficial holding excess",
            ));
        }
    }
    let binding = asset_uid::encode(&(instruction.clone(), link.clone(), authority.clone()))?;
    let verified = VerifiedLinkedFiTransfer {
        authority: authority.clone(),
        source: AssetId::new(
            instruction.asset_definition_id.clone(),
            instruction.account_id,
        ),
        destination: AssetId::new(instruction.asset_definition_id, link.fi_account_id),
        amount: instruction.amount,
        binding,
    };
    super::asset::isi::execute_verified_linked_fi_transfer(tx, verified)
}

impl Execute for TransferToLinkedFiV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_transfer(self, authority, tx, None)
    }
}

/// The executor alone supplies an authenticated frame to contract off-ramps.
pub(crate) fn execute_instruction(
    instruction: &InstructionBox,
    authority: &AccountId,
    tx: &mut StateTransaction<'_, '_>,
    context: Option<&ContractRuntimeExecutionContext>,
) -> Option<Result<(), Error>> {
    instruction
        .as_any()
        .downcast_ref::<TransferToLinkedFiV1>()
        .map(|instruction| execute_transfer(instruction.clone(), authority, tx, context))
}

impl crate::smartcontracts::ValidQuery for iroha_data_model::query::asset_fi::FindAssetFiLinkV1 {
    fn execute(
        self,
        filter: iroha_data_model::query::dsl::CompoundPredicate<
            iroha_data_model::asset::fi_link::AssetFiRelationshipViewV1,
        >,
        state: &impl crate::state::StateReadOnly,
    ) -> Result<
        impl Iterator<Item = iroha_data_model::asset::fi_link::AssetFiRelationshipViewV1>,
        iroha_data_model::query::error::QueryExecutionFail,
    > {
        use iroha_data_model::query::{dsl::EvaluatePredicate, error::QueryExecutionFail};
        let now = state.authenticated_query_ledger_time_ms().ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "FI link query requires authenticated ledger time".into(),
            )
        })?;
        let height = u64::try_from(state.height()).map_err(|_| {
            QueryExecutionFail::Conversion(
                "FI link query height exceeds the supported range".into(),
            )
        })?;
        let row = asset_fi::view(state.world(), &self, now, height)
            .map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
        Ok(core::iter::once(row).filter(move |row| filter.applies(row)))
    }
}
