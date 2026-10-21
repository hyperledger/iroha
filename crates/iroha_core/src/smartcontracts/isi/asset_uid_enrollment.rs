//! Exact issuer enrollment and atomic activation after retained-state reconciliation.

use super::*;
use crate::state::{asset_fi, asset_uid, asset_uid_enrollment};
use iroha_data_model::{
    asset::{AssetBalancePolicy, uid_enrollment::AssetUidEnrollmentV1},
    isi::asset_uid_enrollment::{ActivateAssetUidEnrollmentV1, SetAssetUidSystemAccountV1},
};

fn owner(
    tx: &StateTransaction<'_, '_>,
    definition: &AssetDefinitionId,
    authority: &AccountId,
) -> Result<(), Error> {
    let value = tx.world.asset_definition(definition)?;
    if value.owned_by() != authority || value.balance_scope_policy() != AssetBalancePolicy::Global {
        return Err(asset_fi::reject(
            "asset enrollment requires the exact Global asset owner",
        ));
    }
    Ok(())
}

impl Execute for SetAssetUidSystemAccountV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let value = self.account;
        owner(tx, &value.asset_definition_id, authority)?;
        tx.world.account(&value.account_id)?;
        if asset_uid::binding(tx.world(), &value.asset_definition_id, &value.account_id)?.is_some()
            || asset_fi::fi(tx.world(), &value.asset_definition_id, &value.account_id)?.is_some()
            || tx
                .world
                .asset_escrows
                .iter()
                .any(|(_, record)| record.custody == value.account_id)
        {
            return Err(asset_fi::reject(
                "system enrollment cannot overlap retail, FI or native custody",
            ));
        }
        let old = asset_uid_enrollment::system(
            tx.world(),
            &value.asset_definition_id,
            &value.account_id,
        )?;
        if old.map_or(Some(1), |old| old.revision.checked_add(1)) != Some(value.revision) {
            return Err(asset_fi::reject(
                "system enrollment revision must advance exactly once",
            ));
        }
        let bytes = asset_uid::encode(&value)?;
        tx.world.smart_contract_state.insert(
            asset_uid_enrollment::system_key(&value.asset_definition_id, &value.account_id),
            bytes,
        );
        Ok(())
    }
}

impl Execute for ActivateAssetUidEnrollmentV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        owner(tx, &self.asset_definition_id, authority)?;
        if asset_uid_enrollment::enrollment(tx.world(), &self.asset_definition_id)?.is_some() {
            return Err(asset_fi::reject(
                "mandatory asset enrollment is already active",
            ));
        }
        asset_uid_enrollment::validate_reconciliation(tx.world(), &self.asset_definition_id)?;
        let value = AssetUidEnrollmentV1 {
            asset_definition_id: self.asset_definition_id,
            activated_at_height: tx.block_height(),
        };
        let bytes = asset_uid::encode(&value)?;
        tx.world.smart_contract_state.insert(
            asset_uid_enrollment::enrollment_key(&value.asset_definition_id),
            bytes,
        );
        Ok(())
    }
}


impl crate::smartcontracts::ValidQuery for iroha_data_model::query::asset_uid_enrollment::FindAssetUidEnrollmentV1 {
    fn execute(
        self,
        filter: iroha_data_model::query::dsl::CompoundPredicate<iroha_data_model::asset::uid_enrollment::AssetUidEnrollmentViewV1>,
        state: &impl crate::state::StateReadOnly,
    ) -> Result<impl Iterator<Item = iroha_data_model::asset::uid_enrollment::AssetUidEnrollmentViewV1>, iroha_data_model::query::error::QueryExecutionFail> {
        use iroha_data_model::query::{dsl::EvaluatePredicate, error::QueryExecutionFail};
        let ledger_time_ms = state.authenticated_query_ledger_time_ms().ok_or_else(|| QueryExecutionFail::Conversion("enrollment query requires authenticated ledger time".into()))?;
        let as_of_height = u64::try_from(state.height()).map_err(|_| QueryExecutionFail::CapacityLimit)?;
        state.world().asset_definition(&self.asset_definition_id).map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
        let enrollment = asset_uid_enrollment::enrollment(state.world(), &self.asset_definition_id).map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
        let row = iroha_data_model::asset::uid_enrollment::AssetUidEnrollmentViewV1 { asset_definition_id: self.asset_definition_id, enrollment, ledger_time_ms, as_of_height };
        Ok(core::iter::once(row).filter(move |row| filter.applies(row)))
    }
}
