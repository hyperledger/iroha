//! Native owner-authorized UID policy configuration.
use super::*;
use crate::state::asset_uid;
use iroha_data_model::query::dsl::EvaluatePredicate;
use iroha_data_model::{
    asset::{AssetBalancePolicy, uid::AssetUidBindingV1},
    isi::{asset_uid::SetAssetUidPolicyV1, error::InstructionExecutionError},
};

fn reject(message: &str) -> Error {
    InstructionExecutionError::InvariantViolation(message.into())
}

impl Execute for SetAssetUidPolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let value = self.policy;
        value.validate_shape().map_err(reject)?;
        let definition = stx.world.asset_definition(&value.asset_definition_id)?;
        if definition.owned_by() != authority {
            return Err(reject(
                "only the exact asset-definition owner may configure UID policy",
            ));
        }
        if definition.balance_scope_policy() != AssetBalancePolicy::Global {
            return Err(reject(
                "asset UID policy requires a Global asset definition",
            ));
        }
        for limit in [value.holding_limit.as_ref(), value.daily_limit.as_ref()]
            .into_iter()
            .flatten()
        {
            definition
                .spec()
                .check(limit.as_numeric())
                .map_err(|_| reject("asset UID limit violates asset precision"))?;
        }
        let previous = asset_uid::policy(stx.world(), &value.asset_definition_id, &value.uid)?;
        let expected_revision = previous
            .as_ref()
            .map_or(Some(1), |old| old.revision.checked_add(1));
        if expected_revision != Some(value.revision) {
            return Err(reject(
                "asset UID policy revision must advance exactly once",
            ));
        }
        if previous
            .as_ref()
            .is_some_and(|old| !old.accounts.is_subset(&value.accounts))
        {
            return Err(reject("asset UID membership is append-only"));
        }
        if previous
            .as_ref()
            .is_some_and(|old| old.daily_window != value.daily_window)
        {
            return Err(reject(
                "asset UID calendar cannot change after installation",
            ));
        }
        let mut writes = Vec::new();
        for account in &value.accounts {
            stx.world.account(account)?;
            if stx
                .world
                .asset_escrows
                .iter()
                .any(|(_, escrow)| escrow.custody == *account)
            {
                return Err(reject("native escrow custody cannot become a UID wallet"));
            }
            if let Some(existing) =
                asset_uid::binding(stx.world(), &value.asset_definition_id, account)?
            {
                if existing.uid != value.uid {
                    return Err(reject("asset account is already bound to another UID"));
                }
            } else {
                let member = AssetUidBindingV1 {
                    asset_definition_id: value.asset_definition_id.clone(),
                    account_id: account.clone(),
                    uid: value.uid,
                };
                writes.push((
                    asset_uid::binding_key(&value.asset_definition_id, account),
                    asset_uid::encode(&member)?,
                ));
            }
        }
        // Authorized reductions take effect for subsequent credits even when
        // retained holdings already exceed the cap. They never confiscate funds
        // or reset accumulated activity.
        writes.push((
            asset_uid::policy_key(&value.asset_definition_id, &value.uid),
            asset_uid::encode(&value)?,
        ));
        for (key, bytes) in writes {
            stx.world.smart_contract_state.insert(key, bytes);
        }
        Ok(())
    }
}

impl crate::smartcontracts::ValidQuery
    for iroha_data_model::query::asset_uid::FindAssetUidPoliciesV1
{
    fn execute(
        self,
        filter: iroha_data_model::query::dsl::CompoundPredicate<
            iroha_data_model::asset::uid::AssetUidPolicyViewV1,
        >,
        state: &impl crate::state::StateReadOnly,
    ) -> Result<
        impl Iterator<Item = iroha_data_model::asset::uid::AssetUidPolicyViewV1>,
        iroha_data_model::query::error::QueryExecutionFail,
    > {
        use iroha_data_model::query::error::QueryExecutionFail;
        let ledger_time_ms = state.authenticated_query_ledger_time_ms().ok_or_else(|| {
            QueryExecutionFail::Conversion(
                "UID policy query requires authenticated ledger time".into(),
            )
        })?;
        let height = u64::try_from(state.height()).map_err(|_| {
            QueryExecutionFail::Conversion(
                "UID policy query height is outside the supported range".into(),
            )
        })?;
        let rows = asset_uid::views(
            state.world(),
            &self.asset_definition_id,
            self.uid.as_ref(),
            ledger_time_ms,
            height,
        )
        .map_err(|error| QueryExecutionFail::Conversion(error.to_string()))?;
        Ok(rows.into_iter().filter(move |row| filter.applies(row)))
    }
}

#[cfg(test)]
mod tests;
