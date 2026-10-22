//! Owner-controlled grant lifecycle for private native UID holding quotes.

use super::*;
use crate::state::{asset_uid, asset_uid_reader};
use iroha_data_model::{
    asset::{AssetBalancePolicy, uid::AssetUidPolicyReaderV1},
    isi::asset_uid::SetAssetUidPolicyReaderV1,
};

fn reject(message: &str) -> Error {
    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message.into())
}

impl Execute for SetAssetUidPolicyReaderV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let definition = tx.world.asset_definition(&self.asset_definition_id)?;
        if definition.owned_by() != authority
            || definition.balance_scope_policy() != AssetBalancePolicy::Global
        {
            return Err(reject(
                "UID reader grant requires the exact Global asset owner",
            ));
        }
        tx.world.account(&self.controller.subject_id())?;
        if self.enabled
            && (tx.world.contract_instances.get(&self.controller).is_none()
                || tx
                    .world
                    .contract_subject_addresses
                    .get(&self.controller.subject_id())
                    != Some(&self.controller))
        {
            return Err(reject(
                "UID reader grant requires an existing exact contract instance",
            ));
        }
        let previous =
            asset_uid_reader::reader(tx.world(), &self.asset_definition_id, &self.controller)?;
        if previous.map_or(Some(1), |value| value.revision.checked_add(1)) != Some(self.revision) {
            return Err(reject("UID reader revision must advance exactly once"));
        }
        let value = AssetUidPolicyReaderV1 {
            asset_definition_id: self.asset_definition_id,
            controller: self.controller,
            revision: self.revision,
            enabled: self.enabled,
        };
        let bytes = asset_uid::encode(&value)?;
        tx.world.smart_contract_state.insert(
            asset_uid_reader::reader_key(&value.asset_definition_id, &value.controller),
            bytes,
        );
        Ok(())
    }
}
