//! This module contains enumeration of all possible Iroha Special
//! Instructions `Instruction`, generic instruction types and related
//! implementations.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
pub mod account;
pub mod asset;
pub mod block;
pub mod domain;
pub mod permissions;
pub mod query;
pub mod triggers;
pub mod tx;
pub mod world;

use eyre::Result;
use iroha_data_model::{
    expression::prelude::*,
    isi::{error::InstructionExecutionFailure as Error, *},
    prelude::*,
};
use iroha_logger::prelude::*;
use iroha_primitives::fixed::Fixed;

use super::{Context, Evaluate, Execute};
use crate::{prelude::*, wsv::WorldStateView};

impl Execute for Instruction {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        use Instruction::*;
        match self {
            Register(register_box) => register_box.execute(authority, wsv),
            Unregister(unregister_box) => unregister_box.execute(authority, wsv),
            Mint(mint_box) => mint_box.execute(authority, wsv),
            Burn(burn_box) => burn_box.execute(authority, wsv),
            Transfer(transfer_box) => transfer_box.execute(authority, wsv),
            If(if_box) => if_box.execute(authority, wsv),
            Pair(pair_box) => pair_box.execute(authority, wsv),
            Sequence(sequence) => sequence.execute(authority, wsv),
            Fail(fail_box) => fail_box.execute(authority, wsv),
            SetKeyValue(set_key_value) => set_key_value.execute(authority, wsv),
            RemoveKeyValue(remove_key_value) => remove_key_value.execute(authority, wsv),
            Grant(grant_box) => grant_box.execute(authority, wsv),
            Revoke(revoke_box) => revoke_box.execute(authority, wsv),
            ExecuteTrigger(execute_trigger) => execute_trigger.execute(authority, wsv),
            SetParameter(parameter_box) => parameter_box.execute(authority, wsv),
            NewParameter(parameter_box) => parameter_box.execute(authority, wsv),
        }
    }
}

impl Execute for RegisterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let object_id = self.object.evaluate(&context)?;
        iroha_logger::trace!(?object_id);
        match object_id {
            RegistrableBox::Peer(peer) => Register::<Peer>::new(*peer).execute(authority, wsv),
            RegistrableBox::Domain(domain) => {
                Register::<Domain>::new(*domain).execute(authority, wsv)
            }
            RegistrableBox::Account(account) => {
                Register::<Account>::new(*account).execute(authority, wsv)
            }
            RegistrableBox::AssetDefinition(asset_definition) => {
                Register::<AssetDefinition>::new(*asset_definition).execute(authority, wsv)
            }
            RegistrableBox::Asset(asset) => Register::<Asset>::new(*asset).execute(authority, wsv),
            RegistrableBox::Trigger(trigger) => {
                Register::<Trigger<FilterBox>>::new(*trigger).execute(authority, wsv)
            }
            RegistrableBox::Role(role) => Register::<Role>::new(*role).execute(authority, wsv),
            RegistrableBox::PermissionTokenDefinition(token_definition) => {
                Register::<PermissionTokenDefinition>::new(*token_definition)
                    .execute(authority, wsv)
            }
            RegistrableBox::Validator(validator) => {
                Register::<iroha_data_model::permission::Validator>::new(*validator)
                    .execute(authority, wsv)
            }
        }
    }
}

impl Execute for UnregisterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let object_id = self.object_id.evaluate(&context)?;
        iroha_logger::trace!(?object_id, %authority);
        match object_id {
            IdBox::AccountId(account_id) => {
                Unregister::<Account>::new(account_id).execute(authority, wsv)
            }
            IdBox::AssetId(asset_id) => Unregister::<Asset>::new(asset_id).execute(authority, wsv),
            IdBox::AssetDefinitionId(asset_definition_id) => {
                Unregister::<AssetDefinition>::new(asset_definition_id).execute(authority, wsv)
            }
            IdBox::DomainId(domain_id) => {
                Unregister::<Domain>::new(domain_id).execute(authority, wsv)
            }
            IdBox::PeerId(peer_id) => Unregister::<Peer>::new(peer_id).execute(authority, wsv),
            IdBox::PermissionTokenDefinitionId(definition_id) => {
                Unregister::<PermissionTokenDefinition>::new(definition_id).execute(authority, wsv)
            }
            IdBox::RoleId(role_id) => Unregister::<Role>::new(role_id).execute(authority, wsv),
            IdBox::TriggerId(trigger_id) => {
                Unregister::<Trigger<FilterBox>>::new(trigger_id).execute(authority, wsv)
            }
            IdBox::ValidatorId(validator_id) => {
                Unregister::<iroha_data_model::permission::Validator>::new(validator_id)
                    .execute(authority, wsv)
            }
            IdBox::ParameterId(_) => Err(Error::Evaluate(InstructionType::Unregister.into())),
        }
    }
}

impl Execute for MintBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        iroha_logger::trace!(%destination_id, ?object, %authority);
        match (destination_id, object) {
            (IdBox::AssetId(asset_id), Value::Numeric(NumericValue::U32(quantity))) => {
                Mint::<Asset, u32>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Numeric(NumericValue::U128(quantity))) => {
                Mint::<Asset, u128>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Numeric(NumericValue::Fixed(quantity))) => {
                Mint::<Asset, Fixed>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::PublicKey(public_key)) => {
                Mint::<Account, PublicKey>::new(public_key, account_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::SignatureCheckCondition(condition)) => {
                Mint::<Account, SignatureCheckCondition>::new(condition, account_id)
                    .execute(authority, wsv)
            }
            (IdBox::TriggerId(trigger_id), Value::Numeric(NumericValue::U32(quantity))) => {
                Mint::<Trigger<FilterBox>, u32>::new(quantity, trigger_id).execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::Mint.into())),
        }
    }
}

impl Execute for BurnBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (
            self.destination_id.evaluate(&context)?,
            self.object.evaluate(&context)?,
        ) {
            (IdBox::AssetId(asset_id), Value::Numeric(NumericValue::U32(quantity))) => {
                Burn::<Asset, u32>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Numeric(NumericValue::U128(quantity))) => {
                Burn::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Numeric(NumericValue::Fixed(quantity))) => {
                Burn::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::PublicKey(public_key)) => {
                Burn::new(public_key, account_id).execute(authority, wsv)
            }
            // Not implemented yet.
            // (IdBox::AccountId(account_id), Value::SignatureCheckCondition(condition)) => {
            //     Burn::<Account, SignatureCheckCondition>::new(condition, account_id).execute(authority, wsv)
            // }
            _ => Err(Error::Evaluate(InstructionType::Burn.into())),
        }
    }
}

impl Execute for TransferBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let (IdBox::AssetId(source_asset_id), IdBox::AssetId(destination_asset_id)) = (
            self.source_id.evaluate(&context)?,
            self.destination_id.evaluate(&context)?,
        ) else {
            return Err(Error::Evaluate(InstructionType::Transfer.into()));
        };

        let value = self.object.evaluate(&context)?;
        iroha_logger::trace!(?source_asset_id, ?destination_asset_id, ?value, %authority);

        match value {
            Value::Numeric(NumericValue::U32(quantity)) => {
                Transfer::new(source_asset_id, quantity, destination_asset_id)
                    .execute(authority, wsv)
            }
            Value::Numeric(NumericValue::U128(quantity)) => {
                Transfer::new(source_asset_id, quantity, destination_asset_id)
                    .execute(authority, wsv)
            }
            Value::Numeric(NumericValue::Fixed(quantity)) => {
                Transfer::new(source_asset_id, quantity, destination_asset_id)
                    .execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::Transfer.into())),
        }
    }
}

impl Execute for SetKeyValueBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let key = self.key.evaluate(&context)?;
        let value = self.value.evaluate(&context)?;
        iroha_logger::trace!(?key, ?value, %authority);
        match self.object_id.evaluate(&context)? {
            IdBox::AssetId(asset_id) => {
                SetKeyValue::<Asset, Name, Value>::new(asset_id, key, value).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(definition_id) => {
                SetKeyValue::<AssetDefinition, Name, Value>::new(definition_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::AccountId(account_id) => {
                SetKeyValue::<Account, Name, Value>::new(account_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::DomainId(id) => {
                SetKeyValue::<Domain, Name, Value>::new(id, key, value).execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::SetKeyValue.into())),
        }
    }
}

impl Execute for RemoveKeyValueBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let key = self.key.evaluate(&context)?;
        iroha_logger::trace!(?key, %authority);
        match self.object_id.evaluate(&context)? {
            IdBox::AssetId(asset_id) => {
                RemoveKeyValue::<Asset, Name>::new(asset_id, key).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(definition_id) => {
                RemoveKeyValue::<AssetDefinition, Name>::new(definition_id, key)
                    .execute(authority, wsv)
            }
            IdBox::AccountId(account_id) => {
                RemoveKeyValue::<Account, Name>::new(account_id, key).execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::RemoveKeyValue.into())),
        }
    }
}

impl Execute for If {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        iroha_logger::trace!(?self);
        if self.condition.evaluate(&context)? {
            self.then.execute(authority, wsv)?;
        } else if let Some(otherwise) = self.otherwise {
            otherwise.execute(authority, wsv)?;
        }
        Ok(())
    }
}

impl Execute for Pair {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        iroha_logger::trace!(?self);

        self.left_instruction.execute(authority.clone(), wsv)?;
        self.right_instruction.execute(authority, wsv)?;
        Ok(())
    }
}

impl Execute for SequenceBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        iroha_logger::trace!(?self);

        for instruction in self.instructions {
            instruction.execute(authority.clone(), wsv)?;
        }
        Ok(())
    }
}

impl Execute for FailBox {
    type Error = Error;

    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        iroha_logger::trace!(?self);

        Err(Error::FailBox(self.message))
    }
}

impl Execute for GrantBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (destination_id, object) {
            (IdBox::AccountId(account_id), Value::PermissionToken(permission_token)) => {
                Grant::<Account, PermissionToken>::new(permission_token, account_id)
                    .execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(role_id))) => {
                Grant::<Account, RoleId>::new(role_id, account_id).execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::Grant.into())),
        }
    }
}

impl Execute for RevokeBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (destination_id, object) {
            (IdBox::AccountId(account_id), Value::PermissionToken(permission_token)) => {
                Revoke::<Account, PermissionToken>::new(permission_token, account_id)
                    .execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(role_id))) => {
                Revoke::<Account, RoleId>::new(role_id, account_id).execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::Revoke.into())),
        }
    }
}

impl Execute for SetParameterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let parameter = self.parameter.evaluate(&context)?;
        SetParameter::<Parameter>::new(parameter).execute(authority, wsv)
    }
}

impl Execute for NewParameterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let parameter = self.parameter.evaluate(&context)?;
        NewParameter::<Parameter>::new(parameter).execute(authority, wsv)
    }
}

pub mod prelude {
    //! Re-export important traits and types for glob import `(::*)`
    pub use super::*;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use core::str::FromStr;
    use std::sync::Arc;

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{kura::Kura, wsv::World, PeersIds};

    fn wsv_with_test_domains(kura: &Arc<Kura>) -> Result<WorldStateView> {
        let world = World::with([], PeersIds::new());
        let wsv = WorldStateView::new(world, kura.clone());
        let genesis_account_id = AccountId::from_str("genesis@genesis")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let (public_key, _) = KeyPair::generate()?.into();
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        RegisterBox::new(Domain::new(DomainId::from_str("wonderland")?))
            .execute(genesis_account_id.clone(), &wsv)?;
        RegisterBox::new(Account::new(account_id, [public_key]))
            .execute(genesis_account_id.clone(), &wsv)?;
        RegisterBox::new(AssetDefinition::store(asset_definition_id))
            .execute(genesis_account_id, &wsv)?;
        Ok(wsv)
    }

    #[test]
    fn asset_store() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        SetKeyValueBox::new(
            IdBox::from(asset_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let asset = wsv.asset(&asset_id)?;
        let metadata: &Metadata = asset.try_as_ref()?;
        let bytes = metadata
            .get(&Name::from_str("Bytes").expect("Valid"))
            .cloned();
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                1_u32.to_value(),
                2_u32.to_value(),
                3_u32.to_value(),
            ]))
        );
        Ok(())
    }

    #[test]
    fn account_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(account_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id.clone(), &wsv)?;
        let bytes = wsv.map_account(&account_id, |account| {
            account
                .metadata()
                .get(&Name::from_str("Bytes").expect("Valid"))
                .cloned()
        })?;
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                1_u32.to_value(),
                2_u32.to_value(),
                3_u32.to_value(),
            ]))
        );
        Ok(())
    }

    #[test]
    fn asset_definition_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = wsv_with_test_domains(&kura)?;
        let definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(definition_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let bytes = wsv
            .asset_definition_entry(&definition_id)?
            .definition
            .metadata()
            .get(&Name::from_str("Bytes")?)
            .cloned();
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                1_u32.to_value(),
                2_u32.to_value(),
                3_u32.to_value(),
            ]))
        );
        Ok(())
    }

    #[test]
    fn domain_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = wsv_with_test_domains(&kura)?;
        let domain_id = DomainId::from_str("wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(domain_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let bytes = wsv
            .domain(&domain_id)?
            .metadata()
            .get(&Name::from_str("Bytes")?)
            .cloned();
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                1_u32.to_value(),
                2_u32.to_value(),
                3_u32.to_value(),
            ]))
        );
        Ok(())
    }

    #[test]
    fn executing_unregistered_trigger_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let trigger_id = TriggerId::from_str("test_trigger_id")?;

        assert!(matches!(
            ExecuteTriggerBox::new(trigger_id)
                .execute(account_id, &wsv)
                .expect_err("Error expected"),
            Error::Find(_)
        ));

        Ok(())
    }

    #[test]
    fn unauthorized_trigger_execution_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let fake_account_id = AccountId::from_str("fake@wonderland")?;
        let trigger_id = TriggerId::from_str("test_trigger_id")?;

        // register fake account
        let (public_key, _) = KeyPair::generate()
            .expect("Failed to generate KeyPair")
            .into();
        let register_account =
            RegisterBox::new(Account::new(fake_account_id.clone(), [public_key]));
        register_account.execute(account_id.clone(), &wsv)?;

        // register the trigger
        let register_trigger = RegisterBox::new(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::from(Vec::new()),
                Repeats::Indefinitely,
                account_id.clone(),
                FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                    trigger_id.clone(),
                    account_id.clone(),
                )),
            ),
        ));

        register_trigger.execute(account_id.clone(), &wsv)?;

        // execute with the valid account
        ExecuteTriggerBox::new(trigger_id.clone()).execute(account_id, &wsv)?;

        // execute with the fake account
        assert!(matches!(
            ExecuteTriggerBox::new(trigger_id)
                .execute(fake_account_id, &wsv)
                .expect_err("Error expected"),
            Error::Validate(_)
        ));

        Ok(())
    }
}
