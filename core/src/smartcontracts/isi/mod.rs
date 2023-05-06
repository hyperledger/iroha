//! This module contains enumeration of all possible Iroha Special
//! Instructions [`InstructionBox`], generic instruction types and related
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
    isi::{
        error::{EvaluationError, InstructionExecutionFailure as Error},
        *,
    },
    prelude::*,
};
use iroha_logger::prelude::{Span, *};
use iroha_primitives::fixed::Fixed;

use super::{Context, Evaluate, Execute};
use crate::{prelude::*, wsv::WorldStateView};

/// Trait for proxy objects used for registration.
pub trait Registrable {
    /// Constructed type
    type Target;

    /// Construct [`Self::Target`]
    fn build(self, authority: AccountId) -> Self::Target;
}

impl Execute for InstructionBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        use InstructionBox::*;
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
            Upgrade(upgrade_box) => upgrade_box.execute(authority, wsv),
        }
    }
}

impl Execute for RegisterBox {
    type Error = Error;

    #[iroha_logger::log(name = "register", skip_all, fields(id))]
    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let object_id = self.object.evaluate(&context)?;
        Span::current().record("id", &object_id.to_string());
        iroha_logger::trace!(%authority, "Executing");
        match object_id {
            RegistrableBox::Peer(object) => {
                Register::<Peer> { object: *object }.execute(authority, wsv)
            }
            RegistrableBox::Domain(object) => {
                Register::<Domain> { object: *object }.execute(authority, wsv)
            }
            RegistrableBox::Account(object) => {
                Register::<Account> { object: *object }.execute(authority, wsv)
            }
            RegistrableBox::AssetDefinition(object) => {
                Register::<AssetDefinition> { object: *object }.execute(authority, wsv)
            }
            RegistrableBox::Asset(object) => {
                Register::<Asset> { object: *object }.execute(authority, wsv)
            }
            RegistrableBox::Trigger(object) => {
                Register::<Trigger<FilterBox, Executable>> { object: *object }
                    .execute(authority, wsv)
            }
            RegistrableBox::Role(object) => {
                Register::<Role> { object: *object }.execute(authority, wsv)
            }
            RegistrableBox::PermissionTokenDefinition(object) => {
                Register::<PermissionTokenDefinition> { object: *object }.execute(authority, wsv)
            }
        }
    }
}

impl Execute for UnregisterBox {
    type Error = Error;

    #[iroha_logger::log(name = "unregister", skip_all, fields(id))]
    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let object_id = self.object_id.evaluate(&context)?;
        Span::current().record("id", &object_id.to_string());
        iroha_logger::trace!(%authority, "Executing");
        match object_id {
            IdBox::AccountId(object_id) => {
                Unregister::<Account> { object_id }.execute(authority, wsv)
            }
            IdBox::AssetId(object_id) => Unregister::<Asset> { object_id }.execute(authority, wsv),
            IdBox::AssetDefinitionId(object_id) => {
                Unregister::<AssetDefinition> { object_id }.execute(authority, wsv)
            }
            IdBox::DomainId(object_id) => {
                Unregister::<Domain> { object_id }.execute(authority, wsv)
            }
            IdBox::PeerId(object_id) => Unregister::<Peer> { object_id }.execute(authority, wsv),
            IdBox::PermissionTokenDefinitionId(object_id) => {
                Unregister::<PermissionTokenDefinition> { object_id }.execute(authority, wsv)
            }
            IdBox::RoleId(object_id) => Unregister::<Role> { object_id }.execute(authority, wsv),
            IdBox::TriggerId(object_id) => {
                Unregister::<Trigger<FilterBox, Executable>> { object_id }.execute(authority, wsv)
            }
            IdBox::ParameterId(_) => Err(Error::Evaluate(InstructionType::Unregister.into())),
        }
    }
}

impl Execute for MintBox {
    type Error = Error;

    #[iroha_logger::log(name = "Mint", skip_all, fields(destination))]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        Span::current().record("destination", &destination_id.to_string());
        iroha_logger::trace!(?object, %authority);
        match (destination_id, object) {
            (IdBox::AssetId(destination_id), Value::Numeric(NumericValue::U32(object))) => {
                Mint::<Asset, u32> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AssetId(destination_id), Value::Numeric(NumericValue::U128(object))) => {
                Mint::<Asset, u128> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AssetId(destination_id), Value::Numeric(NumericValue::Fixed(object))) => {
                Mint::<Asset, Fixed> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AccountId(destination_id), Value::PublicKey(object)) => {
                Mint::<Account, PublicKey> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AccountId(destination_id), Value::SignatureCheckCondition(object)) => {
                Mint::<Account, SignatureCheckCondition> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::TriggerId(destination_id), Value::Numeric(NumericValue::U32(object))) => {
                Mint::<Trigger<FilterBox, Executable>, u32> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::Mint.into())),
        }
    }
}

impl Execute for BurnBox {
    type Error = Error;

    #[iroha_logger::log(name = "burn", skip_all, fields(destination))]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        Span::current().record("destination", &destination_id.to_string());
        iroha_logger::trace!(?object, %authority);
        match (
            self.destination_id.evaluate(&context)?,
            self.object.evaluate(&context)?,
        ) {
            (IdBox::AssetId(destination_id), Value::Numeric(NumericValue::U32(object))) => {
                Burn::<Asset, u32> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AssetId(destination_id), Value::Numeric(NumericValue::U128(object))) => Burn {
                object,
                destination_id,
            }
            .execute(authority, wsv),
            (IdBox::AssetId(destination_id), Value::Numeric(NumericValue::Fixed(object))) => Burn {
                object,
                destination_id,
            }
            .execute(authority, wsv),
            (IdBox::AccountId(destination_id), Value::PublicKey(object)) => Burn {
                object,
                destination_id,
            }
            .execute(authority, wsv),
            // TODO: Not implemented yet.
            // (IdBox::AccountId(account_id), Value::SignatureCheckCondition(condition)) => {
            //     Burn::<Account, SignatureCheckCondition>{condition, account_id}.execute(authority, wsv)
            // }
            _ => Err(Error::Evaluate(InstructionType::Burn.into())),
        }
    }
}

impl Execute for TransferBox {
    type Error = Error;

    #[iroha_logger::log(name = "transfer", skip_all, fields(from, to))]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let (IdBox::AssetId(source_id), IdBox::AccountId(destination_id)) = (
            self.source_id.evaluate(&context)?,
            self.destination_id.evaluate(&context)?,
        ) else {
            return Err(Error::Evaluate(InstructionType::Transfer.into()));
        };

        let value = self.object.evaluate(&context)?;
        Span::current().record("from", source_id.to_string());
        Span::current().record("to", destination_id.to_string());
        iroha_logger::trace!(%value, %authority);

        match value {
            Value::Numeric(NumericValue::U32(object)) => Transfer {
                source_id,
                object,
                destination_id,
            }
            .execute(authority, wsv),
            Value::Numeric(NumericValue::U128(object)) => Transfer {
                source_id,
                object,
                destination_id,
            }
            .execute(authority, wsv),
            Value::Numeric(NumericValue::Fixed(object)) => Transfer {
                source_id,
                object,
                destination_id,
            }
            .execute(authority, wsv),
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
            IdBox::AssetId(object_id) => SetKeyValue::<Asset> {
                object_id,
                key,
                value,
            }
            .execute(authority, wsv),
            IdBox::AssetDefinitionId(object_id) => SetKeyValue::<AssetDefinition> {
                object_id,
                key,
                value,
            }
            .execute(authority, wsv),
            IdBox::AccountId(object_id) => SetKeyValue::<Account> {
                object_id,
                key,
                value,
            }
            .execute(authority, wsv),
            IdBox::DomainId(object_id) => SetKeyValue::<Domain> {
                object_id,
                key,
                value,
            }
            .execute(authority, wsv),
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
            IdBox::AssetId(object_id) => {
                RemoveKeyValue::<Asset> { object_id, key }.execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(object_id) => {
                RemoveKeyValue::<AssetDefinition> { object_id, key }.execute(authority, wsv)
            }
            IdBox::AccountId(object_id) => {
                RemoveKeyValue::<Account> { object_id, key }.execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::RemoveKeyValue.into())),
        }
    }
}

impl Execute for Conditional {
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

    #[iroha_logger::log(skip_all, name = "Sequence", fields(count))]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        Span::current().record("count", self.instructions.len());
        for instruction in self.instructions {
            iroha_logger::trace!(%instruction);
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

    #[iroha_logger::log(name = "grant", skip_all, fields(object))]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        Span::current().record("object", &object.to_string());
        iroha_logger::trace!(%destination_id, %authority);
        match (destination_id, object) {
            (IdBox::AccountId(destination_id), Value::PermissionToken(object)) => {
                Grant::<Account, PermissionToken> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AccountId(destination_id), Value::Id(IdBox::RoleId(object))) => {
                Grant::<Account, RoleId> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::Grant.into())),
        }
    }
}

impl Execute for RevokeBox {
    type Error = Error;

    #[iroha_logger::log(name = "revoke", skip_all, fields(object))]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let destination_id = self.destination_id.evaluate(&context)?;
        let object = self.object.evaluate(&context)?;
        Span::current().record("object", &object.to_string());
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (destination_id, object) {
            (IdBox::AccountId(destination_id), Value::PermissionToken(object)) => {
                Revoke::<Account, PermissionToken> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            (IdBox::AccountId(destination_id), Value::Id(IdBox::RoleId(object))) => {
                Revoke::<Account, RoleId> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
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
        SetParameter { parameter }.execute(authority, wsv)
    }
}

impl Execute for NewParameterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let parameter = self.parameter.evaluate(&context)?;
        NewParameter { parameter }.execute(authority, wsv)
    }
}

impl Execute for UpgradeBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new(wsv);
        let object = self.object.evaluate(&context)?;
        match object {
            UpgradableBox::Validator(object) => {
                Upgrade::<Validator> { object }.execute(authority, wsv)
            }
        }
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
            .asset_definition(&definition_id)?
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
