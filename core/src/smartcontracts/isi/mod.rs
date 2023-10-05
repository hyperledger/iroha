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
pub mod query;
pub mod triggers;
pub mod tx;
pub mod world;

use eyre::Result;
use iroha_data_model::{
    evaluate::ExpressionEvaluator,
    isi::{error::InstructionExecutionError as Error, *},
    prelude::*,
};
use iroha_logger::prelude::{Span, *};
use iroha_primitives::fixed::Fixed;

use super::Execute;
use crate::{prelude::*, wsv::WorldStateView};

/// Trait for proxy objects used for registration.
pub trait Registrable {
    /// Constructed type
    type Target;

    /// Construct [`Self::Target`]
    fn build(self, authority: &AccountId) -> Self::Target;
}

impl Execute for InstructionBox {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        iroha_logger::debug!(isi=%self, "Executing");

        macro_rules! match_all {
            ($($isi:ident),+ $(,)?) => {

                match self { $(
                    InstructionBox::$isi(isi) => isi.execute(authority, wsv), )+
                }
            };
        }

        match_all! {
            Register,
            Unregister,
            Mint,
            Burn,
            Transfer,
            If,
            Pair,
            Sequence,
            Fail,
            SetKeyValue,
            RemoveKeyValue,
            Grant,
            Revoke,
            ExecuteTrigger,
            SetParameter,
            NewParameter,
            Upgrade,
            Log,
        }
    }
}

impl Execute for RegisterBox {
    #[iroha_logger::log(name = "register", skip_all, fields(id))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let object_id = wsv.evaluate(&self.object)?;
        Span::current().record("id", &object_id.to_string());
        match object_id {
            RegistrableBox::Peer(object) => Register::<Peer> { object }.execute(authority, wsv),
            RegistrableBox::Domain(object) => Register::<Domain> { object }.execute(authority, wsv),
            RegistrableBox::Account(object) => {
                Register::<Account> { object }.execute(authority, wsv)
            }
            RegistrableBox::AssetDefinition(object) => {
                Register::<AssetDefinition> { object }.execute(authority, wsv)
            }
            RegistrableBox::Asset(object) => Register::<Asset> { object }.execute(authority, wsv),
            RegistrableBox::Trigger(object) => {
                Register::<Trigger<TriggeringFilterBox, Executable>> { object }
                    .execute(authority, wsv)
            }
            RegistrableBox::Role(object) => Register::<Role> { object }.execute(authority, wsv),
        }
    }
}

impl Execute for UnregisterBox {
    #[iroha_logger::log(name = "unregister", skip_all, fields(id))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let object_id = wsv.evaluate(&self.object_id)?;
        Span::current().record("id", &object_id.to_string());
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
            IdBox::RoleId(object_id) => Unregister::<Role> { object_id }.execute(authority, wsv),
            IdBox::TriggerId(object_id) => {
                Unregister::<Trigger<TriggeringFilterBox, Executable>> { object_id }
                    .execute(authority, wsv)
            }
            IdBox::PermissionTokenId(_) | IdBox::ParameterId(_) => {
                Err(Error::Evaluate(InstructionType::Unregister.into()))
            }
        }
    }
}

impl Execute for MintBox {
    #[iroha_logger::log(name = "Mint", skip_all, fields(destination))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let destination_id = wsv.evaluate(&self.destination_id)?;
        let object = wsv.evaluate(&self.object)?;
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
                Mint::<Trigger<TriggeringFilterBox, Executable>, u32> {
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
    #[iroha_logger::log(name = "burn", skip_all, fields(destination))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let destination_id = wsv.evaluate(&self.destination_id)?;
        let object = wsv.evaluate(&self.object)?;
        Span::current().record("destination", &destination_id.to_string());
        iroha_logger::trace!(?object, %authority);
        match (destination_id, object) {
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
            (IdBox::TriggerId(destination_id), Value::Numeric(NumericValue::U32(object))) => {
                Burn::<Trigger<TriggeringFilterBox, Executable>, u32> {
                    object,
                    destination_id,
                }
                .execute(authority, wsv)
            }
            // TODO: Not implemented yet.
            // (IdBox::AccountId(account_id), Value::SignatureCheckCondition(condition)) => {
            //     Burn::<Account, SignatureCheckCondition>{condition, account_id}.execute(authority, wsv)
            // }
            _ => Err(Error::Evaluate(InstructionType::Burn.into())),
        }
    }
}

impl Execute for TransferBox {
    #[iroha_logger::log(name = "transfer", skip_all, fields(from, to))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let source_id = wsv.evaluate(&self.source_id)?;
        let destination_id = wsv.evaluate(&self.destination_id)?;
        let value = wsv.evaluate(&self.object)?;
        iroha_logger::trace!(%value, %authority);
        Span::current().record("from", source_id.to_string());
        Span::current().record("to", destination_id.to_string());

        match (source_id, value, destination_id) {
            (
                IdBox::AssetId(source_id),
                Value::Numeric(value),
                IdBox::AccountId(destination_id),
            ) => match value {
                NumericValue::U32(object) => Transfer {
                    source_id,
                    object,
                    destination_id,
                }
                .execute(authority, wsv),
                NumericValue::U128(object) => Transfer {
                    source_id,
                    object,
                    destination_id,
                }
                .execute(authority, wsv),
                NumericValue::Fixed(object) => Transfer {
                    source_id,
                    object,
                    destination_id,
                }
                .execute(authority, wsv),
                _ => Err(Error::Evaluate(InstructionType::Transfer.into())),
            },
            (
                IdBox::AccountId(source_id),
                Value::Id(IdBox::AssetDefinitionId(object)),
                IdBox::AccountId(destination_id),
            ) => Transfer {
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
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let key = wsv.evaluate(&self.key)?;
        let value = wsv.evaluate(&self.value)?;
        iroha_logger::trace!(?key, ?value, %authority);
        match wsv.evaluate(&self.object_id)? {
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
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let key = wsv.evaluate(&self.key)?;
        iroha_logger::trace!(?key, %authority);
        match wsv.evaluate(&self.object_id)? {
            IdBox::AssetId(object_id) => {
                RemoveKeyValue::<Asset> { object_id, key }.execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(object_id) => {
                RemoveKeyValue::<AssetDefinition> { object_id, key }.execute(authority, wsv)
            }
            IdBox::AccountId(object_id) => {
                RemoveKeyValue::<Account> { object_id, key }.execute(authority, wsv)
            }
            IdBox::DomainId(object_id) => {
                RemoveKeyValue::<Domain> { object_id, key }.execute(authority, wsv)
            }
            _ => Err(Error::Evaluate(InstructionType::RemoveKeyValue.into())),
        }
    }
}

impl Execute for Conditional {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        iroha_logger::trace!(?self);
        if wsv.evaluate(&self.condition)? {
            self.then.execute(authority, wsv)?;
        } else if let Some(otherwise) = self.otherwise {
            otherwise.execute(authority, wsv)?;
        }
        Ok(())
    }
}

impl Execute for Pair {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        iroha_logger::trace!(?self);

        self.left_instruction.execute(authority, wsv)?;
        self.right_instruction.execute(authority, wsv)?;
        Ok(())
    }
}

impl Execute for SequenceBox {
    #[iroha_logger::log(skip_all, name = "Sequence", fields(count))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        Span::current().record("count", self.instructions.len());
        for instruction in self.instructions {
            iroha_logger::trace!(%instruction);
            instruction.execute(authority, wsv)?;
        }
        Ok(())
    }
}

impl Execute for FailBox {
    fn execute(self, _authority: &AccountId, _wsv: &mut WorldStateView) -> Result<(), Error> {
        iroha_logger::trace!(?self);

        Err(Error::Fail(self.message))
    }
}

impl Execute for GrantBox {
    #[iroha_logger::log(name = "grant", skip_all, fields(object))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let destination_id = wsv.evaluate(&self.destination_id)?;
        let object = wsv.evaluate(&self.object)?;
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
    #[iroha_logger::log(name = "revoke", skip_all, fields(object))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let destination_id = wsv.evaluate(&self.destination_id)?;
        let object = wsv.evaluate(&self.object)?;
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
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let parameter = wsv.evaluate(&self.parameter)?;
        SetParameter { parameter }.execute(authority, wsv)
    }
}

impl Execute for NewParameterBox {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let parameter = wsv.evaluate(&self.parameter)?;
        NewParameter { parameter }.execute(authority, wsv)
    }
}

impl Execute for UpgradeBox {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let object = wsv.evaluate(&self.object)?;
        match object {
            UpgradableBox::Validator(object) => {
                Upgrade::<Validator> { object }.execute(authority, wsv)
            }
        }
    }
}

impl Execute for LogBox {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        let level = wsv.evaluate(&self.level)?;
        let msg = wsv.evaluate(&self.msg)?;

        Log { level, msg }.execute(authority, wsv)
    }
}

pub mod prelude {
    //! Re-export important traits and types for glob import `(::*)`
    pub use super::*;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use core::str::FromStr as _;
    use std::sync::Arc;

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{kura::Kura, wsv::World, PeersIds};

    fn wsv_with_test_domains(kura: &Arc<Kura>) -> Result<WorldStateView> {
        let world = World::with([], PeersIds::new());
        let mut wsv = WorldStateView::new(world, kura.clone());
        let genesis_account_id = AccountId::from_str("genesis@genesis")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let (public_key, _) = KeyPair::generate()?.into();
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        RegisterBox::new(Domain::new(DomainId::from_str("wonderland")?))
            .execute(&genesis_account_id, &mut wsv)?;
        RegisterBox::new(Account::new(account_id, [public_key]))
            .execute(&genesis_account_id, &mut wsv)?;
        RegisterBox::new(AssetDefinition::store(asset_definition_id))
            .execute(&genesis_account_id, &mut wsv)?;
        Ok(wsv)
    }

    #[test]
    fn asset_store() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        SetKeyValueBox::new(
            IdBox::from(asset_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(&account_id, &mut wsv)?;
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
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(account_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(&account_id, &mut wsv)?;
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
        let mut wsv = wsv_with_test_domains(&kura)?;
        let definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(definition_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(&account_id, &mut wsv)?;
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
        let mut wsv = wsv_with_test_domains(&kura)?;
        let domain_id = DomainId::from_str("wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(domain_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(&account_id, &mut wsv)?;
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
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let trigger_id = TriggerId::from_str("test_trigger_id")?;

        assert!(matches!(
            ExecuteTriggerBox::new(trigger_id)
                .execute(&account_id, &mut wsv)
                .expect_err("Error expected"),
            Error::Find(_)
        ));

        Ok(())
    }

    #[test]
    fn unauthorized_trigger_execution_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let fake_account_id = AccountId::from_str("fake@wonderland")?;
        let trigger_id = TriggerId::from_str("test_trigger_id")?;

        // register fake account
        let (public_key, _) = KeyPair::generate()
            .expect("Failed to generate KeyPair")
            .into();
        let register_account =
            RegisterBox::new(Account::new(fake_account_id.clone(), [public_key]));
        register_account.execute(&account_id, &mut wsv)?;

        // register the trigger
        let register_trigger = RegisterBox::new(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                account_id.clone(),
                TriggeringFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                    trigger_id.clone(),
                    account_id.clone(),
                )),
            ),
        ));

        register_trigger.execute(&account_id, &mut wsv)?;

        // execute with the valid account
        ExecuteTriggerBox::new(trigger_id.clone()).execute(&account_id, &mut wsv)?;

        // execute with the fake account
        assert!(matches!(
            ExecuteTriggerBox::new(trigger_id)
                .execute(&fake_account_id, &mut wsv)
                .expect_err("Error expected"),
            Error::InvariantViolation(_)
        ));

        Ok(())
    }
}
