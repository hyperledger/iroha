//! This module contains enumeration of all possible Iroha Special
//! Instructions [`InstructionExpr`], generic instruction types and related
//! implementations.
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
    isi::{error::InstructionExecutionError as Error, *},
    prelude::*,
};
use iroha_logger::prelude::*;

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

        match self {
            Self::Register(isi) => isi.execute(authority, wsv),
            Self::Unregister(isi) => isi.execute(authority, wsv),
            Self::Mint(isi) => isi.execute(authority, wsv),
            Self::Burn(isi) => isi.execute(authority, wsv),
            Self::Transfer(isi) => isi.execute(authority, wsv),
            Self::Fail(isi) => isi.execute(authority, wsv),
            Self::SetKeyValue(isi) => isi.execute(authority, wsv),
            Self::RemoveKeyValue(isi) => isi.execute(authority, wsv),
            Self::Grant(isi) => isi.execute(authority, wsv),
            Self::Revoke(isi) => isi.execute(authority, wsv),
            Self::ExecuteTrigger(isi) => isi.execute(authority, wsv),
            Self::SetParameter(isi) => isi.execute(authority, wsv),
            Self::Upgrade(isi) => isi.execute(authority, wsv),
            Self::Log(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for RegisterBox {
    #[iroha_logger::log(name = "register", skip_all, fields(id))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::Peer(isi) => isi.execute(authority, wsv),
            Self::Domain(isi) => isi.execute(authority, wsv),
            Self::Account(isi) => isi.execute(authority, wsv),
            Self::AssetDefinition(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
            Self::Role(isi) => isi.execute(authority, wsv),
            Self::Trigger(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for UnregisterBox {
    #[iroha_logger::log(name = "unregister", skip_all, fields(id))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::Peer(isi) => isi.execute(authority, wsv),
            Self::Domain(isi) => isi.execute(authority, wsv),
            Self::Account(isi) => isi.execute(authority, wsv),
            Self::AssetDefinition(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
            Self::Role(isi) => isi.execute(authority, wsv),
            Self::Trigger(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for MintBox {
    #[iroha_logger::log(name = "Mint", skip_all, fields(destination))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::Account(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
            Self::TriggerRepetitions(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for AccountMintBox {
    fn execute(
        self,
        authority: &AccountId,
        wsv: &mut WorldStateView,
    ) -> std::prelude::v1::Result<(), Error> {
        match self {
            Self::PublicKey(isi) => isi.execute(authority, wsv),
            Self::SignatureCheckCondition(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for AssetMintBox {
    fn execute(
        self,
        authority: &AccountId,
        wsv: &mut WorldStateView,
    ) -> std::prelude::v1::Result<(), Error> {
        match self {
            Self::Quantity(isi) => isi.execute(authority, wsv),
            Self::BigQuantity(isi) => isi.execute(authority, wsv),
            Self::Fixed(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for BurnBox {
    #[iroha_logger::log(name = "burn", skip_all, fields(destination))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::AccountPublicKey(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
            Self::TriggerRepetitions(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for AssetBurnBox {
    fn execute(
        self,
        authority: &AccountId,
        wsv: &mut WorldStateView,
    ) -> std::prelude::v1::Result<(), Error> {
        match self {
            Self::Quantity(isi) => isi.execute(authority, wsv),
            Self::BigQuantity(isi) => isi.execute(authority, wsv),
            Self::Fixed(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for TransferBox {
    #[iroha_logger::log(name = "transfer", skip_all, fields(from, to))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, wsv),
            Self::AssetDefinition(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for AssetTransferBox {
    fn execute(
        self,
        authority: &AccountId,
        wsv: &mut WorldStateView,
    ) -> std::prelude::v1::Result<(), Error> {
        match self {
            Self::Quantity(isi) => isi.execute(authority, wsv),
            Self::BigQuantity(isi) => isi.execute(authority, wsv),
            Self::Fixed(isi) => isi.execute(authority, wsv),
            Self::Store(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for SetKeyValueBox {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, wsv),
            Self::Account(isi) => isi.execute(authority, wsv),
            Self::AssetDefinition(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for RemoveKeyValueBox {
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, wsv),
            Self::Account(isi) => isi.execute(authority, wsv),
            Self::AssetDefinition(isi) => isi.execute(authority, wsv),
            Self::Asset(isi) => isi.execute(authority, wsv),
        }
    }
}

impl Execute for Fail {
    fn execute(self, _authority: &AccountId, _wsv: &mut WorldStateView) -> Result<(), Error> {
        iroha_logger::trace!(?self);

        Err(Error::Fail(self.message))
    }
}

impl Execute for GrantBox {
    #[iroha_logger::log(name = "grant", skip_all, fields(object))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::PermissionToken(sub_isi) => sub_isi.execute(authority, wsv),
            Self::Role(sub_isi) => sub_isi.execute(authority, wsv),
        }
    }
}

impl Execute for RevokeBox {
    #[iroha_logger::log(name = "revoke", skip_all, fields(object))]
    fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
        match self {
            Self::PermissionToken(sub_isi) => sub_isi.execute(authority, wsv),
            Self::Role(sub_isi) => sub_isi.execute(authority, wsv),
        }
    }
}

pub mod prelude {
    //! Re-export important traits and types for glob import `(::*)`
    pub use super::*;
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;
    use std::sync::Arc;

    use iroha_crypto::KeyPair;
    use tokio::test;

    use super::*;
    use crate::{kura::Kura, query::store::LiveQueryStore, wsv::World, PeersIds};

    fn wsv_with_test_domains(kura: &Arc<Kura>) -> Result<WorldStateView> {
        let world = World::with([], PeersIds::new());
        let query_handle = LiveQueryStore::test().start();
        let mut wsv = WorldStateView::new(world, kura.clone(), query_handle);
        let genesis_account_id = AccountId::from_str("genesis@genesis")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let (public_key, _) = KeyPair::generate().into();
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        Register::domain(Domain::new(DomainId::from_str("wonderland")?))
            .execute(&genesis_account_id, &mut wsv)?;
        Register::account(Account::new(account_id, [public_key]))
            .execute(&genesis_account_id, &mut wsv)?;
        Register::asset_definition(AssetDefinition::store(asset_definition_id))
            .execute(&genesis_account_id, &mut wsv)?;
        Ok(wsv)
    }

    #[test]
    async fn asset_store() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        SetKeyValue::asset(
            asset_id.clone(),
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
    async fn account_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValue::account(
            account_id.clone(),
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
    async fn asset_definition_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValue::asset_definition(
            definition_id.clone(),
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
    async fn domain_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let domain_id = DomainId::from_str("wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValue::domain(
            domain_id.clone(),
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
    async fn executing_unregistered_trigger_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let trigger_id = TriggerId::from_str("test_trigger_id")?;

        assert!(matches!(
            ExecuteTrigger::new(trigger_id)
                .execute(&account_id, &mut wsv)
                .expect_err("Error expected"),
            Error::Find(_)
        ));

        Ok(())
    }

    #[test]
    async fn unauthorized_trigger_execution_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = wsv_with_test_domains(&kura)?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        let fake_account_id = AccountId::from_str("fake@wonderland")?;
        let trigger_id = TriggerId::from_str("test_trigger_id")?;

        // register fake account
        let (public_key, _) = KeyPair::generate().into();
        let register_account =
            Register::account(Account::new(fake_account_id.clone(), [public_key]));
        register_account.execute(&account_id, &mut wsv)?;

        // register the trigger
        let register_trigger = Register::trigger(Trigger::new(
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
        ExecuteTrigger::new(trigger_id.clone()).execute(&account_id, &mut wsv)?;

        // execute with the fake account
        assert!(matches!(
            ExecuteTrigger::new(trigger_id)
                .execute(&fake_account_id, &mut wsv)
                .expect_err("Error expected"),
            Error::InvariantViolation(_)
        ));

        Ok(())
    }
}
