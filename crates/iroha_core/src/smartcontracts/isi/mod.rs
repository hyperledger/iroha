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
use mv::storage::StorageReadOnly;

use super::Execute;
use crate::{
    prelude::*,
    smartcontracts::triggers::set::SetReadOnly,
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};

/// Trait for proxy objects used for registration.
pub trait Registrable {
    /// Constructed type
    type Target;

    /// Construct [`Self::Target`]
    fn build(self, authority: &AccountId) -> Self::Target;
}

impl Execute for InstructionBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        iroha_logger::debug!(isi=%self, "Executing");

        match self {
            Self::Register(isi) => isi.execute(authority, state_transaction),
            Self::Unregister(isi) => isi.execute(authority, state_transaction),
            Self::Mint(isi) => isi.execute(authority, state_transaction),
            Self::Burn(isi) => isi.execute(authority, state_transaction),
            Self::Transfer(isi) => isi.execute(authority, state_transaction),
            Self::SetKeyValue(isi) => isi.execute(authority, state_transaction),
            Self::RemoveKeyValue(isi) => isi.execute(authority, state_transaction),
            Self::Grant(isi) => isi.execute(authority, state_transaction),
            Self::Revoke(isi) => isi.execute(authority, state_transaction),
            Self::ExecuteTrigger(isi) => isi.execute(authority, state_transaction),
            Self::SetParameter(isi) => isi.execute(authority, state_transaction),
            Self::Upgrade(isi) => isi.execute(authority, state_transaction),
            Self::Log(isi) => isi.execute(authority, state_transaction),
            Self::Custom(_) => {
                panic!("Custom instructions should be handled in custom executor");
            }
        }
    }
}

impl Execute for RegisterBox {
    #[iroha_logger::log(name = "register", skip_all, fields(id))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Peer(isi) => isi.execute(authority, state_transaction),
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Role(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for UnregisterBox {
    #[iroha_logger::log(name = "unregister", skip_all, fields(id))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Peer(isi) => isi.execute(authority, state_transaction),
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Role(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for MintBox {
    #[iroha_logger::log(name = "Mint", skip_all, fields(destination))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Asset(isi) => isi.execute(authority, state_transaction),
            Self::TriggerRepetitions(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for BurnBox {
    #[iroha_logger::log(name = "burn", skip_all, fields(destination))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Asset(isi) => isi.execute(authority, state_transaction),
            Self::TriggerRepetitions(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for TransferBox {
    #[iroha_logger::log(name = "transfer", skip_all, fields(from, to))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Numeric(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for SetKeyValueBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for RemoveKeyValueBox {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Domain(isi) => isi.execute(authority, state_transaction),
            Self::Account(isi) => isi.execute(authority, state_transaction),
            Self::AssetDefinition(isi) => isi.execute(authority, state_transaction),
            Self::Trigger(isi) => isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for GrantBox {
    #[iroha_logger::log(name = "grant", skip_all, fields(object))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Permission(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::Role(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::RolePermission(sub_isi) => sub_isi.execute(authority, state_transaction),
        }
    }
}

impl Execute for RevokeBox {
    #[iroha_logger::log(name = "revoke", skip_all, fields(object))]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            Self::Permission(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::Role(sub_isi) => sub_isi.execute(authority, state_transaction),
            Self::RolePermission(sub_isi) => sub_isi.execute(authority, state_transaction),
        }
    }
}

pub mod prelude {
    //! Re-export important traits and types for glob import `(::*)`
    pub use super::*;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iroha_test_samples::{
        gen_account_in, ALICE_ID, SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
    };
    use tokio::test;

    use super::*;
    use crate::{
        block::ValidBlock,
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
        tx::AcceptTransactionFail,
    };

    fn state_with_test_domains(kura: &Arc<Kura>) -> Result<State> {
        let world = World::with([], [], []);
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura.clone(), query_handle);
        let asset_definition_id = "rose#wonderland".parse()?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        Register::domain(Domain::new("wonderland".parse()?))
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        Register::asset_definition(AssetDefinition::new(asset_definition_id))
            .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit();
        Ok(state)
    }

    // TODO(nft): #[test]
    // async fn asset_store() -> Result<()> {
    //     let kura = Kura::blank_kura_for_testing();
    //     let state = state_with_test_domains(&kura)?;
    //     let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
    //         .as_ref()
    //         .header();
    //     let mut state_block = state.block(block_header);
    //     let mut state_transaction = state_block.transaction();
    //     let account_id = ALICE_ID.clone();
    //     let asset_definition_id = "rose#wonderland".parse()?;
    //     let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    //     let key = "Bytes".parse::<Name>()?;
    //     SetKeyValue::asset(asset_id.clone(), key.clone(), vec![1_u32, 2_u32, 3_u32])
    //         .execute(&account_id, &mut state_transaction)?;
    //     state_transaction.apply();
    //     state_block.commit();
    //     let asset = state.view().world.asset(&asset_id)?;
    //     let AssetValue::Store(store) = &asset.value else {
    //         panic!("expected store asset");
    //     };
    //     let value = store.get(&key).cloned();
    //     assert_eq!(value, Some(vec![1_u32, 2_u32, 3_u32,].into()));
    //     Ok(())
    // }

    #[test]
    async fn account_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let key = "Bytes".parse::<Name>()?;
        SetKeyValue::account(account_id.clone(), key.clone(), vec![1_u32, 2_u32, 3_u32])
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit();
        let bytes = state
            .view()
            .world
            .map_account(&account_id, |account| account.metadata().get(&key).cloned())?;
        assert_eq!(bytes, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }

    #[test]
    async fn asset_definition_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let definition_id = "rose#wonderland".parse::<AssetDefinitionId>()?;
        let account_id = ALICE_ID.clone();
        let key = "Bytes".parse::<Name>()?;
        SetKeyValue::asset_definition(
            definition_id.clone(),
            key.clone(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit();
        let value = state
            .view()
            .world
            .asset_definition(&definition_id)?
            .metadata()
            .get(&key)
            .cloned();
        assert_eq!(value, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }

    #[test]
    async fn domain_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let domain_id = "wonderland".parse::<DomainId>()?;
        let account_id = ALICE_ID.clone();
        let key = "Bytes".parse::<Name>()?;
        SetKeyValue::domain(domain_id.clone(), key.clone(), vec![1_u32, 2_u32, 3_u32])
            .execute(&account_id, &mut state_transaction)?;
        state_transaction.apply();
        state_block.commit();
        let bytes = state
            .view()
            .world
            .domain(&domain_id)?
            .metadata()
            .get(&key)
            .cloned();
        assert_eq!(bytes, Some(vec![1_u32, 2_u32, 3_u32,].into()));
        Ok(())
    }

    #[test]
    async fn executing_unregistered_trigger_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let trigger_id = "test_trigger_id".parse()?;

        assert!(matches!(
            ExecuteTrigger::new(trigger_id)
                .execute(&account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::Find(_)
        ));

        state_transaction.apply();
        state_block.commit();

        Ok(())
    }

    #[test]
    async fn unauthorized_trigger_execution_should_return_error() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        let (fake_account_id, _fake_account_keypair) = gen_account_in("wonderland");
        let trigger_id = "test_trigger_id".parse::<TriggerId>()?;

        // register fake account
        let register_account = Register::account(Account::new(fake_account_id.clone()));
        register_account.execute(&account_id, &mut state_transaction)?;

        // register the trigger
        let register_trigger = Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(account_id.clone()),
            ),
        ));

        register_trigger.execute(&account_id, &mut state_transaction)?;

        // execute with the valid account
        ExecuteTrigger::new(trigger_id.clone()).execute(&account_id, &mut state_transaction)?;

        // execute with the fake account
        assert!(matches!(
            ExecuteTrigger::new(trigger_id)
                .execute(&fake_account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::InvariantViolation(_)
        ));

        state_transaction.apply();
        state_block.commit();

        Ok(())
    }

    #[test]
    async fn not_allowed_to_register_genesis_domain_or_account() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let block_header = ValidBlock::new_dummy(&KeyPair::random().into_parts().1)
            .as_ref()
            .header();
        let mut state_block = state.block(block_header);
        let mut state_transaction = state_block.transaction();
        let account_id = ALICE_ID.clone();
        assert!(matches!(
            Register::domain(Domain::new("genesis".parse()?))
                .execute(&account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::InvariantViolation(_)
        ));
        let register_account = Register::account(Account::new(SAMPLE_GENESIS_ACCOUNT_ID.clone()));
        assert!(matches!(
            register_account
                .execute(&account_id, &mut state_transaction)
                .expect_err("Error expected"),
            Error::InvariantViolation(_)
        ));
        state_transaction.apply();
        state_block.commit();

        Ok(())
    }

    #[test]
    async fn transaction_signed_by_genesis_account_should_be_rejected() -> Result<()> {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
        let kura = Kura::blank_kura_for_testing();
        let state = state_with_test_domains(&kura)?;
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction)
        };

        let tx = TransactionBuilder::new(chain_id.clone(), SAMPLE_GENESIS_ACCOUNT_ID.clone())
            .with_instructions::<InstructionBox>([])
            .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
        assert!(matches!(
            AcceptedTransaction::accept(tx, &chain_id, max_clock_drift, tx_limits),
            Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature)
        ));
        Ok(())
    }
}
