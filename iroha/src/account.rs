//! This module contains `Account` structure, it's implementation and related traits and
//! instructions implementations.

use crate::prelude::*;
use iroha_data_model::prelude::*;

/// Iroha Special Instructions module provides `AccountInstruction` enum with all possible types of
/// Account related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AccountInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::isi::prelude::*;

    impl Execute for Add<Account, PublicKey> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            //TODO: check permission instruction is just an ISI that will execute Iroha Query!!!
            permission::check(
                authority,
                Box::new(AddSignatory::within_account(self.destination_id)),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            let public_key = self.object.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or("Failed to find account.")?;
            account.signatories.push(public_key);
            Ok(world_state_view)
        }
    }

    impl Execute for Remove<Account, PublicKey> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            //TODO: check permission instruction is just an ISI that will execute Iroha Query!!!
            permission::check(
                authority,
                Box::new(RemoveSignatory::within_account(self.destination_id)),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            let public_key = self.object.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or("Failed to find account.")?;
            if let Some(index) = account
                .signatories
                .iter()
                .position(|key| key == &public_key)
            {
                account.signatories.remove(index);
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Transfer<Account, Asset, Account> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(TransferAsset::with_asset_definition(
                    self.object.id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            let source = world_state_view
                .account(&self.source_id)
                .ok_or("Failed to find accounts.")?
                .assets
                .get_mut(&self.object.id)
                .ok_or("Asset's component was not found.")?;
            let quantity_to_transfer = self.object.quantity;
            if source.quantity < quantity_to_transfer {
                return Err(format!(
                    "Not enough assets: {:?}, {:?}.",
                    source, self.object
                ));
            }
            source.quantity -= quantity_to_transfer;
            let transferred_asset = {
                let mut object = self.object;
                object.id.account_id = self.destination_id;
                object
            };
            match world_state_view
                .account(&self.destination_id)
                .ok_or("Failed to find destination account.")?
                .assets
                .get_mut(&transferred_asset.id)
            {
                Some(destination) => {
                    destination.quantity += quantity_to_transfer;
                }
                None => {
                    world_state_view
                        .account(&self.destination_id)
                        .ok_or("Failed to find destination account.")?
                        .assets
                        .insert(transferred_asset.id, transferred_asset);
                }
            }
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Account related implementations.
pub mod query {
    use super::*;
    use crate::query::QueryResult;
    use iroha_derive::log;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// Result of the `FindAllAccounts` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAccountsResult {
        /// Accounts information.
        pub accounts: Vec<Account>,
    }

    impl Query for FindAllAccounts {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAllAccounts(Box::new(
                FindAllAccountsResult {
                    accounts: world_state_view
                        .read_all_accounts()
                        .into_iter()
                        .cloned()
                        .collect(),
                },
            )))
        }
    }

    /// Result of the `FindAccountById` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountByIdResult {
        /// Account information.
        pub account: Account,
    }

    impl Query for FindAccountById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAccountById(Box::new(
                FindAccountByIdResult {
                    account: world_state_view
                        .read_account(&self.id)
                        .map(Clone::clone)
                        .ok_or("Failed to get an account.")?,
                },
            )))
        }
    }
}
