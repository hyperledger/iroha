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
    use iroha_error::{error, Result};

    impl Execute for Mint<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let public_key = self.object.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            account.signatories.push(public_key);
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Account, SignatureCheckCondition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            account.signature_check_condition = self.object;
            Ok(world_state_view)
        }
    }

    impl Execute for Burn<Account, PublicKey> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let public_key = self.object.clone();
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or_else(|| error!("Failed to find account."))?;
            if let Some(index) = account
                .signatories
                .iter()
                .position(|key| key == &public_key)
            {
                let _ = account.signatories.remove(index);
            }
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Account related implementations.
pub mod query {
    use super::*;
    use iroha_derive::*;
    use iroha_error::{error, Result};

    impl Query for FindAllAccounts {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_accounts()
                .into_iter()
                .cloned()
                .collect())
        }
    }

    impl Query for FindAccountById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_account(&self.id)
                .map(Clone::clone)
                .ok_or_else(|| error!("Failed to get an account."))?
                .into())
        }
    }

    impl Query for FindAccountsByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_accounts()
                .into_iter()
                .filter(|account| account.id.name == self.name)
                .cloned()
                .collect())
        }
    }

    impl Query for FindAccountsByDomainName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_accounts()
                .into_iter()
                .filter(|account| account.id.domain_name == self.domain_name)
                .cloned()
                .collect())
        }
    }
}
