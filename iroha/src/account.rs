//! This module contains `Account` structure, it's implementation and related traits and
//! instructions implementations.

use crate::{isi::prelude::*, prelude::*};
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
};

/// Account entity is an authority which is used to execute `Iroha Special Insturctions`.
#[derive(Debug, Clone, Encode, Decode)]
pub struct Account {
    /// An Identification of the `Account`.
    pub id: Id,
    /// Asset's in this `Account`.
    pub assets: BTreeMap<<Asset as Identifiable>::Id, Asset>,
    signatories: Vec<PublicKey>,
}

impl Account {
    /// Constructor of the detached `Account` entity without signatories.
    ///
    /// This method can be used to create an `Account` which should be registered in the domain.
    /// This method should not be used to create an `Account` to work with as a part of the Iroha
    /// State.
    pub fn new(account_name: &str, domain_name: &str) -> Self {
        Account {
            id: Id::new(account_name, domain_name),
            assets: BTreeMap::new(),
            signatories: Vec::new(),
        }
    }

    /// Constructor of the detached `Account` entity with one signatory.
    ///
    /// This method can be used to create an `Account` which should be registered in the domain.
    /// This method should not be used to create an `Account` to work with as a part of the Iroha
    /// State.
    pub fn with_signatory(account_name: &str, domain_name: &str, public_key: PublicKey) -> Self {
        Account {
            id: Id::new(account_name, domain_name),
            assets: BTreeMap::new(),
            signatories: vec![public_key],
        }
    }

    /// Constructor of the `Transfer<Account, Asset, Account>` Iroha Special Instruction.
    pub fn transfer_asset_to(
        &self,
        object: Asset,
        destination_id: Id,
    ) -> Transfer<Account, Asset, Account> {
        Transfer {
            source_id: self.id.clone(),
            object,
            destination_id,
        }
    }

    /// Returns the account signatories list without ability to modify it.
    pub fn read_signatories(&self) -> &Vec<PublicKey> {
        &self.signatories
    }
}

/// Identification of an Account. Consists of Account's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha::account::Id;
///
/// let id = Id::new("user", "company");
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, std::hash::Hash, Encode, Decode)]
pub struct Id {
    /// Account's name.
    pub name: String,
    /// Domain's name.
    pub domain_name: String,
}

impl Id {
    /// `Id` constructor used to easily create an `Id` from two string slices - one for the
    /// account's name, another one for the container's name.
    pub fn new(name: &str, domain_name: &str) -> Self {
        Id {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
        }
    }
}

impl From<&str> for Id {
    fn from(string: &str) -> Id {
        let vector: Vec<&str> = string.split('@').collect();
        Id {
            name: String::from(vector[0]),
            domain_name: String::from(vector[1]),
        }
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.domain_name)
    }
}

impl Identifiable for Account {
    type Id = Id;
}

/// Iroha Special Instructions module provides `AccountInstruction` enum with all legal types of
/// Account related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AccountInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::permission::isi::PermissionInstruction;
    use iroha_derive::*;
    use std::ops::{AddAssign, SubAssign};

    /// Enumeration of all legal Account related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum AccountInstruction {
        /// Variant of the generic `Transfer` instruction for `Account` --`Asset`--> `Account`.
        TransferAsset(
            <Account as Identifiable>::Id,
            <Account as Identifiable>::Id,
            Asset,
        ),
        /// Variant of the generic `Add` instruction for `PublicKey` --> `Account`.
        AddSignatory(<Account as Identifiable>::Id, PublicKey),
    }

    impl AccountInstruction {
        /// Executes `AccountInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            match self {
                AccountInstruction::TransferAsset(
                    source_account_id,
                    destination_account_id,
                    component,
                ) => Transfer::new(
                    source_account_id.clone(),
                    component.clone(),
                    destination_account_id.clone(),
                )
                .execute(authority, world_state_view),
                AccountInstruction::AddSignatory(account_id, public_key) => {
                    Add::new(*public_key, account_id.clone()).execute(authority, world_state_view)
                }
            }
        }
    }

    /// The purpose of add signatory command is to add an identifier to the account. Such
    /// identifier is a public key of another device or a public key of another user.
    impl AddAssign<PublicKey> for Account {
        fn add_assign(&mut self, signatory: PublicKey) {
            self.signatories.push(signatory);
        }
    }

    impl SubAssign<PublicKey> for Account {
        fn sub_assign(&mut self, signatory: PublicKey) {
            if let Some(index) = self.signatories.iter().position(|key| key == &signatory) {
                self.signatories.remove(index);
            }
        }
    }

    impl Add<Account, PublicKey> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanAddSignatory(authority, self.destination_id.clone(), None)
                .execute(world_state_view)?;
            let public_key = self.object;
            let account = world_state_view
                .account(&self.destination_id)
                .ok_or("Failed to find account.")?;
            *account += public_key;
            Ok(())
        }
    }

    impl From<Add<Account, PublicKey>> for Instruction {
        fn from(instruction: Add<Account, PublicKey>) -> Self {
            Instruction::Account(AccountInstruction::AddSignatory(
                instruction.destination_id,
                instruction.object,
            ))
        }
    }

    impl Transfer<Account, Asset, Account> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanTransferAsset(
                authority,
                self.object.id.definition_id.clone(),
                None,
            )
            .execute(world_state_view)?;
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
                let mut object = self.object.clone();
                object.id.account_id = self.destination_id.clone();
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
                        .insert(transferred_asset.id.clone(), transferred_asset.clone());
                }
            }
            Ok(())
        }
    }

    impl From<Transfer<Account, Asset, Account>> for Instruction {
        fn from(instruction: Transfer<Account, Asset, Account>) -> Self {
            Instruction::Account(AccountInstruction::TransferAsset(
                instruction.source_id,
                instruction.destination_id,
                instruction.object,
            ))
        }
    }
}

/// Query module provides `IrohaQuery` Account related implementations.
pub mod query {
    use super::*;
    use crate::query::IrohaQuery;
    use iroha_derive::*;
    use parity_scale_codec::{Decode, Encode};
    use std::time::SystemTime;

    /// Get information related to the account with a specified `account_id`.
    #[derive(Clone, Debug, Io, IntoQuery, Encode, Decode)]
    pub struct GetAccount {
        /// Identification of an account to find information about.
        pub account_id: <Account as Identifiable>::Id,
    }

    /// Result of the `GetAccount` execution.
    #[derive(Clone, Debug, Encode, Decode)]
    pub struct GetAccountResult {
        /// Account information.
        pub account: Account,
    }

    impl GetAccount {
        /// Build a `GetAccount` query in the form of a `QueryRequest`.
        pub fn build_request(account_id: <Account as Identifiable>::Id) -> QueryRequest {
            let query = GetAccount { account_id };
            QueryRequest {
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
                    .as_millis()
                    .to_string(),
                signature: Option::None,
                query: query.into(),
            }
        }
    }

    impl Query for GetAccount {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::GetAccount(GetAccountResult {
                account: world_state_view
                    .read_account(&self.account_id)
                    .map(Clone::clone)
                    .ok_or("Failed to get an account.")?,
            }))
        }
    }
}
