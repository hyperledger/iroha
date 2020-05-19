//! This module contains `Account` structure, it's implementation and related traits and
//! instructions implementations.

use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;

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
    /// Constructor of the detached `Account` entity.
    ///
    /// This method can be used to create an `Account` which should be registered in the domain.
    /// This method should not be used to create an `Account` to work with as a part of the Iroha
    /// State.
    pub fn new(account_name: &str, container: &str, public_key: PublicKey) -> Self {
        Account {
            id: Id::new(account_name, container),
            assets: BTreeMap::new(),
            signatories: vec![public_key],
        }
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
    /// Container's name.
    pub container: String,
}

impl Id {
    /// `Id` constructor used to easily create an `Id` from two string slices - one for the
    /// account's name, another one for the container's name.
    pub fn new(name: &str, container: &str) -> Self {
        Id {
            name: name.to_string(),
            container: container.to_string(),
        }
    }
}

impl From<&str> for Id {
    fn from(string: &str) -> Id {
        let vector: Vec<&str> = string.split('@').collect();
        Id {
            name: String::from(vector[0]),
            container: String::from(vector[1]),
        }
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
    use crate::isi::prelude::*;
    use iroha_derive::*;
    use std::ops::{Add, Sub};

    /// Enumeration of all legal Account related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum AccountInstruction {
        /// Variant of the generic `Transfer` instruction for `Account` --`Asset`--> `Account`.
        TransferAsset(
            <Account as Identifiable>::Id,
            <Account as Identifiable>::Id,
            Asset,
        ),
    }

    impl AccountInstruction {
        /// Executes `AccountInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                AccountInstruction::TransferAsset(
                    source_account_id,
                    destination_account_id,
                    asset,
                ) => Transfer::new(
                    source_account_id.clone(),
                    asset.clone(),
                    destination_account_id.clone(),
                )
                .execute(world_state_view),
            }
        }
    }

    /// The purpose of add signatory command is to add an identifier to the account. Such
    /// identifier is a public key of another device or a public key of another user.
    impl Add<PublicKey> for Account {
        type Output = Self;

        fn add(mut self, signatory: PublicKey) -> Self {
            self.signatories.push(signatory);
            self
        }
    }

    impl Sub<PublicKey> for Account {
        type Output = Self;

        fn sub(mut self, signatory: PublicKey) -> Self {
            if let Some(index) = self.signatories.iter().position(|key| key == &signatory) {
                self.signatories.remove(index);
            }
            self
        }
    }

    impl Transfer<Account, Asset, Account> {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view
                .account(&self.source_id)
                .ok_or("Failed to find accounts.")?
                .assets
                .get_mut(&self.object.id)
                .expect("Asset not found.")
                .quantity -= self.object.quantity;
            match world_state_view
                .account(&self.destination_id)
                .ok_or("Failed to find destination account.")?
                .assets
                .get_mut(&self.object.id)
            {
                Some(asset) => {
                    asset.quantity += self.object.quantity;
                }
                None => {
                    world_state_view
                        .account(&self.destination_id)
                        .ok_or("Failed to find destination account.")?
                        .assets
                        .insert(self.object.id.clone(), self.object.clone());
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
