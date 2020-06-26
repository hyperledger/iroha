//! This module contains `Domain` structure and related implementations and trait implementations.
use crate::{isi::prelude::*, prelude::*};
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;

type Name = String;

/// Named group of `Account` and `Asset` entities.
#[derive(Debug, Clone, Io, Encode, Decode)]
pub struct Domain {
    /// Domain name, for example company name.
    pub name: Name,
    /// Accounts of the domain.
    pub accounts: BTreeMap<<Account as Identifiable>::Id, Account>,
    /// Assets of the domain.
    pub asset_definitions: BTreeMap<<AssetDefinition as Identifiable>::Id, AssetDefinition>,
}

impl Domain {
    /// Creates new detached `Domain`.
    ///
    /// Should be used for creation of a new `Domain` or while making queries.
    pub fn new(name: Name) -> Self {
        Domain {
            name,
            accounts: BTreeMap::new(),
            asset_definitions: BTreeMap::new(),
        }
    }

    /// Constructor of `Register<Domain, Account>` Iroha Special Instruction.
    pub fn register_account(&self, object: Account) -> Register<Domain, Account> {
        Register {
            object,
            destination_id: self.name.clone(),
        }
    }

    /// Constructor of `Register<Domain, AssetDefinition>` Iroha Special Instruction.
    pub fn register_asset(&self, object: AssetDefinition) -> Register<Domain, AssetDefinition> {
        Register {
            object,
            destination_id: self.name.clone(),
        }
    }
}

impl Identifiable for Domain {
    type Id = Name;
}

/// Iroha Special Instructions module provides `DomainInstruction` enum with all legal types of
/// Domain related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `DomainInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::{isi::Register, permission::isi::PermissionInstruction};

    /// Enumeration of all legal Domain related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum DomainInstruction {
        /// Variant of the generic `Register` instruction for `Account` --> `Domain`.
        RegisterAccount(Name, Account),
        /// Variant of the generic `Register` instruction for `AssetDefinition` --> `Domain`.
        RegisterAsset(Name, AssetDefinition),
    }

    impl DomainInstruction {
        /// Executes `DomainInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            match self {
                DomainInstruction::RegisterAccount(domain_name, account) => {
                    Register::new(account.clone(), domain_name.clone())
                        .execute(authority, world_state_view)
                }
                DomainInstruction::RegisterAsset(domain_name, asset) => {
                    Register::new(asset.clone(), domain_name.clone())
                        .execute(authority, world_state_view)
                }
            }
        }
    }

    impl From<Register<Domain, Account>> for Instruction {
        fn from(instruction: Register<Domain, Account>) -> Self {
            Instruction::Domain(DomainInstruction::RegisterAccount(
                instruction.destination_id,
                instruction.object,
            ))
        }
    }

    impl Register<Domain, Account> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanRegisterAccount(authority, None).execute(world_state_view)?;
            let account = self.object.clone();
            let domain = world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?;
            if domain.accounts.contains_key(&account.id) {
                Err(format!(
                    "Domain already contains an account with an Id: {:?}",
                    &account.id
                ))
            } else {
                domain.accounts.insert(account.id.clone(), account);
                Ok(())
            }
        }
    }

    impl From<Register<Domain, AssetDefinition>> for Instruction {
        fn from(instruction: Register<Domain, AssetDefinition>) -> Self {
            Instruction::Domain(DomainInstruction::RegisterAsset(
                instruction.destination_id,
                instruction.object,
            ))
        }
    }

    impl Register<Domain, AssetDefinition> {
        pub(crate) fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanRegisterAssetDefinition(authority, None)
                .execute(world_state_view)?;
            let asset = self.object.clone();
            world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?
                .asset_definitions
                .insert(asset.id.clone(), asset);
            Ok(())
        }
    }
}
