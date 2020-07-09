//! This module contains `Domain` structure and related implementations.

use crate::prelude::*;
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
}

impl Identifiable for Domain {
    type Id = Name;
}

/// Iroha Special Instructions module provides `DomainInstruction` enum with all legal types of
/// Domain related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `DomainInstruction` variants into generic ISI.
pub mod isi {
    use super::*;

    /// Enumeration of all legal Domain related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum DomainInstruction {
        /// Variant of the generic `Register` instruction for `Account` --> `Domain`.
        RegisterAccount(Name, Account),
        /// Variant of the generic `Register` instruction for `AssetDefinition` --> `Domain`.
        RegisterAsset(Name, AssetDefinition),
    }

    impl From<Register<Domain, Account>> for Instruction {
        fn from(instruction: Register<Domain, Account>) -> Self {
            Instruction::Domain(DomainInstruction::RegisterAccount(
                instruction.destination_id,
                instruction.object,
            ))
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
}
