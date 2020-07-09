//! This module contains `Account` structure and it's implementation.

use crate::prelude::*;
use iroha::crypto::PublicKey;
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
    use iroha_derive::*;

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
        /// Variant of the generic `Remove` instruction for `PublicKey` --> `Account`.
        RemoveSignatory(<Account as Identifiable>::Id, PublicKey),
    }

    impl From<Add<Account, PublicKey>> for Instruction {
        fn from(instruction: Add<Account, PublicKey>) -> Self {
            Instruction::Account(AccountInstruction::AddSignatory(
                instruction.destination_id,
                instruction.object,
            ))
        }
    }

    impl From<Remove<Account, PublicKey>> for Instruction {
        fn from(instruction: Remove<Account, PublicKey>) -> Self {
            Instruction::Account(AccountInstruction::RemoveSignatory(
                instruction.destination_id,
                instruction.object,
            ))
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
}
