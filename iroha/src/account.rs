use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Encode, Decode)]
pub struct Account {
    pub id: Id,
    pub assets: BTreeMap<Id, Asset>,
}

impl Account {
    pub fn new(account_id: Id) -> Self {
        Account {
            id: account_id,
            assets: BTreeMap::new(),
        }
    }
}

pub mod isi {
    use super::*;
    use crate::isi::Contract;
    use iroha_derive::{IntoContract, Io};
    use parity_scale_codec::{Decode, Encode};

    /// The purpose of add signatory command is to add an identifier to the account. Such
    /// identifier is a public key of another device or a public key of another user.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AddSignatory {
        pub account_id: Id,
        pub public_key: [u8; 32],
    }

    /// The purpose of append role command is to promote an account to some created role in the
    /// system, where a role is a set of permissions account has to perform an action (command or
    /// query).
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AppendRole {
        pub account_id: Id,
        pub role_name: String,
    }

    /// The purpose of create account command is to make entity in the system, capable of sending
    /// transactions or queries, storing signatories, personal data and identifiers.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct CreateAccount {
        pub account_id: Id,
        pub domain_name: String,
        pub public_key: [u8; 32],
    }

    impl Instruction for CreateAccount {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view
                .domain(&self.domain_name)
                .ok_or(format!("Failed to get domain: {}", self.domain_name))?
                .accounts
                .insert(
                    self.account_id.clone(),
                    Account::new(self.account_id.clone()),
                );
            Ok(())
        }
    }

    /// The purpose of create role command is to create a new role in the system from the set of
    /// permissions. Combining different permissions into roles, maintainers of Iroha peer network
    /// can create customized security model.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct CreateRole {
        pub role_name: String,
        pub permissions: Vec<String>,
    }
}
