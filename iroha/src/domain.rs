use crate::prelude::*;
use std::collections::HashMap;

type Name = String;

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: Name,
    pub accounts: HashMap<Id, Account>,
}

impl Domain {
    pub fn new(name: Name) -> Self {
        Domain {
            name,
            accounts: HashMap::new(),
        }
    }
}

pub mod isi {
    use super::*;
    use crate::isi::Contract;
    use iroha_derive::{IntoContract, Io};
    use parity_scale_codec::{Decode, Encode};

    /// The purpose of create domain command is to make new domain in Iroha network, which is a
    /// group of accounts.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct CreateDomain {
        pub domain_name: String,
        pub default_role: String,
    }

    impl Instruction for CreateDomain {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view.add_domain(Domain::new(self.domain_name.clone()));
            Ok(())
        }
    }
}
