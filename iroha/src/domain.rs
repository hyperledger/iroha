use crate::prelude::*;
use std::collections::HashMap;

type Name = String;

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: Name,
    pub accounts: HashMap<<Account as Identifiable>::Id, Account>,
    pub assets: HashMap<<Asset as Identifiable>::Id, Asset>,
}

impl Domain {
    pub fn new(name: Name) -> Self {
        Domain {
            name,
            accounts: HashMap::new(),
            assets: HashMap::new(),
        }
    }
}

impl Identifiable for Domain {
    type Id = Name;
}

pub mod isi {
    use super::*;
    use crate::isi::Register;
    use iroha_derive::*;
    use parity_scale_codec::{Decode, Encode};

    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum DomainInstruction {
        RegisterAccount(Name, Account),
        RegisterAsset(Name, Asset),
    }

    impl DomainInstruction {
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                DomainInstruction::RegisterAccount(domain_name, account) => {
                    Register::new(account.clone(), domain_name.clone()).execute(world_state_view)
                }
                DomainInstruction::RegisterAsset(domain_name, asset) => {
                    Register::new(asset.clone(), domain_name.clone()).execute(world_state_view)
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
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
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

    impl From<Register<Domain, Asset>> for Instruction {
        fn from(instruction: Register<Domain, Asset>) -> Self {
            Instruction::Domain(DomainInstruction::RegisterAsset(
                instruction.destination_id,
                instruction.object,
            ))
        }
    }

    impl Register<Domain, Asset> {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            let asset = self.object.clone();
            world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?
                .accounts
                .get_mut(&asset.id.account_id())
                .expect("Failed to find account.")
                .assets
                .insert(asset.id.clone(), asset);
            Ok(())
        }
    }
}
