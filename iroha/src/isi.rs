use crate::{account, asset, domain, peer, prelude::*, wsv::WorldStateView};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, peer::isi::*};
}

/// Iroha provides a library of smart contracts called **I**roha **S**pecial **I**nstructions (ISI).
/// To execute logic on the ledger, these smart contracts can be invoked via either transactions
/// or registered event listeners.
/// This trait represents API which every ISI should be aligned with.
pub trait Instruction {
    /// To execute the instruction this method implementation supplied with a mutable reference
    /// to `WorldStateView`. It's responsibility of the instruction to keep `WSV` in a consistent
    /// state and return `Err` in case of errors.
    fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String>;
}

///
#[derive(Clone, Debug, PartialEq, Io, Encode, Decode)]
pub enum Contract {
    AddSignatory(account::isi::AddSignatory),
    AppendRole(account::isi::AppendRole),
    CreateAccount(account::isi::CreateAccount),
    CreateRole(account::isi::CreateRole),
    AddAssetQuantity(asset::isi::AddAssetQuantity),
    TransferAsset(asset::isi::TransferAsset),
    CreateAsset(asset::isi::CreateAsset),
    CreateDomain(domain::isi::CreateDomain),
    AddPeer(peer::isi::AddPeer),
}

impl Contract {
    pub fn invoke(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
        use Contract::*;
        match self {
            AddAssetQuantity(instruction) => instruction.execute(world_state_view),
            CreateAccount(instruction) => instruction.execute(world_state_view),
            CreateDomain(instruction) => instruction.execute(world_state_view),
            TransferAsset(instruction) => instruction.execute(world_state_view),
            _ => Err("Instruction is not supported yet.".to_string()),
        }
    }
}

pub enum Relation {
    /// Belongs to account with defined identification.
    /// For example we can fill a map of accounts to assets by this relation.
    OwnedBy(Id),
    GoingTo(Id),
}

/// This trait should be implemented for commands with `account_id` field.
/// Marking your command with `impl` of this trait you provide an ability
/// to retrieve information about relation to an account.
pub trait Property {
    fn relations(&self) -> Vec<Relation>;
}

impl Property for Contract {
    //TODO: implement
    fn relations(&self) -> Vec<Relation> {
        use Relation::*;
        match self {
            Contract::TransferAsset(instruction) => {
                let instruction = instruction.clone();
                vec![
                    GoingTo(instruction.destination_account_id),
                    OwnedBy(instruction.source_account_id),
                ]
            }
            _ => Vec::new(),
        }
    }
}

pub trait Assetibility {
    fn assets(&self) -> Vec<Id>;
}

impl Assetibility for Contract {
    //TODO: implement
    fn assets(&self) -> Vec<Id> {
        match self {
            Contract::TransferAsset(instruction) => {
                let instruction = instruction.clone();
                vec![instruction.asset_id]
            }
            _ => Vec::new(),
        }
    }
}
