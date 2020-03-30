use crate::{
    account::isi::CreateAccount,
    asset::isi::{AddAssetQuantity, TransferAsset},
    domain::isi::CreateDomain,
    prelude::*,
    wsv::WorldStateView,
};

/// Identification of an Iroha's entites. Consists of Entity's name and Domain's name.
#[derive(Clone, Debug, PartialEq, Eq, std::hash::Hash, serde::Serialize, serde::Deserialize)]
pub struct Id(pub String, pub String);

impl Id {
    pub fn new(entity_name: &str, domain_name: &str) -> Self {
        Id(entity_name.to_string(), domain_name.to_string())
    }
}

/// A command is an intention to change the state of the network.
/// For example, in order to create a new role in Iroha you have to issue Create role command.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub version: u8,
    pub command_type: u8,
    pub payload: Vec<u8>,
}

impl Command {
    pub fn apply(&self, world_state_view: &mut WorldStateView) {
        println!("World state: {:?}", world_state_view.world);
        match self.command_type {
            1 => {
                let instruction: AddAssetQuantity = self.payload.clone().into();
                world_state_view
                    .world
                    .account(&instruction.account_id)
                    .unwrap()
                    .assets
                    .insert(
                        instruction.asset_id.clone(),
                        Asset::new(instruction.asset_id),
                    );
            }
            5 => {
                let instruction: CreateAccount = self.payload.clone().into();
                world_state_view
                    .world
                    .domain(&instruction.domain_name)
                    .unwrap()
                    .accounts
                    .insert(
                        instruction.account_id.clone(),
                        Account::new(instruction.account_id),
                    );
            }
            7 => {
                let instruction: CreateDomain = self.payload.clone().into();
                world_state_view
                    .world
                    .add_domain(Domain::new(instruction.domain_name));
            }
            17 => {
                let instruction: TransferAsset = self.payload.clone().into();
                let asset = world_state_view
                    .world
                    .account(&instruction.source_account_id)
                    .unwrap()
                    .assets
                    .remove(&instruction.asset_id)
                    .unwrap();
                world_state_view
                    .world
                    .account(&instruction.destination_account_id)
                    .unwrap()
                    .assets
                    .insert(instruction.asset_id.clone(), asset);
            }
            _ => (),
        }
    }
}

/// # Example
/// ```
/// use iroha::isi::Command;
///
/// let command_payload = &Command {
///     version: 0,
///     command_type: 0,
///     payload: Vec::new(),
/// };
/// let result: Vec<u8> = command_payload.into();
/// ```
impl std::convert::From<&Command> for Vec<u8> {
    fn from(command_payload: &Command) -> Self {
        bincode::serialize(command_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::isi::Command;
///
/// # let command_payload = &Command {
/// #     version: 0,
/// #     command_type: 0,
/// #     payload: Vec::new(),
/// # };
/// # let result: Vec<u8> = command_payload.into();
/// let command_payload: Command = result.into();
/// ```
impl std::convert::From<Vec<u8>> for Command {
    fn from(command_payload: Vec<u8>) -> Self {
        bincode::deserialize(&command_payload).expect("Failed to deserialize payload.")
    }
}

//TODO[@humb1t:RH2-16]: rename
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

impl Property for Command {
    //TODO: implement
    fn relations(&self) -> Vec<Relation> {
        use Relation::*;
        match &self.command_type {
            17 => {
                let command: TransferAsset = self.payload.clone().into();
                vec![
                    GoingTo(command.destination_account_id),
                    OwnedBy(command.source_account_id),
                ]
            }
            _ => Vec::new(),
        }
    }
}

pub trait Assetibility {
    fn assets(&self) -> Vec<Id>;
}

impl Assetibility for Command {
    //TODO: implement
    fn assets(&self) -> Vec<Id> {
        match &self.command_type {
            17 => {
                let command: TransferAsset = self.payload.clone().into();
                vec![command.asset_id]
            }
            _ => Vec::new(),
        }
    }
}
