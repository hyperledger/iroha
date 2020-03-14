use crate::model::commands::assets::TransferAsset;

/// A command is an intention to change the state of the network.
/// For example, in order to create a new role in Iroha you have to issue Create role command.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub version: u8,
    pub command_type: u8,
    pub payload: Vec<u8>,
}

/// # Example
/// ```
/// use iroha::model::commands::isi::Command;
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
/// # use iroha::model::commands::isi::Command;
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
    BelongsTo(String),
    GoingTo(String),
    GoingFrom(String),
}

/// This trait should be implemented for commands with `account_id` field.
/// Marking your command with `impl` of this trait you provide an ability
/// to retrieve information about relation to an account.
//TODO[@humb1t:RH2-16]: name is very bad, should be renamed.
pub trait Accountability {
    fn relations(&self) -> Vec<Relation>;
}

impl Accountability for Command {
    //TODO: implement
    fn relations(&self) -> Vec<Relation> {
        use Relation::*;
        match &self.command_type {
            17 => {
                let command: TransferAsset = self.payload.clone().into();
                vec![
                    GoingFrom(command.source_account_id.clone()),
                    GoingTo(command.destination_account_id.clone()),
                    BelongsTo(command.destination_account_id),
                ]
            }
            _ => Vec::new(),
        }
    }
}

pub trait Assetibility {
    fn assets(&self) -> Vec<String>;
}

impl Assetibility for Command {
    //TODO: implement
    fn assets(&self) -> Vec<String> {
        match &self.command_type {
            17 => {
                let command: TransferAsset = self.payload.clone().into();
                vec![command.asset_id]
            }
            _ => Vec::new(),
        }
    }
}
