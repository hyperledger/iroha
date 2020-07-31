//! This module contains enumeration of all possible Iroha Special Instructions `Instruction`,
//! generic instruction types and related implementations.
use crate::{prelude::*, query::IrohaQuery};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, isi::*, peer::isi::*};
}

/// Enumeration of all possible Iroha Special Instructions.
#[derive(Clone, Debug, Io, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
pub enum Instruction {
    /// Variant of instructions related to `Peer`.
    Peer(crate::peer::isi::PeerInstruction),
    /// Instruction variants related to `Domain`.
    Domain(crate::domain::isi::DomainInstruction),
    /// Instruction variants related to `Asset`.
    Asset(crate::asset::isi::AssetInstruction),
    /// Instruction variants related to `Account`.
    Account(crate::account::isi::AccountInstruction),
    /// Instruction variants related to `Permission`.
    Permission(crate::permission::isi::PermissionInstruction),
    /// Instruction variants connected to different Iroha Events.
    Event(crate::event::isi::EventInstruction),
    /// This variant of Iroha Special Instruction composes two other instructions into one, and
    /// executes them both.
    Pair(Box<Instruction>, Box<Instruction>),
    /// This variant of Iroha Special Instruction composes several other instructions into one, and
    /// executes them one by one. If some instruction fails - the whole sequence will fail.
    Sequence(Vec<Instruction>),
    /// This variant of Iroha Special Instruction executes the Iroha Query.
    ExecuteQuery(IrohaQuery),
    /// This variant of Iroha Special Instruction executes the first instruction and if it succeeded
    /// executes the second one, if failed - the third one if presented.
    If(Box<Instruction>, Box<Instruction>, Option<Box<Instruction>>),
    /// This variant of Iroha Special Instructions explicitly returns an error with the given
    /// message.
    Fail(String),
    /// This variant of Iroha Special Instructions sends notifications.
    Notify(String),
}

/// Result of `Instruction` execution with changes in `WorldStateView` and output.
#[derive(Debug)]
pub struct InstructionResult {
    /// Instance of `WorldStateView` with changes applied during `Instruction` execution.
    pub world_state_view: WorldStateView,
    output: Output,
}

/// Enumeration of all possible Outputs for `Instruction` execution.
#[derive(Debug)]
pub enum Output {
    /// Variant of instructions output related to `Peer`.
    Peer(crate::peer::isi::Output),
    /// Instruction output variants related to `Domain`.
    Domain(crate::domain::isi::Output),
    /// Instruction output variants related to `Asset`.
    Asset(crate::asset::isi::Output),
    /// Instruction output variants related to `Account`.
    Account(crate::account::isi::Output),
    /// Instruction output variants related to `Permission`.
    Permission(crate::permission::isi::Output),
    /// Instruction output variants connected to different Iroha Events.
    Event(crate::event::isi::Output),
    /// This variant of Iroha Special Instruction output composes two other instructions output into one.
    Pair(Box<Output>, Box<Output>),
    /// This variant of Iroha Special Instruction output composes several other instructions output into one.
    Sequence(Vec<Output>),
    /// Iroha Query result as output.
    ExecuteQuery(QueryResult),
    /// This variant contains `Some` output for executed steps and `None` for skipped.
    If(
        Option<Box<Output>>,
        Option<Box<Output>>,
        Option<Box<Output>>,
    ),
    /// This variant of Iroha Special Instructions output contains an error with the given
    /// message.
    Fail(String),
    /// This variant of Iroha Special Instructions output contains `Result`.
    Notify(Result<(), String>),
}

impl Instruction {
    /// Defines the type of the underlying instructions and executes them on `WorldStateView`.
    pub fn execute(
        &self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<InstructionResult, String> {
        match self {
            Instruction::Peer(origin) => {
                let output = origin.execute(authority, world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: output.world_state_view(),
                    output: Output::Peer(output),
                })
            }
            Instruction::Domain(origin) => {
                let output = origin.execute(authority, world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: output.world_state_view(),
                    output: Output::Domain(output),
                })
            }
            Instruction::Asset(origin) => {
                let output = origin.execute(authority, world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: output.world_state_view(),
                    output: Output::Asset(output),
                })
            }
            Instruction::Account(origin) => {
                let output = origin.execute(authority, world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: output.world_state_view(),
                    output: Output::Account(output),
                })
            }
            Instruction::Permission(origin) => {
                let output = origin.execute(world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: world_state_view.clone(),
                    output: Output::Permission(output),
                })
            }
            Instruction::Event(origin) => {
                let output = origin.execute(authority, world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: output
                        .world_state_view()
                        .unwrap_or_else(|| world_state_view.clone()),
                    output: Output::Event(output),
                })
            }
            Instruction::Pair(left, right) => {
                let left_output = left.execute(authority.clone(), world_state_view)?;
                let right_output = right.execute(authority, &left_output.world_state_view)?;
                Ok(InstructionResult {
                    world_state_view: right_output.world_state_view,
                    output: Output::Pair(
                        Box::new(left_output.output),
                        Box::new(right_output.output),
                    ),
                })
            }
            Instruction::Sequence(sequence) => {
                let mut world_state_view = world_state_view.clone();
                let mut outputs = Vec::new();
                for instruction in sequence {
                    let result = instruction.execute(authority.clone(), &world_state_view)?;
                    world_state_view = result.world_state_view;
                    outputs.push(result.output);
                }
                Ok(InstructionResult {
                    world_state_view,
                    output: Output::Sequence(outputs),
                })
            }
            Instruction::ExecuteQuery(query) => Ok(InstructionResult {
                world_state_view: world_state_view.clone(),
                output: Output::ExecuteQuery(query.execute(world_state_view)?),
            }),
            Instruction::If(condition, then, otherwise) => {
                match condition.execute(authority.clone(), world_state_view) {
                    Ok(result) => {
                        let then_result = then.execute(authority, &result.world_state_view)?;
                        Ok(InstructionResult {
                            world_state_view: then_result.world_state_view,
                            output: Output::If(
                                Some(Box::new(result.output)),
                                Some(Box::new(then_result.output)),
                                None,
                            ),
                        })
                    }
                    Err(_) => {
                        if let Some(otherwise) = otherwise {
                            let else_result = otherwise.execute(authority, world_state_view)?;
                            Ok(InstructionResult {
                                world_state_view: else_result.world_state_view,
                                output: Output::If(None, None, Some(Box::new(else_result.output))),
                            })
                        } else {
                            Ok(InstructionResult {
                                world_state_view: world_state_view.clone(),
                                output: Output::If(None, None, None),
                            })
                        }
                    }
                }
            }
            Instruction::Fail(message) => Err(message.into()),
            Instruction::Notify(message) => {
                println!("Notification: {}", message);
                Ok(InstructionResult {
                    world_state_view: world_state_view.clone(),
                    output: Output::Notify(Ok(())),
                })
            }
        }
    }
}

/// Generic instruction for an addition of an object to the identifiable destination.
pub struct Add<D, O>
where
    D: Identifiable,
{
    /// Object which should be added.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

impl<D, O> Add<D, O>
where
    D: Identifiable,
{
    /// Default `Add` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Add {
            object,
            destination_id,
        }
    }
}

/// Generic instruction for a removal of an object from the identifiable destination.
pub struct Remove<D, O>
where
    D: Identifiable,
{
    /// Object which should be removed.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

impl<D, O> Remove<D, O>
where
    D: Identifiable,
{
    /// Default `Remove` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Remove {
            object,
            destination_id,
        }
    }
}

/// Generic instruction for a registration of an object to the identifiable destination.
pub struct Register<D, O>
where
    D: Identifiable,
{
    /// Object which should be registered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

impl<D, O> Register<D, O>
where
    D: Identifiable,
{
    /// Default `Register` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Register {
            object,
            destination_id,
        }
    }
}

/// Generic instruction for a mint of an object to the identifiable destination.
pub struct Mint<D, O>
where
    D: Identifiable,
{
    /// Object which should be minted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

impl<D, O> Mint<D, O>
where
    D: Identifiable,
{
    /// Default `Mint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Mint {
            object,
            destination_id,
        }
    }
}

/// Generic instruction for a demint of an object to the identifiable destination.
pub struct Demint<D, O>
where
    D: Identifiable,
{
    /// Object which should be deminted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

impl<D, O> Demint<D, O>
where
    D: Identifiable,
{
    /// Default `Demint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Demint {
            object,
            destination_id,
        }
    }
}

/// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
pub struct Transfer<Src: Identifiable, Obj, Dst: Identifiable> {
    /// Source object `Id`.
    pub source_id: Src::Id,
    /// Object which should be transfered.
    pub object: Obj,
    /// Destination object `Id`.
    pub destination_id: Dst::Id,
}

impl<Src: Identifiable, Obj, Dst: Identifiable> Transfer<Src, Obj, Dst> {
    /// Default `Transfer` constructor.
    pub fn new(source_id: Src::Id, object: Obj, destination_id: Dst::Id) -> Self {
        Transfer {
            source_id,
            object,
            destination_id,
        }
    }
}
