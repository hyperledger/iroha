//! This module contains enumeration of all legal Iroha Special Instructions `Instruction`
//! and related implementations.

use super::query::IrohaQuery;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, isi::*, peer::isi::*};
}

/// Enumeration of all legal Iroha Special Instructions.
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
    Compose(Box<Instruction>, Box<Instruction>),
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
