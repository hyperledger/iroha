use crate::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, isi::*, peer::isi::*};
}

#[derive(Clone, Debug, Io, Encode, Decode)]
pub enum Instruction {
    Peer(crate::peer::isi::PeerInstruction),
    Domain(crate::domain::isi::DomainInstruction),
    Asset(crate::asset::isi::AssetInstruction),
    Account(crate::account::isi::AccountInstruction),
    Compose(Box<Instruction>, Box<Instruction>),
}

impl Instruction {
    pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
        match self {
            Instruction::Peer(origin) => Ok(origin.execute(world_state_view)?),
            Instruction::Domain(origin) => Ok(origin.execute(world_state_view)?),
            Instruction::Asset(origin) => Ok(origin.execute(world_state_view)?),
            Instruction::Account(origin) => Ok(origin.execute(world_state_view)?),
            Instruction::Compose(left, right) => {
                left.execute(world_state_view)?;
                right.execute(world_state_view)?;
                Ok(())
            }
        }
    }
}

pub struct Add<D, O>
where
    D: Identifiable,
{
    pub object: O,
    pub destination_id: D::Id,
}

impl<D, O> Add<D, O>
where
    D: Identifiable,
{
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Add {
            object,
            destination_id,
        }
    }
}

pub struct Register<D, O>
where
    D: Identifiable,
{
    pub object: O,
    pub destination_id: D::Id,
}

impl<D, O> Register<D, O>
where
    D: Identifiable,
{
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Register {
            object,
            destination_id,
        }
    }
}

pub struct Mint<D, O>
where
    D: Identifiable,
{
    pub object: O,
    pub destination_id: D::Id,
}

impl<D, O> Mint<D, O>
where
    D: Identifiable,
{
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Mint {
            object,
            destination_id,
        }
    }
}

pub struct Transfer<Src: Identifiable, Obj, Dst: Identifiable> {
    pub source_id: Src::Id,
    pub object: Obj,
    pub destination_id: Dst::Id,
}

impl<Src: Identifiable, Obj, Dst: Identifiable> Transfer<Src, Obj, Dst> {
    pub fn new(source_id: Src::Id, object: Obj, destination_id: Dst::Id) -> Self {
        Transfer {
            source_id,
            object,
            destination_id,
        }
    }
}
