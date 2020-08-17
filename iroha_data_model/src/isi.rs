//! This library contains basic Iroha Special Instructions.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

use super::prelude::*;
use iroha_crypto::PublicKey;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Sized structure for all possible Instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum InstructionBox {
    /// `RegisterDomain` variant.
    RegisterDomain(Box<Register<Peer, Domain>>),
    /// `UnregisterDomain` variant.
    UnregisterDomain(Box<Unregister<Peer, Domain>>),
    /// `AddSignatory` variant.
    AddSignatory(Box<Add<Account, PublicKey>>),
    /// `RemoveSignatory` variant.
    RemoveSignatory(Box<Remove<Account, PublicKey>>),
    /// `AddTrigger` variant.
    RegisterTrigger(Box<Register<Peer, InstructionBox>>),
    /// `UnregisterTrigger` variant.
    UnregisterTrigger(Box<Unregister<Peer, InstructionBox>>),
    /// `RegisterAccount` variant.
    RegisterAccount(Box<Register<Domain, Account>>),
    /// `UnregisterAccount` variant.
    UnregisterAccount(Box<Unregister<Domain, Account>>),
    /// `RegisterAssetDefinition` variant.
    RegisterAssetDefinition(Box<Register<Domain, AssetDefinition>>),
    /// `UnregisterAssetDefinition` variant.
    UnregisterAssetDefinition(Box<Unregister<Domain, AssetDefinition>>),
    /// `MintU32Asset` variant.
    MintU32Asset(Box<Mint<Asset, u32>>),
    /// `DemintU32Asset` variant.
    DemintU32Asset(Box<Demint<Asset, u32>>),
    /// `TransferU32Asset` variant.
    TransferU32Asset(Box<Transfer<Asset, u32, Asset>>),
    /// `If` variant.
    If(Box<If>),
    /// `GreaterU32` variant.
    Greater(Box<Greater<u32, u32>>),
    /// `Pair` variant.
    Pair(Box<Pair>),
    /// `Sequence` variant.
    Sequence(Box<Sequence>),
    /// `Fail` variant.
    Fail(Box<Fail>),
    /// `Not` variant.
    Not(Box<Not>),
}

/// Generic instruction for an addition of an object to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Add<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be added.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a removal of an object from the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Remove<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be removed.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a registration of an object to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Register<D, O>
where
    D: Identifiable,
{
    /// Object which should be registered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for an unregistration of an object from the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Unregister<D, O>
where
    D: Identifiable,
{
    /// Object which should be unregistered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a mint of an object to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Mint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be minted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a demint of an object to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Demint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be deminted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Transfer<S: Identifiable, O, D: Identifiable>
where
    O: Value,
{
    /// Source object `Id`.
    pub source_id: S::Id,
    /// Object which should be transfered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Mathematical instruction to compare two values and check that left is greater than right.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Greater<L: Value, R: Value> {
    left: L,
    right: R,
}

/// Composite instruction for a pair of instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Pair {
    /// Left instruction
    pub left_instruction: InstructionBox,
    /// Right instruction
    pub right_instruction: InstructionBox,
}

/// Composite instruction for a sequence of instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Sequence {
    /// Sequence of Iroha Special Instructions to execute.
    pub instructions: Vec<InstructionBox>,
}

/// Composite instruction for a conditional execution of other instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct If {
    /// Condition to be checked.
    condition: InstructionBox,
    /// Instruction to be executed if condition pass.
    then: InstructionBox,
    /// Optional instruction to be executed if condition fail.
    otherwise: Option<InstructionBox>,
}

/// Utilitary instruction to fail execution and submit an error `message`.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Fail {
    /// Message to submit.
    message: String,
}

/// Composite instruction to inverse result of the another instruction.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Not {
    instruction: InstructionBox,
}

/// Marker trait for Iroha Special Instructions.
//TODO: develop derive macro for this trait
pub trait Instruction: Debug + Clone {}

impl<D, O> Instruction for Add<D, O>
where
    D: Identifiable,
    O: Value,
{
}

impl<D, O> Instruction for Remove<D, O>
where
    D: Identifiable,
    O: Value,
{
}

impl Instruction for Register<Peer, InstructionBox> {}
impl Instruction for Register<Peer, Domain> {}
impl Instruction for Register<Domain, Account> {}
impl Instruction for Register<Domain, AssetDefinition> {}
impl<O> Instruction for Mint<Asset, O> where O: Value {}
impl<O> Instruction for Demint<Asset, O> where O: Value {}
impl<O> Instruction for Transfer<Asset, O, Asset> where O: Value {}
impl<LV, RV> Instruction for Greater<LV, RV>
where
    LV: Value,
    RV: Value,
{
}
impl Instruction for Pair {}
impl Instruction for Sequence {}
impl Instruction for If {}
impl Instruction for Fail {}
impl Instruction for Not {}

impl<D, O> Add<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Add` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Add {
            object,
            destination_id,
        }
    }
}

impl<D, O> Remove<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Remove` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Remove {
            object,
            destination_id,
        }
    }
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

impl<D, O> Mint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Mint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Mint {
            object,
            destination_id,
        }
    }
}

impl<D, O> Demint<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Demint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Demint {
            object,
            destination_id,
        }
    }
}

impl<S, O, D> Transfer<S, O, D>
where
    S: Identifiable,
    D: Identifiable,
    O: Value,
{
    /// Default `Transfer` constructor.
    pub fn new(source_id: S::Id, object: O, destination_id: D::Id) -> Self {
        Transfer {
            source_id,
            object,
            destination_id,
        }
    }
}

impl<LV, RV> Greater<LV, RV>
where
    LV: Value,
    RV: Value,
{
    /// Default `Greater` constructor.
    pub fn new(left: LV, right: RV) -> Self {
        Greater { left, right }
    }
}

impl Pair {
    /// Default `Pair` constructor.
    pub fn new(left_instruction: InstructionBox, right_instruction: InstructionBox) -> Self {
        Pair {
            left_instruction,
            right_instruction,
        }
    }
}

impl Sequence {
    /// Default `Sequence` constructor.
    pub fn new(instructions: Vec<InstructionBox>) -> Self {
        Sequence { instructions }
    }
}

impl If {
    /// Default `If` constructor.
    pub fn new(condition: InstructionBox, then: InstructionBox) -> Self {
        If {
            condition,
            then,
            otherwise: None,
        }
    }
    /// `If` constructor with `otherwise` instruction.
    pub fn with_otherwise(
        condition: InstructionBox,
        then: InstructionBox,
        otherwise: InstructionBox,
    ) -> Self {
        If {
            condition,
            then,
            otherwise: Some(otherwise),
        }
    }
}

impl Fail {
    /// Default `Fail` constructor.
    pub fn new(message: &str) -> Self {
        Fail {
            message: message.to_string(),
        }
    }
}

impl Not {
    /// Default `Not` constructor.
    pub fn new(instruction: InstructionBox) -> Self {
        Not { instruction }
    }
}

impl From<Transfer<Asset, u32, Asset>> for InstructionBox {
    fn from(instruction: Transfer<Asset, u32, Asset>) -> InstructionBox {
        InstructionBox::TransferU32Asset(Box::new(instruction))
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Add, Demint, Fail, Greater, If, Instruction, InstructionBox, Mint, Not, Pair, Register,
        Remove, Sequence, Transfer,
    };
}
