//! This library contains basic Iroha Special Instructions.

use super::{expression::EvaluatesTo, prelude::*, IdBox, IdentifiableBox, Value, ValueMarker};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Sized structure for all possible Instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum Instruction {
    /// `Register` variant.
    Register(RegisterBox),
    /// `Unregister` variant.
    Unregister(UnregisterBox),
    /// `Mint` variant.
    Mint(MintBox),
    /// `Burn` variant.
    Burn(BurnBox),
    /// `Transfer` variant.
    Transfer(TransferBox),
    /// `If` variant.
    If(Box<If>),
    /// `Pair` variant.
    Pair(Box<Pair>),
    /// `Sequence` variant.
    Sequence(Box<Sequence>),
    /// `Fail` variant.
    Fail(Box<Fail>),
}

/// Sized structure for all possible Sets.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct SetBox {
    /// Object to set as a value.
    pub object: EvaluatesTo<Value>,
}

/// Sized structure for all possible Registers.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RegisterBox {
    /// Object to register on `destination_id`.
    pub object: EvaluatesTo<IdentifiableBox>,
    /// Identification of destination object.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Unregisters.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct UnregisterBox {
    /// Object to unregister from `destination_id`.
    pub object: EvaluatesTo<IdentifiableBox>,
    /// Identification of destination object.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Mints.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct MintBox {
    /// Object to mint.
    pub object: EvaluatesTo<Value>,
    /// Entity to mint to.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Burns.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct BurnBox {
    /// Object to burn.
    pub object: EvaluatesTo<Value>,
    /// Entity to burn from.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Transfers.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct TransferBox {
    /// Entity to transfer from.
    pub source_id: EvaluatesTo<IdBox>,
    /// Object to transfer.
    pub object: EvaluatesTo<Value>,
    /// Entity to transfer to.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Composite instruction for a pair of instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct Pair {
    /// Left instruction
    pub left_instruction: Instruction,
    /// Right instruction
    pub right_instruction: Instruction,
}

/// Composite instruction for a sequence of instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct Sequence {
    /// Sequence of Iroha Special Instructions to execute.
    pub instructions: Vec<Instruction>,
}

/// Composite instruction for a conditional execution of other instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct If {
    /// Condition to be checked.
    pub condition: EvaluatesTo<bool>,
    /// Instruction to be executed if condition pass.
    pub then: Instruction,
    /// Optional instruction to be executed if condition fail.
    pub otherwise: Option<Instruction>,
}

/// Utilitary instruction to fail execution and submit an error `message`.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct Fail {
    /// Message to submit.
    pub message: String,
}

/// Generic instruction to set value to the object.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Set<O>
where
    O: ValueMarker,
{
    /// Object to equate.
    pub object: O,
}

/// Generic instruction for a registration of an object to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Register<D, O>
where
    O: Identifiable,
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
    O: ValueMarker,
{
    /// Object which should be minted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a burn of an object to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Burn<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Object which should be burned.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Transfer<S: Identifiable, O, D: Identifiable>
where
    O: ValueMarker,
{
    /// Source object `Id`.
    pub source_id: S::Id,
    /// Object which should be transfered.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

impl<O> Set<O>
where
    O: ValueMarker,
{
    /// Default `Set` constructor.
    pub fn new(object: O) -> Self {
        Set { object }
    }
}

impl<D, O> Register<D, O>
where
    D: Identifiable,
    O: Identifiable,
{
    /// Default `Register` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Register {
            object,
            destination_id,
        }
    }
}

impl<D, O> Unregister<D, O>
where
    D: Identifiable,
    O: Identifiable,
{
    /// Default `Register` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Unregister {
            object,
            destination_id,
        }
    }
}

impl<D, O> Mint<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Default `Mint` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Mint {
            object,
            destination_id,
        }
    }
}

impl<D, O> Burn<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Default `Burn` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Burn {
            object,
            destination_id,
        }
    }
}

impl<S, O, D> Transfer<S, O, D>
where
    S: Identifiable,
    D: Identifiable,
    O: ValueMarker,
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

impl RegisterBox {
    /// Default `Register` constructor.
    pub fn new<O: Into<EvaluatesTo<IdentifiableBox>>, D: Into<EvaluatesTo<IdBox>>>(
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl UnregisterBox {
    /// Default `Unregister` constructor.
    pub fn new<O: Into<EvaluatesTo<IdentifiableBox>>, D: Into<EvaluatesTo<IdBox>>>(
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl MintBox {
    /// Default `Mint` constructor.
    pub fn new<O: Into<EvaluatesTo<Value>>, D: Into<EvaluatesTo<IdBox>>>(
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl BurnBox {
    /// Default `Burn` constructor.
    pub fn new<O: Into<EvaluatesTo<Value>>, D: Into<EvaluatesTo<IdBox>>>(
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl TransferBox {
    /// Default `Transfer` constructor.
    pub fn new<
        S: Into<EvaluatesTo<IdBox>>,
        O: Into<EvaluatesTo<Value>>,
        D: Into<EvaluatesTo<IdBox>>,
    >(
        source_id: S,
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl Pair {
    /// Default `Pair` constructor.
    pub fn new<LI: Into<Instruction>, RI: Into<Instruction>>(
        left_instruction: LI,
        right_instruction: RI,
    ) -> Self {
        Pair {
            left_instruction: left_instruction.into(),
            right_instruction: right_instruction.into(),
        }
    }
}

impl Sequence {
    /// Default `Sequence` constructor.
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Sequence { instructions }
    }
}

impl If {
    /// Default `If` constructor.
    pub fn new<C: Into<EvaluatesTo<bool>>, T: Into<Instruction>>(condition: C, then: T) -> Self {
        If {
            condition: condition.into(),
            then: then.into(),
            otherwise: None,
        }
    }
    /// `If` constructor with `otherwise` instruction.
    pub fn with_otherwise<
        C: Into<EvaluatesTo<bool>>,
        T: Into<Instruction>,
        O: Into<Instruction>,
    >(
        condition: C,
        then: T,
        otherwise: O,
    ) -> Self {
        If {
            condition: condition.into(),
            then: then.into(),
            otherwise: Some(otherwise.into()),
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

impl From<RegisterBox> for Instruction {
    fn from(instruction: RegisterBox) -> Instruction {
        Instruction::Register(RegisterBox::new(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl From<UnregisterBox> for Instruction {
    fn from(instruction: UnregisterBox) -> Instruction {
        Instruction::Unregister(UnregisterBox::new(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl From<MintBox> for Instruction {
    fn from(instruction: MintBox) -> Instruction {
        Instruction::Mint(MintBox::new(instruction.object, instruction.destination_id))
    }
}

impl From<BurnBox> for Instruction {
    fn from(instruction: BurnBox) -> Instruction {
        Instruction::Burn(BurnBox::new(instruction.object, instruction.destination_id))
    }
}

impl From<TransferBox> for Instruction {
    fn from(instruction: TransferBox) -> Instruction {
        Instruction::Transfer(TransferBox::new(
            instruction.source_id,
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl From<Pair> for Instruction {
    fn from(instruction: Pair) -> Instruction {
        Instruction::Pair(Box::new(instruction))
    }
}

impl From<Sequence> for Instruction {
    fn from(instruction: Sequence) -> Instruction {
        Instruction::Sequence(Box::new(instruction))
    }
}

impl From<If> for Instruction {
    fn from(instruction: If) -> Instruction {
        Instruction::If(Box::new(instruction))
    }
}

impl From<Fail> for Instruction {
    fn from(instruction: Fail) -> Instruction {
        Instruction::Fail(Box::new(instruction))
    }
}

impl Identifiable for Instruction {
    type Id = Name;
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Burn, BurnBox, Fail, If as IfInstruction, Instruction, Mint, MintBox, Pair, Register,
        RegisterBox, Sequence, Transfer, TransferBox, Unregister, UnregisterBox,
    };
}
