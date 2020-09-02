//! This library contains basic Iroha Special Instructions.

use super::{prelude::*, IdBox, IdentifiableBox, ValueBox};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Sized structure for all possible Instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum InstructionBox {
    /// `Add` variant.
    Add(AddBox),
    /// `Subtract` variant.
    Subtract(SubtractBox),
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
    /// `Greater` variant.
    Greater(GreaterBox),
    /// `Pair` variant.
    Pair(Box<Pair>),
    /// `Sequence` variant.
    Sequence(Box<Sequence>),
    /// `Fail` variant.
    Fail(Box<Fail>),
    /// `Not` variant.
    Not(Box<Not>),
}

/// Sized structure for all possible Sets.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SetBox {
    /// Object to set as a value.
    pub object: ValueBox,
}

/// Sized structure for all possible Adds.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AddBox {
    /// Object to add.
    pub object: ValueBox,
    /// Object to add to.
    pub destination_id: IdBox,
}

/// Sized structure for all possible Subtracts.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SubtractBox {
    object: ValueBox,
    destination_id: IdBox,
}

/// Sized structure for all possible Registers.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct RegisterBox {
    /// Object to register on `destination_id`.
    pub object: IdentifiableBox,
    /// Identification of destination object.
    pub destination_id: IdBox,
}

/// Sized structure for all possible Unregisters.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct UnregisterBox {
    /// Object to unregister from `destination_id`.
    pub object: IdentifiableBox,
    /// Identification of destination object.
    pub destination_id: IdBox,
}

/// Sized structure for all possible Mints.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct MintBox {
    /// Object to mint.
    pub object: ValueBox,
    /// Entity to mint to.
    pub destination_id: IdBox,
}

/// Sized structure for all possible Burns.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BurnBox {
    /// Object to burn.
    pub object: ValueBox,
    /// Entity to burn from.
    pub destination_id: IdBox,
}

/// Sized structure for all possible Transfers.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct TransferBox {
    /// Entity to transfer from.
    pub source_id: IdBox,
    /// Object to transfer.
    pub object: ValueBox,
    /// Entity to transfer to.
    pub destination_id: IdBox,
}

/// Sized structure for all possible Greaters.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct GreaterBox {
    /// Left hand side Object to compare with.
    pub left: ValueBox,
    /// Right hand side Object to compare.
    pub right: ValueBox,
}

/// Generic instruction to set value to the object.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Set<O>
where
    O: Value,
{
    /// Object to equate.
    pub object: O,
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
pub struct Subtract<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Object which should be subtracted.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
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
    O: Value,
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
    O: Value,
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
    /// Left hand side Object to compare with.
    pub left: L,
    /// Right hand side Object to compare.
    pub right: R,
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
    pub condition: InstructionBox,
    /// Instruction to be executed if condition pass.
    pub then: InstructionBox,
    /// Optional instruction to be executed if condition fail.
    pub otherwise: Option<InstructionBox>,
}

/// Utilitary instruction to fail execution and submit an error `message`.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Fail {
    /// Message to submit.
    pub message: String,
}

/// Composite instruction to inverse result of the another instruction.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Not {
    /// Instruction to invert result of.
    pub instruction: InstructionBox,
}

/// Marker trait for Iroha Special Instructions.
//TODO: develop derive macro for this trait
pub trait Instruction: Debug + Clone {}

impl<O> Instruction for Set<O> where O: Value {}
impl<D, O> Instruction for Add<D, O>
where
    D: Identifiable,
    O: Value,
{
}
impl<D, O> Instruction for Subtract<D, O>
where
    D: Identifiable,
    O: Value,
{
}
//TODO: Replace instruction box with trigger
impl Instruction for Register<Peer, InstructionBox> {}
impl Instruction for Register<Peer, Domain> {}
impl Instruction for Register<Domain, Account> {}
impl Instruction for Register<Domain, AssetDefinition> {}
impl<O> Instruction for Mint<Asset, O> where O: Value {}
impl<O> Instruction for Burn<Asset, O> where O: Value {}
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

impl AddBox {
    fn new<D: Identifiable, O: Into<ValueBox>>(
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        AddBox {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl SubtractBox {
    fn new<D: Identifiable, O: Into<ValueBox>>(
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        SubtractBox {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl RegisterBox {
    fn new<D: Identifiable, O: Into<IdentifiableBox>>(
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        RegisterBox {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl UnregisterBox {
    fn new<D: Identifiable, O: Into<IdentifiableBox>>(
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        UnregisterBox {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl MintBox {
    fn new<D: Identifiable, O: Into<ValueBox>>(
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        MintBox {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl BurnBox {
    fn new<D: Identifiable, O: Into<ValueBox>>(
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        BurnBox {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl TransferBox {
    fn new<S: Identifiable, O: Into<ValueBox>, D: Identifiable>(
        source_id: <S as Identifiable>::Id,
        object: O,
        destination_id: <D as Identifiable>::Id,
    ) -> Self {
        TransferBox {
            source_id: source_id.into(),
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl GreaterBox {
    fn new<LV: Into<ValueBox>, RV: Into<ValueBox>>(left: LV, right: RV) -> Self {
        GreaterBox {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl<O> Set<O>
where
    O: Value,
{
    /// Default `Set` constructor.
    pub fn new(object: O) -> Self {
        Set { object }
    }
}

//TODO: change to value + value
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

impl<D, O> Subtract<D, O>
where
    D: Identifiable,
    O: Value,
{
    /// Default `Subtract` constructor.
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Subtract {
            object,
            destination_id,
        }
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

impl<D, O> Burn<D, O>
where
    D: Identifiable,
    O: Value,
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
    pub fn new<LI: Into<InstructionBox>, RI: Into<InstructionBox>>(
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
    pub fn new(instructions: Vec<InstructionBox>) -> Self {
        Sequence { instructions }
    }
}

impl If {
    /// Default `If` constructor.
    pub fn new<C: Into<InstructionBox>, T: Into<InstructionBox>>(condition: C, then: T) -> Self {
        If {
            condition: condition.into(),
            then: then.into(),
            otherwise: None,
        }
    }
    /// `If` constructor with `otherwise` instruction.
    pub fn with_otherwise<
        C: Into<InstructionBox>,
        T: Into<InstructionBox>,
        O: Into<InstructionBox>,
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

impl Not {
    /// Default `Not` constructor.
    pub fn new<I: Into<InstructionBox>>(instruction: I) -> Self {
        Not {
            instruction: instruction.into(),
        }
    }
}

impl<D, O> From<Add<D, O>> for InstructionBox
where
    D: Into<IdentifiableBox> + Identifiable,
    O: Into<ValueBox> + Value,
{
    fn from(instruction: Add<D, O>) -> InstructionBox {
        InstructionBox::Add(AddBox::new::<D, O>(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<D, O> From<Subtract<D, O>> for InstructionBox
where
    D: Into<IdentifiableBox> + Identifiable,
    O: Into<ValueBox> + Value,
{
    fn from(instruction: Subtract<D, O>) -> InstructionBox {
        InstructionBox::Subtract(SubtractBox::new::<D, O>(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<D, O> From<Register<D, O>> for InstructionBox
where
    D: Into<IdentifiableBox> + Identifiable,
    O: Into<IdentifiableBox> + Identifiable,
{
    fn from(instruction: Register<D, O>) -> InstructionBox {
        InstructionBox::Register(RegisterBox::new::<D, O>(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<D, O> From<Unregister<D, O>> for InstructionBox
where
    D: Into<IdentifiableBox> + Identifiable,
    O: Into<IdentifiableBox> + Identifiable,
{
    fn from(instruction: Unregister<D, O>) -> InstructionBox {
        InstructionBox::Unregister(UnregisterBox::new::<D, O>(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<D, O> From<Mint<D, O>> for InstructionBox
where
    D: Into<IdentifiableBox> + Identifiable,
    O: Into<ValueBox> + Value,
{
    fn from(instruction: Mint<D, O>) -> InstructionBox {
        InstructionBox::Mint(MintBox::new::<D, O>(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<D, O> From<Burn<D, O>> for InstructionBox
where
    D: Into<IdentifiableBox> + Identifiable,
    O: Into<ValueBox> + Value,
{
    fn from(instruction: Burn<D, O>) -> InstructionBox {
        InstructionBox::Burn(BurnBox::new::<D, O>(
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<S, O, D, I> From<Transfer<S, O, D>> for InstructionBox
where
    S: Identifiable<Id = I>,
    O: Into<ValueBox> + Value,
    D: Identifiable<Id = I>,
    I: Into<IdBox> + Debug + Ord + Clone,
{
    fn from(instruction: Transfer<S, O, D>) -> InstructionBox {
        InstructionBox::Transfer(TransferBox::new::<S, O, D>(
            instruction.source_id,
            instruction.object,
            instruction.destination_id,
        ))
    }
}

impl<LV, RV> From<Greater<LV, RV>> for InstructionBox
where
    LV: Into<ValueBox> + Value,
    RV: Into<ValueBox> + Value,
{
    fn from(instruction: Greater<LV, RV>) -> InstructionBox {
        InstructionBox::Greater(GreaterBox::new::<LV, RV>(
            instruction.left,
            instruction.right,
        ))
    }
}

impl From<Pair> for InstructionBox {
    fn from(instruction: Pair) -> InstructionBox {
        InstructionBox::Pair(Box::new(instruction))
    }
}

impl From<Sequence> for InstructionBox {
    fn from(instruction: Sequence) -> InstructionBox {
        InstructionBox::Sequence(Box::new(instruction))
    }
}

impl From<If> for InstructionBox {
    fn from(instruction: If) -> InstructionBox {
        InstructionBox::If(Box::new(instruction))
    }
}

impl From<Fail> for InstructionBox {
    fn from(instruction: Fail) -> InstructionBox {
        InstructionBox::Fail(Box::new(instruction))
    }
}

impl From<Not> for InstructionBox {
    fn from(instruction: Not) -> InstructionBox {
        InstructionBox::Not(Box::new(instruction))
    }
}

//TODO: replace instruction box with trigger
impl Identifiable for InstructionBox {
    type Id = Name;
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Add, Burn, Fail, Greater, If, Instruction, InstructionBox, Mint, Not, Pair, Register,
        Sequence, Subtract, Transfer, Unregister,
    };
}
