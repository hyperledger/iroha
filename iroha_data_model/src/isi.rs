//! This library contains basic Iroha Special Instructions.

use super::{expression::EvaluatesTo, prelude::*, IdBox, IdentifiableBox, Value, ValueMarker};
use iroha_derive::FromVariant;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Sized structure for all possible Instructions.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, FromVariant)]
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
    Sequence(SequenceBox),
    /// `Fail` variant.
    Fail(FailBox),
}

#[allow(clippy::len_without_is_empty)]
impl Instruction {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        use Instruction::*;

        match self {
            Register(register_box) => register_box.len(),
            Unregister(unregister_box) => unregister_box.len(),
            Mint(mint_box) => mint_box.len(),
            Burn(burn_box) => burn_box.len(),
            Transfer(transfer_box) => transfer_box.len(),
            If(if_box) => if_box.len(),
            Pair(pair_box) => pair_box.len(),
            Sequence(sequence) => sequence.len(),
            Fail(fail_box) => fail_box.len(),
        }
    }
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
pub struct SequenceBox {
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
pub struct FailBox {
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

#[allow(clippy::len_without_is_empty)]
impl RegisterBox {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl UnregisterBox {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl MintBox {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl BurnBox {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl TransferBox {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + self.source_id.len() + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl Pair {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.left_instruction.len() + self.right_instruction.len() + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl SequenceBox {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        self.instructions
            .iter()
            .map(Instruction::len)
            .sum::<usize>()
            + 1
    }

    /// Default `Sequence` constructor.
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self { instructions }
    }
}

#[allow(clippy::len_without_is_empty)]
impl If {
    /// Calculates number of underneath instructions and expressions
    pub fn len(&self) -> usize {
        let otherwise = self.otherwise.as_ref().map(Instruction::len).unwrap_or(0);
        self.condition.len() + self.then.len() + otherwise + 1
    }

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

#[allow(clippy::len_without_is_empty)]
impl FailBox {
    /// Calculates number of underneath instructions and expressions
    pub const fn len(&self) -> usize {
        1
    }

    /// Default `Fail` constructor.
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl Identifiable for Instruction {
    type Id = Name;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn if_instruction(
        c: impl Into<ExpressionBox>,
        then: Instruction,
        otherwise: Option<Instruction>,
    ) -> Instruction {
        let condition: ExpressionBox = c.into();
        let condition = condition.into();
        If {
            condition,
            then,
            otherwise,
        }
        .into()
    }

    fn fail() -> Instruction {
        FailBox {
            message: Default::default(),
        }
        .into()
    }

    #[test]
    fn len_empty_sequence() {
        let instructions = vec![];

        let inst = Instruction::Sequence(SequenceBox { instructions });
        assert_eq!(inst.len(), 1);
    }

    #[test]
    fn len_if_one_branch() {
        let instructions = vec![if_instruction(
            ContextValue {
                value_name: Default::default(),
            },
            fail(),
            None,
        )];

        let inst = Instruction::Sequence(SequenceBox { instructions });
        assert_eq!(inst.len(), 4);
    }

    #[test]
    fn len_sequence_if() {
        let instructions = vec![
            fail(),
            if_instruction(
                ContextValue {
                    value_name: Default::default(),
                },
                fail(),
                Some(fail()),
            ),
            fail(),
        ];

        let inst = Instruction::Sequence(SequenceBox { instructions });
        assert_eq!(inst.len(), 7);
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Burn, BurnBox, FailBox, If as IfInstruction, Instruction, Mint, MintBox, Pair, Register,
        RegisterBox, SequenceBox, Transfer, TransferBox, Unregister, UnregisterBox,
    };
}
