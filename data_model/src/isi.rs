//! This library contains basic Iroha Special Instructions.

#![allow(clippy::len_without_is_empty, clippy::unused_self)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt::Debug;

use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{expression::EvaluatesTo, prelude::*, IdBox, RegistrableBox, Value, ValueMarker};

/// Sized structure for all possible Instructions.
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
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
    /// `SetKeyValue` variant.
    SetKeyValue(SetKeyValueBox),
    /// `RemoveKeyValue` variant.
    RemoveKeyValue(RemoveKeyValueBox),
    /// `Grant` variant.
    Grant(GrantBox),
    /// `Revoke` variant.
    Revoke(RevokeBox),
    /// `ExecuteTrigger` variant.
    ExecuteTrigger(ExecuteTriggerBox),
}

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
            SetKeyValue(set_key_value) => set_key_value.len(),
            RemoveKeyValue(remove_key_value) => remove_key_value.len(),
            Grant(grant_box) => grant_box.len(),
            Revoke(revoke_box) => revoke_box.len(),
            ExecuteTrigger(execute_trigger) => execute_trigger.len(),
        }
    }
}

/// Sized structure for all possible key value set instructions.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SetKeyValueBox {
    /// Where to set this key value.
    pub object_id: EvaluatesTo<IdBox>,
    /// Key string.
    pub key: EvaluatesTo<Name>,
    /// Object to set as a value.
    pub value: EvaluatesTo<Value>,
}

/// Sized structure for all possible key value pair remove instructions.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct RemoveKeyValueBox {
    /// From where to remove this key value.
    pub object_id: EvaluatesTo<IdBox>,
    /// Key string.
    pub key: EvaluatesTo<Name>,
}

/// Sized structure for all possible Registers.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct RegisterBox {
    /// The object that should be registered, should be uniquely identifiable by its id.
    pub object: EvaluatesTo<RegistrableBox>,
}

/// Sized structure for all possible Unregisters.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct UnregisterBox {
    /// The id of the object that should be unregistered.
    pub object_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Mints.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct MintBox {
    /// Object to mint.
    pub object: EvaluatesTo<Value>,
    /// Entity to mint to.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Burns.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct BurnBox {
    /// Object to burn.
    pub object: EvaluatesTo<Value>,
    /// Entity to burn from.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Transfers.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct TransferBox {
    /// Entity to transfer from.
    pub source_id: EvaluatesTo<IdBox>,
    /// Object to transfer.
    pub object: EvaluatesTo<Value>,
    /// Entity to transfer to.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Composite instruction for a pair of instructions.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Pair {
    /// Left instruction
    pub left_instruction: Instruction,
    /// Right instruction
    pub right_instruction: Instruction,
}

/// Composite instruction for a sequence of instructions.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SequenceBox {
    /// Sequence of Iroha Special Instructions to execute.
    pub instructions: Vec<Instruction>,
}

/// Composite instruction for a conditional execution of other instructions.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct If {
    /// Condition to be checked.
    pub condition: EvaluatesTo<bool>,
    /// Instruction to be executed if condition pass.
    pub then: Instruction,
    /// Optional instruction to be executed if condition fail.
    pub otherwise: Option<Instruction>,
}

/// Utilitary instruction to fail execution and submit an error `message`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct FailBox {
    /// Message to submit.
    pub message: String,
}

/// Sized structure for all possible Grants.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct GrantBox {
    /// Object to grant.
    pub object: EvaluatesTo<Value>,
    /// Entity to which to grant this token.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Sized structure for all possible Grants.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, IntoSchema)]
pub struct RevokeBox {
    /// Object to grant.
    pub object: EvaluatesTo<Value>,
    /// Entity to which to grant this token.
    pub destination_id: EvaluatesTo<IdBox>,
}

/// Generic instruction to set value to the object.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Set<O>
where
    O: ValueMarker,
{
    /// Object to equate.
    pub object: O,
}

/// Generic instruction to set key value at the object.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct SetKeyValue<O, K, V>
where
    O: Identifiable,
    K: ValueMarker,
    V: ValueMarker,
{
    /// Where to set key value.
    pub object_id: O::Id,
    /// Key.
    pub key: K,
    /// Value.
    pub value: V,
}

/// Generic instruction to remove key value at the object.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct RemoveKeyValue<O, K>
where
    O: Identifiable,
    K: ValueMarker,
{
    /// From where to remove key value.
    pub object_id: O::Id,
    /// Key of the pair to remove.
    pub key: K,
}

/// Generic instruction for a registration of an object to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Register<O>
where
    O: Identifiable,
{
    /// The object that should be registered, should be uniquely identifiable by its id.
    pub object: O::RegisteredWith,
}

/// Generic instruction for an unregistration of an object from the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Unregister<O>
where
    O: Identifiable,
{
    /// [`Identifiable::Id`] of the object which should be unregistered.
    pub object_id: O::Id,
}

/// Generic instruction for a mint of an object to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Mint<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Object which should be minted.
    pub object: O,
    /// Destination object [`Identifiable::Id`].
    pub destination_id: D::Id,
}

/// Generic instruction for a burn of an object to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Burn<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Object which should be burned.
    pub object: O,
    /// Destination object [`Identifiable::Id`].
    pub destination_id: D::Id,
}

/// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Transfer<S: Identifiable, O, D: Identifiable>
where
    O: ValueMarker,
{
    /// Source object `Id`.
    pub source_id: S::Id,
    /// Object which should be transferred.
    pub object: O,
    /// Destination object `Id`.
    pub destination_id: D::Id,
}

/// Generic instruction for granting permission to an entity.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Grant<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Object to grant.
    pub object: O,
    /// Entity to which to grant this token.
    pub destination_id: D::Id,
}

/// Generic instruction for revoking permission from an entity.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Revoke<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Object to revoke.
    pub object: O,
    /// Entity which is being revoked this token from.
    pub destination_id: D::Id,
}

/// Instruction to execute specified trigger
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, IntoSchema)]
pub struct ExecuteTriggerBox {
    /// Id of a trigger to execute
    pub trigger_id: TriggerId,
}

impl ExecuteTriggerBox {
    /// Construct [`ExecuteTrigger`]
    #[inline]
    pub const fn new(trigger_id: TriggerId) -> Self {
        Self { trigger_id }
    }

    /// Length of contained instructions and queries.
    #[inline]
    pub const fn len(&self) -> usize {
        1
    }
}

impl<O, K, V> SetKeyValue<O, K, V>
where
    O: Identifiable,
    K: ValueMarker,
    V: ValueMarker,
{
    /// Construct [`SetKeyValue`].
    pub fn new(object_id: O::Id, key: K, value: V) -> Self {
        Self {
            object_id,
            key,
            value,
        }
    }
}

impl<O, K> RemoveKeyValue<O, K>
where
    O: Identifiable,
    K: ValueMarker,
{
    /// Construct [`RemoveKeyValue`].
    pub fn new(object_id: O::Id, key: K) -> Self {
        Self { object_id, key }
    }
}

impl<O> Set<O>
where
    O: ValueMarker,
{
    /// Construct [`Set`].
    pub fn new(object: O) -> Self {
        Set { object }
    }
}

impl<O> Register<O>
where
    O: Identifiable,
{
    /// Construct [`Register`].
    pub fn new(object: O::RegisteredWith) -> Self {
        Register { object }
    }
}

impl<O> Unregister<O>
where
    O: Identifiable,
{
    /// Construct [`Register`].
    pub fn new(object_id: O::Id) -> Self {
        Unregister { object_id }
    }
}

impl<D, O> Mint<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Construct [`Mint`].
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
    /// Construct [`Burn`].
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
    /// Construct [`Transfer`].
    pub fn new(source_id: S::Id, object: O, destination_id: D::Id) -> Self {
        Transfer {
            source_id,
            object,
            destination_id,
        }
    }
}

impl<D, O> Grant<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Constructor.
    #[inline]
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Self {
            object,
            destination_id,
        }
    }
}

impl<D, O> Revoke<D, O>
where
    D: Identifiable,
    O: ValueMarker,
{
    /// Constructor
    #[inline]
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Self {
            object,
            destination_id,
        }
    }
}

impl RevokeBox {
    /// Compute the number of contained instructions and expressions.
    #[inline]
    pub fn len(&self) -> usize {
        self.object.len() + self.destination_id.len() + 1
    }

    /// Generic constructor.
    pub fn new<P: Into<EvaluatesTo<Value>>, I: Into<EvaluatesTo<IdBox>>>(
        object: P,
        destination_id: I,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            object: object.into(),
        }
    }
}

impl GrantBox {
    /// Compute the number of contained instructions and expressions.
    pub fn len(&self) -> usize {
        self.object.len() + self.destination_id.len() + 1
    }

    /// Constructor.
    pub fn new<P: Into<EvaluatesTo<Value>>, I: Into<EvaluatesTo<IdBox>>>(
        object: P,
        destination_id: I,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            object: object.into(),
        }
    }
}

impl SetKeyValueBox {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object_id.len() + self.key.len() + self.value.len() + 1
    }

    /// Construct [`SetKeyValueBox`].
    pub fn new<
        I: Into<EvaluatesTo<IdBox>>,
        K: Into<EvaluatesTo<Name>>,
        V: Into<EvaluatesTo<Value>>,
    >(
        object_id: I,
        key: K,
        value: V,
    ) -> Self {
        Self {
            object_id: object_id.into(),
            key: key.into(),
            value: value.into(),
        }
    }
}

impl RemoveKeyValueBox {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object_id.len() + self.key.len() + 1
    }

    /// Construct [`RemoveKeyValueBox`].
    pub fn new<I: Into<EvaluatesTo<IdBox>>, K: Into<EvaluatesTo<Name>>>(
        object_id: I,
        key: K,
    ) -> Self {
        Self {
            object_id: object_id.into(),
            key: key.into(),
        }
    }
}

impl RegisterBox {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object.len() + 1
    }

    /// Construct [`Register`].
    pub fn new<O: Into<EvaluatesTo<RegistrableBox>>>(object: O) -> Self {
        Self {
            object: object.into(),
        }
    }
}

impl UnregisterBox {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object_id.len() + 1
    }

    /// Construct [`Unregister`].
    pub fn new<O: Into<EvaluatesTo<IdBox>>>(object_id: O) -> Self {
        Self {
            object_id: object_id.into(),
        }
    }
}

impl MintBox {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

    /// Construct [`Mint`].
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
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

    /// Construct [`Burn`].
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
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + self.source_id.len() + 1
    }

    /// Construct [`Transfer`].
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
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.left_instruction.len() + self.right_instruction.len() + 1
    }

    /// Construct [`Pair`].
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

impl SequenceBox {
    /// Length of contained instructions and queries.
    pub fn len(&self) -> usize {
        self.instructions
            .iter()
            .map(Instruction::len)
            .sum::<usize>()
            + 1
    }

    /// Construct [`SequenceBox`].
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self { instructions }
    }
}

impl If {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        let otherwise = self.otherwise.as_ref().map_or(0, Instruction::len);
        self.condition.len() + self.then.len() + otherwise + 1
    }

    /// Construct [`If`].
    pub fn new<C: Into<EvaluatesTo<bool>>, T: Into<Instruction>>(condition: C, then: T) -> Self {
        If {
            condition: condition.into(),
            then: then.into(),
            otherwise: None,
        }
    }
    /// [`If`] constructor with `Otherwise` instruction.
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

impl FailBox {
    /// Length of contained instructions and queries.
    pub const fn len(&self) -> usize {
        1
    }

    /// Construct [`FailBox`].
    pub fn new(message: &str) -> Self {
        Self {
            message: String::from(message),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;

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
            message: String::default(),
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
                value_name: String::default(),
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
                    value_name: String::default(),
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
        Burn, BurnBox, ExecuteTriggerBox, FailBox, Grant, GrantBox, If as IfInstruction,
        Instruction, Mint, MintBox, Pair, Register, RegisterBox, RemoveKeyValue, RemoveKeyValueBox,
        Revoke, RevokeBox, SequenceBox, SetKeyValue, SetKeyValueBox, Transfer, TransferBox,
        Unregister, UnregisterBox,
    };
}
