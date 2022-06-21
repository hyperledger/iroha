//! This library contains basic Iroha Special Instructions.

#![allow(clippy::len_without_is_empty, clippy::unused_self)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt::Debug;

use derive_more::Display;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{expression::EvaluatesTo, prelude::*, IdBox, RegistrableBox, Value};
use crate::Registered;

/// Sized structure for all possible Instructions.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
pub enum Instruction<const HASH_LENGTH: usize> {
    /// `Register` variant.
    Register(RegisterBox<{ HASH_LENGTH }>),
    /// `Unregister` variant.
    Unregister(UnregisterBox<{ HASH_LENGTH }>),
    /// `Mint` variant.
    Mint(MintBox<{ HASH_LENGTH }>),
    /// `Burn` variant.
    Burn(BurnBox<{ HASH_LENGTH }>),
    /// `Transfer` variant.
    Transfer(TransferBox<{ HASH_LENGTH }>),
    /// `If` variant.
    If(Box<If<{ HASH_LENGTH }>>),
    /// `Pair` variant.
    Pair(Box<Pair<{ HASH_LENGTH }>>),
    /// `Sequence` variant.
    Sequence(SequenceBox<{ HASH_LENGTH }>),
    /// `Fail` variant.
    Fail(FailBox),
    /// `SetKeyValue` variant.
    SetKeyValue(SetKeyValueBox<{ HASH_LENGTH }>),
    /// `RemoveKeyValue` variant.
    RemoveKeyValue(RemoveKeyValueBox<{ HASH_LENGTH }>),
    /// `Grant` variant.
    Grant(GrantBox<{ HASH_LENGTH }>),
    /// `Revoke` variant.
    Revoke(RevokeBox<{ HASH_LENGTH }>),
    /// `ExecuteTrigger` variant.
    ExecuteTrigger(ExecuteTriggerBox),
}

impl<const HASH_LENGTH: usize> Instruction<HASH_LENGTH> {
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
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "SET {key:?} = {value:?} IN {object_id:?}")]
pub struct SetKeyValueBox<const HASH_LENGTH: usize> {
    /// Where to set this key value.
    pub object_id: EvaluatesTo<IdBox, HASH_LENGTH>,
    /// Key string.
    pub key: EvaluatesTo<Name, HASH_LENGTH>,
    /// Object to set as a value.
    pub value: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
}

/// Sized structure for all possible key value pair remove instructions.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "REMOVE {key:?} from {object_id:?}")]
pub struct RemoveKeyValueBox<const HASH_LENGTH: usize> {
    /// From where to remove this key value.
    pub object_id: EvaluatesTo<IdBox, HASH_LENGTH>,
    /// Key string.
    pub key: EvaluatesTo<Name, HASH_LENGTH>,
}

/// Sized structure for all possible Registers.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "REGISTER {object:?}")] // TODO: Display
pub struct RegisterBox<const HASH_LENGTH: usize> {
    /// The object that should be registered, should be uniquely identifiable by its id.
    pub object: EvaluatesTo<RegistrableBox<HASH_LENGTH>, HASH_LENGTH>,
}

/// Sized structure for all possible Unregisters.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "UNREGISTER {object_id:?}")] // TODO: Display
pub struct UnregisterBox<const HASH_LENGTH: usize> {
    /// The id of the object that should be unregistered.
    pub object_id: EvaluatesTo<IdBox, HASH_LENGTH>,
}

/// Sized structure for all possible Mints.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "MINT {object:?} TO {destination_id:?}")] // TODO: Display
pub struct MintBox<const HASH_LENGTH: usize> {
    /// Object to mint.
    pub object: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Entity to mint to.
    pub destination_id: EvaluatesTo<IdBox, HASH_LENGTH>,
}

/// Sized structure for all possible Burns.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "Burn {object:?} from {destination_id:?}")]
pub struct BurnBox<const HASH_LENGTH: usize> {
    /// Object to burn.
    pub object: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Entity to burn from.
    pub destination_id: EvaluatesTo<IdBox, HASH_LENGTH>,
}

/// Sized structure for all possible Transfers.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "TRANSFER {object:?} FROM {source_id:?} TO {destination_id:?}")]
pub struct TransferBox<const HASH_LENGTH: usize> {
    /// Entity to transfer from.
    pub source_id: EvaluatesTo<IdBox, HASH_LENGTH>,
    /// Object to transfer.
    pub object: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Entity to transfer to.
    pub destination_id: EvaluatesTo<IdBox, HASH_LENGTH>,
}

/// Composite instruction for a pair of instructions.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "({left_instruction}, {right_instruction})")]
pub struct Pair<const HASH_LENGTH: usize> {
    /// Left instruction
    pub left_instruction: Instruction<HASH_LENGTH>,
    /// Right instruction
    pub right_instruction: Instruction<HASH_LENGTH>,
}

/// Composite instruction for a sequence of instructions.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "{instructions:?}")] // TODO: map to Display.
pub struct SequenceBox<const HASH_LENGTH: usize> {
    /// Sequence of Iroha Special Instructions to execute.
    pub instructions: Vec<Instruction<HASH_LENGTH>>,
}

/// Composite instruction for a conditional execution of other instructions.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(
    fmt = "IF {condition:?} THEN {then} ELSE {otherwise:?}", // TODO: Display
)]
pub struct If<const HASH_LENGTH: usize> {
    /// Condition to be checked.
    pub condition: EvaluatesTo<bool, HASH_LENGTH>,
    /// Instruction to be executed if condition pass.
    pub then: Instruction<HASH_LENGTH>,
    /// Optional instruction to be executed if condition fail.
    pub otherwise: Option<Instruction<HASH_LENGTH>>,
}

/// Utilitary instruction to fail execution and submit an error `message`.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "FAIL {message}")]
pub struct FailBox {
    /// Message to submit.
    pub message: String,
}

/// Sized structure for all possible Grants.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "GRANT {object:?} TO {destination_id:?}")]
pub struct GrantBox<const HASH_LENGTH: usize> {
    /// Object to grant.
    pub object: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Entity to which to grant this token.
    pub destination_id: EvaluatesTo<IdBox, HASH_LENGTH>,
}

/// Sized structure for all possible Grants.
#[derive(
    Debug, Display, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, IntoSchema,
)]
#[display(fmt = "REVOKE {object:?} FROM {destination_id:?}")]
pub struct RevokeBox<const HASH_LENGTH: usize> {
    /// Object to grant.
    pub object: EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>,
    /// Entity to which to grant this token.
    pub destination_id: EvaluatesTo<IdBox, HASH_LENGTH>,
}

/// Generic instruction to set value to the object.
#[derive(Debug, Display, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Set<O, const HASH_LENGTH: usize>
where
    O: Into<Value<HASH_LENGTH>>,
{
    /// Object to equate.
    pub object: O,
}

/// Generic instruction to set key value at the object.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct SetKeyValue<O, K, V, const HASH_LENGTH: usize>
where
    O: Identifiable,
    K: Into<Value<HASH_LENGTH>>,
    V: Into<Value<HASH_LENGTH>>,
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
pub struct RemoveKeyValue<O, K, const HASH_LENGTH: usize>
where
    O: Identifiable,
    K: Into<Value<HASH_LENGTH>>,
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
    O: Registered,
{
    /// The object that should be registered, should be uniquely identifiable by its id.
    pub object: O::With,
}

/// Generic instruction for an unregistration of an object from the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Unregister<O>
where
    O: Registered,
{
    /// [`Identifiable::Id`] of the object which should be unregistered.
    pub object_id: O::Id,
}

/// Generic instruction for a mint of an object to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Mint<D, O, const HASH_LENGTH: usize>
where
    D: Identifiable,
    O: Into<Value<HASH_LENGTH>>,
{
    /// Object which should be minted.
    pub object: O,
    /// Destination object [`Identifiable::Id`].
    pub destination_id: D::Id,
}

/// Generic instruction for a burn of an object to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Burn<D, O, const HASH_LENGTH: usize>
where
    D: Identifiable,
    O: Into<Value<HASH_LENGTH>>,
{
    /// Object which should be burned.
    pub object: O,
    /// Destination object [`Identifiable::Id`].
    pub destination_id: D::Id,
}

/// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Transfer<S: Identifiable, O, D: Identifiable, const HASH_LENGTH: usize>
where
    O: Into<Value<HASH_LENGTH>>,
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
pub struct Grant<D, O, const HASH_LENGTH: usize>
where
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
{
    /// Object to grant.
    pub object: O,
    /// Entity to which to grant this token.
    pub destination_id: D::Id,
}

/// Generic instruction for revoking permission from an entity.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Revoke<D, O, const HASH_LENGTH: usize>
where
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
{
    /// Object to revoke.
    pub object: O,
    /// Entity which is being revoked this token from.
    pub destination_id: D::Id,
}

/// Instruction to execute specified trigger
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, IntoSchema,
)]
#[display(fmt = "Execute {trigger_id}")]
pub struct ExecuteTriggerBox {
    /// Id of a trigger to execute
    pub trigger_id: TriggerId,
}

impl ExecuteTriggerBox {
    /// Construct [`ExecuteTriggerBox`]
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

impl<O, K, V, const HASH_LENGTH: usize> SetKeyValue<O, K, V, HASH_LENGTH>
where
    O: Identifiable,
    K: Into<Value<{ HASH_LENGTH }>>,
    V: Into<Value<{ HASH_LENGTH }>>,
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

impl<O, K, const HASH_LENGTH: usize> RemoveKeyValue<O, K, HASH_LENGTH>
where
    O: Identifiable,
    K: Into<Value<HASH_LENGTH>>,
{
    /// Construct [`RemoveKeyValue`].
    pub fn new(object_id: O::Id, key: K) -> Self {
        Self { object_id, key }
    }
}

impl<O, const HASH_LENGTH: usize> Set<O, HASH_LENGTH>
where
    O: Into<Value<HASH_LENGTH>>,
{
    /// Construct [`Set`].
    pub fn new(object: O) -> Self {
        Set { object }
    }
}

impl<O> Register<O>
where
    O: Registered,
{
    /// Construct [`Register`].
    pub fn new(object: O::With) -> Self {
        Register { object }
    }
}

impl<O> Unregister<O>
where
    O: Registered,
{
    /// Construct [`Register`].
    pub fn new(object_id: O::Id) -> Self {
        Unregister { object_id }
    }
}

impl<D, O, const HASH_LENGTH: usize> Mint<D, O, HASH_LENGTH>
where
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
{
    /// Construct [`Mint`].
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Mint {
            object,
            destination_id,
        }
    }
}

impl<D, O, const HASH_LENGTH: usize> Burn<D, O, HASH_LENGTH>
where
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
{
    /// Construct [`Burn`].
    pub fn new(object: O, destination_id: D::Id) -> Self {
        Burn {
            object,
            destination_id,
        }
    }
}

impl<S, O, D, const HASH_LENGTH: usize> Transfer<S, O, D, HASH_LENGTH>
where
    S: Registered,
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
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

impl<D, O, const HASH_LENGTH: usize> Grant<D, O, HASH_LENGTH>
where
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
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

impl<D, O, const HASH_LENGTH: usize> Revoke<D, O, HASH_LENGTH>
where
    D: Registered,
    O: Into<Value<HASH_LENGTH>>,
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

impl<const HASH_LENGTH: usize> RevokeBox<HASH_LENGTH> {
    /// Compute the number of contained instructions and expressions.
    #[inline]
    pub fn len(&self) -> usize {
        self.object.len() + self.destination_id.len() + 1
    }

    /// Generic constructor.
    pub fn new<
        P: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        I: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
    >(
        object: P,
        destination_id: I,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            object: object.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> GrantBox<HASH_LENGTH> {
    /// Compute the number of contained instructions and expressions.
    pub fn len(&self) -> usize {
        self.object.len() + self.destination_id.len() + 1
    }

    /// Constructor.
    pub fn new<
        P: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        I: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
    >(
        object: P,
        destination_id: I,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            object: object.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> SetKeyValueBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object_id.len() + self.key.len() + self.value.len() + 1
    }

    /// Construct [`SetKeyValueBox`].
    pub fn new<
        I: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
        K: Into<EvaluatesTo<Name, HASH_LENGTH>>,
        V: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
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

impl<const HASH_LENGTH: usize> RemoveKeyValueBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object_id.len() + self.key.len() + 1
    }

    /// Construct [`RemoveKeyValueBox`].
    pub fn new<
        I: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
        K: Into<EvaluatesTo<Name, HASH_LENGTH>>,
    >(
        object_id: I,
        key: K,
    ) -> Self {
        Self {
            object_id: object_id.into(),
            key: key.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> RegisterBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object.len() + 1
    }

    /// Construct [`Register`].
    pub fn new<O: Into<EvaluatesTo<RegistrableBox, HASH_LENGTH>>>(object: O) -> Self {
        Self {
            object: object.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> UnregisterBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.object_id.len() + 1
    }

    /// Construct [`Unregister`].
    pub fn new<O: Into<EvaluatesTo<IdBox, HASH_LENGTH>>>(object_id: O) -> Self {
        Self {
            object_id: object_id.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> MintBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

    /// Construct [`Mint`].
    pub fn new<
        O: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        D: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
    >(
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> BurnBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + 1
    }

    /// Construct [`Burn`].
    pub fn new<
        O: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        D: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
    >(
        object: O,
        destination_id: D,
    ) -> Self {
        Self {
            object: object.into(),
            destination_id: destination_id.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> TransferBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.destination_id.len() + self.object.len() + self.source_id.len() + 1
    }

    /// Construct [`Transfer`].
    pub fn new<
        S: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
        O: Into<EvaluatesTo<Value<HASH_LENGTH>, HASH_LENGTH>>,
        D: Into<EvaluatesTo<IdBox, HASH_LENGTH>>,
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

impl<const HASH_LENGTH: usize> Pair<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        self.left_instruction.len() + self.right_instruction.len() + 1
    }

    /// Construct [`Pair`].
    pub fn new<LI: Into<Instruction<HASH_LENGTH>>, RI: Into<Instruction<HASH_LENGTH>>>(
        left_instruction: LI,
        right_instruction: RI,
    ) -> Self {
        Pair {
            left_instruction: left_instruction.into(),
            right_instruction: right_instruction.into(),
        }
    }
}

impl<const HASH_LENGTH: usize> SequenceBox<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    pub fn len(&self) -> usize {
        self.instructions
            .iter()
            .map(Instruction::len)
            .sum::<usize>()
            + 1
    }

    /// Construct [`SequenceBox`].
    pub fn new(instructions: Vec<Instruction<HASH_LENGTH>>) -> Self {
        Self { instructions }
    }
}

impl<const HASH_LENGTH: usize> If<HASH_LENGTH> {
    /// Length of contained instructions and queries.
    #[inline]
    pub fn len(&self) -> usize {
        let otherwise = self.otherwise.as_ref().map_or(0, Instruction::len);
        self.condition.len() + self.then.len() + otherwise + 1
    }

    /// Construct [`If`].
    pub fn new<C: Into<EvaluatesTo<bool, HASH_LENGTH>>, T: Into<Instruction<HASH_LENGTH>>>(
        condition: C,
        then: T,
    ) -> Self {
        If {
            condition: condition.into(),
            then: then.into(),
            otherwise: None,
        }
    }
    /// [`If`] constructor with `Otherwise` instruction.
    pub fn with_otherwise<
        C: Into<EvaluatesTo<bool, HASH_LENGTH>>,
        T: Into<Instruction<HASH_LENGTH>>,
        O: Into<Instruction<HASH_LENGTH>>,
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

    const HASH_LENGTH: usize = 32;

    fn if_instruction(
        c: impl Into<ExpressionBox<HASH_LENGTH>>,
        then: Instruction<HASH_LENGTH>,
        otherwise: Option<Instruction<HASH_LENGTH>>,
    ) -> Instruction<HASH_LENGTH> {
        let condition: ExpressionBox<HASH_LENGTH> = c.into();
        let condition = condition.into();
        If {
            condition,
            then,
            otherwise,
        }
        .into()
    }

    fn fail() -> Instruction<HASH_LENGTH> {
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
        let instructions: Vec<Instruction<HASH_LENGTH>> = vec![if_instruction(
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
        let instructions: Vec<Instruction<HASH_LENGTH>> = vec![
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
