//! This library contains basic Iroha Special Instructions.

#![allow(clippy::len_without_is_empty, clippy::unused_self)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt::Debug;

use derive_more::{DebugCustom, Display};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;

pub use self::model::*;
use super::{expression::EvaluatesTo, prelude::*, IdBox, RegistrableBox, Value};
use crate::{seal, Level, Registered};

/// Marker trait designating instruction
pub trait Instruction: Into<InstructionExpr> + seal::Sealed {}

macro_rules! isi {
    ($($meta:meta)* $item:item) => {
        iroha_data_model_derive::model_single! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, getset::Getters)]
            #[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
            #[derive(serde::Deserialize, serde::Serialize)]
            #[derive(iroha_schema::IntoSchema)]
            #[getset(get = "pub")]
            $($meta)*
            $item
        }
    };
}

#[model]
pub mod model {
    pub use transparent::*;

    use super::*;

    /// Sized structure for all possible Instructions.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        EnumDiscriminants,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[strum_discriminants(
        name(InstructionType),
        derive(
            Display,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema
        ),
        cfg_attr(
            any(feature = "ffi_import", feature = "ffi_export"),
            derive(iroha_ffi::FfiType)
        ),
        allow(missing_docs),
        repr(u8)
    )]
    #[ffi_type(opaque)]
    #[allow(missing_docs)]
    pub enum InstructionExpr {
        #[debug(fmt = "{_0:?}")]
        Register(RegisterExpr),
        #[debug(fmt = "{_0:?}")]
        Unregister(UnregisterExpr),
        #[debug(fmt = "{_0:?}")]
        Mint(MintExpr),
        #[debug(fmt = "{_0:?}")]
        Burn(BurnExpr),
        #[debug(fmt = "{_0:?}")]
        Transfer(TransferExpr),
        #[debug(fmt = "{_0:?}")]
        If(Box<ConditionalExpr>),
        #[debug(fmt = "{_0:?}")]
        Pair(Box<PairExpr>),
        #[debug(fmt = "{_0:?}")]
        Sequence(SequenceExpr),
        #[debug(fmt = "{_0:?}")]
        SetKeyValue(SetKeyValueExpr),
        #[debug(fmt = "{_0:?}")]
        RemoveKeyValue(RemoveKeyValueExpr),
        #[debug(fmt = "{_0:?}")]
        Grant(GrantExpr),
        #[debug(fmt = "{_0:?}")]
        Revoke(RevokeExpr),
        #[debug(fmt = "{_0:?}")]
        ExecuteTrigger(ExecuteTriggerExpr),
        #[debug(fmt = "{_0:?}")]
        SetParameter(SetParameterExpr),
        #[debug(fmt = "{_0:?}")]
        NewParameter(NewParameterExpr),
        Upgrade(UpgradeExpr),
        /// `Log` variant.
        Log(LogExpr),

        #[debug(fmt = "{_0:?}")]
        Fail(Fail),
    }

    impl Instruction for InstructionExpr {}

    impl Instruction for SetKeyValueExpr {}
    impl Instruction for RemoveKeyValueExpr {}
    impl Instruction for RegisterExpr {}
    impl Instruction for UnregisterExpr {}
    impl Instruction for MintExpr {}
    impl Instruction for BurnExpr {}
    impl Instruction for TransferExpr {}
    impl Instruction for GrantExpr {}
    impl Instruction for RevokeExpr {}
    impl Instruction for SetParameterExpr {}
    impl Instruction for NewParameterExpr {}
    impl Instruction for UpgradeExpr {}
    impl Instruction for ExecuteTriggerExpr {}
    impl Instruction for LogExpr {}
    impl Instruction for Fail {}

    // Composite instructions
    impl Instruction for ConditionalExpr {}
    impl Instruction for SequenceExpr {}
    impl Instruction for PairExpr {}
}

mod transparent {
    // NOTE: instructions in this module don't have to be made opaque with `model!`
    // because they are never shared between client and server(http)/host(wasm)

    use super::*;
    use crate::validator::Validator;

    /// Generic instruction to set key value at the object.
    #[derive(Debug, Clone)]
    pub struct SetKeyValue<O: Identifiable> {
        /// Where to set key value.
        pub object_id: O::Id,
        /// Key.
        pub key: Name,
        /// Value.
        pub value: Value,
    }

    /// Generic instruction to remove key value at the object.
    #[derive(Debug, Clone)]
    pub struct RemoveKeyValue<O: Identifiable> {
        /// From where to remove key value.
        pub object_id: O::Id,
        /// Key of the pair to remove.
        pub key: Name,
    }

    /// Generic instruction for a registration of an object to the identifiable destination.
    #[derive(Debug, Clone)]
    pub struct Register<O: Registered> {
        /// The object that should be registered, should be uniquely identifiable by its id.
        pub object: O::With,
    }

    /// Generic instruction for an unregistration of an object from the identifiable destination.
    #[derive(Debug, Clone)]
    pub struct Unregister<O: Identifiable> {
        /// [`Identifiable::Id`] of the object which should be unregistered.
        pub object_id: O::Id,
    }

    /// Generic instruction for a mint of an object to the identifiable destination.
    #[derive(Debug, Clone)]
    pub struct Mint<O: Into<Value>, D: Identifiable> {
        /// Object which should be minted.
        pub object: O,
        /// Destination object [`Identifiable::Id`].
        pub destination_id: D::Id,
    }

    /// Generic instruction for a burn of an object to the identifiable destination.
    #[derive(Debug, Clone)]
    pub struct Burn<O: Into<Value>, D: Identifiable> {
        /// Object which should be burned.
        pub object: O,
        /// Destination object [`Identifiable::Id`].
        pub destination_id: D::Id,
    }

    /// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
    #[derive(Debug, Clone)]
    pub struct Transfer<S: Identifiable, O: Into<Value>, D: Identifiable> {
        /// Source object `Id`.
        pub source_id: S::Id,
        /// Object which should be transferred.
        pub object: O,
        /// Destination object `Id`.
        pub destination_id: D::Id,
    }

    /// Generic instruction for granting permission to an entity.
    #[derive(Debug, Clone)]
    pub struct Grant<O: Into<Value>> {
        /// Object to grant.
        pub object: O,
        /// Entity to which to grant this token.
        pub destination_id: AccountId,
    }

    /// Generic instruction for revoking permission from an entity.
    #[derive(Debug, Clone)]
    pub struct Revoke<O: Into<Value>> {
        /// Object to revoke.
        pub object: O,
        /// Entity which is being revoked this token from.
        pub destination_id: AccountId,
    }

    /// Generic instruction for setting a chain-wide config parameter.
    #[derive(Debug, Clone)]
    pub struct SetParameter {
        /// Parameter to be changed.
        pub parameter: Parameter,
    }

    /// Generic instruction for setting a chain-wide config parameter.
    #[derive(Debug, Clone)]
    pub struct NewParameter {
        /// Parameter to be changed.
        pub parameter: Parameter,
    }

    /// Generic instruction for upgrading runtime objects.
    #[derive(Debug, Clone)]
    pub struct Upgrade<O: Into<UpgradableBox>> {
        /// Object to upgrade.
        pub object: O,
    }

    /// Generic instruction for executing specified trigger
    #[derive(Debug, Clone)]
    pub struct ExecuteTrigger {
        /// Id of a trigger to execute
        pub trigger_id: TriggerId,
    }

    /// Generic instruction for logging messages
    #[derive(Debug, Clone)]
    pub struct Log {
        /// Message to be logged
        pub msg: String,
        /// Log level of the message
        pub level: Level,
    }

    impl<O: Identifiable> From<SetKeyValue<O>> for SetKeyValueExpr {
        fn from(source: SetKeyValue<O>) -> Self {
            Self::new(source.object_id.into(), source.key, source.value)
        }
    }

    impl<O: Identifiable> From<RemoveKeyValue<O>> for RemoveKeyValueExpr {
        fn from(source: RemoveKeyValue<O>) -> Self {
            Self::new(source.object_id.into(), source.key)
        }
    }

    impl<O: Registered> From<Register<O>> for RegisterExpr {
        fn from(source: Register<O>) -> Self {
            Self::new(source.object.into())
        }
    }

    impl<O: Identifiable> From<Unregister<O>> for UnregisterExpr {
        fn from(source: Unregister<O>) -> Self {
            Self::new(source.object_id.into())
        }
    }

    impl<O: Into<Value>, D: Identifiable> From<Mint<O, D>> for MintExpr {
        fn from(source: Mint<O, D>) -> Self {
            Self::new(source.object, source.destination_id.into())
        }
    }

    impl<O: Into<Value>, D: Identifiable> From<Burn<O, D>> for BurnExpr {
        fn from(source: Burn<O, D>) -> Self {
            Self::new(source.object, source.destination_id.into())
        }
    }

    impl<S: Identifiable, O: Into<Value>, D: Identifiable> From<Transfer<S, O, D>> for TransferExpr {
        fn from(source: Transfer<S, O, D>) -> Self {
            Self::new(
                source.source_id.into(),
                source.object,
                source.destination_id.into(),
            )
        }
    }

    impl<O: Into<Value>> From<Grant<O>> for GrantExpr {
        fn from(source: Grant<O>) -> Self {
            Self::new(source.object, source.destination_id)
        }
    }

    impl<O: Into<Value>> From<Revoke<O>> for RevokeExpr {
        fn from(source: Revoke<O>) -> Self {
            Self::new(source.object, source.destination_id)
        }
    }

    impl From<SetParameter> for SetParameterExpr {
        fn from(source: SetParameter) -> Self {
            Self::new(source.parameter)
        }
    }

    impl From<NewParameter> for NewParameterExpr {
        fn from(source: NewParameter) -> Self {
            Self::new(source.parameter)
        }
    }

    impl From<Upgrade<Validator>> for UpgradeExpr {
        fn from(source: Upgrade<Validator>) -> Self {
            Self::new(source.object)
        }
    }

    impl From<ExecuteTrigger> for ExecuteTriggerExpr {
        fn from(source: ExecuteTrigger) -> Self {
            Self::new(source.trigger_id)
        }
    }

    impl From<Log> for LogExpr {
        fn from(source: Log) -> Self {
            Self::new(source.level, source.msg)
        }
    }
}

isi! {
    /// Sized structure for all possible on-chain configuration parameters.
    #[derive(Display)]
    #[display(fmt = "SET `{parameter}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `SetParameterExpr` has no trap representation in `EvaluatesTo<Parameter>`
    #[ffi_type(unsafe {robust})]
    pub struct SetParameterExpr {
        /// The configuration parameter being changed.
        #[serde(flatten)]
        pub parameter: EvaluatesTo<Parameter>,
    }
}

isi! {
    /// Sized structure for all possible on-chain configuration parameters when they are first created.
    #[derive(Display)]
    #[display(fmt = "SET `{parameter}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `NewParameterExpr` has no trap representation in `EvaluatesTo<Parameter>`
    #[ffi_type(unsafe {robust})]
    pub struct NewParameterExpr {
        /// The configuration parameter being created.
        #[serde(flatten)]
        pub parameter: EvaluatesTo<Parameter>,
    }
}

isi! {
    /// Sized structure for all possible key value set instructions.
    #[derive(Display)]
    #[display(fmt = "SET `{key}` = `{value}` IN `{object_id}`")]
    #[ffi_type]
    pub struct SetKeyValueExpr {
        /// Where to set this key value.
        #[serde(flatten)]
        pub object_id: EvaluatesTo<IdBox>,
        /// Key string.
        pub key: EvaluatesTo<Name>,
        /// Object to set as a value.
        pub value: EvaluatesTo<Value>,
    }
}

isi! {
    /// Sized structure for all possible key value pair remove instructions.
    #[derive(Display)]
    #[display(fmt = "REMOVE `{key}` from `{object_id}`")]
    #[ffi_type]
    pub struct RemoveKeyValueExpr {
        /// From where to remove this key value.
        #[serde(flatten)]
        pub object_id: EvaluatesTo<IdBox>,
        /// Key string.
        pub key: EvaluatesTo<Name>,
    }
}

isi! {
    /// Sized structure for all possible Registers.
    #[derive(Display)]
    #[display(fmt = "REGISTER `{object}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `RegisterExpr` has no trap representation in `EvaluatesTo<RegistrableBox>`
    #[ffi_type(unsafe {robust})]
    pub struct RegisterExpr {
        /// The object that should be registered, should be uniquely identifiable by its id.
        pub object: EvaluatesTo<RegistrableBox>,
    }
}

isi! {
    /// Sized structure for all possible Unregisters.
    #[derive(Display)]
    #[display(fmt = "UNREGISTER `{object_id}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `UnregisterExpr` has no trap representation in `EvaluatesTo<IdBox>`
    #[ffi_type(unsafe {robust})]
    pub struct UnregisterExpr {
        /// The id of the object that should be unregistered.
        pub object_id: EvaluatesTo<IdBox>,
    }
}

isi! {
    /// Sized structure for all possible Mints.
    #[derive(Display)]
    #[display(fmt = "MINT `{object}` TO `{destination_id}`")]
    #[ffi_type]
    pub struct MintExpr {
        /// Object to mint.
        pub object: EvaluatesTo<Value>,
        /// Entity to mint to.
        pub destination_id: EvaluatesTo<IdBox>,
    }
}

isi! {
    /// Sized structure for all possible Burns.
    #[derive(Display)]
    #[display(fmt = "BURN `{object}` FROM `{destination_id}`")]
    #[ffi_type]
    pub struct BurnExpr {
        /// Object to burn.
        pub object: EvaluatesTo<Value>,
        /// Entity to burn from.
        pub destination_id: EvaluatesTo<IdBox>,
    }
}

isi! {
    /// Sized structure for all possible Transfers.
    #[derive(Display)]
    #[display(fmt = "TRANSFER `{object}` FROM `{source_id}` TO `{destination_id}`")]
    #[ffi_type]
    pub struct TransferExpr {
        /// Entity to transfer from.
        pub source_id: EvaluatesTo<IdBox>,
        /// Object to transfer.
        pub object: EvaluatesTo<Value>,
        /// Entity to transfer to.
        pub destination_id: EvaluatesTo<IdBox>,
    }
}

isi! {
    /// Composite instruction for a pair of instructions.
    #[derive(Display)]
    #[display(fmt = "(`{left_instruction}`, `{right_instruction}`)")]
    #[ffi_type]
    pub struct PairExpr {
        /// Left instruction
        pub left_instruction: InstructionExpr,
        /// Right instruction
        pub right_instruction: InstructionExpr,
    }
}

isi! {
    /// Composite instruction for a sequence of instructions.
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `SequenceExpr` has no trap representation in `Vec<InstructionExpr>`
    #[ffi_type(unsafe {robust})]
    pub struct SequenceExpr {
        /// Sequence of Iroha Special Instructions to execute.
        pub instructions: Vec<InstructionExpr>,
    }
}

impl core::fmt::Display for SequenceExpr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SEQUENCE [")?;
        let mut first = true;
        for instruction in &self.instructions {
            if !first {
                write!(f, ", ")?;
            }
            first = false;

            write!(f, "`{instruction}`")?;
        }
        write!(f, "]")
    }
}

isi! {
    /// Composite instruction for a conditional execution of other instructions.
    #[ffi_type]
    pub struct ConditionalExpr {
        /// Condition to be checked.
        pub condition: EvaluatesTo<bool>,
        /// Instruction to be executed if condition pass.
        pub then: InstructionExpr,
        /// Optional instruction to be executed if condition fail.
        pub otherwise: Option<InstructionExpr>,
    }
}

impl core::fmt::Display for ConditionalExpr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IF `{}` THEN `{}`", self.condition, self.then)?;
        if let Some(otherwise) = &self.otherwise {
            write!(f, " ELSE `{otherwise}`")?;
        }

        Ok(())
    }
}

isi! {
    /// Utilitary instruction to fail execution and submit an error `message`.
    #[derive(Display)]
    #[display(fmt = "FAIL `{message}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `Fail` has no trap representation in `String`
    #[ffi_type(unsafe {robust})]
    pub struct Fail {
        /// Message to submit.
        pub message: String,
    }
}

isi! {
    /// Sized structure for all possible Grants.
    #[derive(Display)]
    #[display(fmt = "GRANT `{object}` TO `{destination_id}`")]
    #[ffi_type]
    pub struct GrantExpr {
        /// Object to grant.
        pub object: EvaluatesTo<Value>,
        /// Account to which to grant this object.
        pub destination_id: EvaluatesTo<AccountId>,
    }
}

isi! {
    /// Sized structure for all possible Grants.
    #[derive(Display)]
    #[display(fmt = "REVOKE `{object}` FROM `{destination_id}`")]
    #[ffi_type]
    pub struct RevokeExpr {
        /// Object to revoke.
        pub object: EvaluatesTo<Value>,
        /// Account to which to revoke this object from.
        pub destination_id: EvaluatesTo<AccountId>,
    }
}

isi! {
    /// Instruction to execute specified trigger
    #[derive(Display)]
    #[display(fmt = "EXECUTE `{trigger_id}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `ExecuteTriggerExpr` has no trap representation in `TriggerId`
    #[ffi_type(unsafe {robust})]
    pub struct ExecuteTriggerExpr {
        /// Id of a trigger to execute
        pub trigger_id: EvaluatesTo<TriggerId>,
    }
}

isi! {
    /// Sized structure for all possible Upgrades.
    #[derive(Display)]
    #[display(fmt = "UPGRADE `{object}`")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `UpgradeExpr` has no trap representation in `EvaluatesTo<RegistrableBox>`
    #[ffi_type(unsafe {robust})]
    pub struct UpgradeExpr {
        /// The object to upgrade.
        pub object: EvaluatesTo<UpgradableBox>,
    }
}

isi! {
    /// Instruction to print logs
    #[derive(Display)]
    #[display(fmt = "LOG({level}): {msg}")]
    #[ffi_type]
    pub struct LogExpr {
        /// Message log level
        #[serde(flatten)]
        pub level: EvaluatesTo<Level>,
        /// Msg to be logged
        pub msg: EvaluatesTo<String>,
    }
}

impl ExecuteTriggerExpr {
    /// Construct [`ExecuteTriggerExpr`]
    pub fn new<I>(trigger_id: I) -> Self
    where
        I: Into<EvaluatesTo<TriggerId>>,
    {
        Self {
            trigger_id: trigger_id.into(),
        }
    }
}

impl RevokeExpr {
    /// Generic constructor.
    pub fn new<P: Into<EvaluatesTo<Value>>, I: Into<EvaluatesTo<AccountId>>>(
        object: P,
        destination_id: I,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            object: object.into(),
        }
    }
}

impl GrantExpr {
    /// Constructor.
    pub fn new<P: Into<EvaluatesTo<Value>>, I: Into<EvaluatesTo<AccountId>>>(
        object: P,
        destination_id: I,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            object: object.into(),
        }
    }
}

impl SetKeyValueExpr {
    /// Construct [`SetKeyValueExpr`].
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

impl RemoveKeyValueExpr {
    /// Construct [`RemoveKeyValueExpr`].
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

impl RegisterExpr {
    /// Construct [`Register`].
    pub fn new<O: Into<EvaluatesTo<RegistrableBox>>>(object: O) -> Self {
        Self {
            object: object.into(),
        }
    }
}

impl UnregisterExpr {
    /// Construct [`Unregister`].
    pub fn new<O: Into<EvaluatesTo<IdBox>>>(object_id: O) -> Self {
        Self {
            object_id: object_id.into(),
        }
    }
}

impl MintExpr {
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

impl BurnExpr {
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

impl TransferExpr {
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

impl PairExpr {
    /// Construct [`Pair`].
    pub fn new<LI: Into<InstructionExpr>, RI: Into<InstructionExpr>>(
        left_instruction: LI,
        right_instruction: RI,
    ) -> Self {
        PairExpr {
            left_instruction: left_instruction.into(),
            right_instruction: right_instruction.into(),
        }
    }
}

impl SequenceExpr {
    /// Construct [`SequenceExpr`].
    pub fn new(instructions: impl IntoIterator<Item = InstructionExpr>) -> Self {
        Self {
            instructions: instructions.into_iter().collect(),
        }
    }
}

impl ConditionalExpr {
    /// Construct [`If`].
    pub fn new<C: Into<EvaluatesTo<bool>>, T: Into<InstructionExpr>>(
        condition: C,
        then: T,
    ) -> Self {
        Self {
            condition: condition.into(),
            then: then.into(),
            otherwise: None,
        }
    }
    /// [`If`] constructor with `Otherwise` instruction.
    pub fn with_otherwise<
        C: Into<EvaluatesTo<bool>>,
        T: Into<InstructionExpr>,
        O: Into<InstructionExpr>,
    >(
        condition: C,
        then: T,
        otherwise: O,
    ) -> Self {
        Self {
            condition: condition.into(),
            then: then.into(),
            otherwise: Some(otherwise.into()),
        }
    }
}

impl Fail {
    /// Construct [`Fail`].
    pub fn new(message: &str) -> Self {
        Self {
            message: String::from(message),
        }
    }
}

impl SetParameterExpr {
    /// Construct [`SetParameterExpr`].
    pub fn new<P: Into<EvaluatesTo<Parameter>>>(parameter: P) -> Self {
        Self {
            parameter: parameter.into(),
        }
    }
}

impl NewParameterExpr {
    /// Construct [`NewParameterExpr`].
    pub fn new<P: Into<EvaluatesTo<Parameter>>>(parameter: P) -> Self {
        Self {
            parameter: parameter.into(),
        }
    }
}

impl UpgradeExpr {
    /// Construct [`UpgradeExpr`].
    pub fn new<O: Into<EvaluatesTo<UpgradableBox>>>(object: O) -> Self {
        Self {
            object: object.into(),
        }
    }
}

impl LogExpr {
    /// Construct [`LogExpr`]
    pub fn new<L: Into<EvaluatesTo<Level>>, M: Into<EvaluatesTo<String>>>(
        level: L,
        msg: M,
    ) -> Self {
        Self {
            level: level.into(),
            msg: msg.into(),
        }
    }
}

pub mod error {
    //! Module containing errors that can occur during instruction evaluation

    #[cfg(not(feature = "std"))]
    use alloc::{boxed::Box, format, string::String, vec::Vec};
    use core::fmt::Debug;

    use derive_more::Display;
    use iroha_data_model_derive::model;
    use iroha_macro::FromVariant;
    use iroha_primitives::fixed::FixedPointOperationError;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};

    pub use self::model::*;
    use super::InstructionType;
    use crate::{
        asset::AssetValueType,
        evaluate, metadata,
        query::error::{FindError, QueryExecutionFail},
        IdBox, NumericValue, Value,
    };

    #[model]
    pub mod model {
        use serde::{Deserialize, Serialize};

        use super::*;
        use crate::asset::AssetDefinitionId;

        /// Instruction execution error type
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[ignore_extra_doc_attributes]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        // TODO: Only temporarily opaque because of InstructionExecutionError::Repetition
        #[ffi_type(opaque)]
        pub enum InstructionExecutionError {
            /// Instruction does not adhere to Iroha DSL specification
            Evaluate(#[cfg_attr(feature = "std", source)] InstructionEvaluationError),
            /// Query failed
            Query(#[cfg_attr(feature = "std", source)] QueryExecutionFail),
            /// Conversion Error: {0}
            Conversion(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// Entity missing
            Find(#[cfg_attr(feature = "std", source)] Box<FindError>),
            /// Repeated instruction
            Repetition(#[cfg_attr(feature = "std", source)] RepetitionError),
            /// Mintability assertion failed
            Mintability(#[cfg_attr(feature = "std", source)] MintabilityError),
            /// Illegal math operation
            Math(#[cfg_attr(feature = "std", source)] MathError),
            /// Metadata error
            Metadata(#[cfg_attr(feature = "std", source)] metadata::MetadataError),
            /// Execution failed: {0}
            Fail(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// Invalid instruction parameter
            InvalidParameter(#[cfg_attr(feature = "std", source)] InvalidParameterError),
            /// Iroha invariant violation: {0}
            ///
            /// i.e. you can't burn last key
            InvariantViolation(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
        }

        /// Evaluation error. This error indicates instruction is not a valid Iroha DSL
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        // TODO: Only temporarily opaque because of problems with FFI
        #[ffi_type(opaque)]
        pub enum InstructionEvaluationError {
            /// Failed to evaluate expression
            Expression(#[cfg_attr(feature = "std", source)] evaluate::EvaluationError),
            /// Unsupported parameter type for instruction of type `{0}`
            Unsupported(InstructionType),
            /// Failed to find parameter in a permission: {0}
            PermissionParameter(String),
            /// Incorrect value type
            Type(#[cfg_attr(feature = "std", source)] TypeError),
        }

        /// Generic structure used to represent a mismatch
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[display(fmt = "Expected {expected:?}, actual {actual:?}")]
        #[ffi_type]
        pub struct Mismatch<T: Debug> {
            /// The value that is needed for normal execution
            pub expected: T,
            /// The value that caused the error
            pub actual: T,
        }

        /// Type error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type]
        pub enum TypeError {
            /// Asset Ids correspond to assets with different underlying types, {0}
            AssetValueType(#[cfg_attr(feature = "std", source)] Mismatch<AssetValueType>),
            /// Value passed to the parameter doesn't have the right type, {0}
            ParameterValueType(#[cfg_attr(feature = "std", source)] Box<Mismatch<Value>>),
            /// AssetDefinition Ids don't match, {0}
            AssetDefinitionId(
                #[cfg_attr(feature = "std", source)] Box<Mismatch<AssetDefinitionId>>,
            ),
        }

        /// Math error, which occurs during instruction execution
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        // TODO: Only temporarily opaque because of InstructionExecutionError::BinaryOpIncompatibleNumericValueTypes
        #[ignore_extra_doc_attributes]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type(opaque)]
        pub enum MathError {
            /// Overflow error occurred inside instruction
            Overflow,
            /// Not enough quantity to transfer/burn
            NotEnoughQuantity,
            /// Divide by zero
            DivideByZero,
            /// Negative value encountered
            NegativeValue,
            /// Domain violation
            DomainViolation,
            /// Unknown error
            ///
            /// No actual function should ever return this if possible
            Unknown,
            /// Encountered incompatible type of arguments
            BinaryOpIncompatibleNumericValueTypes(
                #[cfg_attr(feature = "std", source)] BinaryOpIncompatibleNumericValueTypesError,
            ),
            /// Conversion failed: {0}
            FixedPointConversion(String),
        }

        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[display(
            fmt = "Binary operation does not support provided combination of arguments ({left}, {right})"
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type]
        pub struct BinaryOpIncompatibleNumericValueTypesError {
            pub left: NumericValue,
            pub right: NumericValue,
        }

        /// Mintability logic error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type]
        #[repr(u8)]
        pub enum MintabilityError {
            /// This asset cannot be minted more than once and it was already minted
            MintUnmintable,
            /// This asset was set as infinitely mintable. You cannot forbid its minting
            ForbidMintOnMintable,
        }

        /// Invalid instruction parameter error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[ignore_extra_doc_attributes]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type(opaque)]
        #[repr(u8)]
        pub enum InvalidParameterError {
            /// Invalid WASM binary: {0}
            Wasm(String),
            /// Name length violation
            ///
            /// i.e. too long [`AccountId`]
            NameLength,
        }

        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[display(fmt = "Repetition of of `{instruction_type}` for id `{id}`")]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type]
        pub struct RepetitionError {
            pub instruction_type: InstructionType,
            pub id: IdBox,
        }
    }

    impl From<TypeError> for InstructionExecutionError {
        fn from(err: TypeError) -> Self {
            Self::Evaluate(InstructionEvaluationError::Type(err))
        }
    }
    impl From<evaluate::EvaluationError> for InstructionExecutionError {
        fn from(err: evaluate::EvaluationError) -> Self {
            Self::Evaluate(InstructionEvaluationError::Expression(err))
        }
    }
    impl From<FixedPointOperationError> for MathError {
        fn from(err: FixedPointOperationError) -> Self {
            match err {
                FixedPointOperationError::NegativeValue(_) => Self::NegativeValue,
                FixedPointOperationError::Conversion(e) => {
                    #[cfg(not(feature = "std"))]
                    use alloc::string::ToString as _;

                    Self::FixedPointConversion(e.to_string())
                }
                FixedPointOperationError::Overflow => Self::Overflow,
                FixedPointOperationError::DivideByZero => Self::DivideByZero,
                FixedPointOperationError::DomainViolation => Self::DomainViolation,
                FixedPointOperationError::Arithmetic => Self::Unknown,
            }
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Burn, BurnExpr, ConditionalExpr, ExecuteTrigger, ExecuteTriggerExpr, Fail, Grant,
        GrantExpr, InstructionExpr, Log, LogExpr, Mint, MintExpr, NewParameter, NewParameterExpr,
        PairExpr, Register, RegisterExpr, RemoveKeyValue, RemoveKeyValueExpr, Revoke, RevokeExpr,
        SequenceExpr, SetKeyValue, SetKeyValueExpr, SetParameter, SetParameterExpr, Transfer,
        TransferExpr, Unregister, UnregisterExpr, Upgrade, UpgradeExpr,
    };
}
