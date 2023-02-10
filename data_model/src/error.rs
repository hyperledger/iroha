//! Errors used in Iroha special instructions and
//! queries. Instruction execution should fail with a specific
//! error variant, as opposed to a generic (printable-only)
//! [`eyre::Report`]. If it is impossible to predict what kind of
//! error shall be raised, there are types that wrap
//! [`eyre::Report`].
#![cfg(feature = "std")]

use iroha_crypto::HashOf;
use iroha_primitives::fixed::FixedPointOperationError;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;

use crate::{
    block::VersionedCommittedBlock, isi::InstructionType, metadata, permission, prelude::*, trigger,
};

/// Query errors.
#[derive(Error, Debug, Decode, Encode, IntoSchema)]
pub enum QueryExecutionFailure {
    /// Query cannot be decoded.
    #[error("Query cannot be decoded")]
    Decode(#[from] Box<iroha_version::error::Error>),
    /// Query has wrong signature.
    #[error("Query has the wrong signature: {0}")]
    Signature(String),
    /// Query is not allowed.
    #[error("Query is not allowed: {0}")]
    Permission(permission::validator::DenialReason),
    /// Query has wrong expression.
    #[error("Query has a malformed expression: {0}")]
    Evaluate(String),
    /// Query found nothing.
    #[error("Query found nothing: {0}")]
    Find(#[from] Box<FindError>),
    /// Query found wrong type of asset.
    #[error("Query found wrong type of asset: {0}")]
    Conversion(String),
    /// Query without account.
    #[error("Unauthorized query: account not provided")]
    Unauthorized,
}

/// Instruction execution error type
#[derive(Debug, Error)]
pub enum InstructionExecutionFailure {
    /// Failed to find some entity
    #[error("Failed to find. {0}")]
    Find(#[from] Box<FindError>),
    /// Failed to assert type
    #[error("Type assertion failed. {0}")]
    Type(#[from] TypeError),
    /// Failed to assert mintability
    #[error("Mintability violation. {0}")]
    Mintability(#[from] MintabilityError),
    /// Failed due to math exception
    #[error("Math error. {0}")]
    Math(#[from] MathError),
    /// Query Error
    #[error("Query failed. {0}")]
    Query(#[from] QueryExecutionFailure),
    /// Metadata Error.
    #[error("Metadata error: {0}")]
    Metadata(#[from] metadata::Error),
    /// Unsupported instruction.
    #[error("Unsupported {0} instruction")]
    Unsupported(InstructionType),
    /// [`FailBox`] error
    #[error("Execution failed {0}")]
    FailBox(String),
    /// Conversion Error
    #[error("Conversion Error: {0}")]
    Conversion(String),
    /// Repeated instruction
    #[error("Repetition")]
    Repetition(InstructionType, IdBox),
    /// Failed to validate.
    #[error("Failed to validate: {0}")]
    Validate(#[from] ValidationError),
}

/// Type assertion error
#[derive(Debug, Error, Decode, Encode, IntoSchema)]
pub enum FindError {
    /// Failed to find asset
    #[error("Failed to find asset: `{0}`")]
    Asset(AssetId),
    /// Failed to find asset definition
    #[error("Failed to find asset definition: `{0}`")]
    AssetDefinition(AssetDefinitionId),
    /// Failed to find account
    #[error("Failed to find account: `{0}`")]
    Account(<Account as Identifiable>::Id),
    /// Failed to find domain
    #[error("Failed to find domain: `{0}`")]
    Domain(DomainId),
    /// Failed to find metadata key
    #[error("Failed to find metadata key")]
    MetadataKey(Name),
    /// Block with supplied parent hash not found. More description in a string.
    #[error("Block with hash {0} not found.")]
    Block(HashOf<VersionedCommittedBlock>),
    /// Transaction with given hash not found.
    #[error("Transaction not found")]
    Transaction(HashOf<VersionedSignedTransaction>),
    /// Value not found in context.
    #[error("Value named {0} not found in context. ")]
    Context(String),
    /// Peer not found.
    #[error("Peer {0} not found")]
    Peer(PeerId),
    /// Trigger not found.
    #[error("Trigger not found.")]
    Trigger(TriggerId),
    /// Failed to find Role by id.
    #[error("Failed to find role by id: `{0}`")]
    Role(RoleId),
    /// Failed to find [`PermissionToken`] by id.
    #[error("Failed to find permission definition token by id: `{0}`")]
    PermissionTokenDefinition(PermissionTokenId),
    /// Failed to find [`Validator`](permission::Validator) by id.
    #[error("Failed to find permission validator by id: `{0}`")]
    Validator(permission::validator::Id),
    /// Failed to find specified [`Parameter`] variant.
    #[error("Failed to find specified parameter variant: `{0}`")]
    Parameter(Parameter),
}

/// Generic structure used to represent a mismatch
#[derive(Debug, Clone, PartialEq, Eq, Error, Decode, Encode, IntoSchema)]
#[error("Expected {expected:?}, actual {actual:?}")]
pub struct Mismatch<T> {
    /// The value that is needed for normal execution
    pub expected: T,
    /// The value that caused the error
    pub actual: T,
}

/// Type error
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[allow(variant_size_differences)] // False-positive
pub enum TypeError {
    /// Asset type assertion error
    #[error("Asset Ids correspond to assets with different underlying types. {0}")]
    AssetValueType(#[from] Mismatch<AssetValueType>),
    /// Parameter type assertion error
    #[error("Value passed to the parameter doesn't have the right type. {0}")]
    ParameterValueType(#[from] Mismatch<Value>),
    /// Asset Id mismatch
    #[error("AssetDefinition Ids don't match. {0}")]
    AssetDefinitionId(#[from] Box<Mismatch<<AssetDefinition as Identifiable>::Id>>),
}

/// Math error, which occurs during instruction execution
#[derive(Debug, Clone, Error, Copy, PartialEq, Eq)]
pub enum MathError {
    /// Overflow error inside instruction
    #[error("Overflow occurred.")]
    Overflow,
    /// Not enough quantity
    #[error("Not enough quantity to transfer/burn.")]
    NotEnoughQuantity,
    /// Divide by zero
    #[error("Divide by zero")]
    DivideByZero,
    /// Negative Value encountered
    #[error("Negative value encountered")]
    NegativeValue,
    /// Domain violation
    #[error("Domain violation")]
    DomainViolation,
    /// Unknown error. No actual function should ever return this if possible.
    #[error("Unknown error")]
    Unknown,
    /// Encountered incompatible type of arguments
    #[error("Binary operation does not support provided combination of arguments ({0}, {1})")]
    BinaryOpIncompatibleNumericValueTypes(NumericValue, NumericValue),
}

impl From<FixedPointOperationError> for InstructionExecutionFailure {
    fn from(err: FixedPointOperationError) -> Self {
        match err {
            FixedPointOperationError::NegativeValue(_) => Self::Math(MathError::NegativeValue),
            FixedPointOperationError::Conversion(e) => {
                Self::Conversion(format!("Mathematical conversion failed. {e}"))
            }
            FixedPointOperationError::Overflow => MathError::Overflow.into(),
            FixedPointOperationError::DivideByZero => MathError::DivideByZero.into(),
            FixedPointOperationError::DomainViolation => MathError::DomainViolation.into(),
            FixedPointOperationError::Arithmetic => MathError::Unknown.into(),
        }
    }
}

impl From<FindError> for InstructionExecutionFailure {
    fn from(err: FindError) -> Self {
        Self::Find(Box::new(err))
    }
}

impl From<FindError> for QueryExecutionFailure {
    fn from(err: FindError) -> Self {
        Box::new(err).into()
    }
}

impl From<trigger::set::ModRepeatsError> for InstructionExecutionFailure {
    fn from(err: trigger::set::ModRepeatsError) -> Self {
        match err {
            trigger::set::ModRepeatsError::NotFound(not_found_id) => {
                FindError::Trigger(not_found_id).into()
            }
            trigger::set::ModRepeatsError::RepeatsOverflow(_) => MathError::Overflow.into(),
        }
    }
}
