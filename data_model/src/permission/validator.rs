//! Structures, traits and impls related to `Validator`s.

#![allow(unused_imports)] // TODO

use super::*;
use crate::{
    expression::Expression,
    isi::Instruction,
    query::QueryBox,
    transaction::{Transaction, WasmSmartContract},
};

ffi_item! {
    /// Permission validator that checks if some operation satisfies some conditions.
    ///
    /// Can be used with things like [`Transaction`]s,
    /// [`Instruction`]s and etc.
    #[derive(
        Debug,
        Display,
        Clone,
        IdOrdEqHash,
        Getters,
        MutGetters,
        Setters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoFfi,
        TryFromReprC,
        IntoSchema,
    )]
    #[allow(clippy::multiple_inherent_impl)]
    #[display(fmt = "({id})")]
    #[id(type = "Id")]
    pub struct Validator {
        id: <Self as Identifiable>::Id,
        validator_type: Type,
        // TODO: use another type like `WasmValidator`?
        wasm: WasmSmartContract,
    }
}

impl Registered for Validator {
    type With = NewValidator;
}

ffi_item! {
    /// Builder which should be submitted in a transaction to create a new [`Validator`]
    #[derive(
        Debug,
        Display,
        Clone,
        IdOrdEqHash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoFfi,
        TryFromReprC,
        IntoSchema,
    )]
    #[id(type = "<Validator as Identifiable>::Id")]
    pub struct NewValidator {
        id: <Validator as Identifiable>::Id,
    }
}

/// Identification of an [`Validator`]. Consists of Validator's name
#[derive(
    Debug,
    Display,
    Constructor,
    FromStr,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[display(fmt = "{name}")]
pub struct Id {
    /// Name given to validator by its creator.
    pub name: Name,
}

/// Type of validator
#[derive(
    Debug, Display, Copy, Clone, PartialEq, Eq, Encode, Decode, Deserialize, Serialize, IntoSchema,
)]
pub enum Type {
    /// Validator checking [`Transaction`]
    // TODO: implement other infrastructure for this variant
    Transaction,
    /// Validator checking [`Instruction`]
    Instruction,
    /// Validator checking [`QueryBox`]
    Query,
    /// Validator checking [`Expression`]
    Expression,
}

/// Operation for which the permission should be checked
pub trait NeedsPermission {
    /// Get the type of validator required to check the operation
    ///
    /// Accepts `self` because of the [`NeedsPermissionBox`]
    fn required_validator_type(&self) -> Type;
}

impl NeedsPermission for Instruction {
    fn required_validator_type(&self) -> Type {
        Type::Instruction
    }
}

impl NeedsPermission for QueryBox {
    fn required_validator_type(&self) -> Type {
        Type::Query
    }
}

// Expression might contain a query, therefore needs to be checked.
impl NeedsPermission for Expression {
    fn required_validator_type(&self) -> Type {
        Type::Expression
    }
}

/// Boxed version of [`NeedsPermission`]
#[derive(Debug, derive_more::From, derive_more::TryInto)]
pub enum NeedsPermissionBox {
    /// [`Instruction`] operation
    Instruction(Instruction),
    /// [`QueryBox`] operation
    Query(QueryBox),
    /// [`Expression`] operation
    Expression(Expression),
    // TODO: Transaction variant
}

impl NeedsPermission for NeedsPermissionBox {
    fn required_validator_type(&self) -> Type {
        match self {
            NeedsPermissionBox::Instruction(_) => Type::Instruction,
            NeedsPermissionBox::Query(_) => Type::Query,
            NeedsPermissionBox::Expression(_) => Type::Expression,
        }
    }
}
