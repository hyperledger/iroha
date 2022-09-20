//! Structures, traits and impls related to *runtime* `Validator`s.
//!
//! # Note
//!
//! Currently Iroha 2 has only builtin validators (see `core/src/smartcontracts/permissions`).
//! They are partly using API from this module.
//! In the future they will be replaced with *runtime validators* that use WASM.
//! The architecture of the new validators is quite different from the old ones.
//! That's why some parts of this module may not be used anywhere yet.

use super::*;
use crate::{
    account::Account,
    expression::Expression,
    isi::Instruction,
    query::QueryBox,
    transaction::{SignedTransaction, WasmSmartContract},
    ParseError,
};

ffi_item! {
    /// Permission validator that checks if an operation satisfies some conditions.
    ///
    /// Can be used with things like [`Transaction`]s,
    /// [`Instruction`]s, etc.
    #[derive(
        Debug,
        Display,
        Constructor,
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
    #[display(fmt = "{id}")]
    #[id(type = "Id")]
    pub struct Validator {
        id: <Self as Identifiable>::Id,
        #[getset(get = "pub")]
        /// Type of the validator
        validator_type: Type,
        // TODO: use another type like `WasmValidator`?
        /// WASM code of the validator
        #[getset(get = "pub")]
        wasm: WasmSmartContract,
    }
}

impl Registered for Validator {
    type With = Self;
}

/// Identification of a [`Validator`].
///
/// Consists of Validator's name and account (authority) id
#[derive(
    Debug,
    Display,
    Constructor,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    DeserializeFromStr,
    SerializeDisplay,
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[display(fmt = "{name}%{account_id}")]
pub struct Id {
    /// Name given to validator by its creator.
    pub name: Name,
    /// Authority id.
    pub account_id: <Account as Identifiable>::Id,
}

impl core::str::FromStr for Id {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseError {
                reason: "`ValidatorId` cannot be empty",
            });
        }

        let mut split = s.split('%');
        match (split.next(), split.next(), split.next()) {
            (Some(name), Some(account_id), None) => Ok(Self {
                name: name.parse()?,
                account_id: account_id.parse()?,
            }),
            _ => Err(ParseError {
                reason: "Validator ID should have format `validator%account_id`",
            }),
        }
    }
}

/// Type of validator
#[derive(
    Debug,
    Display,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Deserialize,
    Serialize,
    IntoSchema,
    Hash,
)]
pub enum Type {
    /// Validator checking [`Transaction`]
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
#[derive(
    Debug,
    Display,
    Clone,
    derive_more::From,
    derive_more::TryInto,
    Encode,
    Decode,
    Serialize,
    Deserialize,
)]
pub enum NeedsPermissionBox {
    /// [`SignedTransaction`] application operation
    Transaction(SignedTransaction),
    /// [`Instruction`] execution operation
    Instruction(Instruction),
    /// [`QueryBox`] execution operations
    Query(QueryBox),
    /// [`Expression`] evaluation operation
    Expression(Expression),
}

impl NeedsPermission for NeedsPermissionBox {
    fn required_validator_type(&self) -> Type {
        match self {
            NeedsPermissionBox::Transaction(_) => Type::Transaction,
            NeedsPermissionBox::Instruction(_) => Type::Instruction,
            NeedsPermissionBox::Query(_) => Type::Query,
            NeedsPermissionBox::Expression(_) => Type::Expression,
        }
    }
}

/// Validation verdict. All *runtime validators* should return this type.
///
/// All operations are considered to be **valid** unless proven otherwise.
/// Validators are allowed to either pass an operation to the next validator
/// or to deny an operation.
///
/// # Note
///
/// There is no `Allow` variant (as well as it isn't a [`Result`] alias)
/// because `Allow` and `Result` have a wrong connotation and suggest
/// an incorrect interpretation of validators system.
///
/// All operations are allowed by default.
/// Validators are checking for operation **incorrectness**, not for operation correctness.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Deserialize, Serialize, IntoSchema)]
pub enum Verdict {
    /// Operation is approved to pass to the next validator
    /// or to be executed if there are no more validators
    Pass,
    /// Operation is denied
    Deny(DenialReason),
}

impl From<Verdict> for Result<(), DenialReason> {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Pass => Ok(()),
            Verdict::Deny(reason) => Err(reason),
        }
    }
}

/// Reason for denying the execution of a particular instruction.
pub type DenialReason = String;
