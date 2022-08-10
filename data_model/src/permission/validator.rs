//! Structures, traits and impls related to `Validator`s.

use super::*;

ffi_item! {
    /// Permission validator that checks if some operation satisfies some conditions.
    ///
    /// Can be used with things like [`Transaction`](crate::transaction::Transaction)s,
    /// [`Instruction`](crate::isi::Instruction)s and etc.
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
