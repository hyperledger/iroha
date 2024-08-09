//! This module contains predicates for role-related objects, mirroring [`crate::role`].

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    prelude::{Role, RoleId},
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::StringPredicateBox,
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
        },
        AstPredicate, CompoundPredicate, EvaluatePredicate, HasPredicateBox, HasPrototype,
    },
};

/// A predicate that can be applied to a [`RoleId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum RoleIdPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(RoleId),
    // projections
    /// Checks if a predicate applies to the name of the input.
    Name(StringPredicateBox),
}

impl_predicate_box!(RoleId: RoleIdPredicateBox);

impl EvaluatePredicate<RoleId> for RoleIdPredicateBox {
    fn applies(&self, input: &RoleId) -> bool {
        match self {
            RoleIdPredicateBox::Equals(expected) => expected == input,
            RoleIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}

/// A predicate that can be applied to a [`Role`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum RolePredicateBox {
    // projections
    /// Checks if a predicate applies to the ID of the input.
    Id(RoleIdPredicateBox),
}

impl_predicate_box!(Role: RolePredicateBox);

impl EvaluatePredicate<Role> for RolePredicateBox {
    fn applies(&self, input: &Role) -> bool {
        match self {
            RolePredicateBox::Id(id) => id.applies(&input.id),
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{RoleIdPredicateBox, RolePredicateBox};
}
