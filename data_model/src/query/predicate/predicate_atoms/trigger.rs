//! This module contains predicates for trigger-related objects, mirroring [`crate::trigger`]

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    prelude::{Trigger, TriggerId},
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_atoms::StringPredicateBox,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, EvaluatePredicate, HasPredicateBox, HasPrototype,
    },
};

/// A predicate that can be applied to a [`TriggerId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TriggerIdPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(TriggerId),
    // projections
    /// Checks if a predicate applies to the name of the input.
    Name(StringPredicateBox),
}

impl EvaluatePredicate<TriggerId> for TriggerIdPredicateBox {
    fn applies(&self, input: &TriggerId) -> bool {
        match self {
            TriggerIdPredicateBox::Equals(expected) => expected == input,
            TriggerIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}

impl_predicate_box!(TriggerId: TriggerIdPredicateBox);

/// A predicate that can be applied to a [`Trigger`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TriggerPredicateBox {
    // projections
    /// Checks if a predicate applies to the ID of the input.
    Id(TriggerIdPredicateBox),
}

impl_predicate_box!(Trigger: TriggerPredicateBox);

impl EvaluatePredicate<Trigger> for TriggerPredicateBox {
    fn applies(&self, input: &Trigger) -> bool {
        match self {
            TriggerPredicateBox::Id(id) => id.applies(&input.id),
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{TriggerIdPredicateBox, TriggerPredicateBox};
}
