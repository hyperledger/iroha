//! This module contains predicates for domain-related objects, mirroring [`crate::domain`].

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{impl_predicate_box, MetadataPredicateBox};
use crate::{
    domain::{Domain, DomainId},
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_atoms::StringPredicateBox,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, EvaluatePredicate, HasPredicateBox, HasPrototype,
    },
};

/// A predicate that can be applied to a [`Domain`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum DomainPredicateBox {
    // projections
    /// Checks if a predicate applies to the ID of the input.
    Id(DomainIdPredicateBox),
    /// Checks if a predicate applies to the metadata of the input.
    Metadata(MetadataPredicateBox),
}

impl_predicate_box!(Domain: DomainPredicateBox);

impl EvaluatePredicate<Domain> for DomainPredicateBox {
    fn applies(&self, input: &Domain) -> bool {
        match self {
            DomainPredicateBox::Id(id) => id.applies(&input.id),
            DomainPredicateBox::Metadata(metadata) => metadata.applies(&input.metadata),
        }
    }
}

/// A predicate that can be applied to a [`DomainId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum DomainIdPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(DomainId),
    // projections
    /// Checks if a predicate applies to the name of the input.
    Name(StringPredicateBox),
}

impl_predicate_box!(DomainId: DomainIdPredicateBox);

impl EvaluatePredicate<DomainId> for DomainIdPredicateBox {
    fn applies(&self, input: &DomainId) -> bool {
        match self {
            DomainIdPredicateBox::Equals(expected) => expected == input,
            DomainIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{DomainIdPredicateBox, DomainPredicateBox};
}
