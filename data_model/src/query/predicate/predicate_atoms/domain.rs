use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{impl_predicate_box, MetadataPredicateBox};
use crate::{
    domain::{Domain, DomainId},
    prelude::PredicateTrait,
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_atoms::StringPredicateBox,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum DomainPredicateBox {
    // projections
    Id(DomainIdPredicateBox),
    Metadata(MetadataPredicateBox),
}

impl_predicate_box!(Domain: DomainPredicateBox);

impl PredicateTrait<Domain> for DomainPredicateBox {
    fn applies(&self, input: &Domain) -> bool {
        match self {
            DomainPredicateBox::Id(id) => id.applies(&input.id),
            DomainPredicateBox::Metadata(metadata) => metadata.applies(&input.metadata),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum DomainIdPredicateBox {
    // object-specific predicates
    Equals(DomainId),
    // projections
    Name(StringPredicateBox),
}

impl_predicate_box!(DomainId: DomainIdPredicateBox);

impl PredicateTrait<DomainId> for DomainIdPredicateBox {
    fn applies(&self, input: &DomainId) -> bool {
        match self {
            DomainIdPredicateBox::Equals(expected) => expected == input,
            DomainIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}
