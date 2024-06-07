use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    prelude::{PredicateTrait, Trigger, TriggerId},
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_atoms::StringPredicateBox,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TriggerIdPredicateBox {
    // object-specific predicates
    Equals(TriggerId),
    // projections
    Name(StringPredicateBox),
}

impl PredicateTrait<TriggerId> for TriggerIdPredicateBox {
    fn applies(&self, input: &TriggerId) -> bool {
        match self {
            TriggerIdPredicateBox::Equals(expected) => expected == input,
            TriggerIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}

impl_predicate_box!(TriggerId: TriggerIdPredicateBox);

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TriggerPredicateBox {
    // projections
    Id(TriggerIdPredicateBox),
}

impl_predicate_box!(Trigger: TriggerPredicateBox);

impl PredicateTrait<Trigger> for TriggerPredicateBox {
    fn applies(&self, input: &Trigger) -> bool {
        match self {
            TriggerPredicateBox::Id(id) => id.applies(&input.id),
        }
    }
}
