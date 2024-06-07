use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    prelude::{PredicateTrait, Role, RoleId},
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::StringPredicateBox,
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
        },
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum RoleIdPredicateBox {
    // object-specific predicates
    Equals(RoleId),
    // projections
    Name(StringPredicateBox),
}

impl_predicate_box!(RoleId: RoleIdPredicateBox);

impl PredicateTrait<RoleId> for RoleIdPredicateBox {
    fn applies(&self, input: &RoleId) -> bool {
        match self {
            RoleIdPredicateBox::Equals(expected) => expected == input,
            RoleIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum RolePredicateBox {
    // projections
    Id(RoleIdPredicateBox),
}

impl_predicate_box!(Role: RolePredicateBox);

impl PredicateTrait<Role> for RolePredicateBox {
    fn applies(&self, input: &Role) -> bool {
        match self {
            RolePredicateBox::Id(id) => id.applies(&input.id),
        }
    }
}
