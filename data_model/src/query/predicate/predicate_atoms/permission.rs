use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    permission::Permission,
    prelude::PredicateTrait,
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum PermissionPredicateBox {
    // nothing here yet
}

impl_predicate_box!(Permission: PermissionPredicateBox);

impl PredicateTrait<Permission> for PermissionPredicateBox {
    fn applies(&self, _input: &Permission) -> bool {
        match self {
            _ => todo!(),
        }
    }
}
