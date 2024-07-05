#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    parameter::Parameter,
    prelude::PredicateTrait,
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum ParameterPredicateBox {
    // nothing here yet
}

impl_predicate_box!(Parameter: ParameterPredicateBox);

impl PredicateTrait<Parameter> for ParameterPredicateBox {
    fn applies(&self, _input: &Parameter) -> bool {
        match self {
            _ => todo!(),
        }
    }
}
