//! This module contains predicates for peer-related objects, mirroring [`crate::peer`].

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    peer::Peer,
    query::predicate::{
        predicate_ast_extensions::AstPredicateExt as _,
        predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
        projectors::BaseProjector,
        AstPredicate, CompoundPredicate, EvaluatePredicate, HasPredicateBox, HasPrototype,
    },
};

/// A predicate that can be applied to a [`Peer`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum PeerPredicateBox {
    // nothing here yet
}

impl_predicate_box!(Peer: PeerPredicateBox);

impl EvaluatePredicate<Peer> for PeerPredicateBox {
    fn applies(&self, _input: &Peer) -> bool {
        match *self {}
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::PeerPredicateBox;
}
