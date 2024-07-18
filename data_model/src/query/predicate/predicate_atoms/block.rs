//! This module contains predicates for block-related objects, mirroring [`crate::block`].

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    block::{BlockHeader, SignedBlock},
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
            AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype, PredicateTrait,
        },
        TransactionQueryOutput,
    },
};

/// A predicate that can be applied to a [`BlockHeader`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum BlockHeaderPredicateBox {
    // nothing here yet
}

impl_predicate_box!(BlockHeader: BlockHeaderPredicateBox);

impl PredicateTrait<BlockHeader> for BlockHeaderPredicateBox {
    fn applies(&self, _input: &BlockHeader) -> bool {
        match *self {}
    }
}

/// A predicate that can be applied to a [`SignedBlock`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum SignedBlockPredicateBox {
    // nothing here yet
}

impl_predicate_box!(SignedBlock: SignedBlockPredicateBox);

impl PredicateTrait<SignedBlock> for SignedBlockPredicateBox {
    fn applies(&self, _input: &SignedBlock) -> bool {
        match *self {}
    }
}

/// A predicate that can be applied to a [`TransactionQueryOutput`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum TransactionQueryOutputPredicateBox {
    // nothing here yet
}

impl_predicate_box!(TransactionQueryOutput: TransactionQueryOutputPredicateBox);

impl PredicateTrait<TransactionQueryOutput> for TransactionQueryOutputPredicateBox {
    fn applies(&self, _input: &TransactionQueryOutput) -> bool {
        match *self {}
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{
        BlockHeaderPredicateBox, SignedBlockPredicateBox, TransactionQueryOutputPredicateBox,
    };
}
