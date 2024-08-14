//! This module contains predicates for account-related objects, mirroring [`crate::account`].

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    account::{Account, AccountId},
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::{
                domain::DomainIdPredicateBox, MetadataPredicateBox, PublicKeyPredicateBox,
            },
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
            EvaluatePredicate,
        },
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

/// A predicate that can be applied to an [`AccountId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AccountIdPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(AccountId),
    // projections
    /// Checks if a predicate applies to the domain ID of the input.
    DomainId(DomainIdPredicateBox),
    /// Checks if a predicate applies to the signatory of the input.
    Signatory(PublicKeyPredicateBox),
}

impl_predicate_box!(AccountId: AccountIdPredicateBox);

impl EvaluatePredicate<AccountId> for AccountIdPredicateBox {
    fn applies(&self, input: &AccountId) -> bool {
        match self {
            AccountIdPredicateBox::Equals(expected) => expected == input,
            AccountIdPredicateBox::DomainId(domain) => domain.applies(&input.domain),
            AccountIdPredicateBox::Signatory(public_key) => public_key.applies(&input.signatory),
        }
    }
}

/// A predicate that can be applied to an [`Account`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AccountPredicateBox {
    // projections
    /// Checks if a predicate applies to the ID of the input.
    Id(AccountIdPredicateBox),
    /// Checks if a predicate applies to the metadata of the input.
    Metadata(MetadataPredicateBox),
}

impl_predicate_box!(Account: AccountPredicateBox);

impl EvaluatePredicate<Account> for AccountPredicateBox {
    fn applies(&self, input: &Account) -> bool {
        match self {
            AccountPredicateBox::Id(id) => id.applies(&input.id),
            AccountPredicateBox::Metadata(metadata) => metadata.applies(&input.metadata),
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{AccountIdPredicateBox, AccountPredicateBox};
}
