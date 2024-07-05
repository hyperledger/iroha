#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    account::{Account, AccountId},
    prelude::PredicateTrait,
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::{
                domain::DomainIdPredicateBox, MetadataPredicateBox, PublicKeyPredicateBox,
            },
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
        },
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AccountIdPredicateBox {
    // object-specific predicates
    Equals(AccountId),
    // projections
    DomainId(DomainIdPredicateBox),
    Signatory(PublicKeyPredicateBox),
}

impl_predicate_box!(AccountId: AccountIdPredicateBox);

impl PredicateTrait<AccountId> for AccountIdPredicateBox {
    fn applies(&self, input: &AccountId) -> bool {
        match self {
            AccountIdPredicateBox::Equals(expected) => expected == input,
            AccountIdPredicateBox::DomainId(domain) => domain.applies(&input.domain),
            AccountIdPredicateBox::Signatory(public_key) => public_key.applies(&input.signatory),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AccountPredicateBox {
    // projections
    Id(AccountIdPredicateBox),
    Metadata(MetadataPredicateBox),
}

impl_predicate_box!(Account: AccountPredicateBox);

impl PredicateTrait<Account> for AccountPredicateBox {
    fn applies(&self, input: &Account) -> bool {
        match self {
            AccountPredicateBox::Id(id) => id.applies(&input.id),
            AccountPredicateBox::Metadata(metadata) => metadata.applies(&input.metadata),
        }
    }
}
