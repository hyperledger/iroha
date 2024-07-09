#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use iroha_version::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::impl_predicate_box;
use crate::{
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId, AssetValue},
    query::{
        predicate::{
            predicate_ast_extensions::AstPredicateExt as _,
            predicate_atoms::{
                account::AccountIdPredicateBox, domain::DomainIdPredicateBox, MetadataPredicateBox,
                StringPredicateBox,
            },
            predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
            projectors::BaseProjector,
            PredicateTrait,
        },
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetDefinitionPredicateBox {
    // projections
    Id(AssetDefinitionIdPredicateBox),
    Metadata(MetadataPredicateBox),
    OwnedBy(AccountIdPredicateBox),
}

impl_predicate_box!(AssetDefinition: AssetDefinitionPredicateBox);

impl PredicateTrait<AssetDefinition> for AssetDefinitionPredicateBox {
    fn applies(&self, input: &AssetDefinition) -> bool {
        match self {
            AssetDefinitionPredicateBox::Id(id) => id.applies(&input.id),
            AssetDefinitionPredicateBox::Metadata(metadata) => metadata.applies(&input.metadata),
            AssetDefinitionPredicateBox::OwnedBy(account_id) => account_id.applies(&input.owned_by),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetPredicateBox {
    // projections
    Id(AssetIdPredicateBox),
    Value(AssetValuePredicateBox),
}

impl_predicate_box!(Asset: AssetPredicateBox);

impl PredicateTrait<Asset> for AssetPredicateBox {
    fn applies(&self, input: &Asset) -> bool {
        match self {
            AssetPredicateBox::Id(id) => id.applies(&input.id),
            AssetPredicateBox::Value(value) => value.applies(&input.value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetValuePredicateBox {
    // TODO: populate
}

impl_predicate_box!(AssetValue: AssetValuePredicateBox);

impl PredicateTrait<AssetValue> for AssetValuePredicateBox {
    fn applies(&self, _input: &AssetValue) -> bool {
        match self {
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetIdPredicateBox {
    // object-specific predicates
    Equals(AssetId),
    // projections
    DefinitionId(AssetDefinitionIdPredicateBox),
    AccountId(AccountIdPredicateBox),
}

impl_predicate_box!(AssetId: AssetIdPredicateBox);

impl PredicateTrait<AssetId> for AssetIdPredicateBox {
    fn applies(&self, input: &AssetId) -> bool {
        match self {
            AssetIdPredicateBox::Equals(expected) => expected == input,
            AssetIdPredicateBox::DefinitionId(definition_id) => {
                definition_id.applies(&input.definition)
            }
            AssetIdPredicateBox::AccountId(account_id) => account_id.applies(&input.account),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetDefinitionIdPredicateBox {
    // object-specific predicates
    Equals(AssetDefinitionId),
    // projections
    DomainId(DomainIdPredicateBox),
    Name(StringPredicateBox),
}

impl_predicate_box!(AssetDefinitionId: AssetDefinitionIdPredicateBox);

impl PredicateTrait<AssetDefinitionId> for AssetDefinitionIdPredicateBox {
    fn applies(&self, input: &AssetDefinitionId) -> bool {
        match self {
            AssetDefinitionIdPredicateBox::Equals(expected) => expected == input,
            AssetDefinitionIdPredicateBox::DomainId(domain) => domain.applies(&input.domain),
            AssetDefinitionIdPredicateBox::Name(name) => name.applies(&input.name),
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{
        AssetDefinitionIdPredicateBox, AssetDefinitionPredicateBox, AssetIdPredicateBox,
        AssetPredicateBox, AssetValuePredicateBox,
    };
}
