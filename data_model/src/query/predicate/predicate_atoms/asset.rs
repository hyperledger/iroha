//! This module contains predicates for asset-related objects, mirroring [`crate::asset`].

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
            EvaluatePredicate,
        },
        AstPredicate, CompoundPredicate, HasPredicateBox, HasPrototype,
    },
};

/// A predicate that can be applied to an [`AssetDefinitionId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetDefinitionPredicateBox {
    // projections
    /// Checks if a predicate applies to the ID of the input.
    Id(AssetDefinitionIdPredicateBox),
    /// Checks if a predicate applies to the metadata of the input.
    Metadata(MetadataPredicateBox),
    /// Checks if a predicate applies to the owner of the input.
    OwnedBy(AccountIdPredicateBox),
}

impl_predicate_box!(AssetDefinition: AssetDefinitionPredicateBox);

impl EvaluatePredicate<AssetDefinition> for AssetDefinitionPredicateBox {
    fn applies(&self, input: &AssetDefinition) -> bool {
        match self {
            AssetDefinitionPredicateBox::Id(id) => id.applies(&input.id),
            AssetDefinitionPredicateBox::Metadata(metadata) => metadata.applies(&input.metadata),
            AssetDefinitionPredicateBox::OwnedBy(account_id) => account_id.applies(&input.owned_by),
        }
    }
}

/// A predicate that can be applied to an [`Asset`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetPredicateBox {
    // projections
    /// Checks if a predicate applies to the ID of the input.
    Id(AssetIdPredicateBox),
    /// Checks if a predicate applies to the value of the input.
    Value(AssetValuePredicateBox),
}

impl_predicate_box!(Asset: AssetPredicateBox);

impl EvaluatePredicate<Asset> for AssetPredicateBox {
    fn applies(&self, input: &Asset) -> bool {
        match self {
            AssetPredicateBox::Id(id) => id.applies(&input.id),
            AssetPredicateBox::Value(value) => value.applies(&input.value),
        }
    }
}

/// A predicate that can be applied to an [`AssetValue`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetValuePredicateBox {
    // TODO: populate
}

impl_predicate_box!(AssetValue: AssetValuePredicateBox);

impl EvaluatePredicate<AssetValue> for AssetValuePredicateBox {
    fn applies(&self, _input: &AssetValue) -> bool {
        match *self {}
    }
}

/// A predicate that can be applied to an [`AssetId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetIdPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(AssetId),
    // projections
    /// Checks if a predicate applies to the definition ID of the input.
    DefinitionId(AssetDefinitionIdPredicateBox),
    /// Checks if a predicate applies to the account ID of the input.
    AccountId(AccountIdPredicateBox),
}

impl_predicate_box!(AssetId: AssetIdPredicateBox);

impl EvaluatePredicate<AssetId> for AssetIdPredicateBox {
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

/// A predicate that can be applied to an [`AssetDefinitionId`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum AssetDefinitionIdPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(AssetDefinitionId),
    // projections
    /// Checks if a predicate applies to the domain ID of the input.
    DomainId(DomainIdPredicateBox),
    /// Checks if a predicate applies to the name of the input.
    Name(StringPredicateBox),
}

impl_predicate_box!(AssetDefinitionId: AssetDefinitionIdPredicateBox);

impl EvaluatePredicate<AssetDefinitionId> for AssetDefinitionIdPredicateBox {
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
