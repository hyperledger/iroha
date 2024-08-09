//! This module contains atomic predicates for all the different types supported by the predicate system.
//!
//! Generally, each of the atomic predicates is an enum that has two categories of variants:
//! - Object-specific predicates, which check something that applies to the whole object, like [`account::AccountIdPredicateBox::Equals`] or [`StringPredicateBox::Contains`]
//! - Projections, which check a predicate on some of the fields/inner values of the object, like [`account::AccountIdPredicateBox::DomainId`]

#![allow(missing_copy_implementations)] // some predicates are not yet populated, but will be. They will stop being `Copy`able later, so don't bother with marking them as such now.

pub mod account;
pub mod asset;
pub mod block;
pub mod domain;
pub mod parameter;
pub mod peer;
pub mod permission;
pub mod role;
pub mod trigger;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_crypto::PublicKey;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{
    predicate_ast_extensions::AstPredicateExt as _,
    predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
    projectors::BaseProjector,
    AstPredicate, CompoundPredicate, EvaluatePredicate, HasPredicateBox, HasPrototype,
};
use crate::{metadata::Metadata, name::Name};

/// Adds common methods to a predicate box.
///
/// Implements:
/// 1. `build` and `build_fragment` methods for building a predicate using the dsl.
/// 2. base-case `AstPredicate` for the predicate box (emits an atom expression).
/// 3. `Not`, `BitAnd`, and `BitOr` operators for combining predicates.
macro_rules! impl_predicate_box {
    ($($ty:ty),+: $predicate_ty:ty) => {
        impl $predicate_ty {
            /// Build a new predicate in a normalized form. This predicate has limited composability and is generally useful only to be passed to queries.
            pub fn build<F, O>(predicate: F) -> CompoundPredicate<Self>
            where
                F: FnOnce(<Self as HasPrototype>::Prototype<BaseProjector<Self>>) -> O,
                O: AstPredicate<Self>,
            {
                predicate(Default::default()).normalize()
            }

            /// Build a new predicate without normalizing it. The resulting predicate can be freely composed with other predicates using logical operators, or by calling `.satisfies` method on a prototype.
            pub fn build_fragment<F, O>(predicate: F) -> O
            where
                F: FnOnce(<Self as HasPrototype>::Prototype<BaseProjector<Self>>) -> O,
                O: AstPredicate<Self>,
            {
                predicate(Default::default())
            }
        }

        $(
            impl HasPredicateBox for $ty {
                type PredicateBoxType = $predicate_ty;
            }
        )+

        impl AstPredicate<$predicate_ty> for $predicate_ty {
            fn normalize_with_proj<OutputType, Proj>(self, proj: Proj) -> CompoundPredicate<OutputType>
            where
                Proj: Fn($predicate_ty) -> OutputType + Copy,
            {
                CompoundPredicate::Atom(proj(self))
            }
        }

        impl core::ops::Not for $predicate_ty
        where
            Self: AstPredicate<$predicate_ty>,
        {
            type Output = NotAstPredicate<Self>;

            fn not(self) -> Self::Output {
                NotAstPredicate(self)
            }
        }

        impl<PRhs> core::ops::BitAnd<PRhs> for $predicate_ty
        where
            Self: AstPredicate<$predicate_ty>,
            PRhs: AstPredicate<$predicate_ty>,
        {
            type Output = AndAstPredicate<Self, PRhs>;

            fn bitand(self, rhs: PRhs) -> Self::Output {
                AndAstPredicate(self, rhs)
            }
        }

        impl<PRhs> core::ops::BitOr<PRhs> for $predicate_ty
        where
            Self: AstPredicate<$predicate_ty>,
            PRhs: AstPredicate<$predicate_ty>,
        {
            type Output = OrAstPredicate<Self, PRhs>;

            fn bitor(self, rhs: PRhs) -> Self::Output {
                OrAstPredicate(self, rhs)
            }
        }
    };
}
pub(crate) use impl_predicate_box;

/// A predicate that can be applied to a [`String`]-like types.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum StringPredicateBox {
    /// Checks if the input is equal to the expected value
    Equals(String),
    /// Checks if the input contains an expected substring, like [`str::contains()`]
    Contains(String),
    /// Checks if the input starts with an expected substring, like [`str::starts_with()`]
    StartsWith(String),
    /// Checks if the input ends with an expected substring, like [`str::ends_with()`]
    EndsWith(String),
}

impl_predicate_box!(String, Name: StringPredicateBox);

impl<T> EvaluatePredicate<T> for StringPredicateBox
where
    T: AsRef<str>,
{
    fn applies(&self, input: &T) -> bool {
        let input = input.as_ref();
        match self {
            StringPredicateBox::Contains(content) => input.contains(content),
            StringPredicateBox::StartsWith(content) => input.starts_with(content),
            StringPredicateBox::EndsWith(content) => input.ends_with(content),
            StringPredicateBox::Equals(content) => *input == *content,
        }
    }
}

/// A predicate that can be applied to [`Metadata`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum MetadataPredicateBox {}

impl_predicate_box!(Metadata: MetadataPredicateBox);

impl EvaluatePredicate<Metadata> for MetadataPredicateBox {
    fn applies(&self, _input: &Metadata) -> bool {
        match *self {}
    }
}

/// A predicate that can be applied to a [`PublicKey`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum PublicKeyPredicateBox {
    // object-specific predicates
    /// Checks if the input is equal to the expected value.
    Equals(PublicKey),
}

impl_predicate_box!(PublicKey: PublicKeyPredicateBox);

impl EvaluatePredicate<PublicKey> for PublicKeyPredicateBox {
    fn applies(&self, input: &PublicKey) -> bool {
        match self {
            PublicKeyPredicateBox::Equals(expected) => expected == input,
        }
    }
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{
        account::prelude::*, asset::prelude::*, block::prelude::*, domain::prelude::*,
        parameter::prelude::*, peer::prelude::*, permission::prelude::*, role::prelude::*,
        trigger::prelude::*, MetadataPredicateBox, PublicKeyPredicateBox, StringPredicateBox,
    };
}
