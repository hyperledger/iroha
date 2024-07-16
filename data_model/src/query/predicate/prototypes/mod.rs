//! This module contains prototypes for all types predicates can be applied to. The prototypes are used to construct predicates.
//!
//! The prototypes are zero-sized types that mimic the shape of objects in the data model, allowing for an ergonomic way to construct predicates.

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
use alloc::string::String;
use core::marker::PhantomData;

use iroha_crypto::PublicKey;

use super::{projectors::ObjectProjector, AstPredicate, HasPrototype};
use crate::query::predicate::predicate_atoms::{
    MetadataPredicateBox, PublicKeyPredicateBox, StringPredicateBox,
};

macro_rules! impl_prototype {
    ($prototype:ident: $predicate:ty) => {
        impl<Projector> $prototype<Projector>
        where
            Projector: ObjectProjector<Input = $predicate>,
        {
            /// Creates a predicate that delegates to the given predicate.
            pub fn satisfies<P>(&self, predicate: P) -> Projector::ProjectedPredicate<P>
            where
                P: AstPredicate<$predicate>,
            {
                Projector::project_predicate(predicate)
            }
        }

        impl HasPrototype for $predicate {
            type Prototype<Projector: Default> = $prototype<Projector>;
        }
    };
}
pub(crate) use impl_prototype;

/// A prototype of [`String`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct StringPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(StringPrototype: StringPredicateBox);

impl<Projector> StringPrototype<Projector>
where
    Projector: ObjectProjector<Input = StringPredicateBox>,
{
    /// Creates a predicate that checks if the string is equal to the expected value.
    pub fn eq(
        &self,
        expected: impl Into<String>,
    ) -> Projector::ProjectedPredicate<StringPredicateBox> {
        Projector::project_predicate(StringPredicateBox::Equals(expected.into()))
    }

    /// Creates a predicate that checks if the string contains the expected value.
    pub fn contains(
        &self,
        expected: impl Into<String>,
    ) -> Projector::ProjectedPredicate<StringPredicateBox> {
        Projector::project_predicate(StringPredicateBox::Contains(expected.into()))
    }

    /// Creates a predicate that checks if the string starts with the expected value.
    pub fn starts_with(
        &self,
        expected: impl Into<String>,
    ) -> Projector::ProjectedPredicate<StringPredicateBox> {
        Projector::project_predicate(StringPredicateBox::StartsWith(expected.into()))
    }

    /// Creates a predicate that checks if the string ends with the expected value.
    pub fn ends_with(
        &self,
        expected: impl Into<String>,
    ) -> Projector::ProjectedPredicate<StringPredicateBox> {
        Projector::project_predicate(StringPredicateBox::EndsWith(expected.into()))
    }
}

/// A prototype of [`crate::metadata::Metadata`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct MetadataPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(MetadataPrototype: MetadataPredicateBox);

/// A prototype of [`PublicKey`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct PublicKeyPrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(PublicKeyPrototype: PublicKeyPredicateBox);

impl<Projector> PublicKeyPrototype<Projector>
where
    Projector: ObjectProjector<Input = PublicKeyPredicateBox>,
{
    /// Creates a predicate that checks if the public key is equal to the expected value.
    pub fn eq(&self, expected: PublicKey) -> Projector::ProjectedPredicate<PublicKeyPredicateBox> {
        Projector::project_predicate(PublicKeyPredicateBox::Equals(expected))
    }
}
