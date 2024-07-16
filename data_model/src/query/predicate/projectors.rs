//! Defines projectors and projections for predicates DSL.
//!
//! Projection is an AST predicate combinator that changes the type of the inner predicate by wrapping it in a projection variant on normalization.
//!
//! Projector is a helper struct implementing the [`ObjectProjector`] trait that applies the projection.

use core::marker::PhantomData;

use super::{AstPredicate, CompoundPredicate};
use crate::query::predicate::{
    predicate_atoms::{
        account::{AccountIdPredicateBox, AccountPredicateBox},
        asset::{
            AssetDefinitionIdPredicateBox, AssetDefinitionPredicateBox, AssetIdPredicateBox,
            AssetPredicateBox, AssetValuePredicateBox,
        },
        domain::{DomainIdPredicateBox, DomainPredicateBox},
        role::{RoleIdPredicateBox, RolePredicateBox},
        trigger::{TriggerIdPredicateBox, TriggerPredicateBox},
        MetadataPredicateBox, PublicKeyPredicateBox, StringPredicateBox,
    },
    predicate_combinators::{AndAstPredicate, NotAstPredicate, OrAstPredicate},
};

/// Describes how to convert `AstPredicate<Input>` to `AstPredicate<Output>` by wrapping them in some projection predicate combinator.
pub trait ObjectProjector: Default + Copy + Clone {
    /// The type of the input atomic predicate (the more concrete type).
    type Input;
    /// The type of the output atomic predicate (the more general type).
    type Output;

    /// The type of result of projecting `P` AST predicate.
    type ProjectedPredicate<P: AstPredicate<Self::Input>>: AstPredicate<Self::Output>;

    /// Project the given predicate.
    fn project_predicate<P: AstPredicate<Self::Input>>(predicate: P)
        -> Self::ProjectedPredicate<P>;
}

/// An [`ObjectProjector`] that does not change the type, serving as a base case for the recursion.
pub struct BaseProjector<T>(PhantomData<T>);

// manual implementation of traits to not add bounds on `T`
impl<T> Default for BaseProjector<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> Copy for BaseProjector<T> {}

impl<T> Clone for BaseProjector<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> ObjectProjector for BaseProjector<T> {
    type Input = T;
    type Output = T;
    type ProjectedPredicate<P: AstPredicate<T>> = P;

    fn project_predicate<P: AstPredicate<T>>(predicate: P) -> Self::ProjectedPredicate<P> {
        predicate
    }
}

/// A helper macro to define a projector and a projection
macro_rules! proj {
    ($projector:ident($projection:ident): $in_predicate:ident => $out_predicate:ident::$proj_variant:ident) => {
        #[doc = "An AST predicate that projects [`"]
        #[doc = stringify!($in_predicate)]
        #[doc = "`] to [`"]
        #[doc = stringify!($out_predicate)]
        #[doc = "`] by wrapping it in [`"]
        #[doc = concat!(stringify!($out_predicate), "::", stringify!($proj_variant))]
        #[doc = "`]."]
        #[derive(Default, Copy, Clone)]
        pub struct $projection<P>(P);

        impl<P> AstPredicate<$out_predicate> for $projection<P>
        where
            P: AstPredicate<$in_predicate>,
        {
            fn normalize_with_proj<OutputType, Proj>(
                self,
                proj: Proj,
            ) -> CompoundPredicate<OutputType>
            where
                Proj: Fn($out_predicate) -> OutputType + Copy,
            {
                self.0
                    .normalize_with_proj(|p| proj($out_predicate::$proj_variant(p)))
            }
        }

        impl<P> core::ops::Not for $projection<P>
        where
            Self: AstPredicate<$out_predicate>,
        {
            type Output = NotAstPredicate<Self>;

            fn not(self) -> Self::Output {
                NotAstPredicate(self)
            }
        }

        impl<P, PRhs> core::ops::BitAnd<PRhs> for $projection<P>
        where
            Self: AstPredicate<$out_predicate>,
            PRhs: AstPredicate<$out_predicate>,
        {
            type Output = AndAstPredicate<Self, PRhs>;

            fn bitand(self, rhs: PRhs) -> Self::Output {
                AndAstPredicate(self, rhs)
            }
        }

        impl<P, PRhs> core::ops::BitOr<PRhs> for $projection<P>
        where
            Self: AstPredicate<$out_predicate>,
            PRhs: AstPredicate<$out_predicate>,
        {
            type Output = OrAstPredicate<Self, PRhs>;

            fn bitor(self, rhs: PRhs) -> Self::Output {
                OrAstPredicate(self, rhs)
            }
        }

        #[doc = "An [`ObjectProjector`] that applies [`"]
        #[doc = stringify!($projection)]
        #[doc = "`]."]
        #[derive(Default, Copy, Clone)]
        pub struct $projector<Base>(PhantomData<Base>);

        impl<Base: ObjectProjector<Input = $out_predicate>> ObjectProjector for $projector<Base> {
            type Input = $in_predicate;
            type Output = Base::Output;
            type ProjectedPredicate<P: AstPredicate<Self::Input>> =
                Base::ProjectedPredicate<$projection<P>>;

            fn project_predicate<P: AstPredicate<Self::Input>>(
                predicate: P,
            ) -> Self::ProjectedPredicate<P> {
                Base::project_predicate($projection(predicate))
            }
        }
    };
}

// projections on AccountId
proj!(AccountIdDomainIdProjector(AccountIdDomainIdProjection): DomainIdPredicateBox => AccountIdPredicateBox::DomainId);
proj!(AccountIdSignatoryProjector(AccountIdSignatoryProjection): PublicKeyPredicateBox => AccountIdPredicateBox::Signatory);

// projections on Account
proj!(AccountIdProjector(AccountIdProjection): AccountIdPredicateBox => AccountPredicateBox::Id);
proj!(AccountMetadataProjector(AccountMetadataProjection): MetadataPredicateBox => AccountPredicateBox::Metadata);

// projections on AssetDefinitionId
proj!(AssetDefinitionIdDomainIdProjector(AssetDefinitionIdDomainIdProjection): DomainIdPredicateBox => AssetDefinitionIdPredicateBox::DomainId);
proj!(AssetDefinitionIdNameProjector(AssetDefinitionIdNameProjection): StringPredicateBox => AssetDefinitionIdPredicateBox::Name);

// projections on AssetId
proj!(AssetIdDefinitionIdProjector(AssetIdDefinitionIdProjection): AssetDefinitionIdPredicateBox => AssetIdPredicateBox::DefinitionId);
proj!(AssetIdAccountIdProjector(AssetIdAccountIdProjection): AccountIdPredicateBox => AssetIdPredicateBox::AccountId);

// projections in AssetDefinition
proj!(AssetDefinitionIdProjector(AssetDefinitionIdProjection): AssetDefinitionIdPredicateBox => AssetDefinitionPredicateBox::Id);
proj!(AssetDefinitionMetadataProjector(AssetDefinitionMetadataProjection): MetadataPredicateBox => AssetDefinitionPredicateBox::Metadata);

// projections on Asset
proj!(AssetIdProjector(AssetIdProjection): AssetIdPredicateBox => AssetPredicateBox::Id);
proj!(AssetValueProjector(AssetValueProjection): AssetValuePredicateBox => AssetPredicateBox::Value);

// projections on DomainId
proj!(DomainIdNameProjector(DomainIdNameProjection): StringPredicateBox => DomainIdPredicateBox::Name);

// projections on Domain
proj!(DomainIdProjector(DomainIdProjection): DomainIdPredicateBox => DomainPredicateBox::Id);
proj!(DomainMetadataProjector(DomainMetadataProjection): MetadataPredicateBox => DomainPredicateBox::Metadata);

// projections on RoleId
proj!(RoleIdNameProjector(RoleIdNameProjection): StringPredicateBox => RoleIdPredicateBox::Name);

// projections on Role
proj!(RoleIdProjector(RoleIdProjection): RoleIdPredicateBox => RolePredicateBox::Id);

// projections in TriggerId
proj!(TriggerIdNameProjector(TriggerIdNameProjection): StringPredicateBox => TriggerIdPredicateBox::Name);

// projections in Trigger
proj!(TriggerIdProjector(TriggerIdProjection): TriggerIdPredicateBox => TriggerPredicateBox::Id);
