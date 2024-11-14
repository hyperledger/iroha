#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_where::derive_where;
use iroha_crypto::{HashOf, PublicKey};
use iroha_macro::serde_where;
use serde::{Deserialize, Serialize};

// used in the macro
use crate::query::dsl::{
    EvaluatePredicate, EvaluateSelector, HasProjection, HasPrototype, IntoSelector,
    ObjectProjector, PredicateMarker, Projectable, SelectorMarker,
};
use crate::{
    account::{Account, AccountId},
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId, AssetValue},
    block::{BlockHeader, SignedBlock},
    domain::{Domain, DomainId},
    metadata::Metadata,
    name::Name,
    parameter::Parameter,
    peer::PeerId,
    permission::Permission,
    query::{CommittedTransaction, QueryOutputBatchBox},
    role::{Role, RoleId},
    transaction::{error::TransactionRejectionReason, SignedTransaction},
    trigger::{Trigger, TriggerId},
};

macro_rules! type_descriptions {
    (@check_attrs) => {};
    (@check_attrs #[custom_evaluate] $($rest:tt)*) => {
        type_descriptions!(@check_attrs $($rest)*);
    };

    (@evaluate
        (#[custom_evaluate] $($rest:tt)*)
        ($ty:ty) $projection_name:ident
        ($($field_name:ident($proj_variant:ident))*)
    ) => {
        // the user has requested a custom evaluation impl, so do not derive it
    };
    (@evaluate
        ()
        ($ty:ty) $projection_name:ident
        ($($field_name:ident($proj_variant:ident))*)
    ) => {
        impl EvaluatePredicate<$ty> for $projection_name<PredicateMarker> {
            fn applies(&self, input: &$ty) -> bool {
                match self {
                    $projection_name::Atom(atom) => atom.applies(input),
                    $(
                        $projection_name::$proj_variant(field) => EvaluatePredicate::applies(field, &input.$field_name),
                    )*
                }
            }
        }

        impl EvaluateSelector<$ty> for $projection_name<SelectorMarker> {
                #[expect(single_use_lifetimes)] // FP, this the suggested change is not allowed on stable
                fn project_clone<'a>(&self, batch: impl Iterator<Item = &'a $ty>) -> QueryOutputBatchBox {
                    match self {
                        $projection_name::Atom(_) => batch.cloned().collect::<Vec<_>>().into(),
                        $(
                            $projection_name::$proj_variant(field) => field.project_clone(batch.map(|item| &item.$field_name)),
                        )*
                    }
                }

                fn project(&self, batch: impl Iterator<Item = $ty>) -> QueryOutputBatchBox {
                    match self {
                        $projection_name::Atom(_) => batch.collect::<Vec<_>>().into(),
                        $(
                            $projection_name::$proj_variant(field) => field.project(batch.map(|item| item.$field_name)),
                        )*
                    }
                }
        }
    };
    (@object_projector
        ($ty:ty) $projection_name:ident
        ($field_name:ident($proj_variant:ident, $projector_name:ident): $field_ty:ty)
        // unpack tt sequence back
        ($($dep_ty_bounds:tt)*)
    ) => {
        pub struct $projector_name<Marker, Base>(core::marker::PhantomData<(Marker, Base)>);

        impl<Marker, Base> ObjectProjector<Marker> for $projector_name<Marker, Base>
        where
            Base: ObjectProjector<Marker, InputType = $ty>,
            $ty: Projectable<Marker>
            $($dep_ty_bounds)*
        {
            type InputType = $field_ty;
            type OutputType = Base::OutputType;

            fn project(
                projection: <$field_ty as HasProjection<Marker>>::Projection
            ) -> <Self::OutputType as HasProjection<Marker>>::Projection {
                Base::project($projection_name::$proj_variant(projection))
            }
        }
    };
    (@object_projector_repeated
        ($ty:ty) $projection_name:ident
        ($(
            $field_name:ident($proj_variant:ident, $projector_name:ident): $field_ty:ty,
        )*)
        // smuggle a tt sequence as a single tt
        $dep_ty_bounds:tt
    ) => {
        $(
            type_descriptions!{ @object_projector ($ty) $projection_name
                ($field_name($proj_variant, $projector_name): $field_ty)
                $dep_ty_bounds
            }
        )*
    };

    ($(
        $(#[$($attrs:tt)*])*
        $ty:ty[$projection_name:ident, $prototype_name:ident] $(: $($dep_ty:ty),+)? {
        $(
            $field_name:ident($proj_variant:ident, $projector_name:ident): $field_ty:ty,
        )*
        }
    )*) => {
        $(
            type_descriptions!(@check_attrs $(#[$($attrs)*])*);

            // hints to the IDE that these are types
            const _:() = {
                let t: $ty;
                $($(let t: $dep_ty;)+)?
                $(let t: $field_ty;)*
            };

            // projection enum
            // use derive_where to generate trait bounds
            #[derive_where::derive_where(Debug, Eq, PartialEq, Copy, Clone;
                <$ty as Projectable<Marker>>::AtomType
                $(, <$field_ty as HasProjection<Marker>>::Projection)*
            )]
            // parity-scale-codec and iroha_schema generates correct bounds by themselves
            #[derive(parity_scale_codec::Decode, parity_scale_codec::Encode, iroha_schema::IntoSchema)]
            // use serde_where macro to generate the correct #[serde(bounds(...))] attribute
            #[iroha_macro::serde_where(
                <$ty as Projectable<Marker>>::AtomType
                $(, <$field_ty as HasProjection<Marker>>::Projection)*
            )]
            #[derive(serde::Deserialize, serde::Serialize)]
            pub enum $projection_name<Marker>
            where
                $ty: Projectable<Marker>
                $($(, $dep_ty: HasProjection<Marker>)*)?
            {
                Atom(<$ty as Projectable<Marker>>::AtomType),
                $(
                    $proj_variant(
                        <$field_ty as HasProjection<Marker>>::Projection
                    ),
                )*
            }

            impl<Marker> HasProjection<Marker> for $ty
            where
                $ty: Projectable<Marker>
                $($(, $dep_ty: HasProjection<Marker>)*)?
            {
                type Projection = $projection_name<Marker>;

                fn atom(atom: Self::AtomType) -> Self::Projection {
                    $projection_name::Atom(atom)
                }
            }

            type_descriptions!(@evaluate
                ($(#[$($attrs)*])*)
                ($ty) $projection_name
                ($($field_name($proj_variant))*)
            );

            // projector structs
            // because we need to repeat $dep_ty inside a disjoint repetition, use another macro
            type_descriptions!(@object_projector_repeated ($ty) $projection_name ($(
                $field_name($proj_variant, $projector_name): $field_ty,
            )*) ($(, $($dep_ty: Projectable<Marker>),*)?));

            // prototype struct
            #[derive_where::derive_where(Default, Copy, Clone)]
            pub struct $prototype_name<Marker, Projector> {
                $(
                    pub $field_name: <$field_ty as HasPrototype>::Prototype<Marker, $projector_name<Marker, Projector>>,
                )*
                phantom: core::marker::PhantomData<(Marker, Projector)>,
            }

            impl HasPrototype for $ty
            {
                type Prototype<Marker, Projector> = $prototype_name<Marker, Projector>;
            }

            impl<Projector> IntoSelector for $prototype_name<SelectorMarker, Projector>
            where
                Projector: ObjectProjector<SelectorMarker, InputType = $ty>,
                Projector::OutputType: HasProjection<SelectorMarker, AtomType = ()>,
            {
                type SelectingType = Projector::OutputType;
                type SelectedType = Projector::InputType;

                fn into_selector(self) -> <Projector::OutputType as HasProjection<SelectorMarker>>::Projection {
                    Projector::wrap_atom(())
                }
            }
        )*

        mod projections {
            $(
                pub use super::$projection_name;
            )*
        }
    };
}

type_descriptions! {
    // Type[ProjectionName, PrototypeName]: Dependency1, Dependency2, ...
    Account[AccountProjection, AccountPrototype]: AccountId, DomainId, Name, PublicKey, Metadata {
        // field_name(ProjectionVariant, ProjectorName): FieldType
        id(Id, AccountIdProjector): AccountId,
        metadata(Metadata, AccountMetadataProjector): Metadata,
    }
    AccountId[AccountIdProjection, AccountIdPrototype]: DomainId, Name, PublicKey {
        domain(Domain, AccountIdDomainProjector): DomainId,
        signatory(Signatory, AccountIdSignatoryProjector): PublicKey,
    }

    // asset
    AssetDefinition[AssetDefinitionProjection, AssetDefinitionPrototype]: AssetDefinitionId, DomainId, Name, Metadata {
        id(Id, AssetDefinitionIdProjector): AssetDefinitionId,
        metadata(Metadata, AssetDefinitionMetadataProjector): Metadata,
    }
    AssetDefinitionId[AssetDefinitionIdProjection, AssetDefinitionIdPrototype]: DomainId, Name {
        domain(Domain, AssetDefinitionIdDomainProjector): DomainId,
        name(Name, AssetDefinitionIdNameProjector): Name,
    }
    Asset[AssetProjection, AssetPrototype]: AssetId, AccountId, DomainId, Name, PublicKey, AssetDefinitionId, AssetValue {
        id(Id, AssetIdProjector): AssetId,
        value(Value, AssetValueProjector): AssetValue,
    }
    AssetId[AssetIdProjection, AssetIdPrototype]: AccountId, DomainId, Name, PublicKey, AssetDefinitionId {
        account(Account, AssetIdAccountProjector): AccountId,
        definition(Definition, AssetIdDefinitionProjector): AssetDefinitionId,
    }
    AssetValue[AssetValueProjection, AssetValuePrototype] {}

    // block
    HashOf<BlockHeader>[BlockHeaderHashProjection, BlockHeaderHashPrototype] {}
    #[custom_evaluate] // hash needs to be computed on-the-fly
    BlockHeader[BlockHeaderProjection, BlockHeaderPrototype]: HashOf<BlockHeader> {
        hash(Hash, BlockHeaderHashProjector): HashOf<BlockHeader>,
    }
    #[custom_evaluate] // SignedBlock is opaque, so `header` is a method
    SignedBlock[SignedBlockProjection, SignedBlockPrototype]: BlockHeader, HashOf<BlockHeader> {
        header(Header, SignedBlockHeaderProjector): BlockHeader,
    }
    HashOf<SignedTransaction>[TransactionHashProjection, TransactionHashPrototype] {}
    #[custom_evaluate] // hash needs to be computed on-the-fly
    SignedTransaction[SignedTransactionProjection, SignedTransactionPrototype]: HashOf<SignedTransaction>, AccountId, DomainId, Name, PublicKey {
        hash(Hash, SignedTransactionHashProjector): HashOf<SignedTransaction>,
        authority(Authority, SignedTransactionAuthorityProjector): AccountId,
    }
    Option<TransactionRejectionReason>[TransactionErrorProjection, TransactionErrorPrototype] {}
    CommittedTransaction[CommittedTransactionProjection, CommittedTransactionPrototype]: HashOf<BlockHeader>, SignedTransaction, HashOf<SignedTransaction>, AccountId, DomainId, Name, PublicKey, Option<TransactionRejectionReason> {
        block_hash(BlockHash, CommittedTransactionBlockHashProjector): HashOf<BlockHeader>,
        value(Value, CommittedTransactionValueProjector): SignedTransaction,
        error(Error, CommittedTransactionErrorProjector): Option<TransactionRejectionReason>,
    }

    // domain
    Domain[DomainProjection, DomainPrototype]: DomainId, Name, Metadata {
        id(Id, DomainIdProjector): DomainId,
        metadata(Metadata, DomainMetadataProjector): Metadata,
    }
    DomainId[DomainIdProjection, DomainIdPrototype]: Name {
        name(Name, DomainIdNameProjector): Name,
    }

    // peer
    PeerId[PeerIdProjection, PeerIdPrototype]: PublicKey {
        public_key(PublicKey, PeerIdPublicKeyProjector): PublicKey,
    }

    // permission
    Permission[PermissionProjection, PermissionPrototype] {}

    // parameter
    Parameter[ParameterProjection, ParameterPrototype] {}

    // role
    RoleId[RoleIdProjection, RoleIdPrototype]: Name {
        name(Name, RoleIdNameProjector): Name,
    }
    Role[RoleProjection, RolePrototype]: RoleId, Name {
        id(Id, RoleIdProjector): RoleId,
        // TODO: it would be nice to have predicate on permissions, but we do not support  predicates on collections yet
        // permissions(Permissions, RolePermissionsProjector): Permissions,
    }

    // trigger
    TriggerId[TriggerIdProjection, TriggerIdPrototype]: Name {
        name(Name, TriggerIdNameProjector): Name,
    }
    Trigger[TriggerProjection, TriggerPrototype]: TriggerId, Name {
        id(Id, TriggerIdProjector): TriggerId,
    }

    // note: even though `NameProjection` and `StringProjection` are distinct types,
    // their predicates types are the same
    Name[NameProjection, NamePrototype] {}
    String[StringProjection, StringPrototype] {}

    PublicKey[PublicKeyProjection, PublicKeyPrototype] {}
    Metadata[MetadataProjection, MetadataPrototype] {
        // TODO: we will probably want to have a special-cased metadata projection that allows accessing fields by string keys (because metadata is not statically typed)
    }
}

// evaluate implementations that could not be implemented in a macro
impl EvaluatePredicate<BlockHeader> for BlockHeaderProjection<PredicateMarker> {
    fn applies(&self, input: &BlockHeader) -> bool {
        match self {
            BlockHeaderProjection::Atom(atom) => atom.applies(input),
            BlockHeaderProjection::Hash(hash) => hash.applies(&input.hash()),
        }
    }
}

impl EvaluateSelector<BlockHeader> for BlockHeaderProjection<SelectorMarker> {
    #[expect(single_use_lifetimes)] // FP, this the suggested change is not allowed on stable
    fn project_clone<'a>(
        &self,
        batch: impl Iterator<Item = &'a BlockHeader>,
    ) -> QueryOutputBatchBox {
        match self {
            BlockHeaderProjection::Atom(_) => batch.cloned().collect::<Vec<_>>().into(),
            BlockHeaderProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
        }
    }

    fn project(&self, batch: impl Iterator<Item = BlockHeader>) -> QueryOutputBatchBox {
        match self {
            BlockHeaderProjection::Atom(_) => batch.collect::<Vec<_>>().into(),
            BlockHeaderProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
        }
    }
}

impl EvaluatePredicate<SignedBlock> for SignedBlockProjection<PredicateMarker> {
    fn applies(&self, input: &SignedBlock) -> bool {
        match self {
            SignedBlockProjection::Atom(atom) => atom.applies(input),
            SignedBlockProjection::Header(header) => header.applies(&input.header()),
        }
    }
}

impl EvaluateSelector<SignedBlock> for SignedBlockProjection<SelectorMarker> {
    #[expect(single_use_lifetimes)] // FP, this the suggested change is not allowed on stable
    fn project_clone<'a>(
        &self,
        batch: impl Iterator<Item = &'a SignedBlock>,
    ) -> QueryOutputBatchBox {
        match self {
            SignedBlockProjection::Atom(_) => batch.cloned().collect::<Vec<_>>().into(),
            SignedBlockProjection::Header(header) => {
                header.project(batch.map(|item| item.header()))
            }
        }
    }

    fn project(&self, batch: impl Iterator<Item = SignedBlock>) -> QueryOutputBatchBox {
        match self {
            SignedBlockProjection::Atom(_) => batch.collect::<Vec<_>>().into(),
            SignedBlockProjection::Header(header) => {
                header.project(batch.map(|item| item.header()))
            }
        }
    }
}

impl EvaluatePredicate<SignedTransaction> for SignedTransactionProjection<PredicateMarker> {
    fn applies(&self, input: &SignedTransaction) -> bool {
        match self {
            SignedTransactionProjection::Atom(atom) => atom.applies(input),
            SignedTransactionProjection::Hash(hash) => hash.applies(&input.hash()),
            SignedTransactionProjection::Authority(authority) => {
                authority.applies(&input.authority())
            }
        }
    }
}

impl EvaluateSelector<SignedTransaction> for SignedTransactionProjection<SelectorMarker> {
    #[expect(single_use_lifetimes)] // FP, this the suggested change is not allowed on stable
    fn project_clone<'a>(
        &self,
        batch: impl Iterator<Item = &'a SignedTransaction>,
    ) -> QueryOutputBatchBox {
        match self {
            SignedTransactionProjection::Atom(_) => batch.cloned().collect::<Vec<_>>().into(),
            SignedTransactionProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
            SignedTransactionProjection::Authority(authority) => {
                authority.project_clone(batch.map(|item| item.authority()))
            }
        }
    }

    fn project(&self, batch: impl Iterator<Item = SignedTransaction>) -> QueryOutputBatchBox {
        match self {
            SignedTransactionProjection::Atom(_) => batch.collect::<Vec<_>>().into(),
            SignedTransactionProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
            SignedTransactionProjection::Authority(authority) => {
                authority.project(batch.map(|item| item.authority().clone()))
            }
        }
    }
}

pub mod prelude {
    pub use super::projections::*;
}
