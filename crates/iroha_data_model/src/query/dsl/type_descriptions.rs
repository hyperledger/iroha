//! This module contains definitions of prototypes and projections for the data model types. See the [module-level documentation](crate::query::dsl) for more information.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use derive_where::derive_where;
use iroha_crypto::{HashOf, PublicKey};
use iroha_primitives::{json::Json, numeric::Numeric};

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
    query::{
        error::{FindError, QueryExecutionFail},
        CommittedTransaction, QueryOutputBatchBox,
    },
    role::{Role, RoleId},
    transaction::{error::TransactionRejectionReason, SignedTransaction},
    trigger::{action, Trigger, TriggerId},
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
                fn project_clone<'a>(&self, batch: impl Iterator<Item = &'a $ty>) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
                    match self {
                        $projection_name::Atom(_) => Ok(batch.cloned().collect::<Vec<_>>().into()),
                        $(
                            $projection_name::$proj_variant(field) => field.project_clone(batch.map(|item| &item.$field_name)),
                        )*
                    }
                }

                fn project(&self, batch: impl Iterator<Item = $ty>) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
                    match self {
                        $projection_name::Atom(_) => Ok(batch.collect::<Vec<_>>().into()),
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
        #[doc = concat!("A projector on [`", stringify!($ty), "`] for its `", stringify!($field_name), "` field.")]
        #[derive_where::derive_where(Default, Copy, Clone; Base)]
        pub struct $projector_name<Marker, Base> {
            base: Base,
            phantom: core::marker::PhantomData<Marker>
        }

        impl<Marker, Base> ObjectProjector<Marker> for $projector_name<Marker, Base>
        where
            Base: ObjectProjector<Marker, InputType = $ty>,
            $ty: Projectable<Marker>
            $($dep_ty_bounds)*
        {
            type InputType = $field_ty;
            type OutputType = Base::OutputType;

            fn project(
                &self,
                projection: <$field_ty as HasProjection<Marker>>::Projection
            ) -> <Self::OutputType as HasProjection<Marker>>::Projection {
                self.base.project($projection_name::$proj_variant(projection))
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
            #[allow(unused_variables)]
            const _:() = {
                let t: $ty;
                $($(let t: $dep_ty;)+)?
                $(let t: $field_ty;)*
            };

            // projection enum
            #[doc = concat!("A projection for the [`", stringify!($ty), "`] type.")]
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
                #[doc = "Finish the projection with an atom."]
                Atom(<$ty as Projectable<Marker>>::AtomType),
                $(
                    #[doc = concat!("Projection for the `", stringify!($field_name), "` field.")]
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
            #[doc = concat!("A prototype for the [`", stringify!($ty), "`] type.")]
            #[derive_where::derive_where(Default, Copy, Clone; Projector)]
            pub struct $prototype_name<Marker, Projector> {
                $(
                    // TODO: I think it might make sense to provide field documentation here. How would we do that without copying the docs to the type description macro though?
                    #[doc = concat!("Accessor for the `", stringify!($field_name), "` field.")]
                    pub $field_name: <$field_ty as HasPrototype>::Prototype<Marker, $projector_name<Marker, Projector>>,
                )*
                pub(super) projector: Projector,
                phantom: core::marker::PhantomData<Marker>,
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
                    self.projector.wrap_atom(())
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
    Account[AccountProjection, AccountPrototype]: AccountId, DomainId, Name, PublicKey, Metadata, Json {
        // field_name(ProjectionVariant, ProjectorName): FieldType
        id(Id, AccountIdProjector): AccountId,
        metadata(Metadata, AccountMetadataProjector): Metadata,
    }
    AccountId[AccountIdProjection, AccountIdPrototype]: DomainId, Name, PublicKey {
        domain(Domain, AccountIdDomainProjector): DomainId,
        signatory(Signatory, AccountIdSignatoryProjector): PublicKey,
    }

    // asset
    AssetDefinition[AssetDefinitionProjection, AssetDefinitionPrototype]: AssetDefinitionId, DomainId, Name, Metadata, Json {
        id(Id, AssetDefinitionIdProjector): AssetDefinitionId,
        metadata(Metadata, AssetDefinitionMetadataProjector): Metadata,
    }
    AssetDefinitionId[AssetDefinitionIdProjection, AssetDefinitionIdPrototype]: DomainId, Name {
        domain(Domain, AssetDefinitionIdDomainProjector): DomainId,
        name(Name, AssetDefinitionIdNameProjector): Name,
    }
    Asset[AssetProjection, AssetPrototype]: AssetId, AccountId, DomainId, Name, PublicKey, AssetDefinitionId, AssetValue, Numeric, Metadata, Json {
        id(Id, AssetIdProjector): AssetId,
        value(Value, AssetValueProjector): AssetValue,
    }
    AssetId[AssetIdProjection, AssetIdPrototype]: AccountId, DomainId, Name, PublicKey, AssetDefinitionId {
        account(Account, AssetIdAccountProjector): AccountId,
        definition(Definition, AssetIdDefinitionProjector): AssetDefinitionId,
    }
    #[custom_evaluate]
    AssetValue[AssetValueProjection, AssetValuePrototype]: Numeric, Metadata, Json {
        numeric(Numeric, AssetValueNumericProjector): Numeric,
        store(Store, AssetValueStoreProjector): Metadata,
    }

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
    Domain[DomainProjection, DomainPrototype]: DomainId, Name, Metadata, Json {
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
    Trigger[TriggerProjection, TriggerPrototype]: TriggerId, Name, action::Action, Metadata, Json {
        id(Id, TriggerIdProjector): TriggerId,
        action(Action, TriggerActionProjector): action::Action,
    }
    action::Action[ActionProjection, ActionPrototype]: Metadata, Json {
        metadata(Metadata, ActionMetadataProjector): Metadata,
    }

    // note: even though `NameProjection` and `StringProjection` are distinct types,
    // their predicates types are the same
    Name[NameProjection, NamePrototype] {}
    String[StringProjection, StringPrototype] {}

    PublicKey[PublicKeyProjection, PublicKeyPrototype] {}
    Json[JsonProjection, JsonPrototype] {}
    Numeric[NumericProjection, NumericPrototype] {}
}

/// A set of helpers for [`EvaluateSelector`] implementations that are fallible
mod fallible_selector {
    use crate::query::{
        dsl::{EvaluateSelector, HasProjection, SelectorMarker},
        error::QueryExecutionFail,
        QueryOutputBatchBox,
    };

    trait Collector<TOut> {
        fn collect(
            &self,
            iter: impl Iterator<Item = TOut>,
        ) -> Result<QueryOutputBatchBox, QueryExecutionFail>;
    }

    struct CollectorClone<'proj, T: HasProjection<SelectorMarker>>(&'proj T::Projection);

    impl<'a, T> Collector<&'a T> for CollectorClone<'_, T>
    where
        T: HasProjection<SelectorMarker> + 'static,
        T::Projection: EvaluateSelector<T>,
    {
        fn collect(
            &self,
            iter: impl Iterator<Item = &'a T>,
        ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
            self.0.project_clone(iter)
        }
    }

    struct CollectorNoClone<'proj, T: HasProjection<SelectorMarker>>(&'proj T::Projection);

    impl<T> Collector<T> for CollectorNoClone<'_, T>
    where
        T: HasProjection<SelectorMarker> + 'static,
        T::Projection: EvaluateSelector<T>,
    {
        fn collect(
            &self,
            iter: impl Iterator<Item = T>,
        ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
            self.0.project(iter)
        }
    }

    fn map_general<TIn, TOut, IterIn>(
        iterator: IterIn,
        map: impl Fn(TIn) -> Result<TOut, QueryExecutionFail>,
        collector: impl Collector<TOut>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail>
    where
        IterIn: Iterator<Item = TIn>,
    {
        // what we do here is a bit unwieldy
        // the `project_clone` method accepts an iterator over references to the items
        // however, while iterating over the metadatas we can find out that a key is missing
        // in this case we need to fail the whole operation and return an error
        // the `project_clone` by itself doesn't provide such a mechanism
        // but we can achieve this by storing an error indicator in a variable and checking it after the iteration
        let mut error_accumulator = None;

        let iter_out = iterator
            // we use map_while to stop on first error
            .map_while(|item| {
                let res = map(item);

                match res {
                    Ok(value) => Some(value),
                    Err(error) => {
                        error_accumulator.get_or_insert(error);
                        None
                    }
                }
            });
        let result = collector.collect(iter_out);

        // errors on this layer of projection take precedence
        if let Some(error) = error_accumulator {
            return Err(error);
        }

        result
    }

    pub fn map<TIn, TOut, IterIn>(
        iterator: IterIn,
        map: impl Fn(TIn) -> Result<TOut, QueryExecutionFail>,
        proj: &TOut::Projection,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail>
    where
        IterIn: Iterator<Item = TIn>,
        TOut: HasProjection<SelectorMarker> + 'static,
        TOut::Projection: EvaluateSelector<TOut>,
    {
        map_general(iterator, map, CollectorNoClone(proj))
    }

    pub fn map_clone<'a, TIn, TOut, IterIn>(
        iterator: IterIn,
        map: impl Fn(TIn) -> Result<&'a TOut, QueryExecutionFail>,
        proj: &TOut::Projection,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail>
    where
        IterIn: Iterator<Item = TIn>,
        TOut: HasProjection<SelectorMarker> + 'static,
        TOut::Projection: EvaluateSelector<TOut>,
    {
        map_general(iterator, map, CollectorClone(proj))
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
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            BlockHeaderProjection::Atom(_) => Ok(batch.cloned().collect::<Vec<_>>().into()),
            BlockHeaderProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
        }
    }

    fn project(
        &self,
        batch: impl Iterator<Item = BlockHeader>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            BlockHeaderProjection::Atom(_) => Ok(batch.collect::<Vec<_>>().into()),
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
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            SignedBlockProjection::Atom(_) => Ok(batch.cloned().collect::<Vec<_>>().into()),
            SignedBlockProjection::Header(header) => {
                header.project(batch.map(|item| item.header()))
            }
        }
    }

    fn project(
        &self,
        batch: impl Iterator<Item = SignedBlock>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            SignedBlockProjection::Atom(_) => Ok(batch.collect::<Vec<_>>().into()),
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
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            SignedTransactionProjection::Atom(_) => Ok(batch.cloned().collect::<Vec<_>>().into()),
            SignedTransactionProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
            SignedTransactionProjection::Authority(authority) => {
                authority.project_clone(batch.map(|item| item.authority()))
            }
        }
    }

    fn project(
        &self,
        batch: impl Iterator<Item = SignedTransaction>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            SignedTransactionProjection::Atom(_) => Ok(batch.collect::<Vec<_>>().into()),
            SignedTransactionProjection::Hash(hash) => hash.project(batch.map(|item| item.hash())),
            SignedTransactionProjection::Authority(authority) => {
                authority.project(batch.map(|item| item.authority().clone()))
            }
        }
    }
}

impl EvaluatePredicate<AssetValue> for AssetValueProjection<PredicateMarker> {
    fn applies(&self, input: &AssetValue) -> bool {
        match self {
            AssetValueProjection::Atom(atom) => atom.applies(input),
            AssetValueProjection::Numeric(numeric) => match input {
                AssetValue::Numeric(v) => numeric.applies(v),
                AssetValue::Store(_) => false,
            },
            AssetValueProjection::Store(store) => match input {
                AssetValue::Numeric(_) => false,
                AssetValue::Store(v) => store.applies(v),
            },
        }
    }
}

impl EvaluateSelector<AssetValue> for AssetValueProjection<SelectorMarker> {
    #[expect(single_use_lifetimes)]
    fn project_clone<'a>(
        &self,
        batch: impl Iterator<Item = &'a AssetValue>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            AssetValueProjection::Atom(_) => Ok(batch.cloned().collect::<Vec<_>>().into()),
            AssetValueProjection::Numeric(proj) => fallible_selector::map_clone(
                batch,
                |item| match item {
                    AssetValue::Numeric(v) => Ok(v),
                    AssetValue::Store(_) => Err(QueryExecutionFail::Conversion(
                        "Expected numeric value, got store".to_string(),
                    )),
                },
                proj,
            ),
            AssetValueProjection::Store(proj) => fallible_selector::map_clone(
                batch,
                |item| match item {
                    AssetValue::Numeric(_) => Err(QueryExecutionFail::Conversion(
                        "Expected store value, got numeric".to_string(),
                    )),
                    AssetValue::Store(v) => Ok(v),
                },
                proj,
            ),
        }
    }

    fn project(
        &self,
        batch: impl Iterator<Item = AssetValue>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            AssetValueProjection::Atom(_) => Ok(batch.collect::<Vec<_>>().into()),
            AssetValueProjection::Numeric(proj) => fallible_selector::map(
                batch,
                |item| match item {
                    AssetValue::Numeric(v) => Ok(v),
                    AssetValue::Store(_) => Err(QueryExecutionFail::Conversion(
                        "Expected numeric value, got store".to_string(),
                    )),
                },
                proj,
            ),
            AssetValueProjection::Store(proj) => fallible_selector::map(
                batch,
                |item| match item {
                    AssetValue::Numeric(_) => Err(QueryExecutionFail::Conversion(
                        "Expected store value, got numeric".to_string(),
                    )),
                    AssetValue::Store(v) => Ok(v),
                },
                proj,
            ),
        }
    }
}

// metadata is a special case because we allow projecting on string-typed keys
/// A projection for the [`Metadata`] type.
#[derive_where(Debug, Eq, PartialEq, Copy, Clone; <Metadata as Projectable<Marker>>::AtomType, MetadataKeyProjection<Marker>)]
// parity-scale-codec and iroha_schema generates correct bounds by themselves
#[derive(parity_scale_codec::Decode, parity_scale_codec::Encode, iroha_schema::IntoSchema)]
// use serde_where macro to generate the correct #[serde(bounds(...))] attribute
#[iroha_macro::serde_where(<Metadata as Projectable<Marker>>::AtomType, MetadataKeyProjection<Marker>)]
#[derive(serde::Deserialize, serde::Serialize)]
pub enum MetadataProjection<Marker>
where
    Metadata: Projectable<Marker>,
    Json: HasProjection<Marker>,
{
    /// Finish the projection with an atom.
    Atom(<Metadata as Projectable<Marker>>::AtomType),
    // unlike other projections, this one needs to store a value (key being projected)
    // hence the separate struct (iroha does not allow enums with more than one field)
    /// Projection for a key in the metadata.
    Key(MetadataKeyProjection<Marker>),
}

/// A projection for a key in the [`Metadata`] type.
#[derive_where(Debug, Eq, PartialEq, Clone; <Json as HasProjection<Marker>>::Projection)]
// parity-scale-codec and iroha_schema generates correct bounds by themselves
#[derive(parity_scale_codec::Decode, parity_scale_codec::Encode, iroha_schema::IntoSchema)]
// use serde_where macro to generate the correct #[serde(bounds(...))] attribute
#[iroha_macro::serde_where(<Json as HasProjection<Marker>>::Projection)]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct MetadataKeyProjection<Marker>
where
    Json: HasProjection<Marker>,
{
    key: Name,
    projection: <Json as HasProjection<Marker>>::Projection,
}

impl<Marker> HasProjection<Marker> for Metadata
where
    Metadata: Projectable<Marker>,
    Json: HasProjection<Marker>,
{
    type Projection = MetadataProjection<Marker>;

    fn atom(atom: Self::AtomType) -> Self::Projection {
        MetadataProjection::Atom(atom)
    }
}
impl EvaluatePredicate<Metadata> for MetadataProjection<PredicateMarker> {
    fn applies(&self, input: &Metadata) -> bool {
        match self {
            MetadataProjection::Atom(atom) => atom.applies(input),
            MetadataProjection::Key(proj) => input
                .get(&proj.key)
                .map_or(false, |value| proj.projection.applies(value)),
        }
    }
}
impl EvaluateSelector<Metadata> for MetadataProjection<SelectorMarker> {
    #[expect(single_use_lifetimes)]
    fn project_clone<'a>(
        &self,
        batch: impl Iterator<Item = &'a Metadata>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            MetadataProjection::Atom(_) => Ok(batch.cloned().collect::<Vec<_>>().into()),
            MetadataProjection::Key(proj) => fallible_selector::map_clone(
                batch,
                |item| {
                    item.get(&proj.key).ok_or_else(|| {
                        QueryExecutionFail::Find(FindError::MetadataKey(proj.key.clone()))
                    })
                },
                &proj.projection,
            ),
        }
    }
    fn project(
        &self,
        batch: impl Iterator<Item = Metadata>,
    ) -> Result<QueryOutputBatchBox, QueryExecutionFail> {
        match self {
            MetadataProjection::Atom(_) => Ok(batch.collect::<Vec<_>>().into()),
            MetadataProjection::Key(proj) => fallible_selector::map(
                batch,
                |item| {
                    // using remove here to get a value, not a reference
                    item.get(&proj.key).cloned().ok_or_else(|| {
                        QueryExecutionFail::Find(FindError::MetadataKey(proj.key.clone()))
                    })
                },
                &proj.projection,
            ),
        }
    }
}

/// A prototype for the [`Metadata`] type.
#[derive_where(Default, Copy, Clone; Projector)]
pub struct MetadataPrototype<Marker, Projector> {
    projector: Projector,
    phantom: core::marker::PhantomData<Marker>,
}

impl HasPrototype for Metadata {
    type Prototype<Marker, Projector> = MetadataPrototype<Marker, Projector>;
}
impl<Projector> IntoSelector for MetadataPrototype<SelectorMarker, Projector>
where
    Projector: ObjectProjector<SelectorMarker, InputType = Metadata>,
    Projector::OutputType: HasProjection<SelectorMarker, AtomType = ()>,
{
    type SelectingType = Projector::OutputType;
    type SelectedType = Projector::InputType;

    fn into_selector(self) -> <Projector::OutputType as HasProjection<SelectorMarker>>::Projection {
        self.projector.wrap_atom(())
    }
}

impl<Marker, Projector> MetadataPrototype<Marker, Projector>
where
    Projector: ObjectProjector<Marker, InputType = Metadata>,
{
    /// Accessor for a key in the metadata.
    ///
    /// ## Nonexistent keys
    ///
    /// When a nonexistent key is accessed in a predicate, it will evaluate to `false`.
    ///
    /// When a nonexistent key is accessed in a selector, the query will fail with a [`FindError::MetadataKey`] error.
    pub fn key(self, key: Name) -> JsonPrototype<Marker, MetadataKeyProjector<Marker, Projector>> {
        JsonPrototype {
            projector: MetadataKeyProjector {
                key,
                base: self.projector,
                phantom: core::marker::PhantomData,
            },
            phantom: core::marker::PhantomData,
        }
    }
}

/// A projector on [`Metadata`] for one of its keys.
pub struct MetadataKeyProjector<Marker, Base> {
    key: Name,
    base: Base,
    phantom: core::marker::PhantomData<Marker>,
}

impl<Marker, Base> ObjectProjector<Marker> for MetadataKeyProjector<Marker, Base>
where
    Base: ObjectProjector<Marker, InputType = Metadata>,
    Json: Projectable<Marker>,
    Metadata: Projectable<Marker>,
{
    type InputType = Json;
    type OutputType = Base::OutputType;

    fn project(
        &self,
        projection: <Json as HasProjection<Marker>>::Projection,
    ) -> <Self::OutputType as HasProjection<Marker>>::Projection {
        self.base
            .project(MetadataProjection::Key(MetadataKeyProjection {
                key: self.key.clone(),
                projection,
            }))
    }
}

pub mod prelude {
    //! Re-export all projections for a glob import `(::*)`
    pub use super::{projections::*, MetadataKeyProjection, MetadataProjection};
}
