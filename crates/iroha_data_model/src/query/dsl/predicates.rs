//! This module contains predicate definitions for all queryable types. See the [module-level documentation](crate::query::dsl) for more information.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_crypto::{HashOf, PublicKey};
use iroha_primitives::{json::Json, numeric::Numeric};

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
        dsl::{
            type_descriptions::{
                AccountIdPrototype, AccountPrototype, ActionPrototype, AssetDefinitionIdPrototype,
                AssetDefinitionPrototype, AssetIdPrototype, AssetPrototype, AssetValuePrototype,
                BlockHeaderHashPrototype, BlockHeaderPrototype, CommittedTransactionPrototype,
                DomainIdPrototype, DomainPrototype, JsonPrototype, MetadataPrototype,
                NamePrototype, NumericPrototype, ParameterPrototype, PeerIdPrototype,
                PermissionPrototype, PublicKeyPrototype, RoleIdPrototype, RolePrototype,
                SignedBlockPrototype, SignedTransactionPrototype, StringPrototype,
                TransactionErrorPrototype, TransactionHashPrototype, TriggerIdPrototype,
                TriggerPrototype,
            },
            CompoundPredicate, ObjectProjector, PredicateMarker,
        },
        CommittedTransaction,
    },
    role::{Role, RoleId},
    transaction::{error::TransactionRejectionReason, SignedTransaction},
    trigger::{action, Trigger, TriggerId},
};

macro_rules! impl_predicate_atom {
    (@impl_evaluate_for_all_types $atom_name:ident $input_name:ident ($($ty_name:ty),*) $body:expr) => {
        $(
            impl crate::query::dsl::EvaluatePredicate<$ty_name> for $atom_name {
                fn applies(&self, $input_name: &$ty_name) -> bool {
                    ($body)(self)
                }
            }
        )*
    };
    (
        $(
            $(#[$($atom_attrs:tt)*])*
            $atom_name:ident($input_name:ident: $ty_name:ty) [$prototype_name:ident] {
                $(
                    $(#[$($variant_attrs:tt)*])*
                    $variant_name:ident$(($variant_pat:ident: $variant_ty:ty))? [$constructor_name:ident] => $variant_expr:expr
                ),*
                $(,)?
            }
        )*
    ) => {
        $(
            #[doc = concat!("At atomic predicate on [`", stringify!($ty_name), "`]")]
            #[derive(
                Debug, Clone, PartialEq, Eq,
                parity_scale_codec::Decode, parity_scale_codec::Encode, serde::Deserialize, serde::Serialize, iroha_schema::IntoSchema
            )]
            // we can't know whether the atom can implement `Copy` or not in this macro
            // it's also better for future compatibility, since adding branches can make the atom non-`Copy`
            #[allow(missing_copy_implementations)]
            $(#[$($atom_attrs)*])*
            pub enum $atom_name {
                $(
                    $(#[$($variant_attrs)*])*
                    $variant_name$(($variant_ty))?,
                )*
            }


            impl crate::query::dsl::HasPredicateAtom for $ty_name {
                type Predicate = $atom_name;
            }

            // cannot directly put all of the impl blocks here, because rust gets confused with repetitions over $variant_* not being enclosed by repetitions over $ty_name
            impl_predicate_atom!{ @impl_evaluate_for_all_types $atom_name $input_name ($ty_name)
                // can't use `self` directly because of the macro hygiene, hence using a closure instead
                |this: &$atom_name| match *this {
                    $($atom_name::$variant_name$((ref $variant_pat))? => $variant_expr,)*
                }
            }

            // add constructor methods on the prototype
            impl<Projector> $prototype_name<PredicateMarker, Projector>
            where
                Projector: ObjectProjector<PredicateMarker, InputType = $ty_name>,
            {
                $(
                    $(#[$($variant_attrs)*])*
                    pub fn $constructor_name(self $(, $variant_pat: $variant_ty)?) -> CompoundPredicate<Projector::OutputType> {
                        CompoundPredicate::Atom(self.projector.wrap_atom(
                            $atom_name::$variant_name$(($variant_pat))?
                        ))
                    }
                )*
            }
        )*
    };
}

/// An atomic predicate on [`String`] or [`Name`]
// Defined separately because it is shared between [String] and [Name]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    parity_scale_codec::Decode,
    parity_scale_codec::Encode,
    serde::Deserialize,
    serde::Serialize,
    iroha_schema::IntoSchema,
)]
pub enum StringPredicateAtom {
    /// Checks if the input is equal to the expected value.
    Equals(String),
    /// Checks if the input contains an expected substring, like [`str::contains()`].
    Contains(String),
    /// Checks if the input starts with an expected substring, like [`str::starts_with()`].
    StartsWith(String),
    /// Checks if the input ends with an expected substring, like [`str::ends_with()`].
    EndsWith(String),
}

impl super::HasPredicateAtom for String {
    type Predicate = StringPredicateAtom;
}

impl super::HasPredicateAtom for Name {
    type Predicate = StringPredicateAtom;
}

impl StringPredicateAtom {
    fn applies_to_str(&self, input: &str) -> bool {
        match self {
            StringPredicateAtom::Equals(content) => input == content,
            StringPredicateAtom::Contains(content) => input.contains(content),
            StringPredicateAtom::StartsWith(content) => input.starts_with(content),
            StringPredicateAtom::EndsWith(content) => input.ends_with(content),
        }
    }
}

impl super::EvaluatePredicate<String> for StringPredicateAtom {
    fn applies(&self, input: &String) -> bool {
        self.applies_to_str(input.as_str())
    }
}

impl super::EvaluatePredicate<Name> for StringPredicateAtom {
    fn applies(&self, input: &Name) -> bool {
        self.applies_to_str(input.as_ref())
    }
}

// It is unfortunate that we have to repeat the prototype methods on String and Name, but I don't think it's possible to remove this duplication
impl<Projector> StringPrototype<PredicateMarker, Projector>
where
    Projector: ObjectProjector<PredicateMarker, InputType = String>,
{
    /// Checks if the input is equal to the expected value.
    pub fn eq(self, expected: impl Into<String>) -> CompoundPredicate<Projector::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::Equals(expected.into())),
        )
    }

    /// Checks if the input contains an expected substring, like [`str::contains()`].
    pub fn contains(self, expected: impl Into<String>) -> CompoundPredicate<Projector::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::Contains(expected.into())),
        )
    }

    /// Checks if the input starts with an expected substring, like [`str::starts_with()`].
    pub fn starts_with(
        self,
        expected: impl Into<String>,
    ) -> CompoundPredicate<Projector::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::StartsWith(expected.into())),
        )
    }

    /// Checks if the input ends with an expected substring, like [`str::ends_with()`].
    pub fn ends_with(
        self,
        expected: impl Into<String>,
    ) -> CompoundPredicate<Projector::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::EndsWith(expected.into())),
        )
    }
}

impl<Projection> NamePrototype<PredicateMarker, Projection>
where
    Projection: ObjectProjector<PredicateMarker, InputType = Name>,
{
    /// Checks if the input is equal to the expected value.
    pub fn eq(self, expected: impl Into<String>) -> CompoundPredicate<Projection::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::Equals(expected.into())),
        )
    }

    /// Checks if the input contains an expected substring, like [`str::contains()`].
    pub fn contains(
        self,
        expected: impl Into<String>,
    ) -> CompoundPredicate<Projection::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::Contains(expected.into())),
        )
    }

    /// Checks if the input starts with an expected substring, like [`str::starts_with()`].
    pub fn starts_with(
        self,
        expected: impl Into<String>,
    ) -> CompoundPredicate<Projection::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::StartsWith(expected.into())),
        )
    }

    /// Checks if the input ends with an expected substring, like [`str::ends_with()`].
    pub fn ends_with(
        self,
        expected: impl Into<String>,
    ) -> CompoundPredicate<Projection::OutputType> {
        CompoundPredicate::Atom(
            self.projector
                .wrap_atom(StringPredicateAtom::EndsWith(expected.into())),
        )
    }
}

impl_predicate_atom! {
    MetadataPredicateAtom(_input: Metadata) [MetadataPrototype] {
        // TODO: populate
    }
    PublicKeyPredicateAtom(input: PublicKey) [PublicKeyPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: PublicKey) [eq] => input == expected,
    }
    JsonPredicateAtom(input: Json) [JsonPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: Json) [eq] => input == expected,
    }
    NumericPredicateAtom(_input: Numeric) [NumericPrototype] {
        // TODO: populate
    }

    // account
    AccountIdPredicateAtom(input: AccountId) [AccountIdPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: AccountId) [eq] => input == expected,
    }
    AccountPredicateAtom(_input: Account) [AccountPrototype] {}

    // asset
    AssetDefinitionPredicateAtom(_input: AssetDefinition) [AssetDefinitionPrototype] {}
    AssetPredicateAtom(_input: Asset) [AssetPrototype] {}
    AssetValuePredicateAtom(input: AssetValue) [AssetValuePrototype] {
        /// Checks if the asset value is numeric
        IsNumeric [is_numeric] => matches!(input, AssetValue::Numeric(_)),
        /// Checks if the asset value is a store
        IsStore [is_store] => matches!(input, AssetValue::Store(_)),
    }
    AssetIdPredicateAtom(input: AssetId) [AssetIdPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: AssetId) [eq] => input == expected,
    }
    AssetDefinitionIdPredicateAtom(input: AssetDefinitionId) [AssetDefinitionIdPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: AssetDefinitionId) [eq] => input == expected,
    }

    // block
    BlockHeaderHashPredicateAtom(input: HashOf<BlockHeader>) [BlockHeaderHashPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: HashOf<BlockHeader>) [eq] => input == expected,
    }
    BlockHeaderPredicateAtom(_input: BlockHeader) [BlockHeaderPrototype] {}
    SignedBlockPredicateAtom(_input: SignedBlock) [SignedBlockPrototype] {}
    TransactionHashPredicateAtom(input: HashOf<SignedTransaction>) [TransactionHashPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: HashOf<SignedTransaction>) [eq] => input == expected,
    }
    SignedTransactionPredicateAtom(_input: SignedTransaction) [SignedTransactionPrototype] {}
    TransactionErrorPredicateAtom(input: Option<TransactionRejectionReason>) [TransactionErrorPrototype] {
        /// Checks if there was an error while applying the transaction.
        IsSome [is_some] => input.is_some(),
    }
    CommittedTransactionPredicateAtom(_input: CommittedTransaction) [CommittedTransactionPrototype] {}

    // domain
    DomainPredicateAtom(_input: Domain) [DomainPrototype] {}
    DomainIdPredicateAtom(input: DomainId) [DomainIdPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: DomainId) [eq] => input == expected,
    }

    // peer
    PeerIdPredicateAtom(_input: PeerId) [PeerIdPrototype] {}

    // permission
    PermissionPredicateAtom(_input: Permission) [PermissionPrototype] {}

    // parameter
    ParameterPredicateAtom(_input: Parameter) [ParameterPrototype] {}

    // role
    RoleIdPredicateAtom(input: RoleId) [RoleIdPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: RoleId) [eq] => input == expected,
    }
    RolePredicateAtom(_input: Role) [RolePrototype] {}

    // trigger
    TriggerIdPredicateAtom(input: TriggerId) [TriggerIdPrototype] {
        /// Checks if the input is equal to the expected value.
        Equals(expected: TriggerId) [eq] => input == expected,
    }
    TriggerPredicateAtom(_input: Trigger) [TriggerPrototype] {}
    ActionPredicateAtom(_input: action::Action) [ActionPrototype] {}
}

pub mod prelude {
    //! Re-export all predicate boxes for a glob import `(::*)`
    pub use super::{
        AccountIdPredicateAtom, AccountPredicateAtom, ActionPredicateAtom,
        AssetDefinitionIdPredicateAtom, AssetDefinitionPredicateAtom, AssetIdPredicateAtom,
        AssetPredicateAtom, AssetValuePredicateAtom, BlockHeaderHashPredicateAtom,
        BlockHeaderPredicateAtom, CommittedTransactionPredicateAtom, DomainIdPredicateAtom,
        DomainPredicateAtom, JsonPredicateAtom, MetadataPredicateAtom, NumericPredicateAtom,
        ParameterPredicateAtom, PeerIdPredicateAtom, PermissionPredicateAtom,
        PublicKeyPredicateAtom, RoleIdPredicateAtom, RolePredicateAtom, SignedBlockPredicateAtom,
        SignedTransactionPredicateAtom, StringPredicateAtom, TransactionErrorPredicateAtom,
        TransactionHashPredicateAtom, TriggerIdPredicateAtom, TriggerPredicateAtom,
    };
}
