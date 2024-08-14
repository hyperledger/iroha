//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

use derive_more::Constructor;
use iroha_crypto::{PublicKey, SignatureOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_primitives::{json::JsonString, numeric::Numeric};
use iroha_schema::IntoSchema;
use iroha_version::prelude::*;
use parameters::{ForwardCursor, QueryParams, MAX_FETCH_SIZE};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use self::{
    account::*, asset::*, block::*, domain::*, executor::*, peer::*, permission::*, predicate::*,
    role::*, transaction::*, trigger::*,
};
use crate::{
    account::{Account, AccountId},
    asset::{Asset, AssetDefinition},
    block::{BlockHeader, SignedBlock},
    domain::Domain,
    parameter::{Parameter, Parameters},
    peer::Peer,
    permission::Permission,
    role::{Role, RoleId},
    seal::Sealed,
    transaction::{CommittedTransaction, SignedTransaction},
    trigger::TriggerId,
};

pub mod builder;
pub mod parameters;
pub mod predicate;

/// A query that either returns a single value or errors out
// NOTE: we are planning to remove this class of queries (https://github.com/hyperledger/iroha/issues/4933)
pub trait SingularQuery: Sealed {
    /// The type of the output of the query
    type Output;
}

/// A query that returns an iterable collection of values
///
/// Iterable queries logically return a stream of items.
/// In the actual implementation, the items collected into batches and a cursor is used to fetch the next batch.
/// [`builder::QueryIterator`] abstracts over this and allows the query consumer to use a familiar [`Iterator`] interface to iterate over the results.
pub trait Query: Sealed {
    /// The type of single element of the output collection
    type Item: HasPredicateBox;
}

#[model]
mod model {

    use getset::Getters;
    use iroha_crypto::HashOf;

    use super::*;
    use crate::block::SignedBlock;

    /// An iterable query bundled with a filter
    ///
    /// The `P` type doesn't have any bounds to simplify generic trait bounds in some places.
    /// Use [`super::QueryWithFilterFor`] if you have a concrete query type to avoid specifying `P` manually.
    #[derive(
        Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, Constructor,
    )]
    pub struct QueryWithFilter<Q, P> {
        pub query: Q,
        #[serde(default = "predicate_default")]
        pub predicate: CompoundPredicate<P>,
    }

    fn predicate_default<P>() -> CompoundPredicate<P> {
        CompoundPredicate::PASS
    }

    /// An enum of all possible iterable queries
    #[derive(
        Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, FromVariant,
    )]
    pub enum QueryBox {
        FindDomains(QueryWithFilterFor<FindDomains>),
        FindAccounts(QueryWithFilterFor<FindAccounts>),
        FindAssets(QueryWithFilterFor<FindAssets>),
        FindAssetsDefinitions(QueryWithFilterFor<FindAssetsDefinitions>),
        FindRoles(QueryWithFilterFor<FindRoles>),

        FindRoleIds(QueryWithFilterFor<FindRoleIds>),
        FindPermissionsByAccountId(QueryWithFilterFor<FindPermissionsByAccountId>),
        FindRolesByAccountId(QueryWithFilterFor<FindRolesByAccountId>),
        FindTransactionsByAccountId(QueryWithFilterFor<FindTransactionsByAccountId>),
        FindAccountsWithAsset(QueryWithFilterFor<FindAccountsWithAsset>),

        FindPeers(QueryWithFilterFor<FindPeers>),
        FindActiveTriggerIds(QueryWithFilterFor<FindActiveTriggerIds>),
        FindTransactions(QueryWithFilterFor<FindTransactions>),
        FindBlocks(QueryWithFilterFor<FindBlocks>),
        FindBlockHeaders(QueryWithFilterFor<FindBlockHeaders>),
    }

    /// An enum of all possible iterable query batches.
    ///
    /// We have an enum of batches instead of individual elements, because it makes it easier to check that the batches have elements of the same type and reduces serialization overhead.
    #[derive(
        Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, FromVariant,
    )]
    pub enum QueryOutputBatchBox {
        Domain(Vec<Domain>),
        Account(Vec<Account>),
        Asset(Vec<Asset>),
        AssetDefinition(Vec<AssetDefinition>),
        Role(Vec<Role>),
        Parameter(Vec<Parameter>),
        Permission(Vec<Permission>),
        Transaction(Vec<TransactionQueryOutput>),
        Peer(Vec<Peer>),
        RoleId(Vec<RoleId>),
        TriggerId(Vec<TriggerId>),
        Block(Vec<SignedBlock>),
        BlockHeader(Vec<BlockHeader>),
    }

    /// An enum of all possible singular queries
    #[derive(
        Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, FromVariant,
    )]
    pub enum SingularQueryBox {
        FindAssetQuantityById(FindAssetQuantityById),
        FindExecutorDataModel(FindExecutorDataModel),
        FindParameters(FindParameters),
        FindTotalAssetQuantityByAssetDefinitionId(FindTotalAssetQuantityByAssetDefinitionId),
        FindTriggerById(FindTriggerById),

        FindDomainMetadata(FindDomainMetadata),
        FindAccountMetadata(FindAccountMetadata),
        FindAssetMetadata(FindAssetMetadata),
        FindAssetDefinitionMetadata(FindAssetDefinitionMetadata),
        FindTriggerMetadata(FindTriggerMetadata),

        FindTransactionByHash(FindTransactionByHash),
        FindBlockHeaderByHash(FindBlockHeaderByHash),
    }

    /// An enum of all possible singular query outputs
    #[derive(
        Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, FromVariant,
    )]
    pub enum SingularQueryOutputBox {
        Numeric(Numeric),
        ExecutorDataModel(crate::executor::ExecutorDataModel),
        JsonString(JsonString),
        Trigger(crate::trigger::Trigger),
        Parameters(Parameters),
        Transaction(TransactionQueryOutput),
        BlockHeader(BlockHeader),
    }

    /// The results of a single iterable query request.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct QueryOutput {
        /// A single batch of results
        pub batch: QueryOutputBatchBox,
        /// If not `None`, contains a cursor that can be used to fetch the next batch of results. Otherwise the current batch is the last one.
        pub continue_cursor: Option<ForwardCursor>,
    }

    /// A type-erased iterable query, along with all the parameters needed to execute it
    #[derive(
        Debug, Clone, PartialEq, Eq, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    pub struct QueryWithParams {
        pub query: QueryBox,
        #[serde(default)]
        pub params: QueryParams,
    }

    /// A query request that can be sent to an Iroha peer.
    ///
    /// In case of HTTP API, the query request must also be signed (see [`QueryRequestWithAuthority`] and [`SignedQuery`]).
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum QueryRequest {
        Singular(SingularQueryBox),
        Start(QueryWithParams),
        Continue(ForwardCursor),
    }

    /// An enum containing either a singular or an iterable query
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AnyQueryBox {
        Singular(SingularQueryBox),
        Iterable(QueryWithParams),
    }

    /// A response to a [`QuertRequest`] from an Iroha peer
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum QueryResponse {
        Singular(SingularQueryOutputBox),
        Iterable(QueryOutput),
    }

    /// A [`QueryRequest`], combined with an authority that wants to execute the query
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct QueryRequestWithAuthority {
        pub authority: AccountId,
        pub request: QueryRequest,
    }

    /// A signature of [`QueryRequestWithAuthority`] to be used in [`SignedQueryV1`]
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct QuerySignature(pub SignatureOf<QueryRequestWithAuthority>);

    declare_versioned!(SignedQuery 1..2, Debug, Clone, FromVariant, IntoSchema);

    /// A signed and authorized query request
    #[derive(Debug, Clone, Encode, Serialize, IntoSchema)]
    #[version_with_scale(version = 1, versioned_alias = "SignedQuery")]
    pub struct SignedQueryV1 {
        pub signature: QuerySignature,
        pub payload: QueryRequestWithAuthority,
    }

    /// Output of [`FindTransactions`] query
    #[derive(
        Debug,
        Clone,
        PartialOrd,
        Ord,
        PartialEq,
        Eq,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionQueryOutput {
        /// The hash of the block to which `tx` belongs to
        pub block_hash: HashOf<SignedBlock>,
        /// Transaction
        #[getset(skip)]
        pub transaction: CommittedTransaction,
    }
}

/// A type alias to refer to a [`QueryWithFilter`] paired with a correct predicate
pub type QueryWithFilterFor<Q> =
    QueryWithFilter<Q, <<Q as Query>::Item as HasPredicateBox>::PredicateBoxType>;

impl QueryOutputBatchBox {
    // this is used in client cli to do type-erased iterable queries
    /// Extends this batch with another batch of the same type
    ///
    /// # Panics
    ///
    /// Panics if the types of the two batches do not match
    pub fn extend(&mut self, other: QueryOutputBatchBox) {
        match (self, other) {
            (Self::Domain(v1), Self::Domain(v2)) => v1.extend(v2),
            (Self::Account(v1), Self::Account(v2)) => v1.extend(v2),
            (Self::Asset(v1), Self::Asset(v2)) => v1.extend(v2),
            (Self::AssetDefinition(v1), Self::AssetDefinition(v2)) => v1.extend(v2),
            (Self::Role(v1), Self::Role(v2)) => v1.extend(v2),
            (Self::Parameter(v1), Self::Parameter(v2)) => v1.extend(v2),
            (Self::Permission(v1), Self::Permission(v2)) => v1.extend(v2),
            (Self::Transaction(v1), Self::Transaction(v2)) => v1.extend(v2),
            (Self::Peer(v1), Self::Peer(v2)) => v1.extend(v2),
            (Self::RoleId(v1), Self::RoleId(v2)) => v1.extend(v2),
            (Self::TriggerId(v1), Self::TriggerId(v2)) => v1.extend(v2),
            (Self::Block(v1), Self::Block(v2)) => v1.extend(v2),
            (Self::BlockHeader(v1), Self::BlockHeader(v2)) => v1.extend(v2),
            _ => panic!("Cannot extend different types of IterableQueryOutputBatchBox"),
        }
    }

    /// Returns length of this batch
    #[allow(clippy::len_without_is_empty)] // having a len without `is_empty` is fine, we don't return empty batches
    pub fn len(&self) -> usize {
        match self {
            Self::Domain(v) => v.len(),
            Self::Account(v) => v.len(),
            Self::Asset(v) => v.len(),
            Self::AssetDefinition(v) => v.len(),
            Self::Role(v) => v.len(),
            Self::Parameter(v) => v.len(),
            Self::Permission(v) => v.len(),
            Self::Transaction(v) => v.len(),
            Self::Peer(v) => v.len(),
            Self::RoleId(v) => v.len(),
            Self::TriggerId(v) => v.len(),
            Self::Block(v) => v.len(),
            Self::BlockHeader(v) => v.len(),
        }
    }
}

impl SingularQuery for SingularQueryBox {
    type Output = SingularQueryOutputBox;
}

impl QueryOutput {
    /// Create a new [`QueryOutput`] from the iroha response parts.
    pub fn new(batch: QueryOutputBatchBox, continue_cursor: Option<ForwardCursor>) -> Self {
        Self {
            batch,
            continue_cursor,
        }
    }

    /// Split this [`QueryOutput`] into its constituent parts.
    pub fn into_parts(self) -> (QueryOutputBatchBox, Option<ForwardCursor>) {
        (self.batch, self.continue_cursor)
    }
}

impl QueryRequest {
    /// Construct a [`QueryRequestWithAuthority`] from this [`QueryRequest`] and an authority
    pub fn with_authority(self, authority: AccountId) -> QueryRequestWithAuthority {
        QueryRequestWithAuthority {
            authority,
            request: self,
        }
    }
}

impl QueryRequestWithAuthority {
    /// Sign this [`QueryRequestWithAuthority`], creating a [`SignedQuery`]
    #[inline]
    #[must_use]
    pub fn sign(self, key_pair: &iroha_crypto::KeyPair) -> SignedQuery {
        let signature = SignatureOf::new(key_pair.private_key(), &self);

        SignedQueryV1 {
            signature: QuerySignature(signature),
            payload: self,
        }
        .into()
    }
}

impl SignedQuery {
    /// Get authority that has signed this query
    pub fn authority(&self) -> &AccountId {
        let SignedQuery::V1(query) = self;
        &query.payload.authority
    }

    /// Get the request that was signed
    pub fn request(&self) -> &QueryRequest {
        let SignedQuery::V1(query) = self;
        &query.payload.request
    }
}

mod candidate {
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode, Deserialize)]
    struct SignedQueryCandidate {
        signature: QuerySignature,
        payload: QueryRequestWithAuthority,
    }

    impl SignedQueryCandidate {
        fn validate(self) -> Result<SignedQueryV1, &'static str> {
            let QuerySignature(signature) = &self.signature;

            signature
                .verify(&self.payload.authority.signatory, &self.payload)
                .map_err(|_| "Query request signature is not valid")?;

            Ok(SignedQueryV1 {
                payload: self.payload,
                signature: self.signature,
            })
        }
    }

    impl Decode for SignedQueryV1 {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            SignedQueryCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }

    impl<'de> Deserialize<'de> for SignedQueryV1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            SignedQueryCandidate::deserialize(deserializer)?
                .validate()
                .map_err(D::Error::custom)
        }
    }

    #[cfg(test)]
    mod tests {
        use iroha_crypto::KeyPair;
        use once_cell::sync::Lazy;
        use parity_scale_codec::{DecodeAll, Encode};

        use crate::{
            account::AccountId,
            query::{
                candidate::SignedQueryCandidate, FindExecutorDataModel, QueryRequest,
                QuerySignature, SignedQuery, SingularQueryBox,
            },
        };

        static ALICE_ID: Lazy<AccountId> = Lazy::new(|| {
            format!("{}@{}", ALICE_KEYPAIR.public_key(), "wonderland")
                .parse()
                .unwrap()
        });
        static ALICE_KEYPAIR: Lazy<KeyPair> = Lazy::new(|| {
            KeyPair::new(
                "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                    .parse()
                    .unwrap(),
                "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
                    .parse()
                    .unwrap(),
            )
            .unwrap()
        });

        static BOB_KEYPAIR: Lazy<KeyPair> = Lazy::new(|| {
            KeyPair::new(
                "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016"
                    .parse()
                    .unwrap(),
                "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
                    .parse()
                    .unwrap(),
            )
            .unwrap()
        });

        #[test]
        fn valid() {
            let SignedQuery::V1(signed_query) = QueryRequest::Singular(
                SingularQueryBox::FindExecutorDataModel(FindExecutorDataModel),
            )
            .with_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);

            let candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload: signed_query.payload,
            };

            candidate.validate().unwrap();
        }

        #[test]
        fn invalid_signature() {
            let SignedQuery::V1(signed_query) = QueryRequest::Singular(
                SingularQueryBox::FindExecutorDataModel(FindExecutorDataModel),
            )
            .with_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);

            let mut candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload: signed_query.payload,
            };

            // corrupt the signature by changing a single byte in an encoded signature
            let mut signature_bytes = candidate.signature.encode();
            let idx = signature_bytes.len() - 1;
            signature_bytes[idx] = signature_bytes[idx].wrapping_add(1);
            candidate.signature = QuerySignature::decode_all(&mut &signature_bytes[..]).unwrap();

            assert_eq!(
                candidate.validate().unwrap_err(),
                "Query request signature is not valid"
            );
        }

        #[test]
        fn mismatching_authority() {
            let SignedQuery::V1(signed_query) = QueryRequest::Singular(
                SingularQueryBox::FindExecutorDataModel(FindExecutorDataModel),
            )
            // signing with a wrong key here
            .with_authority(ALICE_ID.clone())
            .sign(&BOB_KEYPAIR);

            let candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload: signed_query.payload,
            };

            assert_eq!(
                candidate.validate().unwrap_err(),
                "Query request signature is not valid"
            );
        }
    }
}

/// Use a custom syntax to implement [`Query`] for applicable types
macro_rules! impl_iter_queries {
    ($ty:ty => $item:ty $(, $($rest:tt)*)?) => {
        impl Query for $ty {
            type Item = $item;
        }

        $(
            impl_iter_queries!($($rest)*);
        )?
    };
    // allow for a trailing comma
    () => {}
}

/// Use a custom syntax to implement [`SingularQueries`] for applicable types
macro_rules! impl_singular_queries {
    ($ty:ty => $output:ty $(, $($rest:tt)*)?) => {
        impl SingularQuery for $ty {
            type Output = $output;
        }

        $(
            impl_singular_queries!($($rest)*);
        )?
    };
    // allow for a trailing comma
    () => {}
}

impl_iter_queries! {
    FindRoles => crate::role::Role,
    FindRoleIds => crate::role::RoleId,
    FindRolesByAccountId => crate::role::RoleId,
    FindPermissionsByAccountId => crate::permission::Permission,
    FindAccounts => crate::account::Account,
    FindAssets => crate::asset::Asset,
    FindAssetsDefinitions => crate::asset::AssetDefinition,
    FindDomains => crate::domain::Domain,
    FindPeers => crate::peer::Peer,
    FindActiveTriggerIds => crate::trigger::TriggerId,
    FindTransactions => TransactionQueryOutput,
    FindTransactionsByAccountId => TransactionQueryOutput,
    FindAccountsWithAsset => crate::account::Account,
    FindBlockHeaders => crate::block::BlockHeader,
    FindBlocks => SignedBlock,
}

impl_singular_queries! {
    FindAccountMetadata => JsonString,
    FindAssetQuantityById => Numeric,
    FindTotalAssetQuantityByAssetDefinitionId => Numeric,
    FindAssetMetadata => JsonString,
    FindAssetDefinitionMetadata => JsonString,
    FindDomainMetadata => JsonString,
    FindParameters => crate::parameter::Parameters,
    FindTriggerById => crate::trigger::Trigger,
    FindTriggerMetadata => JsonString,
    FindTransactionByHash => TransactionQueryOutput,
    FindBlockHeaderByHash => crate::block::BlockHeader,
    FindExecutorDataModel => crate::executor::ExecutorDataModel,
}

impl AsRef<CommittedTransaction> for TransactionQueryOutput {
    fn as_ref(&self) -> &CommittedTransaction {
        &self.transaction
    }
}

/// A macro reducing boilerplate when defining query types.
macro_rules! queries {
    ($($($meta:meta)* $item:item)+) => {
        pub use self::model::*;

        #[iroha_data_model_derive::model]
        mod model{
            use super::*; $(

            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
            #[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
            #[derive(serde::Deserialize, serde::Serialize)]
            #[derive(derive_more::Constructor)]
            #[derive(iroha_schema::IntoSchema)]
            $($meta)*
            $item )+
        }
    };
}

pub mod role {
    //! Queries related to [`Role`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    queries! {
        /// [`FindRoles`] Iroha Query finds all [`Role`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all roles")]
        #[ffi_type]
        pub struct FindRoles;

        /// [`FindRoleIds`] Iroha Query finds [`Id`](crate::RoleId)s of
        /// all [`Role`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all role ids")]
        #[ffi_type]
        pub struct FindRoleIds;

        /// [`FindRolesByAccountId`] Iroha Query finds all [`Role`]s for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find all roles for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindRolesByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindRolesByAccountId {
            /// `Id` of an account to find.
            pub id: AccountId,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindRoleIds, FindRoles, FindRolesByAccountId};
    }
}

pub mod permission {
    //! Queries related to [`Permission`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    queries! {
        /// [`FindPermissionsByAccountId`] Iroha Query finds all [`Permission`]s
        /// for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find permission tokens specified for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindPermissionsByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindPermissionsByAccountId {
            /// `Id` of an account to find.
            pub id: AccountId,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::FindPermissionsByAccountId;
    }
}

pub mod account {
    //! Queries related to [`Account`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    queries! {
        // TODO: Better to have find all account ids query instead.
        /// [`FindAccounts`] Iroha Query finds all [`Account`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all accounts")]
        #[ffi_type]
        pub struct FindAccounts;

        /// [`FindAccountMetadata`] Iroha Query finds an [`MetadataValue`]
        /// of the key-value metadata pair in the specified account.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` account")]
        #[ffi_type]
        pub struct FindAccountMetadata {
            /// `Id` of an account to find.
            pub id: AccountId,
            /// Key of the specific key-value in the Account's metadata.
            pub key: Name,
        }

        /// [`FindAccountsWithAsset`] Iroha Query gets [`AssetDefinition`]s id as input and
        /// finds all [`Account`]s storing [`Asset`] with such definition.
        #[derive(Display)]
        #[display(fmt = "Find accounts with `{asset_definition}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAccountsWithAsset` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountsWithAsset {
            /// `Id` of the definition of the asset which should be stored in founded accounts.
            pub asset_definition: AssetDefinitionId,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAccountMetadata, FindAccounts, FindAccountsWithAsset};
    }
}

pub mod asset {
    //! Queries related to [`Asset`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    queries! {
        /// [`FindAssets`] Iroha Query finds all [`Asset`]s presented in Iroha Peer.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all assets")]
        #[ffi_type]
        pub struct FindAssets;

        /// [`FindAssetsDefinitions`] Iroha Query finds all [`AssetDefinition`]s presented
        /// in Iroha Peer.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all asset definitions")]
        #[ffi_type]
        pub struct FindAssetsDefinitions; // TODO: Should it be renamed to [`FindAllAssetDefinitions`?

        /// [`FindAssetQuantityById`] Iroha Query gets [`AssetId`] as input and finds [`Asset::quantity`]
        /// value if [`Asset`] is presented in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find quantity of the `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAssetQuantityById` has no trap representation in `EvaluatesTo<AssetId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetQuantityById {
            /// `Id` of an [`Asset`] to find quantity of.
            pub id: AssetId,
        }

        /// [`FindTotalAssetQuantityByAssetDefinitionId`] Iroha Query gets [`AssetDefinitionId`] as input and finds total [`Asset::quantity`]
        /// if [`AssetDefinitionId`] is presented in Iroha Peer.
        /// In case of `Store` asset value type total quantity is sum of assets through all accounts with provided [`AssetDefinitionId`].
        #[derive(Display)]
        #[display(fmt = "Find total quantity of the `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindTotalAssetQuantityByAssetDefinitionId` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTotalAssetQuantityByAssetDefinitionId {
            /// `Id` of an [`Asset`] to find quantity of.
            pub id: AssetDefinitionId,
        }

        /// [`FindAssetMetadata`] Iroha Query gets [`AssetId`] and key as input and finds [`MetadataValue`]
        /// of the key-value pair stored in this asset.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` asset")]
        #[ffi_type]
        pub struct FindAssetMetadata {
            /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store).
            pub id: AssetId,
            /// The key of the key-value pair stored in the asset.
            pub key: Name,
        }

        /// [`FindAssetDefinitionMetadata`] Iroha Query gets [`AssetDefinitionId`] and key as input and finds [`MetadataValue`]
        /// of the key-value pair stored in this asset definition.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` asset definition")]
        #[ffi_type]
        pub struct FindAssetDefinitionMetadata {
            /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store)..
            pub id: AssetDefinitionId,
            /// The key of the key-value pair stored in the asset.
            pub key: Name,
        }

    }
    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAssetDefinitionMetadata, FindAssetMetadata, FindAssetQuantityById, FindAssets,
            FindAssetsDefinitions, FindTotalAssetQuantityByAssetDefinitionId,
        };
    }
}

pub mod domain {
    //! Queries related to [`Domain`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    queries! {
        /// [`FindDomains`] Iroha Query finds all [`Domain`]s presented in Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all domains")]
        #[ffi_type]
        pub struct FindDomains;

        /// [`FindDomainMetadata`] Iroha Query finds a [`MetadataValue`] of the key-value metadata pair
        /// in the specified domain.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with key `{key}` in `{id}` domain")]
        #[ffi_type]
        pub struct FindDomainMetadata {
            /// `Id` of an domain to find.
            pub id: DomainId,
            /// Key of the specific key-value in the domain's metadata.
            pub key: Name,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindDomainMetadata, FindDomains};
    }
}

pub mod peer {
    //! Queries related to [`crate::peer`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    queries! {
        /// [`FindPeers`] Iroha Query finds all trusted [`Peer`]s presented in current Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers")]
        #[ffi_type]
        pub struct FindPeers;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::FindPeers;
    }
}

pub mod executor {
    //! Queries related to [`crate::executor`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    queries! {
        /// [`FindExecutorDataModel`] Iroha Query finds the data model of the current executor.
        #[derive(Copy, Display)]
        #[display(fmt = "Find executor data model")]
        #[ffi_type]
        pub struct FindExecutorDataModel;

        /// [`FindParameters`] Iroha Query finds all defined executor configuration parameters.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers parameters")]
        #[ffi_type]
        pub struct FindParameters;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindExecutorDataModel, FindParameters};
    }
}

pub mod trigger {
    //! Trigger-related queries.
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::{trigger::TriggerId, Name};

    queries! {
        /// Find all currently active (as in not disabled and/or expired)
        /// trigger IDs.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all trigger ids")]
        #[ffi_type]
        pub struct FindActiveTriggerIds;

        /// Find Trigger given its ID.
        #[derive(Display)]
        #[display(fmt = "Find `{id}` trigger")]
        #[repr(transparent)]
        // SAFETY: `FindTriggerById` has no trap representation in `EvaluatesTo<TriggerId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTriggerById {
            /// The Identification of the trigger to be found.
            pub id: TriggerId,
        }

        /// Find Trigger's metadata key-value pairs.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` trigger")]
        #[ffi_type]
        pub struct FindTriggerMetadata {
            /// The Identification of the trigger to be found.
            pub id: TriggerId,
            /// The key inside the metadata dictionary to be returned.
            pub key: Name,
        }
    }

    pub mod prelude {
        //! Prelude Re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{FindActiveTriggerIds, FindTriggerById, FindTriggerMetadata};
    }
}

pub mod transaction {
    //! Queries related to transactions.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_crypto::HashOf;

    use crate::{account::AccountId, transaction::SignedTransaction};

    queries! {
        /// [`FindTransactions`] Iroha Query lists all transactions included in a blockchain
        #[derive(Copy, Display)]
        #[display(fmt = "Find all transactions")]
        #[ffi_type]
        pub struct FindTransactions;

        /// [`FindTransactionsByAccountId`] Iroha Query finds all transactions included in a blockchain
        /// for the account
        #[derive(Display)]
        #[display(fmt = "Find all transactions for `{account}` account")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionsByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionsByAccountId {
            /// Signer's [`AccountId`] under which transactions should be found.
            pub account: AccountId,
        }

        /// [`FindTransactionByHash`] Iroha Query finds a transaction (if any)
        /// with corresponding hash value
        #[derive(Copy, Display)]
        #[display(fmt = "Find transaction with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionByHash` has no trap representation in `EvaluatesTo<HashOf<SignedTransaction>>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionByHash {
            /// Transaction hash.
            pub hash: HashOf<SignedTransaction>,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindTransactionByHash, FindTransactions, FindTransactionsByAccountId};
    }
}

pub mod block {
    //! Queries related to blocks.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_crypto::HashOf;

    use super::SignedBlock;

    queries! {
        /// [`FindBlocks`] Iroha Query lists all blocks sorted by
        /// height in descending order
        #[derive(Copy, Display)]
        #[display(fmt = "Find all blocks")]
        #[ffi_type]
        pub struct FindBlocks;

        /// [`FindBlockHeaders`] Iroha Query lists all block headers
        /// sorted by height in descending order
        #[derive(Copy, Display)]
        #[display(fmt = "Find all block headers")]
        #[ffi_type]
        pub struct FindBlockHeaders;

        /// [`FindBlockHeaderByHash`] Iroha Query finds block header by block hash
        #[derive(Copy, Display)]
        #[display(fmt = "Find block header with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindBlockHeaderByHash` has no trap representation in `EvaluatesTo<HashOf<SignedBlock>>`
        #[ffi_type(unsafe {robust})]
        pub struct FindBlockHeaderByHash {
            /// Block hash.
            pub hash: HashOf<SignedBlock>,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindBlockHeaderByHash, FindBlockHeaders, FindBlocks};
    }
}

pub mod error {
    //! Module containing errors that can occur during query execution

    use iroha_crypto::HashOf;
    use iroha_data_model_derive::model;
    use iroha_macro::FromVariant;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};

    pub use self::model::*;
    use super::*;
    use crate::prelude::*;

    #[model]
    mod model {
        use super::*;

        /// Query errors.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        pub enum QueryExecutionFail {
            /// {0}
            #[cfg_attr(feature = "std", error(transparent))]
            Find(FindError),
            /// Query found wrong type of asset: {0}
            Conversion(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// Unknown query cursor
            UnknownCursor,
            /// fetch_size could not be greater than {MAX_FETCH_SIZE:?}
            FetchSizeTooBig,
            /// Some of the specified parameters (filter/pagination/fetch_size/sorting) are not applicable to singular queries
            InvalidSingularParameters,
            /// Reached limit of parallel queries. Either wait for previous queries to complete, or increase the limit in the config.
            CapacityLimit,
        }

        /// Type assertion error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        // TODO: Only temporary
        #[ffi_type(opaque)]
        pub enum FindError {
            /// Failed to find asset: `{0}`
            Asset(AssetId),
            /// Failed to find asset definition: `{0}`
            AssetDefinition(AssetDefinitionId),
            /// Failed to find account: `{0}`
            Account(AccountId),
            /// Failed to find domain: `{0}`
            Domain(DomainId),
            /// Failed to find metadata key: `{0}`
            MetadataKey(Name),
            /// Block with hash `{0}` not found
            Block(HashOf<SignedBlock>),
            /// Transaction with hash `{0}` not found
            Transaction(HashOf<SignedTransaction>),
            /// Peer with id `{0}` not found
            Peer(PeerId),
            /// Trigger with id `{0}` not found
            Trigger(TriggerId),
            /// Role with id `{0}` not found
            Role(RoleId),
            /// Failed to find [`Permission`] by id.
            Permission(Permission),
            /// Failed to find public key: `{0}`
            PublicKey(PublicKey),
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
#[allow(ambiguous_glob_reexports)]
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, block::prelude::*, builder::prelude::*,
        domain::prelude::*, executor::prelude::*, parameters::prelude::*, peer::prelude::*,
        permission::prelude::*, predicate::prelude::*, role::prelude::*, transaction::prelude::*,
        trigger::prelude::*, QueryBox, QueryRequest, SingularQueryBox, TransactionQueryOutput,
    };
}
