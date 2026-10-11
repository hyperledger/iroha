//! Iroha Queries provides declarative API for Iroha queries.
//!
//! Queries implement the [`crate::query::Query`] trait and can be stored as trait objects for
//! dynamic dispatch. The [`crate::query::QueryBox`] alias wraps a `Box<dyn ErasedQuery + Send + Sync>` and is used
//! throughout the data model whenever heterogeneous queries need to be passed around.
#![allow(clippy::missing_inline_in_public_items)]
pub use self::model::*;
use self::{
    account::*, asset::*, block::*, domain::*, dsl::*, executor::*, nft::*, peer::*, permission::*,
    role::*, rwa::*, transaction::*, trigger::*,
};
use crate::{
    NetworkId,
    account::{Account, AccountId},
    asset::{
        definition::AssetDefinition,
        id::{AssetDefinitionId, AssetId},
        value::Asset,
    },
    block::{BlockHeader, SignedBlock},
    domain::Domain,
    nft::{Nft, NftId},
    parameter::{Parameter, Parameters},
    permission::Permission,
    repo::RepoAgreement,
    role::{Role, RoleId},
    rwa::{Rwa, RwaId},
    seal,
    transaction::TransactionEntrypoint,
    trigger::{Trigger, TriggerId},
};
use derive_more::Constructor;
use iroha_crypto::{Hash, HashOf, MerkleProof, PublicKey, SignatureOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::{json::Json, numeric::Numeric};
use iroha_schema::IntoSchema;
use iroha_version::Version;
use norito::codec::{Decode, Encode};
use parameters::{ForwardCursor, QueryParams};
use std::{
    any::Any,
    boxed::Box,
    format,
    num::NonZeroU64,
    string::String,
    sync::OnceLock,
    vec::{self, Vec},
};
/// Structural error in a column-oriented iterable-query batch.
#[derive(Debug, Copy, Clone, PartialEq, Eq, displaydoc::Display, thiserror::Error)]
pub enum QueryOutputBatchBoxTupleError {
    /// An iterable-query batch must contain at least one column
    NoColumns,
    /// Column {column} contains {actual} rows, but column 0 contains {expected}
    ColumnLengthMismatch {
        /// Zero-based index of the column with the unexpected length.
        column: usize,
        /// Row count established by the first column.
        expected: usize,
        /// Row count found in the offending column.
        actual: usize,
    },
    /// Cannot extend {expected} columns with {actual} columns
    ColumnCountMismatch {
        /// Number of columns in the destination batch.
        expected: usize,
        /// Number of columns in the appended batch.
        actual: usize,
    },
    /// Cannot extend column {column} because its batch type differs
    ColumnTypeMismatch {
        /// Zero-based index of the column whose batch types differ.
        column: usize,
    },
}
/// Error returned when attempting to append different erased batch variants.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot extend query-output batches of different types")]
pub struct QueryOutputBatchBoxTypeMismatch;
/// Error returned when an erased iterable query has no canonical V1 envelope mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("erased iterable query type `{type_name}` has no canonical V1 item mapping")]
pub struct QueryWithParamsError {
    type_name: &'static str,
}
impl QueryWithParamsError {
    const fn unsupported(type_name: &'static str) -> Self {
        Self { type_name }
    }

    /// Return the concrete erased-query type that has no canonical mapping.
    #[must_use]
    pub const fn type_name(self) -> &'static str {
        self.type_name
    }
}
/// Error returned when a signed query fails request or signature validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignedQueryValidationError {
    /// The JSON query request could not be reconstructed.
    #[error("{0}")]
    InvalidRequest(&'static str),
    /// Query request authority must be single-key
    #[error("Query request authority must be single-key")]
    AuthorityNotSingleKey,
    /// Query request signature material is not valid
    #[error("Query request signature material is not valid")]
    InvalidSignatureMaterial,
    /// Query request signature is not valid
    #[error("Query request signature is not valid")]
    InvalidSignature,
    /// JSON reconstruction exceeded its caller-provided decode budget.
    #[error("Query request JSON exceeded its decode resource limit")]
    DecodeResourceLimit,
}
impl SignedQueryValidationError {
    /// Return whether validation stopped at an active decode resource bound.
    #[doc(hidden)]
    #[must_use]
    pub const fn is_decode_resource_limit(self) -> bool {
        matches!(self, Self::DecodeResourceLimit)
    }
}
fn verify_query_signature_for_signer(
    signature: &SignatureOf<QueryRequestWithAuthority>,
    signer: &PublicKey,
    payload: &QueryRequestWithAuthority,
) -> Result<(), SignedQueryValidationError> {
    match signer.try_algorithm() {
        Ok(iroha_crypto::Algorithm::Ed25519) => {
            iroha_crypto::ed25519_parse_signature(signature.payload())
                .map_err(|_| SignedQueryValidationError::InvalidSignatureMaterial)?;
        }
        Ok(iroha_crypto::Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(signature.payload())
                .map_err(|_| SignedQueryValidationError::InvalidSignatureMaterial)?;
        }
        _ => {}
    }
    signature
        .verify(signer, payload)
        .map_err(|_| SignedQueryValidationError::InvalidSignature)
}
impl iroha_version::Version for SignedQuery {
    fn version(&self) -> u8 {
        1
    }
    fn supported_versions() -> core::ops::Range<u8> {
        1..2
    }
}
#[cfg(test)]
mod signature_tests {
    include!("tests/signatures.rs");
}
impl iroha_version::codec::EncodeVersioned for SignedQuery {
    fn encode_versioned(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1);
        bytes.push(self.version());
        bytes.extend(norito::codec::encode_adaptive(self));
        bytes
    }
}
impl iroha_version::codec::DecodeVersioned for SignedQuery {
    fn decode_all_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
        iroha_version::codec::decode_exact_versioned(input)
    }
}
/// Norito-compatible JSON representations for query payloads.
#[cfg(not(doc))]
pub mod json_wrappers {
    use super::*;
    /// Failure to reconstruct the native request carried by a JSON wrapper.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    pub enum QueryRequestJsonError {
        /// A required field or encoded payload is invalid.
        #[error("{0}")]
        Invalid(&'static str),
        /// An active decode scope rejected an owned allocation.
        #[error("query request JSON exceeded its decode resource limit")]
        DecodeResourceLimit,
    }
    impl From<&'static str> for QueryRequestJsonError {
        fn from(message: &'static str) -> Self {
            Self::Invalid(message)
        }
    }
    /// JSON wrapper for iterable query parameters (roundtrip-capable).
    ///
    /// Carries the canonical iterable-query item discriminator, encoded query
    /// components, and query parameters alongside the request.
    #[derive(
        Debug, Clone, PartialEq, Eq, crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct QueryWithParamsJson {
        /// Parameters controlling pagination, sorting, and projections.
        pub params: parameters::QueryParams,
        /// Query item discriminator for canonical iterable-query envelopes.
        pub item_kind: QueryItemKind,
        /// Base64-encoded concrete query payload.
        pub query_payload_b64: String,
        /// Base64-encoded predicate fragment associated with the query, if any.
        pub predicate_b64: String,
        /// Base64-encoded selector fragment narrowing the result set.
        pub selector_b64: String,
    }
    /// JSON wrapper for `QueryRequest` enum.
    #[derive(
        Debug, Clone, PartialEq, Eq, crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize,
    )]
    #[norito(tag = "kind", content = "content", deny_unknown_fields)]
    pub enum QueryRequestJson {
        /// Singular (non-iterable) query request.
        Singular(SingularQueryBox),
        /// Iterable query request together with its parameters.
        Start(QueryWithParamsJson),
        /// Continuation token for paginated iterable queries.
        Continue(parameters::ForwardCursor),
    }
    /// JSON wrapper for `QueryRequestWithAuthority`.
    #[derive(
        Debug, Clone, PartialEq, Eq, crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct QueryRequestWithAuthorityJson {
        /// Exact genesis-lineage identity for the target network.
        pub network_id: NetworkId,
        /// Account that authorised the query.
        pub authority: crate::account::AccountId,
        /// Unix creation timestamp in milliseconds.
        pub creation_time_ms: u64,
        /// Mandatory nonzero request lifetime in milliseconds.
        pub time_to_live_ms: NonZeroU64,
        /// Caller-generated one-shot replay nonce.
        #[norito(json = "crate::json_helpers::fixed_bytes_hex")]
        pub nonce: [u8; 32],
        /// Request being authorised.
        pub request: QueryRequestJson,
    }
    /// JSON wrapper for the canonical `SignedQuery` form.
    #[derive(
        Debug, Clone, PartialEq, Eq, crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct SignedQueryCanonicalJson {
        /// Signature authenticating the query payload.
        pub signature: super::model::QuerySignature,
        /// Canonical payload describing the authorised query.
        pub payload: QueryRequestWithAuthorityJson,
    }
    /// JSON wrapper for versioned `SignedQuery`.
    ///
    /// Version is a string per common versioned JSON conventions elsewhere.
    #[derive(
        Debug, Clone, PartialEq, Eq, crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize,
    )]
    #[norito(tag = "version", content = "content", deny_unknown_fields)]
    pub enum SignedQueryJson {
        /// Canonical JSON representation of a signed query.
        #[norito(rename = "canonical")]
        Canonical(SignedQueryCanonicalJson),
    }
    /// Convert a JSON-wrapped query request into the native query request.
    ///
    /// # Errors
    /// Returns a fixed validation class when required fields are missing or an
    /// encoded payload is invalid, and preserves active decode-budget failures.
    pub fn query_request_from_json(
        req: QueryRequestJson,
    ) -> Result<QueryRequest, QueryRequestJsonError> {
        match req {
            QueryRequestJson::Singular(q) => Ok(QueryRequest::Singular(q)),
            QueryRequestJson::Continue(c) => Ok(QueryRequest::Continue(c)),
            QueryRequestJson::Start(s) => {
                let decode = |encoded: String, invalid: &'static str| {
                    base64_decode(encoded).map_err(|error| {
                        if error.is_decode_resource_limit() {
                            QueryRequestJsonError::DecodeResourceLimit
                        } else {
                            QueryRequestJsonError::Invalid(invalid)
                        }
                    })
                };
                let qp = decode(s.query_payload_b64, "bad query_payload_b64")?;
                let pr = decode(s.predicate_b64, "bad predicate_b64")?;
                let se = decode(s.selector_b64, "bad selector_b64")?;
                Ok(QueryRequest::Start(QueryWithParams {
                    query: (),
                    query_payload: qp,
                    item: s.item_kind,
                    predicate_bytes: pr,
                    selector_bytes: se,
                    params: s.params,
                }))
            }
        }
    }
    /// Convert a query request into its JSON wrapper form.
    pub fn query_request_to_json(req: &QueryRequest) -> QueryRequestJson {
        match req {
            QueryRequest::Singular(q) => QueryRequestJson::Singular(q.clone()),
            QueryRequest::Continue(c) => QueryRequestJson::Continue(c.clone()),
            QueryRequest::Start(qwp) => QueryRequestJson::Start(QueryWithParamsJson {
                params: qwp.params.clone(),
                item_kind: qwp.item,
                query_payload_b64: base64_encode(&qwp.query_payload),
                predicate_b64: base64_encode(&qwp.predicate_bytes),
                selector_b64: base64_encode(&qwp.selector_bytes),
            }),
        }
    }
    impl TryFrom<SignedQueryJson> for SignedQuery {
        type Error = SignedQueryValidationError;
        fn try_from(v: SignedQueryJson) -> Result<Self, Self::Error> {
            match v {
                SignedQueryJson::Canonical(v1) => {
                    let request =
                        query_request_from_json(v1.payload.request).map_err(
                            |error| match error {
                                QueryRequestJsonError::Invalid(message) => {
                                    SignedQueryValidationError::InvalidRequest(message)
                                }
                                QueryRequestJsonError::DecodeResourceLimit => {
                                    SignedQueryValidationError::DecodeResourceLimit
                                }
                            },
                        )?;
                    let payload = QueryRequestWithAuthority {
                        network_id: v1.payload.network_id,
                        authority: v1.payload.authority,
                        creation_time_ms: v1.payload.creation_time_ms,
                        time_to_live_ms: v1.payload.time_to_live_ms,
                        nonce: v1.payload.nonce,
                        request,
                    };
                    Ok(SignedQuery {
                        signature: v1.signature,
                        payload,
                    })
                }
            }
        }
    }
    impl From<&SignedQuery> for SignedQueryJson {
        fn from(sq: &SignedQuery) -> Self {
            let req_json = query_request_to_json(&sq.payload.request);
            SignedQueryJson::Canonical(SignedQueryCanonicalJson {
                signature: sq.signature.clone(),
                payload: QueryRequestWithAuthorityJson {
                    network_id: sq.payload.network_id,
                    authority: sq.payload.authority.clone(),
                    creation_time_ms: sq.payload.creation_time_ms,
                    time_to_live_ms: sq.payload.time_to_live_ms,
                    nonce: sq.payload.nonce,
                    request: req_json,
                },
            })
        }
    }
    pub(super) fn base64_encode(bytes: &[u8]) -> String {
        use base64::engine::{Engine, general_purpose::STANDARD};
        STANDARD.encode(bytes)
    }
    fn base64_value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    /// Decode canonical padded base64 by reusing the owned JSON string buffer.
    ///
    /// Each four-byte input quantum is loaded before its three-byte output is
    /// written, so the forward in-place transform cannot overwrite unread
    /// input. This removes the attacker-sized second destination allocation.
    pub(super) fn base64_decode(encoded: String) -> Result<Vec<u8>, norito::json::Error> {
        let mut bytes = encoded.into_bytes();
        if !bytes.len().is_multiple_of(4) {
            return Err(norito::json::Error::InvalidField {
                field: String::from("base64"),
                message: String::from("invalid base64 payload"),
            });
        }
        let groups = bytes.len() / 4;
        let mut written = 0usize;
        for group in 0..groups {
            let offset = group * 4;
            let last = group + 1 == groups;
            let first = base64_value(bytes[offset]);
            let second = base64_value(bytes[offset + 1]);
            let third = base64_value(bytes[offset + 2]);
            let fourth = base64_value(bytes[offset + 3]);
            let (Some(first), Some(second)) = (first, second) else {
                return Err(norito::json::Error::InvalidField {
                    field: String::from("base64"),
                    message: String::from("invalid base64 payload"),
                });
            };
            bytes[written] = (first << 2) | (second >> 4);
            written += 1;
            match (third, fourth, bytes[offset + 2], bytes[offset + 3], last) {
                (Some(third), Some(fourth), _, _, _) => {
                    bytes[written] = (second << 4) | (third >> 2);
                    bytes[written + 1] = (third << 6) | fourth;
                    written += 2;
                }
                (Some(third), None, _, b'=', true) if third.trailing_zeros() >= 2 => {
                    bytes[written] = (second << 4) | (third >> 2);
                    written += 1;
                }
                (None, None, b'=', b'=', true) if second.trailing_zeros() >= 4 => {}
                _ => {
                    return Err(norito::json::Error::InvalidField {
                        field: String::from("base64"),
                        message: String::from("invalid base64 payload"),
                    });
                }
            }
        }
        bytes.truncate(written);
        Ok(bytes)
    }
    pub(super) fn base64_encode_to<S: norito::json::JsonWriteSink + ?Sized>(
        bytes: &[u8],
        output: &mut S,
    ) -> Result<(), norito::json::BoundedJsonError> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let groups = bytes
            .len()
            .checked_add(2)
            .ok_or(norito::json::BoundedJsonError::BodyTooLarge)?
            / 3;
        let encoded_bytes = groups
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(norito::json::BoundedJsonError::BodyTooLarge)?;
        output.reserve(encoded_bytes)?;
        output.push('"')?;
        let mut chunks = bytes.chunks_exact(3);
        for chunk in &mut chunks {
            output.push(ALPHABET[usize::from(chunk[0] >> 2)] as char)?;
            output
                .push(ALPHABET[usize::from(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4))] as char)?;
            output
                .push(ALPHABET[usize::from(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6))] as char)?;
            output.push(ALPHABET[usize::from(chunk[2] & 0x3f)] as char)?;
        }
        match chunks.remainder() {
            [] => {}
            [first] => {
                output.push(ALPHABET[usize::from(*first >> 2)] as char)?;
                output.push(ALPHABET[usize::from((*first & 0x03) << 4)] as char)?;
                output.push_str("==")?;
            }
            [first, second] => {
                output.push(ALPHABET[usize::from(*first >> 2)] as char)?;
                output
                    .push(ALPHABET[usize::from(((*first & 0x03) << 4) | (*second >> 4))] as char)?;
                output.push(ALPHABET[usize::from((*second & 0x0f) << 2)] as char)?;
                output.push('=')?;
            }
            _ => unreachable!("chunks_exact remainder is shorter than three bytes"),
        }
        output.push('"')
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[derive(Default)]
        struct StringSink(String);
        impl norito::json::JsonWriteSink for StringSink {
            fn push(&mut self, value: char) -> Result<(), norito::json::BoundedJsonError> {
                self.0.push(value);
                Ok(())
            }
            fn push_str(&mut self, value: &str) -> Result<(), norito::json::BoundedJsonError> {
                self.0.push_str(value);
                Ok(())
            }
            fn reserve(&mut self, additional: usize) -> Result<(), norito::json::BoundedJsonError> {
                self.0
                    .try_reserve(additional)
                    .map_err(|_| norito::json::BoundedJsonError::AllocationFailed)
            }
        }
        #[test]
        fn streaming_base64_matches_standard_encoding() {
            for input in [
                &b""[..],
                &b"a"[..],
                &b"ab"[..],
                &b"abc"[..],
                &b"abcd"[..],
                &[0, 1, 2, 0xfe, 0xff][..],
            ] {
                let mut sink = StringSink::default();
                base64_encode_to(input, &mut sink).expect("bounded base64 write");
                assert_eq!(sink.0, format!("\"{}\"", base64_encode(input)));
            }
        }
        #[test]
        fn base64_decode_reuses_the_owned_input_allocation() {
            let encoded = String::from("YWJjZA==");
            let allocation = encoded.as_ptr();
            let capacity = encoded.capacity();
            let decoded = base64_decode(encoded).expect("valid base64");
            assert_eq!(decoded, b"abcd");
            assert_eq!(decoded.as_ptr(), allocation);
            assert_eq!(decoded.capacity(), capacity);
        }
        #[test]
        fn base64_decode_rejects_noncanonical_padding_and_tail_bits() {
            for invalid in ["A", "====", "AA=A", "AA==AAAA", "AB==", "AAB="] {
                base64_decode(invalid.to_owned()).expect_err("noncanonical base64");
            }
        }
    }
}
/// JSON utilities for assembling and parsing queries.
#[doc = "JSON conversion helpers used by query APIs."]
pub mod json;
// NOTE: Additional encode instrumentation for queries lives in iroha_crypto (SignatureOf::new, HashOf::new).
#[cfg(feature = "fault_injection")]
use crate::{
    ValidationFail,
    prelude::{InstructionBox, TransactionRejectionReason},
};
/// Builder helpers for constructing query instances.
#[doc = "Builder utilities for composing typed queries."]
pub mod builder;
/// Ergonomic DSL for building queries.
#[doc = "Canonical query DSL for filtering and projection."]
#[path = "dsl_fast.rs"]
pub mod dsl;
/// Query parameter types and helpers.
#[doc = "Query parameter storage and cursor types."]
pub mod parameters;
mod transaction_read_scope;
pub(crate) mod tx_predicate;
/// A query that either returns a single value or errors out
// NOTE: we are planning to remove this class of queries (https://github.com/hyperledger-iroha/iroha/issues/4933)
/// Trait implemented by query types participating in the Iroha API.
pub trait SingularQuery: seal::SingularQuery {
    /// The type of the output of the query
    type Output;
    /// Execute the query. No-op by default
    fn execute(&self) {}
    /// Encode the query into bytes using Norito binary serialization
    fn dyn_encode(&self) -> Vec<u8>;
    /// Downcast to concrete type
    fn as_any(&self) -> &dyn Any;
}
/// A query that returns an iterable collection of values.
///
/// Implementations are typically used through the [`QueryBox`] type alias
/// (`Box<dyn Query + Send + Sync>`), which allows storing different query types behind a
/// single interface.
///
/// Iterable queries logically return a stream of items.
/// In the actual implementation, the items collected into batches and a cursor is used to fetch the next batch.
/// [`builder::QueryIterator`] abstracts over this and allows the query consumer to use a familiar [`Iterator`] interface to iterate over the results.
pub trait Query: seal::Query + Send + Sync + 'static {
    /// The type of single element of the output collection
    type Item: HasProjection<PredicateMarker> + HasProjection<SelectorMarker, AtomType = ()>;
    /// Execute the query. No-op by default
    fn execute(&self) {}
    /// Return the wire discriminator for this concrete iterable query.
    ///
    /// Most queries use the discriminator of their output item. Queries whose payloads would
    /// otherwise be ambiguous can override this method with a query-specific discriminator.
    fn query_item_kind(&self) -> QueryItemKind
    where
        Self::Item: ItemKindTag,
    {
        <Self::Item as ItemKindTag>::kind()
    }
    /// Encode the query into bytes using Norito binary serialization
    fn dyn_encode(&self) -> Vec<u8>
    where
        Self: Encode,
    {
        self.encode()
    }
    /// Return the exact fixed-v1 bare payload length without erasing through an owned buffer.
    #[doc(hidden)]
    fn dyn_encoded_len_exact(&self) -> Option<usize>
    where
        Self: Sized + norito::core::SerializePayload,
    {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::core::SerializePayload::encoded_len_exact(self)
    }
    /// Stream the fixed-v1 bare payload into an existing Norito encoder.
    #[doc(hidden)]
    fn dyn_encode_to(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> Result<usize, norito::core::Error>
    where
        Self: Sized + norito::core::SerializePayload,
    {
        norito::codec::encode_adaptive_into(self, writer)
    }
    /// Downcast to concrete type
    fn as_any(&self) -> &dyn Any
    where
        Self: Sized,
    {
        self
    }
}
/// Function signature used to construct a query from raw bytes.
pub type QueryConstructor = fn(&[u8]) -> Result<QueryBox<QueryOutputBatchBox>, norito::Error>;
#[derive(Clone, Copy)]
struct QueryRegistryEntry {
    type_name: &'static str,
    wire_id: &'static str,
    ctor: QueryConstructor,
}
impl QueryRegistryEntry {
    fn collides_with(&self, other: &Self) -> bool {
        [self.type_name, self.wire_id]
            .iter()
            .any(|key| [other.type_name, other.wire_id].contains(key))
    }
}
/// Registry mapping Rust type names for encoding and stable wire identifiers for decoding.
#[derive(Default)]
pub struct QueryRegistry {
    entries: Vec<QueryRegistryEntry>,
}
impl QueryRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a query type with an explicit, path-independent wire identifier.
    ///
    /// The concrete Rust [`std::any::type_name`] is retained only as the encoding-side key;
    /// decoders accept only `wire_id`.
    #[must_use]
    pub fn register_with_id<T>(mut self, wire_id: &'static str) -> Self
    where
        T: Query<Item = QueryOutputBatchBox> + Decode + Encode + 'static,
    {
        fn ctor<T>(input: &[u8]) -> Result<QueryBox<QueryOutputBatchBox>, norito::Error>
        where
            T: Query<Item = QueryOutputBatchBox> + Decode + Encode + 'static,
        {
            let query = T::decode(&mut &*input)?;
            Ok(Box::new(query))
        }
        let entry = QueryRegistryEntry {
            type_name: std::any::type_name::<T>(),
            wire_id,
            ctor: ctor::<T>,
        };
        assert!(
            entry.type_name != entry.wire_id,
            "query registry key collision for `{}`: the wire identifier must differ from the concrete Rust type name",
            entry.type_name
        );
        if let Some(previous) = self
            .entries
            .iter()
            .find(|previous| previous.collides_with(&entry))
        {
            panic!(
                "query registry key collision between `{}` and `{}`",
                previous.type_name, entry.type_name
            );
        }
        self.entries.push(entry);
        self
    }
    fn assert_compatible_with(&self, other: &Self) {
        for entry in &other.entries {
            if let Some(previous) = self
                .entries
                .iter()
                .find(|previous| previous.collides_with(entry))
            {
                panic!(
                    "query registry key collision between `{}` and `{}`",
                    previous.type_name, entry.type_name
                );
            }
        }
    }
    /// Decode a query using its registered stable wire identifier.
    pub fn decode(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Option<Result<QueryBox<QueryOutputBatchBox>, norito::Error>> {
        self.entries
            .iter()
            .find(|entry| entry.wire_id == name)
            .map(|entry| (entry.ctor)(bytes))
    }
    /// Return the canonical wire identifier for a registered Rust type name.
    #[must_use]
    pub fn wire_id(&self, type_name: &str) -> Option<&'static str> {
        self.entries
            .iter()
            .find(|entry| entry.type_name == type_name)
            .map(|entry| entry.wire_id)
    }
}
static QUERY_REGISTRY: OnceLock<QueryRegistry> = OnceLock::new();
static DEFAULT_QUERY_REGISTRY: OnceLock<QueryRegistry> = OnceLock::new();
macro_rules! define_builtin_query_registry {
    ($($ty:ty => $wire_id:literal),* $(,)?) => {
        #[cfg(test)]
        const BUILTIN_QUERY_WIRE_ASSIGNMENTS: &[(&str, &str)] = &[
            $((stringify!($ty), $wire_id)),*
        ];
        #[cfg(test)]
        fn builtin_query_runtime_assignments() -> Vec<(&'static str, &'static str)> {
            vec![$((std::any::type_name::<$ty>(), $wire_id)),*]
        }
        fn build_builtin_query_registry() -> QueryRegistry {
            QueryRegistry::new()
                $(.register_with_id::<$ty>($wire_id))*
        }
    };
}
define_builtin_query_registry! {
    ErasedIterQuery<crate::domain::Domain>
        => "iroha.query.v1::iterable::domain::Domain",
    ErasedIterQuery<crate::account::Account>
        => "iroha.query.v1::iterable::account::Account",
    ErasedIterQuery<crate::account::AccountId>
        => "iroha.query.v1::iterable::account::AccountId",
    ErasedIterQuery<crate::asset::value::Asset>
        => "iroha.query.v1::iterable::asset::Asset",
    ErasedIterQuery<crate::asset::definition::AssetDefinition>
        => "iroha.query.v1::iterable::asset::AssetDefinition",
    ErasedIterQuery<crate::repo::RepoAgreement>
        => "iroha.query.v1::iterable::repo::RepoAgreement",
    ErasedIterQuery<crate::nft::Nft>
        => "iroha.query.v1::iterable::nft::Nft",
    ErasedIterQuery<crate::rwa::Rwa>
        => "iroha.query.v1::iterable::rwa::Rwa",
    ErasedIterQuery<crate::role::Role>
        => "iroha.query.v1::iterable::role::Role",
    ErasedIterQuery<crate::role::RoleId>
        => "iroha.query.v1::iterable::role::RoleId",
    ErasedIterQuery<iroha_model_base::peer::PeerId>
        => "iroha.query.v1::iterable::peer::PeerId",
    ErasedIterQuery<crate::trigger::TriggerId>
        => "iroha.query.v1::iterable::trigger::TriggerId",
    ErasedIterQuery<crate::trigger::Trigger>
        => "iroha.query.v1::iterable::trigger::Trigger",
    ErasedIterQuery<CommittedTransaction>
        => "iroha.query.v1::iterable::transaction::CommittedTransaction",
    ErasedIterQuery<crate::block::SignedBlock>
        => "iroha.query.v1::iterable::block::SignedBlock",
    ErasedIterQuery<crate::block::BlockHeader>
        => "iroha.query.v1::iterable::block::BlockHeader",
    ErasedIterQuery<crate::proof::ProofRecord>
        => "iroha.query.v1::iterable::proof::ProofRecord",
    ErasedIterQuery<crate::oracle::FeedConfig>
        => "iroha.query.v1::iterable::oracle::FeedConfig",
    ErasedIterQuery<crate::events::data::oracle::FeedEventRecord>
        => "iroha.query.v1::iterable::oracle::FeedEventRecord",
    ErasedIterQuery<crate::oracle::OracleProviderStatsRecord>
        => "iroha.query.v1::iterable::oracle::OracleProviderStatsRecord",
    ErasedIterQuery<crate::oracle::OracleDispute>
        => "iroha.query.v1::iterable::oracle::OracleDispute",
    ErasedIterQuery<crate::oracle::OracleChangeProposal>
        => "iroha.query.v1::iterable::oracle::OracleChangeProposal",
    ErasedIterQuery<crate::oracle::TwitterBindingRecord>
        => "iroha.query.v1::iterable::oracle::TwitterBindingRecord",
    ErasedIterQuery<crate::oracle::DefiOracleAttestation>
        => "iroha.query.v1::iterable::oracle::DefiOracleAttestation",
    ErasedIterQuery<crate::permission::Permission>
        => "iroha.query.v1::iterable::permission::Permission",
    ErasedIterQuery<crate::escrow::AssetEscrowRecord>
        => "iroha.query.v1::iterable::escrow::AssetEscrowRecord",
    ErasedIterQuery<crate::nexus::FeeSponsorProgram>
        => "iroha.query.v1::iterable::nexus::FeeSponsorProgram",
    ErasedIterQuery<crate::nexus::FeeSponsorProgramId>
        => "iroha.query.v1::iterable::nexus::FeeSponsorProgramId",
}
/// Set the global query registry used to decode queries by stable wire identifier.
///
/// This should be called exactly once during application start-up. Subsequent calls are ignored.
///
/// If this function is never invoked, the data model falls back to a built-in
/// registry covering the standard iterable query set, allowing JSON and Norito
/// decoding to work out of the box in tests and utilities.
///
/// A custom registry may add only new concrete query types with unique wire identifiers.
///
/// # Panics
///
/// Panics if an entry re-registers a built-in type or wire identifier.
pub fn set_query_registry(registry: QueryRegistry) {
    if QUERY_REGISTRY.get().is_some() {
        return;
    }
    builtin_query_registry().assert_compatible_with(&registry);
    let _ = QUERY_REGISTRY.set(registry);
}
fn query_wire_id_from_registries(
    type_name: &'static str,
    builtin: &QueryRegistry,
    installed: Option<&QueryRegistry>,
) -> Option<&'static str> {
    builtin
        .wire_id(type_name)
        .or_else(|| installed.and_then(|registry| registry.wire_id(type_name)))
}
fn query_wire_id(type_name: &'static str) -> Option<&'static str> {
    query_wire_id_from_registries(type_name, builtin_query_registry(), QUERY_REGISTRY.get())
}
fn decode_query_from_registries(
    name: &str,
    bytes: &[u8],
    builtin: &QueryRegistry,
    installed: Option<&QueryRegistry>,
) -> Option<Result<QueryBox<QueryOutputBatchBox>, norito::Error>> {
    builtin
        .decode(name, bytes)
        .or_else(|| installed.and_then(|registry| registry.decode(name, bytes)))
}
fn decode_registered_query(
    name: &str,
    bytes: &[u8],
) -> Option<Result<QueryBox<QueryOutputBatchBox>, norito::Error>> {
    decode_query_from_registries(name, bytes, builtin_query_registry(), QUERY_REGISTRY.get())
}
fn builtin_query_registry() -> &'static QueryRegistry {
    DEFAULT_QUERY_REGISTRY.get_or_init(build_builtin_query_registry)
}
#[cfg(test)]
#[path = "tests/wire_ids.rs"]
mod wire_id_tests;
#[model]
mod model {
    use super::*;
    use crate::{
        prelude::{TransactionEntrypoint, TransactionResult},
        trigger::action,
    };
    use getset::Getters;
    use iroha_crypto::HashOf;
    /// An iterable query bundled with a filter.
    ///
    /// The concrete query payload is carried by [`QueryWithParams`]; this
    /// structure contains the predicate and selector applied to its item type.
    #[derive(Decode, Encode, Constructor, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryWithFilter")]
    pub struct QueryWithFilter<T>
    where
        T: HasProjection<PredicateMarker>
            + HasProjection<SelectorMarker, AtomType = ()>
            + Send
            + Sync,
    {
        /// Unit marker; the concrete query is encoded separately.
        pub query: (),
        pub predicate: CompoundPredicate<T>,
        pub selector: SelectorTuple<T>,
    }
    impl<T> QueryWithFilter<T>
    where
        T: HasProjection<PredicateMarker>
            + HasProjection<SelectorMarker, AtomType = ()>
            + Send
            + Sync,
    {
        /// Construct a filtered query whose concrete payload is carried elsewhere.
        #[inline]
        pub fn new_with_query(
            (): (),
            predicate: CompoundPredicate<T>,
            selector: SelectorTuple<T>,
        ) -> Self {
            Self::new((), predicate, selector)
        }
    }
    /// Type-erased iterable query used throughout the data model.
    ///
    /// This is an alias for `Box<dyn ErasedQuery<T> + Send + Sync>` enabling heterogeneous
    /// query collections.
    ///
    /// # Examples
    /// ```rust
    /// use iroha_data_model::prelude::*;
    ///
    /// let query: QueryBox<Account> = Box::new(FindAccounts);
    /// ```
    pub trait ErasedEncode {
        /// Encode the erased query into Norito bytes.
        fn erased_encode(&self) -> Vec<u8>;
    }
    impl<T: Encode> ErasedEncode for T {
        fn erased_encode(&self) -> Vec<u8> {
            self.encode()
        }
    }
    use std::any::Any;
    /// Trait implemented by query types participating in the Iroha API.
    pub trait ErasedQuery<T>: Query<Item = T> + ErasedEncode + Any + Send + Sync {
        /// Expose the concrete query as `Any` for downcasting.
        fn erased_as_any(&self) -> &dyn Any;
        /// Encode the concrete query behind the erased trait object without
        /// re-encoding the `QueryBox` wrapper (avoids recursion).
        fn encode_bytes(&self) -> Vec<u8>;
        /// Return the exact fixed-v1 bare payload length without allocating an output buffer.
        fn encoded_payload_len_exact(&self) -> Option<usize>;
        /// Stream the fixed-v1 bare payload without allocating an intermediate payload buffer.
        ///
        /// # Errors
        ///
        /// Returns an error if the query payload cannot be encoded into the destination writer.
        fn encode_payload_to(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<usize, norito::core::Error>;
        /// Return the concrete Rust type key used for in-process registry lookup.
        ///
        /// The registry maps this key to the stable identifier emitted on the wire. Using a
        /// dedicated method avoids relying on `type_name_of_val` for trait objects, which returns
        /// the trait object type rather than the concrete type.
        fn type_name_key(&self) -> &'static str;
    }
    impl<T, Q> ErasedQuery<T> for Q
    where
        Q: Query<Item = T> + ErasedEncode + Any + Send + Sync + norito::core::SerializePayload,
    {
        fn erased_as_any(&self) -> &dyn Any {
            self
        }
        fn encode_bytes(&self) -> Vec<u8> {
            // Delegate to dynamic encoder; concrete types may override it.
            self.dyn_encode()
        }
        fn encoded_payload_len_exact(&self) -> Option<usize> {
            self.dyn_encoded_len_exact()
        }
        fn encode_payload_to(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<usize, norito::core::Error> {
            self.dyn_encode_to(writer)
        }
        fn type_name_key(&self) -> &'static str {
            std::any::type_name::<Self>()
        }
    }
    /// Type alias used for ergonomic query handling.
    pub type QueryBox<T> = Box<dyn ErasedQuery<T> + Send + Sync>;
    impl norito::NoritoSchema for QueryBox<QueryOutputBatchBox> {
        fn nominal_name() -> String {
            let query = norito::schema::identity::generic_name(
                "iroha_data_model::query::model::ErasedQuery",
                &[<QueryOutputBatchBox as norito::NoritoSchema>::nominal_name()],
            );
            norito::schema::identity::generic_name(
                "alloc::boxed::Box",
                &[format!(
                    "dyn {query} + core::marker::Send + core::marker::Sync"
                )],
            )
        }
    }
    fn query_box_tuple_flags() -> u8 {
        norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
    }
    fn query_box_encoded_len(name: &str, payload_len: usize, flags: u8) -> Option<usize> {
        let name_len = name
            .len()
            .checked_add(norito::core::len_prefix_len_with_flags(name.len(), flags))?;
        let payload_len = payload_len.checked_add(8)?;
        norito::core::len_prefix_len_with_flags(name_len, flags)
            .checked_add(name_len)?
            .checked_add(norito::core::len_prefix_len_with_flags(payload_len, flags))?
            .checked_add(payload_len)
    }

    impl norito::core::SerializePayload for QueryBox<QueryOutputBatchBox> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            let query = &**self;
            let name = query_wire_id(query.type_name_key()).ok_or_else(|| {
                norito::core::Error::Message(format!(
                    "query type `{}` has no registered wire identifier",
                    query.type_name_key()
                ))
            })?;
            let flags = query_box_tuple_flags();
            let payload_len = if let Some(exact) = query.encoded_payload_len_exact() {
                exact
            } else {
                // Count one streaming pass, then write the length-delimited field in a second
                // pass without retaining an owned payload-sized staging buffer.
                let mut sink = std::io::sink();
                let mut counter = norito::core::Encoder::new(&mut sink);
                query.encode_payload_to(&mut counter)?
            };
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let name_len = name
                .len()
                .checked_add(norito::core::len_prefix_len_with_flags(name.len(), flags))
                .ok_or(norito::core::Error::LengthMismatch)?;
            norito::core::write_len_with_flags(
                writer,
                u64::try_from(name_len).map_err(|_| norito::core::Error::LengthMismatch)?,
                flags,
            )?;
            norito::core::write_len_with_flags(
                writer,
                u64::try_from(name.len()).map_err(|_| norito::core::Error::LengthMismatch)?,
                flags,
            )?;
            writer.write_all(name.as_bytes())?;
            let payload_field_len = payload_len
                .checked_add(8)
                .ok_or(norito::core::Error::LengthMismatch)?;
            norito::core::write_len_with_flags(
                writer,
                u64::try_from(payload_field_len)
                    .map_err(|_| norito::core::Error::LengthMismatch)?,
                flags,
            )?;
            norito::core::write_seq_len(
                writer,
                u64::try_from(payload_len).map_err(|_| norito::core::Error::LengthMismatch)?,
            )?;
            let written = query.encode_payload_to(writer)?;
            if written != payload_len {
                return Err(norito::core::Error::LengthMismatch);
            }
            Ok(())
        }
        fn encoded_len_hint(&self) -> Option<usize> {
            self.encoded_len_exact()
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            let query = &**self;
            let name = query_wire_id(query.type_name_key())?;
            let flags = query_box_tuple_flags();
            query_box_encoded_len(name, query.encoded_payload_len_exact()?, flags)
        }
    }

    impl<'a> norito::core::DeserializePayload<'a> for QueryBox<QueryOutputBatchBox> {
        fn deserialize(
            archived: &'a norito::core::Archived<QueryBox<QueryOutputBatchBox>>,
        ) -> Self {
            Self::try_deserialize(archived)
                .expect("QueryBox deserialization must reject invalid canonical payloads")
        }

        fn try_deserialize(
            archived: &'a norito::core::Archived<QueryBox<QueryOutputBatchBox>>,
        ) -> Result<Self, norito::core::Error> {
            let (name, bytes): (String, Vec<u8>) =
                norito::core::DeserializePayload::try_deserialize(archived.cast())?;
            decode_registered_query(&name, &bytes).ok_or_else(|| {
                norito::core::Error::Message("unknown query wire identifier".to_owned())
            })?
        }
    }
    /// An enum of all possible iterable query batches.
    ///
    /// We have an enum of batches instead of individual elements, because it makes it easier to check that the batches have elements of the same type and reduces serialization overhead.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        IntoSchema,
        FromVariant,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Boxed batch of query output items.
    #[norito(tag = "kind", content = "content")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryOutputBatchBox")]
    pub enum QueryOutputBatchBox {
        /// Batch of public keys.
        PublicKey(Vec<PublicKey>),
        /// Batch of string values.
        String(Vec<String>),
        /// Batch of metadata entries.
        Metadata(Vec<Metadata>),
        /// Batch of JSON values.
        Json(Vec<Json>),
        /// Batch of numeric values.
        Numeric(Vec<Numeric>),
        /// Batch of names.
        Name(Vec<Name>),
        /// Batch of domain identifiers.
        DomainId(Vec<DomainId>),
        /// Batch of domain definitions.
        Domain(Vec<Domain>),
        /// Batch of account identifiers.
        AccountId(Vec<AccountId>),
        /// Batch of accounts.
        Account(Vec<Account>),
        /// Batch of asset identifiers.
        AssetId(Vec<AssetId>),
        /// Batch of assets.
        Asset(Vec<Asset>),
        /// Batch of asset definition identifiers.
        AssetDefinitionId(Vec<AssetDefinitionId>),
        /// Batch of asset definitions.
        AssetDefinition(Vec<AssetDefinition>),
        /// Batch of repository agreements.
        RepoAgreement(Vec<RepoAgreement>),
        /// Batch of NFT identifiers.
        NftId(Vec<NftId>),
        /// Batch of NFTs.
        Nft(Vec<Nft>),
        /// Batch of RWA identifiers.
        RwaId(Vec<RwaId>),
        /// Batch of RWAs.
        Rwa(Vec<Rwa>),
        /// Batch of roles.
        Role(Vec<Role>),
        /// Batch of parameters.
        Parameter(Vec<Parameter>),
        /// Batch of permissions.
        Permission(Vec<Permission>),
        /// Batch of committed transactions.
        CommittedTransaction(Vec<CommittedTransaction>),
        /// Batch of transaction results.
        TransactionResult(Vec<TransactionResult>),
        /// Batch of transaction result hashes.
        TransactionResultHash(Vec<HashOf<TransactionResult>>),
        /// Batch of transaction entrypoints.
        TransactionEntrypoint(Vec<TransactionEntrypoint>),
        /// Batch of transaction entrypoint hashes.
        TransactionEntrypointHash(Vec<HashOf<TransactionEntrypoint>>),
        /// Batch of peer identifiers.
        Peer(Vec<PeerId>),
        /// Batch of role identifiers.
        RoleId(Vec<RoleId>),
        /// Batch of trigger identifiers.
        TriggerId(Vec<TriggerId>),
        /// Batch of triggers.
        Trigger(Vec<Trigger>),
        /// Batch of actions.
        Action(Vec<action::Action>),
        /// Batch of signed blocks.
        Block(Vec<SignedBlock>),
        /// Batch of block headers.
        BlockHeader(Vec<BlockHeader>),
        /// Batch of block header hashes.
        BlockHeaderHash(Vec<HashOf<BlockHeader>>),
        /// Batch of proof records.
        ProofRecord(Vec<crate::proof::ProofRecord>),
        /// Batch of oracle feed configurations.
        OracleFeedConfig(Vec<crate::oracle::FeedConfig>),
        /// Batch of oracle feed history records.
        OracleFeedEventRecord(Vec<crate::events::data::oracle::FeedEventRecord>),
        /// Batch of oracle provider statistics records.
        OracleProviderStatsRecord(Vec<crate::oracle::OracleProviderStatsRecord>),
        /// Batch of oracle disputes.
        OracleDispute(Vec<crate::oracle::OracleDispute>),
        /// Batch of oracle change proposals.
        OracleChangeProposal(Vec<crate::oracle::OracleChangeProposal>),
        /// Batch of twitter binding records.
        TwitterBindingRecord(Vec<crate::oracle::TwitterBindingRecord>),
        /// Batch of `DeFi` oracle attestations.
        DefiOracleAttestation(Vec<crate::oracle::DefiOracleAttestation>),
        /// Batch of native asset escrow records.
        AssetEscrowRecord(Vec<crate::escrow::AssetEscrowRecord>),
        /// Batch of fee sponsor programs.
        FeeSponsorProgram(Vec<crate::nexus::FeeSponsorProgram>),
        /// Batch of fee sponsor program identifiers.
        FeeSponsorProgramId(Vec<crate::nexus::FeeSponsorProgramId>),
    }
    #[derive(Debug, Clone, PartialEq, Eq, Encode, IntoSchema, crate :: DeriveJsonSerialize)]
    /// Helper tuple to materialise batches into Norito collections.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryOutputBatchBoxTuple")]
    pub struct QueryOutputBatchBoxTuple {
        /// Sequence of batches produced by an iterable query.
        pub(super) tuple: Vec<QueryOutputBatchBox>,
    }
    /// An enum of all possible singular queries
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        IntoSchema,
        FromVariant,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Boxed trait-object for singular queries.
    #[norito(tag = "kind", content = "content")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::SingularQueryBox")]
    pub enum SingularQueryBox {
        /// Fetch the current executor data model definition.
        FindExecutorDataModel(FindExecutorDataModel),
        /// Fetch current global parameters.
        FindParameters(FindParameters),
        /// Fetch an account by identifier.
        FindAccountById(account::prelude::FindAccountById),
        /// Fetch aliases bound to an account subject.
        FindAliasesByAccountId(account::prelude::FindAliasesByAccountId),
        /// Fetch the recovery policy keyed by a stable account alias.
        FindAccountRecoveryPolicyByAlias(account::prelude::FindAccountRecoveryPolicyByAlias),
        /// Fetch the recovery request keyed by a stable account alias.
        FindAccountRecoveryRequestByAlias(account::prelude::FindAccountRecoveryRequestByAlias),
        /// Fetch a proof record by its identifier.
        FindProofRecordById(proof::prelude::FindProofRecordById),
        /// Fetch a contract manifest by its code hash.
        FindContractManifestByArtifactId(smart_contract::prelude::FindContractManifestByArtifactId),
        /// Fetch the active ABI version.
        FindAbiVersion(runtime::prelude::FindAbiVersion),
        /// Fetch an asset by identifier.
        FindAssetById(asset::prelude::FindAssetById),
        /// Fetch an asset definition by identifier.
        FindAssetDefinitionById(asset::prelude::FindAssetDefinitionById),
        /// Fetch a native asset escrow by identifier.
        FindAssetEscrowById(escrow::prelude::FindAssetEscrowById),
        /// Fetch a trigger by identifier.
        FindTriggerById(trigger::prelude::FindTriggerById),
        /// Fetch a Twitter binding record by hash.
        FindTwitterBindingByHash(oracle::prelude::FindTwitterBindingByHash),
        /// Fetch an oracle feed by identifier.
        FindOracleFeedById(oracle::prelude::FindOracleFeedById),
        /// Fetch an oracle dispute by identifier.
        FindOracleDisputeById(oracle::prelude::FindOracleDisputeById),
        /// Fetch an oracle change by identifier.
        FindOracleChangeById(oracle::prelude::FindOracleChangeById),
        /// Fetch oracle provider statistics by key.
        FindOracleProviderStatsByKey(oracle::prelude::FindOracleProviderStatsByKey),
        /// Fetch the latest `DeFi` oracle attestation for a key.
        FindLatestDefiOracleAttestation(oracle::prelude::FindLatestDefiOracleAttestation),
        /// Fetch domain endorsement records.
        FindDomainEndorsements(endorsement::prelude::FindDomainEndorsements),
        /// Fetch the domain endorsement policy.
        FindDomainEndorsementPolicy(endorsement::prelude::FindDomainEndorsementPolicy),
        /// Fetch the committee for a domain.
        FindDomainCommittee(endorsement::prelude::FindDomainCommittee),
        /// Fetch a DA pin intent by storage ticket.
        FindDaPinIntentByTicket(self::da::prelude::FindDaPinIntentByTicket),
        /// Fetch a DA pin intent by manifest digest.
        FindDaPinIntentByManifest(self::da::prelude::FindDaPinIntentByManifest),
        /// Fetch a DA pin intent by alias.
        FindDaPinIntentByAlias(self::da::prelude::FindDaPinIntentByAlias),
        /// Fetch a DA pin intent by lane/epoch/sequence tuple.
        FindDaPinIntentByLaneEpochSequence(self::da::prelude::FindDaPinIntentByLaneEpochSequence),
        /// Fetch a fee sponsor program by identifier.
        FindFeeSponsorProgramById(self::nexus::prelude::FindFeeSponsorProgramById),
        /// Fetch the immutable native business receipt, including every exact movement.
        FindSettlementReceiptById(self::settlement::prelude::FindSettlementReceiptById),
        /// Fetch the protected native FX corridor policy registry.
        FindFxCorridorPolicyRegistry(self::settlement::prelude::FindFxCorridorPolicyRegistry),
        /// Fetch one native FX corridor policy by identifier.
        FindFxCorridorPolicyById(self::settlement::prelude::FindFxCorridorPolicyById),
        /// Fetch the registered owner for a `SoraFS` provider.
        FindSorafsProviderOwner(sorafs::prelude::FindSorafsProviderOwner),
        /// Fetch one finalized chain-authoritative `SoraFS` pin manifest.
        FindSorafsPinManifest(sorafs::prelude::FindSorafsPinManifest),
        /// Fetch a finalized, keyset-bounded page of `SoraFS` pin manifests.
        FindSorafsPinManifests(sorafs::prelude::FindSorafsPinManifests),
        /// Fetch the active authoritative `SoraFS` orderbook policy.
        FindSorafsOrderbookPolicy(sorafs::prelude::FindSorafsOrderbookPolicy),
        /// Fetch one authoritative `SoraFS` order by identifier.
        FindSorafsOrderbookOrderById(sorafs::prelude::FindSorafsOrderbookOrderById),
        /// Fetch one admitted `SoraFS` order cancellation by order identifier.
        FindSorafsOrderbookCancellationByOrderId(
            sorafs::prelude::FindSorafsOrderbookCancellationByOrderId,
        ),
        /// Fetch one authoritative `SoraFS` settlement receipt by identifier.
        FindSorafsOrderbookReceiptById(sorafs::prelude::FindSorafsOrderbookReceiptById),
        /// Fetch one authoritative `SoraFS` trade by identifier.
        FindSorafsOrderbookTradeById(sorafs::prelude::FindSorafsOrderbookTradeById),
        /// Fetch one authoritative `SoraFS` settlement channel by identifier.
        FindSorafsOrderbookChannelById(sorafs::prelude::FindSorafsOrderbookChannelById),
        /// Fetch constant-time authoritative `SoraFS` orderbook counters.
        FindSorafsOrderbookStatus(sorafs::prelude::FindSorafsOrderbookStatus),
        /// Fetch a cursor-bounded page of authoritative `SoraFS` orders.
        FindSorafsOrderbookOrders(sorafs::prelude::FindSorafsOrderbookOrders),
        /// Fetch a cursor-bounded page of authoritative `SoraFS` settlement receipts.
        FindSorafsOrderbookReceipts(sorafs::prelude::FindSorafsOrderbookReceipts),
        /// Fetch a cursor-bounded page of authoritative `SoraFS` trades.
        FindSorafsOrderbookTrades(sorafs::prelude::FindSorafsOrderbookTrades),
        /// Fetch a cursor-bounded page of authoritative `SoraFS` settlement channels.
        FindSorafsOrderbookChannels(sorafs::prelude::FindSorafsOrderbookChannels),
        /// Fetch a cursor-bounded page of committed `SoraFS` orderbook events.
        FindSorafsOrderbookEvents(sorafs::prelude::FindSorafsOrderbookEvents),
        /// Fetch the active authoritative `SoraFS` reserve policy.
        FindSorafsReservePolicy(sorafs::prelude::FindSorafsReservePolicy),
        /// Fetch one authoritative provider reserve account.
        FindSorafsReserveProviderById(sorafs::prelude::FindSorafsReserveProviderById),
        /// Fetch one authoritative reserve movement.
        FindSorafsReserveMovementById(sorafs::prelude::FindSorafsReserveMovementById),
        /// Fetch one authoritative reserve appeal.
        FindSorafsReserveAppealById(sorafs::prelude::FindSorafsReserveAppealById),
        /// Fetch a cursor-bounded page of authoritative provider reserve accounts.
        FindSorafsReserveProviders(sorafs::prelude::FindSorafsReserveProviders),
        /// Fetch a cursor-bounded page of authoritative reserve movements.
        FindSorafsReserveMovements(sorafs::prelude::FindSorafsReserveMovements),
        /// Fetch a cursor-bounded page of authoritative reserve appeals.
        FindSorafsReserveAppeals(sorafs::prelude::FindSorafsReserveAppeals),
        /// Fetch a cursor-bounded page of committed `SoraFS` reserve events.
        FindSorafsReserveEvents(sorafs::prelude::FindSorafsReserveEvents),
        /// Fetch the active authoritative `SoraFS` `PoP` issuer policy.
        FindSorafsPopIssuerPolicy(sorafs::prelude::FindSorafsPopIssuerPolicy),
        /// Fetch one payload-free `PoP` credential commitment.
        FindSorafsPopCredentialCommitmentByDigest(
            sorafs::prelude::FindSorafsPopCredentialCommitmentByDigest,
        ),
        /// Fetch one signed `PoP` commitment-root publication by version.
        FindSorafsPopCommitmentRootByVersion(sorafs::prelude::FindSorafsPopCommitmentRootByVersion),
        /// Fetch one signed `PoP` revocation publication by version.
        FindSorafsPopRevocationPublicationByVersion(
            sorafs::prelude::FindSorafsPopRevocationPublicationByVersion,
        ),
        /// Fetch one payload-free `PoP` revocation by nonce commitment.
        FindSorafsPopRevocationByNonceCommitment(
            sorafs::prelude::FindSorafsPopRevocationByNonceCommitment,
        ),
        /// Fetch one `PoP` registry audit-chain link by sequence.
        FindSorafsPopAuditDigestBySequence(sorafs::prelude::FindSorafsPopAuditDigestBySequence),
        /// Fetch constant-time authoritative `PoP` registry anchors and counters.
        FindSorafsPopRegistryStatus(sorafs::prelude::FindSorafsPopRegistryStatus),
        /// Fetch one commitment-only citizen bond by immutable serial commitment.
        FindSorafsCitizenBondBySerialCommitment(
            sorafs::prelude::FindSorafsCitizenBondBySerialCommitment,
        ),
        /// Fetch the current frozen citizen-bond membership snapshot.
        FindSorafsCitizenBondSnapshot(sorafs::prelude::FindSorafsCitizenBondSnapshot),
        /// Fetch one chain-authoritative repair task by canonical ticket identifier.
        FindSorafsRepairTask(sorafs::prelude::FindSorafsRepairTask),
        /// Fetch a cursor-bounded page of chain-authoritative repair tasks.
        FindSorafsRepairTasks(sorafs::prelude::FindSorafsRepairTasks),
        /// Fetch constant-time chain-authoritative repair-ledger counters.
        FindSorafsRepairStatus(sorafs::prelude::FindSorafsRepairStatus),
        /// Fetch a cursor-bounded page of committed repair-ledger events.
        FindSorafsRepairEvents(sorafs::prelude::FindSorafsRepairEvents),
        /// Fetch one finalized chain-authoritative PDP/PoTR proof outcome.
        FindSorafsProofOutcome(sorafs::prelude::FindSorafsProofOutcome),
        /// Fetch a cursor-bounded page of finalized PDP/PoTR proof-outcome events.
        FindSorafsProofOutcomeEvents(sorafs::prelude::FindSorafsProofOutcomeEvents),
        /// Fetch the active authoritative `SoraFS` reputation-journal authority policy.
        FindSorafsReputationJournalAuthorityPolicy(
            sorafs::prelude::FindSorafsReputationJournalAuthorityPolicy,
        ),
        /// Fetch one finalized reputation-journal event by authoritative source identifier.
        FindSorafsReputationJournalEventBySourceId(
            sorafs::prelude::FindSorafsReputationJournalEventBySourceId,
        ),
        /// Fetch a cursor-bounded page of finalized reputation-journal events.
        FindSorafsReputationJournalEvents(sorafs::prelude::FindSorafsReputationJournalEvents),
        /// Fetch the active authoritative `SoraFS` moderation policy.
        FindSorafsModerationPolicy(sorafs::prelude::FindSorafsModerationPolicy),
        /// Fetch one authoritative moderation appeal intake and sortition lifecycle.
        FindSorafsModerationAppeal(sorafs::prelude::FindSorafsModerationAppeal),
        /// Fetch one payload-free, PoP-verified juror eligibility record.
        FindSorafsModerationJurorEligibility(sorafs::prelude::FindSorafsModerationJurorEligibility),
        /// Fetch one authoritative `SoraFS` moderation case.
        FindSorafsModerationCase(sorafs::prelude::FindSorafsModerationCase),
        /// Fetch one authoritative juror commitment.
        FindSorafsModerationCommit(sorafs::prelude::FindSorafsModerationCommit),
        /// Fetch one authoritative juror reveal.
        FindSorafsModerationReveal(sorafs::prelude::FindSorafsModerationReveal),
        /// Fetch one authoritative moderation challenge.
        FindSorafsModerationChallenge(sorafs::prelude::FindSorafsModerationChallenge),
        /// Fetch one terminal authoritative moderation outcome.
        FindSorafsModerationOutcome(sorafs::prelude::FindSorafsModerationOutcome),
        /// Fetch one derived no-show penalty record.
        FindSorafsModerationNoShow(sorafs::prelude::FindSorafsModerationNoShow),
        /// Fetch constant-time authoritative moderation-ledger counters.
        FindSorafsModerationStatus(sorafs::prelude::FindSorafsModerationStatus),
        /// Fetch a complete bounded moderation projection at one finalized block.
        FindSorafsModerationSnapshot(sorafs::prelude::FindSorafsModerationSnapshot),
        /// Fetch a cursor-bounded page of committed moderation events.
        FindSorafsModerationEvents(sorafs::prelude::FindSorafsModerationEvents),
        /// Fetch the active SNS owner for a dataspace alias.
        FindDataspaceNameOwnerById(sns::prelude::FindDataspaceNameOwnerById),
        /// Fetch one exact Musubi V1 package record.
        FindMusubiExactPackageV1(musubi::prelude::FindMusubiExactPackageV1),
        /// Fetch one paired finalized Musubi V1 home/universal release view.
        FindMusubiExactReleaseV1(musubi::prelude::FindMusubiExactReleaseV1),
        /// Fetch one exact immutable Musubi V1 provider bundle-attestation record.
        FindMusubiProviderBundleAttestationV1(
            musubi::prelude::FindMusubiProviderBundleAttestationV1,
        ),
        /// Fetch a finalized page from the universal Musubi V1 resolver index.
        FindMusubiResolverIndexV1(musubi::prelude::FindMusubiResolverIndexV1),
        /// Fetch a finalized page of structured Musubi V1 versions.
        FindMusubiVersionsV1(musubi::prelude::FindMusubiVersionsV1),
        /// Fetch a finalized page of accepted Musubi V1 package members.
        FindMusubiMaintainersV1(musubi::prelude::FindMusubiMaintainersV1),
        /// Fetch a finalized page of renewable Musubi V1 archive locations.
        FindMusubiArchiveLocationsV1(musubi::prelude::FindMusubiArchiveLocationsV1),
        /// Fetch bounded exact finalized Musubi V1 cache-retention decisions.
        FindMusubiArchiveRetentionV1(musubi::prelude::FindMusubiArchiveRetentionV1),
        /// Fetch one permanent Musubi V1 global alias record.
        FindMusubiAliasV1(musubi::prelude::FindMusubiAliasV1),
        /// Fetch a finalized page of permanent Musubi V1 alias history.
        FindMusubiAliasHistoryV1(musubi::prelude::FindMusubiAliasHistoryV1),
        /// Fetch a finalized ordered-prefix page from the Musubi V1 directory.
        FindMusubiOrderedPrefixV1(musubi::prelude::FindMusubiOrderedPrefixV1),
        /// Fetch an account by stable alias.
        FindAccountByAlias(account::prelude::FindAccountByAlias),
        /// Fetch a domain by identifier.
        FindDomainById(domain::prelude::FindDomainById),
        /// Fetch a non-fungible asset by identifier.
        FindNftById(nft::prelude::FindNftById),
        #[cfg(test)]
        #[doc(hidden)]
        __TestFallback,
        /// Read one consensus-owned generic game session.
        FindGameSessionById(game::FindGameSessionById),
        /// Read one bounded proof-verification receipt.
        FindExecutionProofVerificationById(game::FindExecutionProofVerificationById),
        /// Read a native one-shot exact-price NFT offer.
        FindNftSaleOfferById(nft_market::FindNftSaleOfferById),
        /// Fetch the immutable direct dataspace home row of an asset definition.
        FindAssetDefinitionDirectHome(asset::prelude::FindAssetDefinitionDirectHome),
    }
    /// An enum of all possible singular query outputs
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        IntoSchema,
        FromVariant,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Boxed output of a singular query.
    #[norito(tag = "kind", content = "content")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::SingularQueryOutputBox")]
    pub enum SingularQueryOutputBox {
        /// Executor data model payload.
        ExecutorDataModel(crate::executor::ExecutorDataModel),
        /// Parameter set payload.
        Parameters(Parameters),
        /// Linked domain identifier list.
        DomainIds(Vec<DomainId>),
        /// Account payload.
        Account(Account),
        /// Bound account alias records.
        AccountAliasBindingRecords(Vec<account::AccountAliasBindingRecord>),
        /// Account recovery policy payload.
        AccountRecoveryPolicy(crate::account::AccountRecoveryPolicy),
        /// Account recovery request payload.
        AccountRecoveryRequest(crate::account::AccountRecoveryRequest),
        /// Linked account identifier list.
        AccountIds(Vec<AccountId>),
        /// Proof record payload.
        ProofRecord(crate::proof::ProofRecord),
        /// Smart contract manifest payload.
        ContractManifest(crate::smart_contract::manifest::ContractManifest),
        /// Active ABI version payload.
        AbiVersion(runtime::AbiVersion),
        /// Asset payload.
        Asset(crate::asset::value::Asset),
        /// Asset definition payload.
        AssetDefinition(crate::asset::definition::AssetDefinition),
        /// Native asset escrow payload.
        AssetEscrowRecord(crate::escrow::AssetEscrowRecord),
        /// Trigger payload.
        Trigger(crate::trigger::Trigger),
        /// Twitter binding payload.
        TwitterBindingRecord(crate::oracle::TwitterBindingRecord),
        /// Oracle feed configuration payload.
        OracleFeedConfig(crate::oracle::FeedConfig),
        /// Oracle dispute payload.
        OracleDispute(crate::oracle::OracleDispute),
        /// Oracle change proposal payload.
        OracleChangeProposal(crate::oracle::OracleChangeProposal),
        /// Oracle provider statistics payload.
        OracleProviderStats(crate::oracle::OracleProviderStats),
        /// Latest `DeFi` oracle attestation payload.
        DefiOracleAttestation(crate::oracle::DefiOracleAttestation),
        /// Domain endorsements payload.
        DomainEndorsements(Vec<crate::nexus::DomainEndorsementRecord>),
        /// Domain endorsement policy payload.
        DomainEndorsementPolicy(crate::nexus::DomainEndorsementPolicy),
        /// Domain committee payload.
        DomainCommittee(crate::nexus::DomainCommittee),
        /// DA pin intent payload.
        DaPinIntent(crate::da::pin_intent::DaPinIntentWithLocation),
        /// Fee sponsor policy payload.
        FeeSponsorProgram(crate::nexus::FeeSponsorProgram),
        /// Finalized chain-authoritative `SoraFS` pin manifest.
        SorafsPinManifest(crate::sorafs::pin_registry::PinManifestFinalizedRecordV1),
        /// Finalized, keyset-bounded `SoraFS` pin-manifest page.
        SorafsPinManifestPage(crate::sorafs::pin_registry::PinManifestPageV1),
        /// Active authoritative `SoraFS` orderbook policy payload.
        SorafsOrderbookPolicy(crate::sorafs::orderbook::OrderbookAdmissionPolicyRecord),
        /// Authoritative `SoraFS` order payload.
        SorafsOrderbookOrder(crate::sorafs::orderbook::OrderbookOrderRecord),
        /// Authoritative `SoraFS` cancellation payload.
        SorafsOrderbookCancellation(crate::sorafs::orderbook::OrderbookCancellationRecord),
        /// Authoritative `SoraFS` settlement receipt payload.
        SorafsOrderbookReceipt(crate::sorafs::orderbook::OrderbookSettlementReceiptRecord),
        /// Authoritative `SoraFS` trade payload.
        SorafsOrderbookTrade(crate::sorafs::orderbook::OrderbookTradeRecord),
        /// Authoritative `SoraFS` settlement channel payload.
        SorafsOrderbookChannel(crate::sorafs::orderbook::OrderbookSettlementChannelRecord),
        /// Authoritative `SoraFS` orderbook status payload.
        SorafsOrderbookStatus(crate::sorafs::orderbook::OrderbookLedgerStatusV1),
        /// Cursor-bounded authoritative `SoraFS` order page.
        SorafsOrderbookOrderPage(crate::sorafs::orderbook::OrderbookOrderPageV1),
        /// Cursor-bounded authoritative `SoraFS` settlement-receipt page.
        SorafsOrderbookReceiptPage(crate::sorafs::orderbook::OrderbookSettlementReceiptPageV1),
        /// Cursor-bounded authoritative `SoraFS` trade page.
        SorafsOrderbookTradePage(crate::sorafs::orderbook::OrderbookTradePageV1),
        /// Cursor-bounded authoritative `SoraFS` settlement-channel page.
        SorafsOrderbookChannelPage(crate::sorafs::orderbook::OrderbookSettlementChannelPageV1),
        /// Cursor-bounded page of committed `SoraFS` orderbook events.
        SorafsOrderbookEventPage(crate::sorafs::orderbook::OrderbookFinalizedEventPageV1),
        /// Active authoritative `SoraFS` reserve policy.
        SorafsReservePolicy(crate::sorafs::reserve::ReserveAuthorityPolicyRecordV1),
        /// Authoritative provider reserve account.
        SorafsReserveProvider(crate::sorafs::reserve::ReserveProviderAccountV1),
        /// Authoritative reserve movement.
        SorafsReserveMovement(crate::sorafs::reserve::ReserveMovementRecordV1),
        /// Authoritative reserve appeal.
        SorafsReserveAppeal(crate::sorafs::reserve::ReserveAppealRecordV1),
        /// Cursor-bounded authoritative provider reserve-account page.
        SorafsReserveProviderPage(crate::sorafs::reserve::ReserveProviderAccountPageV1),
        /// Cursor-bounded authoritative reserve-movement page.
        SorafsReserveMovementPage(crate::sorafs::reserve::ReserveMovementPageV1),
        /// Cursor-bounded authoritative reserve-appeal page.
        SorafsReserveAppealPage(crate::sorafs::reserve::ReserveAppealPageV1),
        /// Cursor-bounded page of committed `SoraFS` reserve events.
        SorafsReserveEventPage(crate::sorafs::reserve::ReserveFinalizedEventPageV1),
        /// Active authoritative `SoraFS` `PoP` issuer policy.
        SorafsPopIssuerPolicy(crate::sorafs::pop_registry::PopIssuerPolicyRecordV1),
        /// Payload-free authoritative `PoP` credential commitment.
        SorafsPopCredentialCommitment(crate::sorafs::pop_registry::PopCredentialCommitmentRecordV1),
        /// Authoritative signed `PoP` commitment-root publication.
        SorafsPopCommitmentRoot(crate::sorafs::pop_registry::PopCommitmentRootRecordV1),
        /// Authoritative signed `PoP` revocation publication.
        SorafsPopRevocationPublication(
            crate::sorafs::pop_registry::PopRevocationPublicationRecordV1,
        ),
        /// Payload-free authoritative `PoP` revocation.
        SorafsPopRevocation(crate::sorafs::pop_registry::PopRevocationRecordV1),
        /// Authoritative `PoP` registry audit-chain link.
        SorafsPopAuditDigest(crate::sorafs::pop_registry::PopRegistryAuditDigestRecordV1),
        /// Authoritative `PoP` registry anchors and counters.
        SorafsPopRegistryStatus(crate::sorafs::pop_registry::PopRegistryStatusV1),
        /// Commitment-only citizen-bond record.
        SorafsCitizenBond(crate::sorafs::anonymity::SorafsCitizenBondV1),
        /// Current frozen citizen-bond membership snapshot.
        SorafsCitizenBondSnapshot(crate::sorafs::anonymity::SorafsCitizenBondSnapshotV1),
        /// Finalized chain-authoritative repair task, lease, outcome, slash, and appeal.
        SorafsRepairTask(crate::sorafs::moderation_ledger::RepairFinalizedTaskV1),
        /// Cursor-bounded chain-authoritative repair-task page.
        SorafsRepairTaskPage(crate::sorafs::moderation_ledger::RepairLedgerTaskPageV1),
        /// Finalized chain-authoritative repair-ledger counters.
        SorafsRepairStatus(crate::sorafs::moderation_ledger::RepairFinalizedStatusV1),
        /// Cursor-bounded page of committed repair-ledger events.
        SorafsRepairEventPage(crate::sorafs::moderation_ledger::RepairFinalizedEventPageV1),
        /// Finalized chain-authoritative PDP or `PoTR` proof outcome.
        SorafsProofOutcome(crate::sorafs::proof_ledger::ProofOutcomeFinalizedRecordV1),
        /// Cursor-bounded page of committed PDP/PoTR proof-outcome events.
        SorafsProofOutcomeEventPage(crate::sorafs::proof_ledger::ProofOutcomeFinalizedEventPageV1),
        /// Active authoritative `SoraFS` reputation-journal authority policy.
        SorafsReputationJournalAuthorityPolicy(
            crate::sorafs::reputation::ReputationJournalAuthorityPolicyRecordV1,
        ),
        /// Finalized reputation-journal event resolved by authoritative source.
        SorafsReputationJournalEvent(crate::sorafs::reputation::ReputationJournalFinalizedEventV1),
        /// Cursor-bounded page of committed reputation-journal events.
        SorafsReputationJournalEventPage(
            crate::sorafs::reputation::ReputationJournalFinalizedEventPageV1,
        ),
        /// Active authoritative `SoraFS` moderation policy payload.
        SorafsModerationPolicy(crate::sorafs::moderation_ledger::ModerationLedgerPolicyRecord),
        /// Authoritative appeal intake, citizen-bond snapshot, and sortition lifecycle.
        SorafsModerationAppeal(crate::sorafs::moderation_ledger::ModerationAppealRecordV1),
        /// Payload-free, PoP-verified juror eligibility record.
        SorafsModerationJurorEligibility(
            crate::sorafs::moderation_ledger::ModerationJurorEligibilityRecordV1,
        ),
        /// Authoritative `SoraFS` moderation case payload.
        SorafsModerationCase(crate::sorafs::moderation_ledger::ModerationCaseRecordV1),
        /// Authoritative `SoraFS` moderation commitment payload.
        SorafsModerationCommit(crate::sorafs::moderation_ledger::ModerationCommitRecordV1),
        /// Authoritative `SoraFS` moderation reveal payload.
        SorafsModerationReveal(crate::sorafs::moderation_ledger::ModerationRevealRecordV1),
        /// Authoritative `SoraFS` moderation challenge payload.
        SorafsModerationChallenge(crate::sorafs::moderation_ledger::ModerationChallengeRecordV1),
        /// Terminal authoritative `SoraFS` moderation outcome payload.
        SorafsModerationOutcome(crate::sorafs::moderation_ledger::ModerationOutcomeRecordV1),
        /// Authoritative `SoraFS` moderation no-show payload.
        SorafsModerationNoShow(crate::sorafs::moderation_ledger::ModerationNoShowRecordV1),
        /// Authoritative `SoraFS` moderation status payload.
        SorafsModerationStatus(crate::sorafs::moderation_ledger::ModerationLedgerStatusV1),
        /// Complete bounded moderation projection at one finalized block.
        SorafsModerationSnapshot(
            crate::sorafs::moderation_ledger::ModerationFinalizedLedgerSnapshotV1,
        ),
        /// Cursor-bounded page of committed moderation events.
        SorafsModerationEventPage(crate::sorafs::moderation_ledger::ModerationFinalizedEventPageV1),
        /// Immutable native settlement business receipt with exact resolved movements.
        SettlementReceipt(crate::isi::SettlementReceipt),
        /// Protected native FX corridor policy registry payload.
        FxCorridorPolicyRegistry(crate::isi::settlement::FxCorridorPolicyRegistry),
        /// Native FX corridor policy payload.
        FxCorridorPolicy(crate::isi::settlement::FxCorridorPolicy),
        /// Exact authoritative Musubi V1 package payload.
        MusubiPackage(crate::musubi::MusubiPackageRecordV1),
        /// Paired finalized home/universal view of one exact Musubi V1 release.
        MusubiRelease(crate::musubi::MusubiExactReleaseSnapshotV1),
        /// Exact immutable provider bundle-attestation audit record.
        MusubiProviderBundleAttestation(crate::musubi::MusubiProviderBundleAttestationRecordV1),
        /// Finalized universal resolver-index page.
        MusubiResolverIndexPage(crate::musubi::MusubiResolverIndexPageV1),
        /// Finalized structured-version page.
        MusubiVersionPage(crate::musubi::MusubiVersionPageV1),
        /// Finalized accepted-maintainer page.
        MusubiMaintainerPage(crate::musubi::MusubiMaintainerPageV1),
        /// Finalized renewable archive-location page.
        MusubiArchiveLocationPage(crate::musubi::MusubiArchiveLocationPageV1),
        /// Exact bounded finalized cache-retention decisions.
        MusubiArchiveRetentionPage(crate::musubi::MusubiArchiveRetentionPageV1),
        /// Exact permanent global-alias payload.
        MusubiAlias(crate::musubi::MusubiAliasRecordV1),
        /// Finalized permanent alias-history page.
        MusubiAliasHistoryPage(crate::musubi::MusubiAliasHistoryPageV1),
        /// Finalized ordered package-directory page.
        MusubiOrderedPackagePage(crate::musubi::MusubiOrderedPackagePageV1),
        /// Account identifier payload.
        AccountId(AccountId),
        /// Domain payload.
        Domain(crate::domain::Domain),
        /// Non-fungible asset payload.
        Nft(crate::nft::Nft),
        /// Native generic game state and terminal receipt.
        GameSessionRecord(crate::game::GameSessionRecordV1),
        /// Compact reference to a verified execution proof in a finalized block.
        ExecutionProofVerification(crate::execution_proofs::ExecutionProofVerificationV1),
        /// Complete immutable NFT sale terms and terminal decision.
        NftSaleRecord(crate::nft_market::NftSaleRecordV1),
        /// Immutable direct dataspace home row of one live asset-definition incarnation.
        AssetDefinitionDirectHome(crate::asset::AssetDefinitionDirectHomeV1),
    }
    /// The results of a single iterable query request.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Materialised batch of query results with pagination metadata.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryOutput")]
    pub struct QueryOutput {
        /// A single batch of results
        pub batch: QueryOutputBatchBoxTuple,
        /// The exact number of items remaining after this batch, when it was requested and cheap
        /// enough to compute.
        pub remaining_items: Option<u64>,
        /// Whether more items are available after this batch.
        pub has_more: bool,
        /// If not `None`, contains a cursor that can be used to fetch the next batch of results. Otherwise the current batch is the last one.
        pub continue_cursor: Option<ForwardCursor>,
    }
    /// A canonical iterable-query envelope with all parameters needed to execute it.
    #[derive(Decode, Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryWithParams")]
    pub struct QueryWithParams {
        /// Unit marker preserving the canonical query envelope layout.
        pub query: (),
        /// Encoded concrete query payload.
        pub query_payload: Vec<u8>,
        /// Query/item discriminator for the iterable query.
        pub item: QueryItemKind,
        /// Encoded predicate.
        pub predicate_bytes: Vec<u8>,
        /// Encoded selector.
        pub selector_bytes: Vec<u8>,
        /// Cursor and pagination parameters.
        pub params: QueryParams,
    }
    impl Clone for QueryWithParams {
        fn clone(&self) -> Self {
            Self {
                query: (),
                query_payload: self.query_payload.clone(),
                item: self.item,
                predicate_bytes: self.predicate_bytes.clone(),
                selector_bytes: self.selector_bytes.clone(),
                params: self.params.clone(),
            }
        }
    }
    impl QueryWithParams {
        /// Construct the canonical query envelope from an erased query and parameters.
        ///
        /// An erased carrier retains only the output item type, so it cannot distinguish query
        /// types whose payload shapes are identical. Build seller-, buyer-, and status-filtered
        /// escrow queries through [`crate::query::builder::QueryBuilder`] (or construct this
        /// envelope with the corresponding query-specific [`QueryItemKind`]) instead.
        ///
        /// # Errors
        ///
        /// Returns [`QueryWithParamsError`] when the concrete erased query type has no canonical
        /// V1 [`QueryItemKind`] mapping.
        pub fn new(
            query: &QueryBox<QueryOutputBatchBox>,
            params: QueryParams,
        ) -> Result<Self, QueryWithParamsError> {
            macro_rules! try_build {
                ($item:ty, $kind:ident) => {
                    if let Some(erased) = super::iter_query_inner::<$item>(query) {
                        return Ok(Self {
                            query: (),
                            query_payload: erased.payload().to_vec(),
                            item: QueryItemKind::$kind,
                            predicate_bytes: norito::codec::Encode::encode(erased.predicate()),
                            selector_bytes: norito::codec::Encode::encode(erased.selector()),
                            params,
                        });
                    }
                };
            }
            try_build!(crate::domain::Domain, Domain);
            try_build!(crate::account::Account, Account);
            try_build!(crate::account::AccountId, AccountId);
            try_build!(crate::asset::value::Asset, Asset);
            try_build!(crate::asset::definition::AssetDefinition, AssetDefinition);
            try_build!(crate::repo::RepoAgreement, RepoAgreement);
            try_build!(crate::nft::Nft, Nft);
            try_build!(crate::rwa::Rwa, Rwa);
            try_build!(crate::role::Role, Role);
            try_build!(crate::role::RoleId, RoleId);
            try_build!(iroha_model_base::peer::PeerId, PeerId);
            try_build!(crate::trigger::TriggerId, TriggerId);
            try_build!(crate::trigger::Trigger, Trigger);
            try_build!(crate::query::CommittedTransaction, CommittedTransaction);
            try_build!(crate::block::SignedBlock, SignedBlock);
            try_build!(crate::block::BlockHeader, BlockHeader);
            try_build!(crate::proof::ProofRecord, ProofRecord);
            try_build!(crate::nexus::FeeSponsorProgram, FeeSponsorProgram);
            try_build!(crate::nexus::FeeSponsorProgramId, FeeSponsorProgramId);
            try_build!(crate::permission::Permission, Permission);
            try_build!(crate::oracle::FeedConfig, OracleFeedConfig);
            try_build!(
                crate::events::data::oracle::FeedEventRecord,
                OracleFeedEventRecord
            );
            try_build!(
                crate::oracle::OracleProviderStatsRecord,
                OracleProviderStatsRecord
            );
            try_build!(crate::oracle::OracleDispute, OracleDispute);
            try_build!(crate::oracle::OracleChangeProposal, OracleChangeProposal);
            try_build!(crate::oracle::TwitterBindingRecord, TwitterBindingRecord);
            try_build!(crate::oracle::DefiOracleAttestation, DefiOracleAttestation);
            try_build!(crate::escrow::AssetEscrowRecord, AssetEscrowRecord);
            Err(QueryWithParamsError::unsupported(query.type_name_key()))
        }
        /// Access the canonical iterable-query payload components.
        pub fn parts(&self) -> (QueryItemKind, &[u8], &[u8], &[u8]) {
            (
                self.item,
                &self.predicate_bytes,
                &self.selector_bytes,
                &self.query_payload,
            )
        }
    }
    /// Wire discriminator identifying an iterable query or its target item type.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Categories of iterable queries used for dispatch, pagination, and filtering.
    #[norito(tag = "kind", content = "content")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryItemKind")]
    pub enum QueryItemKind {
        /// Domain items.
        Domain,
        /// Account items.
        Account,
        /// Account identifier items.
        AccountId,
        /// Asset items.
        Asset,
        /// Asset definition items.
        AssetDefinition,
        /// Repository agreement items.
        RepoAgreement,
        /// NFT items.
        Nft,
        /// RWA lot items.
        Rwa,
        /// Role items.
        Role,
        /// Role identifier items.
        RoleId,
        /// Peer identifier items.
        PeerId,
        /// Trigger identifier items.
        TriggerId,
        /// Trigger items.
        Trigger,
        /// Committed transaction items.
        CommittedTransaction,
        /// Signed block items.
        SignedBlock,
        /// Block header items.
        BlockHeader,
        /// Proof record items.
        ProofRecord,
        /// Oracle feed configuration items.
        OracleFeedConfig,
        /// Oracle feed history record items.
        OracleFeedEventRecord,
        /// Oracle provider statistics record items.
        OracleProviderStatsRecord,
        /// Oracle dispute items.
        OracleDispute,
        /// Oracle change proposal items.
        OracleChangeProposal,
        /// Twitter binding record items.
        TwitterBindingRecord,
        /// `DeFi` oracle attestation items.
        DefiOracleAttestation,
        /// Permission items.
        Permission,
        /// Native asset escrow records.
        AssetEscrowRecord,
        /// Fee sponsor policy records.
        FeeSponsorProgram,
        /// Fee sponsor program identifier records.
        FeeSponsorProgramId,
        /// Native asset escrows filtered by seller (wire tag 28).
        ///
        /// This query-specific tag is appended because seller and buyer query payloads both encode
        /// as a single [`AccountId`]. The tag is therefore the consensus-visible discriminator;
        /// existing variants above must never be reordered.
        AssetEscrowsBySeller,
        /// Native asset escrows filtered by buyer (wire tag 29).
        AssetEscrowsByBuyer,
        /// Native asset escrows filtered by lifecycle status (wire tag 30).
        AssetEscrowsByStatus,
    }
    /// Trait mapping item types to a `QueryItemKind` marker.
    ///
    /// Implemented for each supported canonical iterable-query item type.
    pub trait ItemKindTag {
        /// Return the [`QueryItemKind`] discriminator for the implementing type.
        fn kind() -> QueryItemKind;
    }
    impl ItemKindTag for Domain {
        fn kind() -> QueryItemKind {
            QueryItemKind::Domain
        }
    }
    impl ItemKindTag for Account {
        fn kind() -> QueryItemKind {
            QueryItemKind::Account
        }
    }
    impl ItemKindTag for AccountId {
        fn kind() -> QueryItemKind {
            QueryItemKind::AccountId
        }
    }
    impl ItemKindTag for Asset {
        fn kind() -> QueryItemKind {
            QueryItemKind::Asset
        }
    }
    impl ItemKindTag for AssetDefinition {
        fn kind() -> QueryItemKind {
            QueryItemKind::AssetDefinition
        }
    }
    impl ItemKindTag for RepoAgreement {
        fn kind() -> QueryItemKind {
            QueryItemKind::RepoAgreement
        }
    }
    impl ItemKindTag for Nft {
        fn kind() -> QueryItemKind {
            QueryItemKind::Nft
        }
    }
    impl ItemKindTag for Rwa {
        fn kind() -> QueryItemKind {
            QueryItemKind::Rwa
        }
    }
    impl ItemKindTag for Role {
        fn kind() -> QueryItemKind {
            QueryItemKind::Role
        }
    }
    impl ItemKindTag for RoleId {
        fn kind() -> QueryItemKind {
            QueryItemKind::RoleId
        }
    }
    impl ItemKindTag for PeerId {
        fn kind() -> QueryItemKind {
            QueryItemKind::PeerId
        }
    }
    impl ItemKindTag for TriggerId {
        fn kind() -> QueryItemKind {
            QueryItemKind::TriggerId
        }
    }
    impl ItemKindTag for Trigger {
        fn kind() -> QueryItemKind {
            QueryItemKind::Trigger
        }
    }
    impl ItemKindTag for CommittedTransaction {
        fn kind() -> QueryItemKind {
            QueryItemKind::CommittedTransaction
        }
    }
    impl ItemKindTag for SignedBlock {
        fn kind() -> QueryItemKind {
            QueryItemKind::SignedBlock
        }
    }
    impl ItemKindTag for BlockHeader {
        fn kind() -> QueryItemKind {
            QueryItemKind::BlockHeader
        }
    }
    impl ItemKindTag for crate::proof::ProofRecord {
        fn kind() -> QueryItemKind {
            QueryItemKind::ProofRecord
        }
    }
    impl ItemKindTag for crate::oracle::FeedConfig {
        fn kind() -> QueryItemKind {
            QueryItemKind::OracleFeedConfig
        }
    }
    impl ItemKindTag for crate::events::data::oracle::FeedEventRecord {
        fn kind() -> QueryItemKind {
            QueryItemKind::OracleFeedEventRecord
        }
    }
    impl ItemKindTag for crate::oracle::OracleProviderStatsRecord {
        fn kind() -> QueryItemKind {
            QueryItemKind::OracleProviderStatsRecord
        }
    }
    impl ItemKindTag for crate::oracle::OracleDispute {
        fn kind() -> QueryItemKind {
            QueryItemKind::OracleDispute
        }
    }
    impl ItemKindTag for crate::oracle::OracleChangeProposal {
        fn kind() -> QueryItemKind {
            QueryItemKind::OracleChangeProposal
        }
    }
    impl ItemKindTag for crate::oracle::TwitterBindingRecord {
        fn kind() -> QueryItemKind {
            QueryItemKind::TwitterBindingRecord
        }
    }
    impl ItemKindTag for crate::oracle::DefiOracleAttestation {
        fn kind() -> QueryItemKind {
            QueryItemKind::DefiOracleAttestation
        }
    }
    impl ItemKindTag for crate::permission::Permission {
        fn kind() -> QueryItemKind {
            QueryItemKind::Permission
        }
    }
    impl ItemKindTag for crate::escrow::AssetEscrowRecord {
        fn kind() -> QueryItemKind {
            QueryItemKind::AssetEscrowRecord
        }
    }
    impl ItemKindTag for crate::nexus::FeeSponsorProgram {
        fn kind() -> QueryItemKind {
            QueryItemKind::FeeSponsorProgram
        }
    }
    impl ItemKindTag for crate::nexus::FeeSponsorProgramId {
        fn kind() -> QueryItemKind {
            QueryItemKind::FeeSponsorProgramId
        }
    }
    // Manual schema for QueryWithParams: represent only `params` field.
    impl iroha_schema::TypeId for QueryWithParams {
        fn id() -> String {
            "QueryWithParams".to_owned()
        }
    }
    impl iroha_schema::IntoSchema for QueryWithParams {
        fn type_name() -> String {
            "QueryWithParams".to_owned()
        }
        fn update_schema_map(map: &mut iroha_schema::MetaMap) {
            use iroha_schema::{Declaration, Metadata, NamedFieldsMeta};
            if !map.contains_key::<Self>() {
                map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                    declarations: vec![Declaration {
                        name: "params".to_owned(),
                        ty: core::any::TypeId::of::<QueryParams>(),
                    }],
                }));
                <QueryParams as iroha_schema::IntoSchema>::update_schema_map(map);
            }
        }
    }
    /// A query request that can be sent to an Iroha peer.
    ///
    /// In case of HTTP API, the query request must also be signed (see [`QueryRequestWithAuthority`] and [`SignedQuery`]).
    #[derive(Decode, Encode, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryRequest")]
    pub enum QueryRequest {
        /// Singular query (non-iterable) request.
        Singular(SingularQueryBox),
        /// Start an iterable query with parameters.
        Start(QueryWithParams),
        /// Continue an iterable query from a cursor.
        Continue(ForwardCursor),
    }
    /// An enum containing either a singular or an iterable query
    #[derive(Decode, Encode, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::AnyQueryBox")]
    pub enum AnyQueryBox {
        /// Wrapped singular query.
        Singular(SingularQueryBox),
        /// Wrapped iterable query.
        Iterable(QueryWithParams),
    }
    /// A response to a [`QueryRequest`] from an Iroha peer
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// Result returned by Torii in response to a query.
    #[norito(tag = "kind", content = "content")]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryResponse")]
    pub enum QueryResponse {
        /// Singular query output.
        Singular(SingularQueryOutputBox),
        /// Iterable query output.
        Iterable(QueryOutput),
    }
    /// A [`QueryRequest`], combined with an authority that wants to execute the query
    #[derive(Decode, Encode, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::QueryRequestWithAuthority")]
    pub struct QueryRequestWithAuthority {
        /// Exact genesis-lineage identity for the target network.
        pub network_id: NetworkId,
        /// Account executing the query.
        pub authority: AccountId,
        /// Unix creation timestamp in milliseconds.
        pub creation_time_ms: u64,
        /// Mandatory nonzero request lifetime in milliseconds.
        pub time_to_live_ms: NonZeroU64,
        /// Caller-generated one-shot replay nonce.
        #[norito(json = "crate::json_helpers::fixed_bytes_hex")]
        pub nonce: [u8; 32],
        /// Query payload.
        pub request: QueryRequest,
    }
    /// A signature of [`QueryRequestWithAuthority`] to be used in [`SignedQuery`]
    #[derive(Debug, Clone, PartialEq, Eq, IntoSchema)]
    /// Container type for `QuerySignature(pub` query data.
    pub struct QuerySignature(pub SignatureOf<QueryRequestWithAuthority>);
    impl norito::NoritoSchema for QuerySignature {
        fn nominal_name() -> String {
            "iroha_data_model::query::model::QuerySignature".to_owned()
        }
        fn frame_name() -> String {
            <SignatureOf<QueryRequestWithAuthority> as norito::NoritoSchema>::frame_name()
        }
    }
    impl<'a> norito::core::DecodeFromSlice<'a> for QuerySignature {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let (signature, used) =
                <SignatureOf<QueryRequestWithAuthority> as norito::core::DecodeFromSlice>::decode_from_slice(
                    bytes,
                )?;
            Ok((QuerySignature(signature), used))
        }
    }

    impl norito::core::SerializePayload for QuerySignature {
        fn encoded_len_hint(&self) -> Option<usize> {
            norito::core::SerializePayload::encoded_len_hint(&self.0)
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            norito::core::SerializePayload::encoded_len_exact(&self.0)
        }
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            norito::core::SerializePayload::serialize(&self.0, writer)
        }
    }

    impl<'de> norito::core::DeserializePayload<'de> for QuerySignature {
        fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
            let as_sig = archived.cast::<SignatureOf<QueryRequestWithAuthority>>();
            let sig = <SignatureOf<QueryRequestWithAuthority> as norito::core::DeserializePayload>::deserialize(as_sig);
            QuerySignature(sig)
        }
        fn try_deserialize(
            archived: &'de norito::core::Archived<Self>,
        ) -> Result<Self, norito::core::Error> {
            let as_sig = archived.cast::<SignatureOf<QueryRequestWithAuthority>>();
            let sig = <SignatureOf<QueryRequestWithAuthority> as norito::core::DeserializePayload>::try_deserialize(as_sig)?;
            Ok(QuerySignature(sig))
        }
    }

    impl norito::json::FastJsonWrite for QuerySignature {
        fn write_json(&self, out: &mut String) {
            let encoded = super::json_wrappers::base64_encode(self.0.payload());
            norito::json::write_json_string(&encoded, out);
        }
        fn write_json_to(
            &self,
            out: &mut dyn norito::json::JsonWriteSink,
        ) -> Result<(), norito::json::BoundedJsonError> {
            super::json_wrappers::base64_encode_to(self.0.payload(), out)
        }
    }

    impl norito::json::JsonDeserialize for QuerySignature {
        fn json_deserialize(
            parser: &mut norito::json::Parser<'_>,
        ) -> Result<Self, norito::json::Error> {
            let encoded = parser.parse_string()?;
            let bytes = super::json_wrappers::base64_decode(encoded).map_err(|error| {
                if error.is_decode_resource_limit() {
                    error
                } else {
                    norito::json::Error::InvalidField {
                        field: String::from("QuerySignature"),
                        message: String::from("invalid base64 signature payload"),
                    }
                }
            })?;
            norito::core::reserve_decode_allocation(bytes.len())
                .map_err(norito::json::Error::from_decode_resource)?;
            let signature = iroha_crypto::Signature::try_from_bytes(&bytes).map_err(|error| {
                norito::json::Error::InvalidField {
                    field: String::from("QuerySignature"),
                    message: error.to_string(),
                }
            })?;
            Ok(QuerySignature(SignatureOf::from_signature(signature)))
        }
    }
    /// A signed and authorized query request
    #[derive(Encode, IntoSchema, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::SignedQuery")]
    pub struct SignedQuery {
        pub signature: QuerySignature,
        pub payload: QueryRequestWithAuthority,
    }
    /// Response returned by [`FindTransactions`] query.
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
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[getset(get = "pub")]
    /// Snapshot representing a transaction committed to the ledger.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::model::CommittedTransaction")]
    #[norito(deny_unknown_fields)]
    pub struct CommittedTransaction {
        /// Hash of the block containing this transaction.
        pub block_hash: HashOf<BlockHeader>,
        /// Hash of the transaction entrypoint.
        pub entrypoint_hash: HashOf<TransactionEntrypoint>,
        /// Merkle inclusion proof for the transaction entrypoint.
        pub entrypoint_proof: MerkleProof<TransactionEntrypoint>,
        /// The initial execution step of the transaction.
        pub entrypoint: TransactionEntrypoint,
        /// Hash of the one full typed Network output, including its source index and completions.
        pub output_hash: HashOf<crate::block::execution_output::ExecutionOutputV1>,
        /// Merkle proof in the separate complete typed-output tree.
        pub output_proof: MerkleProof<crate::block::execution_output::ExecutionOutputV1>,
        /// Sole full output; this query cannot represent an internal invocation as a network input.
        pub output: crate::block::execution_output::ExecutionOutputV1,
    }
}
impl CommittedTransaction {
    /// Selective exact Network input/output inclusion. The caller MUST first
    /// authenticate this header, complete `ExecutionCommitment`, native `NetworkId`
    /// and exact authenticated epoch committee from its independently pinned finality root.
    /// Passing a raw commitment only checks inclusion and never creates a finality capability.
    /// This method does not authorize disclosing the selected record.
    #[must_use]
    pub fn verify_selective_in_authenticated_execution(
        &self,
        expected_network: &crate::NetworkId,
        header: &crate::block::BlockHeader,
        commitment: &crate::sumeragi_finality::ExecutionCommitment,
    ) -> bool {
        if commitment.validate().is_err()
            || self.block_hash != header.hash()
            || self.entrypoint_hash != self.entrypoint.hash()
            || self.output_hash != HashOf::new(&self.output)
        {
            return false;
        }
        let TransactionEntrypoint::External(signed) = &self.entrypoint else {
            return false;
        };
        if signed.network_id() != Some(expected_network) || signed.verify_signature().is_err() {
            return false;
        }
        let crate::block::execution_output::ExecutionOutputV1::Network(output) = &self.output
        else {
            return false;
        };
        let (Some(inputs), Some(outputs)) = (
            commitment.transaction_input_commitment,
            commitment.transaction_output_commitment,
        ) else {
            return false;
        };
        output.input_index == self.entrypoint_proof.leaf_index()
            && self.entrypoint_proof.verify(&self.entrypoint_hash, &inputs)
            && self.output_proof.verify(&self.output_hash, &outputs)
    }

    /// Borrow the sole full result from this query's typed output.
    pub fn result(&self) -> &crate::transaction::TransactionResult {
        self.output.result()
    }
    /// Verify exact wire binding against an independently authenticated execution commitment.
    /// The caller owns QC/finality authentication; a self-asserted commitment is not authority.
    #[must_use]
    pub fn verify_inclusion_in_authenticated_execution(
        &self,
        block: &SignedBlock,
        commitment: &crate::sumeragi_finality::ExecutionCommitment,
    ) -> bool {
        if commitment.transaction_input_commitment != block.network_input_merkle_commitment()
            || commitment.transaction_output_commitment != block.output_merkle_commitment()
            || commitment.validate().is_err()
            || !block.has_results()
            || block.validate_output_merkle_cache().is_err()
        {
            return false;
        }
        let Ok(wire) = block.encode_wire() else {
            return false;
        };
        u64::try_from(wire.len()).ok() == Some(commitment.executed_block_wire_len)
            && Hash::new(&wire) == commitment.executed_block_wire_hash
            && block
                .execution_context()
                .is_none_or(crate::block::BlockExecutionContextBundle::has_current_version)
            && self.verify_inclusion_in_block(block)
    }
    /// Structural inclusion under exact full-wire commitments. The caller must authenticate
    /// that wire separately. Header signatures alone never authenticate outputs.
    #[must_use]
    pub fn verify_inclusion_in_block(&self, block: &SignedBlock) -> bool {
        let crate::block::execution_output::ExecutionOutputV1::Network(output) = &self.output
        else {
            return false;
        };
        if block.hash() != self.block_hash
            || self.entrypoint_hash != self.entrypoint.hash()
            || self.output_hash != HashOf::new(&self.output)
            || output.input_index != self.entrypoint_proof.leaf_index()
            || block.validate_output_merkle_cache().is_err()
            || block.network_entrypoint_at(output.input_index as usize) != Some(&self.entrypoint)
            || block
                .execution_outputs()
                .get(self.output_proof.leaf_index() as usize)
                != Some(&self.output)
        {
            return false;
        }
        let Some(inputs) = block.network_input_merkle_commitment() else {
            return false;
        };
        let Some(outputs) = block.output_merkle_commitment() else {
            return false;
        };
        self.entrypoint_proof.verify(&self.entrypoint_hash, &inputs)
            && self.output_proof.verify(&self.output_hash, &outputs)
    }
}
// Server-side predicate support for CommittedTransaction (feature-gated on std)
/// Filters applied when matching committed transactions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct CommittedTxFilters {
    /// Require the carrier block hash to equal the provided hash.
    pub block_eq: Option<HashOf<BlockHeader>>,
    /// Require the carrier block hash to differ from the provided hash.
    pub block_ne: Option<HashOf<BlockHeader>>,
    /// Require the carrier block hash to be one of the listed hashes.
    pub block_in: std::vec::Vec<HashOf<BlockHeader>>,
    /// Require the carrier block hash to be absent from the listed hashes.
    pub block_nin: std::vec::Vec<HashOf<BlockHeader>>,
    /// Require the presence (`true`) or absence (`false`) of a carrier block hash.
    pub block_exists: Option<bool>,
    /// Require the authority to equal the provided account.
    pub authority_eq: Option<crate::account::AccountId>,
    /// Require the authority to differ from the provided account.
    pub authority_ne: Option<crate::account::AccountId>,
    /// Require the authority to be one of the listed accounts.
    pub authority_in: std::vec::Vec<crate::account::AccountId>,
    /// Require the authority to be absent from the listed accounts.
    pub authority_nin: std::vec::Vec<crate::account::AccountId>,
    /// Require the presence (`true`) or absence (`false`) of an authority.
    pub authority_exists: Option<bool>,
    /// Require the transaction timestamp (ms) to be greater than or equal to this bound.
    pub ts_ge: Option<u64>,
    /// Require the transaction timestamp (ms) to be less than or equal to this bound.
    pub ts_le: Option<u64>,
    /// Require the entrypoint hash to equal the provided hash.
    pub entry_eq: Option<HashOf<crate::transaction::signed::TransactionEntrypoint>>,
    /// Require the entrypoint hash to be one of the listed hashes.
    pub entry_in: std::vec::Vec<HashOf<crate::transaction::signed::TransactionEntrypoint>>,
    /// Require the entrypoint hash to differ from the provided hash.
    pub entry_ne: Option<HashOf<crate::transaction::signed::TransactionEntrypoint>>,
    /// Require the entrypoint hash to be absent from the listed hashes.
    pub entry_nin: std::vec::Vec<HashOf<crate::transaction::signed::TransactionEntrypoint>>,
    /// Require the presence (`true`) or absence (`false`) of an entrypoint hash.
    pub entry_exists: Option<bool>,
    /// Require the execution result to be `Ok` (`true`) or `Err` (`false`).
    pub result_ok: Option<bool>,
    /// Require the execution result to differ from the provided outcome.
    pub result_ok_ne: Option<bool>,
    /// Require the execution result to be one of the listed boolean outcomes.
    pub result_ok_in: std::vec::Vec<bool>,
    /// Require the execution result to be absent from the listed boolean outcomes.
    pub result_ok_nin: std::vec::Vec<bool>,
    /// Require whether a result is present (`true`) or absent (`false`).
    pub result_exists: Option<bool>,
}
impl CommittedTxFilters {
    /// Helper associated with query processing.
    #[allow(clippy::too_many_lines)]
    pub fn applies(&self, tx: &CommittedTransaction) -> bool {
        if self.block_exists == Some(false) {
            return false;
        }
        if self
            .block_eq
            .as_ref()
            .is_some_and(|hash| &tx.block_hash != hash)
        {
            return false;
        }
        if self
            .block_ne
            .as_ref()
            .is_some_and(|hash| &tx.block_hash == hash)
        {
            return false;
        }
        if !self.block_in.is_empty() && !self.block_in.iter().any(|hash| hash == &tx.block_hash) {
            return false;
        }
        if self.block_nin.iter().any(|hash| hash == &tx.block_hash) {
            return false;
        }
        let authority_val = tx.entrypoint.authority_opt().cloned();
        if let Some(required) = self.authority_exists
            && (required != authority_val.is_some())
        {
            return false;
        }
        if self
            .authority_eq
            .as_ref()
            .is_some_and(|eq| authority_val.as_ref() != Some(eq))
        {
            return false;
        }
        if self
            .authority_ne
            .as_ref()
            .is_some_and(|ne| authority_val.as_ref() == Some(ne))
        {
            return false;
        }
        if !self.authority_in.is_empty()
            && !authority_val
                .as_ref()
                .is_some_and(|a| self.authority_in.iter().any(|x| x == a))
        {
            return false;
        }
        if !self.authority_nin.is_empty()
            && authority_val
                .as_ref()
                .is_some_and(|a| self.authority_nin.iter().any(|x| x == a))
        {
            return false;
        }
        // timestamp lower bound
        if let Some(ge) = self.ts_ge {
            let created_ms = tx.entrypoint.creation_time_ms().unwrap_or(0);
            if created_ms < ge {
                return false;
            }
        }
        // timestamp upper bound
        if let Some(le) = self.ts_le {
            let created_ms = tx.entrypoint.creation_time_ms().unwrap_or(u64::MAX);
            if created_ms > le {
                return false;
            }
        }
        // entrypoint hash
        if self
            .entry_eq
            .as_ref()
            .is_some_and(|eq| &tx.entrypoint_hash != eq)
        {
            return false;
        }
        if self
            .entry_ne
            .as_ref()
            .is_some_and(|ne| &tx.entrypoint_hash == ne)
        {
            return false;
        }
        if let Some(required) = self.entry_exists {
            // Entrypoint hash always exists for committed transactions.
            // If the predicate requires non-existence, this cannot match.
            if !required {
                return false;
            }
        }
        if !self.entry_in.is_empty() && !self.entry_in.iter().any(|h| h == &tx.entrypoint_hash) {
            return false;
        }
        if !self.entry_nin.is_empty() && self.entry_nin.iter().any(|h| h == &tx.entrypoint_hash) {
            return false;
        }
        // result_ok
        if let Some(required) = self.result_exists {
            // Result is always present for committed transactions; require true.
            if !required {
                return false;
            }
        }
        if let Some(ok) = self.result_ok {
            let actual = tx.result().as_ref().is_ok();
            if actual != ok {
                return false;
            }
        }
        if let Some(ne) = self.result_ok_ne {
            let actual = tx.result().as_ref().is_ok();
            if actual == ne {
                return false;
            }
        }
        if !self.result_ok_in.is_empty() {
            let actual = tx.result().as_ref().is_ok();
            if !self.result_ok_in.contains(&actual) {
                return false;
            }
        }
        if !self.result_ok_nin.is_empty() {
            let actual = tx.result().as_ref().is_ok();
            if self.result_ok_nin.contains(&actual) {
                return false;
            }
        }
        true
    }
}
impl crate::seal::SingularQuery for SingularQueryBox {}
/// A type-erased iterable query retaining its predicate and selector.
///
/// `ErasedIterQuery` allows storing queries with different concrete types in a
/// uniform container. Consumers can later attempt to recover the underlying
/// `QueryWithFilter` using [`iter_query_inner`].
#[derive(Debug, Clone, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::query::ErasedIterQuery")]
pub struct ErasedIterQuery<T>
where
    T: HasProjection<PredicateMarker> + HasProjection<SelectorMarker, AtomType = ()> + Send + Sync,
{
    predicate: CompoundPredicate<T>,
    selector: SelectorTuple<T>,
    /// Opaque bytes of the original concrete query (e.g., `FindAccounts`, `FindAccountsWithAsset`).
    ///
    /// The server uses this payload to reconstruct the concrete query when
    /// executing on the node, so variant-specific parameters (like
    /// `asset_definition` for `FindAccountsWithAsset`) are preserved.
    payload: Vec<u8>,
}

struct QueryFieldRef<'a>(&'a dyn norito::core::SerializePayload);

impl norito::core::SerializePayload for QueryFieldRef<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.0.serialize(writer)
    }
}

fn query_field_encoded_len(value: &dyn norito::core::SerializePayload) -> Option<usize> {
    value
        .encoded_len_exact()
        .or_else(|| norito::core::encoded_payload_len(&QueryFieldRef(value)).ok())
}

struct ErasedIterQueryStreaming<'a, T>(&'a ErasedIterQuery<T>)
where
    T: HasProjection<PredicateMarker> + HasProjection<SelectorMarker, AtomType = ()> + Send + Sync;

impl<T> norito::core::SerializePayload for ErasedIterQueryStreaming<'_, T>
where
    T: HasProjection<PredicateMarker> + HasProjection<SelectorMarker, AtomType = ()> + Send + Sync,
{
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let values: [&dyn norito::core::SerializePayload; 3] =
            [&self.0.predicate, &self.0.selector, &self.0.payload];
        for value in values {
            norito::core::write_len_prefixed(writer, value)?;
        }
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let mut total = 0_usize;
        let values: [&dyn norito::core::SerializePayload; 3] =
            [&self.0.predicate, &self.0.selector, &self.0.payload];
        for value in values {
            let field_len = query_field_encoded_len(value)?;
            total = total
                .checked_add(norito::core::len_prefix_len(field_len))?
                .checked_add(field_len)?;
        }
        Some(total)
    }
}
/// Attempt to extract a concrete `&QueryWithFilter<T>` from a type-erased iterable query.
///
/// This enables downstream crates (e.g., visitor utilities) to dispatch on the
/// concrete query type without depending on private wrapper internals.
// Helper: downcast a type-erased iterable query to a concrete erased form
/// Helper associated with query processing.
pub fn iter_query_inner<T>(q: &QueryBox<QueryOutputBatchBox>) -> Option<&ErasedIterQuery<T>>
where
    T: HasProjection<PredicateMarker>
        + HasProjection<SelectorMarker, AtomType = ()>
        + Send
        + Sync
        + 'static,
{
    let any: &dyn Any = &**q;
    any.downcast_ref::<ErasedIterQuery<T>>()
}
impl<T> seal::Query for ErasedIterQuery<T> where
    T: HasProjection<PredicateMarker>
        + HasProjection<SelectorMarker, AtomType = ()>
        + Send
        + Sync
        + 'static
{
}
impl<T> Query for ErasedIterQuery<T>
where
    T: HasProjection<PredicateMarker>
        + HasProjection<SelectorMarker, AtomType = ()>
        + Send
        + Sync
        + 'static,
{
    type Item = QueryOutputBatchBox;
    fn dyn_encode(&self) -> Vec<u8> {
        norito::codec::encode_adaptive(&ErasedIterQueryStreaming(self))
    }
    fn dyn_encoded_len_exact(&self) -> Option<usize> {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::core::SerializePayload::encoded_len_exact(&ErasedIterQueryStreaming(self))
    }
    fn dyn_encode_to(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> Result<usize, norito::core::Error> {
        norito::codec::encode_adaptive_into(&ErasedIterQueryStreaming(self), writer)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl<T> ErasedIterQuery<T>
where
    T: HasProjection<PredicateMarker> + HasProjection<SelectorMarker, AtomType = ()> + Send + Sync,
{
    /// Construct from parts.
    pub fn new(
        predicate: CompoundPredicate<T>,
        selector: SelectorTuple<T>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            predicate,
            selector,
            payload,
        }
    }
    /// Borrow the stored predicate
    pub fn predicate(&self) -> &CompoundPredicate<T> {
        &self.predicate
    }
    /// Borrow the stored selector
    pub fn selector(&self) -> &SelectorTuple<T> {
        &self.selector
    }
    /// Cloned predicate value
    pub fn predicate_cloned(&self) -> CompoundPredicate<T> {
        self.predicate.clone()
    }
    /// Cloned selector value
    pub fn selector_cloned(&self) -> SelectorTuple<T> {
        self.selector.clone()
    }
    /// Borrow the encoded payload of the original concrete query.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
// NOTE: Projection traits for QueryOutputBatchBox are provided generically in the DSL.
impl<T> From<QueryWithFilter<T>> for QueryBox<QueryOutputBatchBox>
where
    T: HasProjection<PredicateMarker>
        + HasProjection<SelectorMarker, AtomType = ()>
        + Send
        + Sync
        + 'static,
{
    fn from(query: QueryWithFilter<T>) -> Self {
        // This conversion has no concrete query value to encode. The primary
        // builder path carries the concrete payload explicitly.
        let payload = Vec::new();
        Box::new(ErasedIterQuery::new(
            query.predicate,
            query.selector,
            payload,
        ))
    }
}
#[cfg(feature = "fault_injection")]
impl CommittedTransaction {
    /// Injects a set of fictitious instructions into the transaction payload to simulate tampering.
    ///
    /// Only available when the `fault_injection` feature is enabled.
    pub fn inject_instructions(
        &mut self,
        extra_instructions: impl IntoIterator<Item = impl Into<InstructionBox>>,
    ) {
        let additions: Vec<InstructionBox> =
            extra_instructions.into_iter().map(Into::into).collect();
        if additions.is_empty() {
            return;
        }
        match &mut self.entrypoint {
            TransactionEntrypoint::External(entrypoint) => {
                entrypoint.inject_instructions(additions.clone());
            }
            TransactionEntrypoint::SealedCommitment(_) => {}
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                entrypoint
                    .signed_transaction
                    .inject_instructions(additions.clone());
            }
        }
        // Update the leaf hash to match the tampered entrypoint.
        self.entrypoint_hash = self.entrypoint.hash();
    }
    /// Swaps the transaction result between `Ok` and `Err` to simulate tampering.
    ///
    /// Only available when the `fault_injection` feature is enabled.
    pub fn swap_result(&mut self) {
        let result = match &mut self.output {
            crate::block::execution_output::ExecutionOutputV1::Network(row) => &mut row.result.0,
            crate::block::execution_output::ExecutionOutputV1::Pipeline(row) => &mut row.result.0,
            crate::block::execution_output::ExecutionOutputV1::Time(row) => &mut row.result.0,
        };
        *result = if result.is_ok() {
            Err(TransactionRejectionReason::Validation(
                ValidationFail::InternalError("result swapped".into()),
            ))
        } else {
            Ok(Vec::new())
        };
        // Update the leaf hash to match the tampered result.
        self.output_hash = HashOf::new(&self.output);
    }
}
impl QueryOutputBatchBox {
    // this is used in client cli to do type-erased iterable queries
    /// Extends this batch with another batch of the same type.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch variants differ.
    pub fn extend(
        &mut self,
        other: QueryOutputBatchBox,
    ) -> Result<(), QueryOutputBatchBoxTypeMismatch> {
        match (self, other) {
            (Self::PublicKey(v1), Self::PublicKey(v2)) => v1.extend(v2),
            (Self::String(v1), Self::String(v2)) => v1.extend(v2),
            (Self::Metadata(v1), Self::Metadata(v2)) => v1.extend(v2),
            (Self::Json(v1), Self::Json(v2)) => v1.extend(v2),
            (Self::Numeric(v1), Self::Numeric(v2)) => v1.extend(v2),
            (Self::Name(v1), Self::Name(v2)) => v1.extend(v2),
            (Self::DomainId(v1), Self::DomainId(v2)) => v1.extend(v2),
            (Self::Domain(v1), Self::Domain(v2)) => v1.extend(v2),
            (Self::AccountId(v1), Self::AccountId(v2)) => v1.extend(v2),
            (Self::Account(v1), Self::Account(v2)) => v1.extend(v2),
            (Self::AssetId(v1), Self::AssetId(v2)) => v1.extend(v2),
            (Self::Asset(v1), Self::Asset(v2)) => v1.extend(v2),
            (Self::AssetDefinitionId(v1), Self::AssetDefinitionId(v2)) => v1.extend(v2),
            (Self::AssetDefinition(v1), Self::AssetDefinition(v2)) => v1.extend(v2),
            (Self::NftId(v1), Self::NftId(v2)) => v1.extend(v2),
            (Self::Nft(v1), Self::Nft(v2)) => v1.extend(v2),
            (Self::RwaId(v1), Self::RwaId(v2)) => v1.extend(v2),
            (Self::Rwa(v1), Self::Rwa(v2)) => v1.extend(v2),
            (Self::Role(v1), Self::Role(v2)) => v1.extend(v2),
            (Self::Parameter(v1), Self::Parameter(v2)) => v1.extend(v2),
            (Self::Permission(v1), Self::Permission(v2)) => v1.extend(v2),
            (Self::CommittedTransaction(v1), Self::CommittedTransaction(v2)) => v1.extend(v2),
            (Self::TransactionResult(v1), Self::TransactionResult(v2)) => v1.extend(v2),
            (Self::TransactionResultHash(v1), Self::TransactionResultHash(v2)) => v1.extend(v2),
            (Self::TransactionEntrypoint(v1), Self::TransactionEntrypoint(v2)) => v1.extend(v2),
            (Self::TransactionEntrypointHash(v1), Self::TransactionEntrypointHash(v2)) => {
                v1.extend(v2)
            }
            (Self::Peer(v1), Self::Peer(v2)) => v1.extend(v2),
            (Self::RoleId(v1), Self::RoleId(v2)) => v1.extend(v2),
            (Self::TriggerId(v1), Self::TriggerId(v2)) => v1.extend(v2),
            (Self::Trigger(v1), Self::Trigger(v2)) => v1.extend(v2),
            (Self::Action(v1), Self::Action(v2)) => v1.extend(v2),
            (Self::Block(v1), Self::Block(v2)) => v1.extend(v2),
            (Self::BlockHeader(v1), Self::BlockHeader(v2)) => v1.extend(v2),
            (Self::BlockHeaderHash(v1), Self::BlockHeaderHash(v2)) => v1.extend(v2),
            (Self::ProofRecord(v1), Self::ProofRecord(v2)) => v1.extend(v2),
            (Self::RepoAgreement(v1), Self::RepoAgreement(v2)) => v1.extend(v2),
            (Self::OracleFeedConfig(v1), Self::OracleFeedConfig(v2)) => v1.extend(v2),
            (Self::OracleFeedEventRecord(v1), Self::OracleFeedEventRecord(v2)) => v1.extend(v2),
            (Self::OracleProviderStatsRecord(v1), Self::OracleProviderStatsRecord(v2)) => {
                v1.extend(v2)
            }
            (Self::OracleDispute(v1), Self::OracleDispute(v2)) => v1.extend(v2),
            (Self::OracleChangeProposal(v1), Self::OracleChangeProposal(v2)) => v1.extend(v2),
            (Self::TwitterBindingRecord(v1), Self::TwitterBindingRecord(v2)) => v1.extend(v2),
            (Self::DefiOracleAttestation(v1), Self::DefiOracleAttestation(v2)) => v1.extend(v2),
            (Self::AssetEscrowRecord(v1), Self::AssetEscrowRecord(v2)) => v1.extend(v2),
            (Self::FeeSponsorProgram(v1), Self::FeeSponsorProgram(v2)) => v1.extend(v2),
            (Self::FeeSponsorProgramId(v1), Self::FeeSponsorProgramId(v2)) => v1.extend(v2),
            _ => return Err(QueryOutputBatchBoxTypeMismatch),
        }
        Ok(())
    }
    /// Returns the number of rows in this batch column.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::PublicKey(v) => v.len(),
            Self::String(v) => v.len(),
            Self::Metadata(v) => v.len(),
            Self::Json(v) => v.len(),
            Self::Numeric(v) => v.len(),
            Self::Name(v) => v.len(),
            Self::DomainId(v) => v.len(),
            Self::Domain(v) => v.len(),
            Self::AccountId(v) => v.len(),
            Self::Account(v) => v.len(),
            Self::AssetId(v) => v.len(),
            Self::Asset(v) => v.len(),
            Self::AssetDefinitionId(v) => v.len(),
            Self::AssetDefinition(v) => v.len(),
            Self::NftId(v) => v.len(),
            Self::Nft(v) => v.len(),
            Self::RwaId(v) => v.len(),
            Self::Rwa(v) => v.len(),
            Self::Role(v) => v.len(),
            Self::Parameter(v) => v.len(),
            Self::Permission(v) => v.len(),
            Self::CommittedTransaction(v) => v.len(),
            Self::TransactionResult(v) => v.len(),
            Self::TransactionResultHash(v) => v.len(),
            Self::TransactionEntrypoint(v) => v.len(),
            Self::TransactionEntrypointHash(v) => v.len(),
            Self::Peer(v) => v.len(),
            Self::RoleId(v) => v.len(),
            Self::TriggerId(v) => v.len(),
            Self::Trigger(v) => v.len(),
            Self::Action(v) => v.len(),
            Self::Block(v) => v.len(),
            Self::BlockHeader(v) => v.len(),
            Self::BlockHeaderHash(v) => v.len(),
            Self::ProofRecord(v) => v.len(),
            Self::RepoAgreement(v) => v.len(),
            Self::OracleFeedConfig(v) => v.len(),
            Self::OracleFeedEventRecord(v) => v.len(),
            Self::OracleProviderStatsRecord(v) => v.len(),
            Self::OracleDispute(v) => v.len(),
            Self::OracleChangeProposal(v) => v.len(),
            Self::TwitterBindingRecord(v) => v.len(),
            Self::DefiOracleAttestation(v) => v.len(),
            Self::AssetEscrowRecord(v) => v.len(),
            Self::FeeSponsorProgram(v) => v.len(),
            Self::FeeSponsorProgramId(v) => v.len(),
        }
    }
    /// Returns `true` if this batch column contains no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
#[derive(norito::SerializePayload, norito::DeserializePayload)]
struct QueryOutputBatchBoxTupleCandidate {
    tuple: Vec<QueryOutputBatchBox>,
}
impl QueryOutputBatchBoxTupleCandidate {
    fn validate(self) -> Result<QueryOutputBatchBoxTuple, QueryOutputBatchBoxTupleError> {
        QueryOutputBatchBoxTuple::new(self.tuple)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for QueryOutputBatchBoxTuple {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("valid QueryOutputBatchBoxTuple archive must satisfy column invariants")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let candidate =
            <QueryOutputBatchBoxTupleCandidate as norito::core::DeserializePayload>::try_deserialize(
                archived.cast(),
            )?;
        candidate
            .validate()
            .map_err(|error| norito::core::Error::Message(error.to_string()))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for QueryOutputBatchBoxTuple {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (candidate, used) =
            norito::core::decode_field_canonical::<QueryOutputBatchBoxTupleCandidate>(bytes)?;
        let batch = candidate
            .validate()
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        Ok((batch, used))
    }
}

impl norito::json::JsonDeserialize for QueryOutputBatchBoxTuple {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        #[derive(crate::DeriveJsonDeserialize)]
        struct Candidate {
            tuple: Vec<QueryOutputBatchBox>,
        }
        let candidate = Candidate::json_deserialize(parser)?;
        Self::new(candidate.tuple).map_err(|error| norito::json::Error::Message(error.to_string()))
    }
}
impl QueryOutputBatchBoxTuple {
    /// Constructs a validated column-oriented query batch.
    ///
    /// Empty columns are allowed and represent a zero-row page, but the batch
    /// must contain at least one column and every column must have the same row count.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no columns or their row counts differ.
    pub fn new(tuple: Vec<QueryOutputBatchBox>) -> Result<Self, QueryOutputBatchBoxTupleError> {
        Self::validate_columns(&tuple)?;
        Ok(Self { tuple })
    }
    /// Constructs a query batch containing exactly one column.
    #[must_use]
    pub fn from_batch(batch: QueryOutputBatchBox) -> Self {
        Self { tuple: vec![batch] }
    }
    fn validate_columns(
        tuple: &[QueryOutputBatchBox],
    ) -> Result<usize, QueryOutputBatchBoxTupleError> {
        let Some(first) = tuple.first() else {
            return Err(QueryOutputBatchBoxTupleError::NoColumns);
        };
        let expected = first.len();
        for (column, batch) in tuple.iter().enumerate().skip(1) {
            let actual = batch.len();
            if actual != expected {
                return Err(QueryOutputBatchBoxTupleError::ColumnLengthMismatch {
                    column,
                    expected,
                    actual,
                });
            }
        }
        Ok(expected)
    }
    /// Extends this batch tuple with another batch tuple of the same shape and types.
    ///
    /// The operation is atomic: validation completes before any column is mutated.
    ///
    /// # Errors
    ///
    /// Returns an error if the column counts or corresponding batch types differ.
    pub fn extend(&mut self, other: Self) -> Result<(), QueryOutputBatchBoxTupleError> {
        if self.tuple.len() != other.tuple.len() {
            return Err(QueryOutputBatchBoxTupleError::ColumnCountMismatch {
                expected: self.tuple.len(),
                actual: other.tuple.len(),
            });
        }
        for (column, (left, right)) in self.tuple.iter().zip(&other.tuple).enumerate() {
            if core::mem::discriminant(left) != core::mem::discriminant(right) {
                return Err(QueryOutputBatchBoxTupleError::ColumnTypeMismatch { column });
            }
        }
        for (column, (self_batch, other_batch)) in
            self.tuple.iter_mut().zip(other.tuple).enumerate()
        {
            self_batch
                .extend(other_batch)
                .map_err(|_| QueryOutputBatchBoxTupleError::ColumnTypeMismatch { column })?;
        }
        Ok(())
    }
    /// Returns the number of rows in this batch tuple.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tuple.first().map_or(0, QueryOutputBatchBox::len)
    }
    /// Returns `true` if this batch tuple contains zero rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns the number of columns in this batch tuple.
    #[must_use]
    pub fn column_count(&self) -> usize {
        self.tuple.len()
    }
    /// Borrows the column batches in their selector order.
    #[must_use]
    pub fn columns(&self) -> &[QueryOutputBatchBox] {
        &self.tuple
    }
    /// Consumes the tuple and returns its column batches in selector order.
    #[must_use]
    pub fn into_columns(self) -> Vec<QueryOutputBatchBox> {
        self.tuple
    }
    /// Returns an iterator over the columns in this tuple.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &QueryOutputBatchBox> {
        self.tuple.iter()
    }
}
impl TryFrom<Vec<QueryOutputBatchBox>> for QueryOutputBatchBoxTuple {
    type Error = QueryOutputBatchBoxTupleError;
    fn try_from(tuple: Vec<QueryOutputBatchBox>) -> Result<Self, Self::Error> {
        Self::new(tuple)
    }
}
impl From<QueryOutputBatchBox> for QueryOutputBatchBoxTuple {
    fn from(batch: QueryOutputBatchBox) -> Self {
        Self::from_batch(batch)
    }
}
impl IntoIterator for QueryOutputBatchBoxTuple {
    type Item = QueryOutputBatchBox;
    type IntoIter = QueryOutputBatchBoxIntoIter;
    fn into_iter(self) -> Self::IntoIter {
        QueryOutputBatchBoxIntoIter(self.tuple.into_iter())
    }
}
/// An iterator over the batches in a [`QueryOutputBatchBoxTuple`]
pub struct QueryOutputBatchBoxIntoIter(vec::IntoIter<QueryOutputBatchBox>);
impl Iterator for QueryOutputBatchBoxIntoIter {
    type Item = QueryOutputBatchBox;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
#[cfg(test)]
#[path = "tests/query_output_batch_box_tuple.rs"]
mod query_output_batch_box_tuple_tests;
impl SingularQuery for SingularQueryBox {
    type Output = SingularQueryOutputBox;
    fn dyn_encode(&self) -> Vec<u8> {
        self.encode()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl QueryOutput {
    /// Create a new [`QueryOutput`] from the iroha response parts.
    pub fn new(
        batch: QueryOutputBatchBoxTuple,
        remaining_items: u64,
        continue_cursor: Option<ForwardCursor>,
    ) -> Self {
        let has_more = remaining_items > 0 || continue_cursor.is_some();
        Self {
            batch,
            remaining_items: Some(remaining_items),
            has_more,
            continue_cursor,
        }
    }
    /// Create a new [`QueryOutput`] when the exact remaining count is intentionally not computed.
    pub fn new_bounded(
        batch: QueryOutputBatchBoxTuple,
        has_more: bool,
        continue_cursor: Option<ForwardCursor>,
    ) -> Self {
        Self {
            batch,
            remaining_items: None,
            has_more: has_more || continue_cursor.is_some(),
            continue_cursor,
        }
    }
    /// Return an exact remaining count when available, or `0` when the exact count was omitted.
    pub fn remaining_items_hint(&self) -> u64 {
        self.remaining_items.unwrap_or(0)
    }
    /// Split this [`QueryOutput`] into its constituent parts.
    pub fn into_parts(self) -> (QueryOutputBatchBoxTuple, u64, Option<ForwardCursor>) {
        let remaining_items = self.remaining_items.unwrap_or(0);
        (self.batch, remaining_items, self.continue_cursor)
    }
    /// Split this [`QueryOutput`] into its parts without forcing an exact count.
    pub fn into_parts_with_count_mode(
        self,
    ) -> (
        QueryOutputBatchBoxTuple,
        Option<u64>,
        bool,
        Option<ForwardCursor>,
    ) {
        (
            self.batch,
            self.remaining_items,
            self.has_more,
            self.continue_cursor,
        )
    }
}
impl QueryRequest {
    /// Construct the exact network-, time-, and nonce-bound payload an authority will sign.
    pub fn with_authority(
        self,
        network_id: NetworkId,
        authority: AccountId,
        creation_time_ms: u64,
        time_to_live_ms: NonZeroU64,
        nonce: [u8; 32],
    ) -> QueryRequestWithAuthority {
        QueryRequestWithAuthority {
            network_id,
            authority,
            creation_time_ms,
            time_to_live_ms,
            nonce,
            request: self,
        }
    }
    #[cfg(test)]
    fn with_test_authority(self, authority: AccountId) -> QueryRequestWithAuthority {
        let genesis_hash = HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xA5; Hash::LENGTH]),
        );
        self.with_authority(
            NetworkId::from_genesis_hash(genesis_hash),
            authority,
            1_000_000,
            NonZeroU64::new(10_000).expect("nonzero test query TTL"),
            [0x5A; 32],
        )
    }
}
impl QueryWithParams {
    /// Borrow the parameters attached to this iterable query request.
    #[must_use]
    pub fn params(&self) -> &QueryParams {
        &self.params
    }
}
impl QueryRequestWithAuthority {
    /// Return the exact genesis-lineage identity this request targets.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Return the authority that issued this request.
    #[must_use]
    pub fn authority(&self) -> &AccountId {
        &self.authority
    }
    /// Return the underlying query payload.
    #[must_use]
    pub fn request(&self) -> &QueryRequest {
        &self.request
    }
    /// Return the signed Unix creation timestamp in milliseconds.
    #[must_use]
    pub const fn creation_time_ms(&self) -> u64 {
        self.creation_time_ms
    }
    /// Return the signed nonzero request lifetime in milliseconds.
    #[must_use]
    pub const fn time_to_live_ms(&self) -> NonZeroU64 {
        self.time_to_live_ms
    }
    /// Return the signed one-shot replay nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// Consume `self`, returning its components.
    #[must_use]
    pub fn into_parts(self) -> (AccountId, QueryRequest) {
        (self.authority, self.request)
    }
    /// Sign this [`QueryRequestWithAuthority`], creating a [`SignedQuery`].
    ///
    /// # Errors
    ///
    /// Returns an error when the configured signature backend cannot sign the
    /// query payload with the supplied key pair.
    #[inline]
    pub fn try_sign(
        self,
        key_pair: &iroha_crypto::KeyPair,
    ) -> Result<SignedQuery, iroha_crypto::Error> {
        let signature = SignatureOf::try_new(key_pair.private_key(), &self)?;
        Ok(SignedQuery {
            signature: QuerySignature(signature),
            payload: self,
        })
    }
    /// Sign this [`QueryRequestWithAuthority`], creating a [`SignedQuery`]
    #[inline]
    #[must_use]
    pub fn sign(self, key_pair: &iroha_crypto::KeyPair) -> SignedQuery {
        self.try_sign(key_pair)
            .expect("signing should succeed for a valid key pair and query request")
    }
}
impl SignedQuery {
    /// Get authority that has signed this query
    pub fn authority(&self) -> &AccountId {
        &self.payload.authority
    }
    /// Get the request that was signed
    pub fn request(&self) -> &QueryRequest {
        &self.payload.request
    }
    /// Verify that the single-key authority signed the complete query payload.
    ///
    /// Decoding a [`SignedQuery`] is intentionally structural only. Network ingress must validate
    /// inexpensive network and freshness bounds before calling this method, then consume the
    /// request nonce before performing authorization or query work.
    ///
    /// # Errors
    ///
    /// Returns an error when the authority is not single-key, the signature material is malformed,
    /// or the signature does not authenticate the complete payload.
    pub fn verify_signature(&self) -> Result<(), SignedQueryValidationError> {
        let QuerySignature(signature) = &self.signature;
        let signatory = self
            .payload
            .authority
            .try_signatory()
            .ok_or(SignedQueryValidationError::AuthorityNotSingleKey)?;
        verify_query_signature_for_signer(signature, signatory, &self.payload)
    }
}
mod candidate {
    use super::*;
    #[derive(norito::SerializePayload, norito::DeserializePayload)]
    struct SignedQueryCandidate {
        signature: QuerySignature,
        payload: QueryRequestWithAuthority,
    }
    impl SignedQueryCandidate {
        fn into_signed(self) -> SignedQuery {
            SignedQuery {
                payload: self.payload,
                signature: self.signature,
            }
        }
    }
    impl<'a> norito::core::DecodeFromSlice<'a> for SignedQuery {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let _guard = norito::core::PayloadCtxGuard::enter(bytes);
            let mut cursor = std::io::Cursor::new(bytes);
            let candidate: SignedQueryCandidate =
                <SignedQueryCandidate as norito::codec::Decode>::decode(&mut cursor)?;
            let used = usize::try_from(cursor.position())
                .map_err(|_| norito::core::Error::LengthMismatch)?;
            Ok((candidate.into_signed(), used))
        }
    }

    impl<'de> norito::core::DeserializePayload<'de> for SignedQuery {
        fn deserialize(archived: &'de norito::core::Archived<SignedQuery>) -> Self {
            let candidate = <SignedQueryCandidate as norito::core::DeserializePayload>::deserialize(
                archived.cast(),
            );
            candidate.into_signed()
        }
        fn try_deserialize(
            archived: &'de norito::core::Archived<SignedQuery>,
        ) -> Result<Self, norito::core::Error> {
            let candidate =
                <SignedQueryCandidate as norito::core::DeserializePayload>::try_deserialize(
                    archived.cast(),
                )?;
            Ok(candidate.into_signed())
        }
    }
    // JSON deserialization for SignedQuery is disabled in non-json builds.
    #[cfg(test)]
    mod tests {
        use crate::{
            account::{AccountId, MultisigMember, MultisigPolicy},
            query::{
                FindExecutorDataModel, QueryRequest, SignedQueryValidationError, SingularQueryBox,
                candidate::SignedQueryCandidate, parameters,
            },
        };
        use iroha_crypto::KeyPair;

        use norito::json;
        use std::sync::LazyLock;

        #[test]
        fn query_with_params_json_requires_canonical_fields_and_rejects_retired_fields() {
            let params = parameters::QueryParams::default();
            let canonical = super::json_wrappers::QueryWithParamsJson {
                params,
                item_kind: crate::query::QueryItemKind::Domain,
                query_payload_b64: String::new(),
                predicate_b64: String::new(),
                selector_b64: String::new(),
            };
            let value = json::to_value(&canonical).expect("canonical query JSON");
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .expect("query wrapper object")
                .remove("item_kind");
            assert!(
                json::from_value::<super::json_wrappers::QueryWithParamsJson>(missing).is_err(),
                "canonical query fields must be mandatory"
            );

            for retired in ["wire", "payload_b64"] {
                let mut candidate = value.clone();
                candidate
                    .as_object_mut()
                    .expect("query wrapper object")
                    .insert(retired.to_owned(), json::Value::String(String::new()));
                assert!(
                    json::from_value::<super::json_wrappers::QueryWithParamsJson>(candidate)
                        .is_err(),
                    "retired field {retired} must be rejected"
                );
            }
        }
        static ALICE_ID: LazyLock<AccountId> =
            LazyLock::new(|| AccountId::new(ALICE_KEYPAIR.public_key().clone()));
        static ALICE_KEYPAIR: LazyLock<KeyPair> = LazyLock::new(|| {
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
        static BOB_KEYPAIR: LazyLock<KeyPair> = LazyLock::new(|| {
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
        fn multisig_authority() -> AccountId {
            let member =
                MultisigMember::new(ALICE_KEYPAIR.public_key().clone(), 1).expect("valid member");
            let policy = MultisigPolicy::new(1, vec![member]).expect("valid multisig policy");
            AccountId::new_multisig(policy)
        }
        #[test]
        fn valid() {
            let signed_query = QueryRequest::Singular(SingularQueryBox::FindExecutorDataModel(
                FindExecutorDataModel,
            ))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
            let candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload: signed_query.payload,
            };
            candidate.into_signed().verify_signature().unwrap();
        }
        #[test]
        fn invalid_signature() {
            let signed_query = QueryRequest::Singular(SingularQueryBox::FindExecutorDataModel(
                FindExecutorDataModel,
            ))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
            let mut candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload: signed_query.payload,
            };
            // Corrupt the raw signature payload and rebuild the signature
            let mut sig_bytes = candidate.signature.0.payload().to_vec();
            let idx = sig_bytes.len() - 1;
            sig_bytes[idx] = sig_bytes[idx].wrapping_add(1);
            *candidate.signature.0 = iroha_crypto::Signature::try_from_bytes(&sig_bytes)
                .expect("tampered query signature remains structurally admissible");
            let err = candidate
                .into_signed()
                .verify_signature()
                .expect_err("expected signature validation to fail");
            assert_eq!(err, SignedQueryValidationError::InvalidSignature);
        }
        #[test]
        fn malformed_ed25519_signature_r_rejected_before_verify() {
            const SMALL_ORDER_R: [u8; 32] = [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ];
            const NONCANONICAL_R: [u8; 32] = [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ];
            for (label, replacement_r) in [
                ("small-order", SMALL_ORDER_R),
                ("noncanonical", NONCANONICAL_R),
            ] {
                let signed_query = QueryRequest::Singular(SingularQueryBox::FindExecutorDataModel(
                    FindExecutorDataModel,
                ))
                .with_test_authority(ALICE_ID.clone())
                .sign(&ALICE_KEYPAIR);
                let mut candidate = SignedQueryCandidate {
                    signature: signed_query.signature,
                    payload: signed_query.payload,
                };
                let mut sig_bytes = candidate.signature.0.payload().to_vec();
                sig_bytes[..replacement_r.len()].copy_from_slice(&replacement_r);
                *candidate.signature.0 = iroha_crypto::Signature::from_bytes(&sig_bytes);
                let err = candidate
                    .into_signed()
                    .verify_signature()
                    .err()
                    .unwrap_or_else(|| panic!("{label} Ed25519 signature R must be rejected"));
                assert_eq!(err, SignedQueryValidationError::InvalidSignatureMaterial);
            }
        }
        #[test]
        fn malformed_mldsa_signature_lengths_rejected_before_verify() {
            let keypair = KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::MlDsa)
                .expect("generate checked ML-DSA query fixture keypair");
            let make_signed_query = || {
                QueryRequest::Singular(SingularQueryBox::FindExecutorDataModel(
                    FindExecutorDataModel,
                ))
                .with_test_authority(AccountId::new(keypair.public_key().clone()))
                .sign(&keypair)
            };
            let signed_query = make_signed_query();
            let valid_signature = signed_query.signature.0.payload().to_vec();
            iroha_crypto::mldsa65_parse_signature(&valid_signature)
                .expect("valid ML-DSA signed query signature parses");
            for (label, replacement_signature) in [
                (
                    "short",
                    valid_signature[..valid_signature.len() - 1].to_vec(),
                ),
                ("overlong", {
                    let mut payload = valid_signature.clone();
                    payload.push(0x5C);
                    payload
                }),
            ] {
                let signed_query = make_signed_query();
                let mut candidate = SignedQueryCandidate {
                    signature: signed_query.signature,
                    payload: signed_query.payload,
                };
                *candidate.signature.0 =
                    iroha_crypto::Signature::from_bytes(&replacement_signature);
                let err = candidate
                    .into_signed()
                    .verify_signature()
                    .err()
                    .unwrap_or_else(|| panic!("{label} ML-DSA signature length must be rejected"));
                assert_eq!(err, SignedQueryValidationError::InvalidSignatureMaterial);
            }
        }
        #[test]
        fn mismatching_authority() {
            let signed_query = QueryRequest::Singular(SingularQueryBox::FindExecutorDataModel(
                FindExecutorDataModel,
            ))
            // signing with a wrong key here
            .with_test_authority(ALICE_ID.clone())
            .sign(&BOB_KEYPAIR);
            let candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload: signed_query.payload,
            };
            let err = candidate
                .into_signed()
                .verify_signature()
                .expect_err("expected signature validation to fail");
            assert_eq!(err, SignedQueryValidationError::InvalidSignature);
        }
        #[test]
        fn multisig_authority_is_rejected_without_unwinding() {
            let signed_query = QueryRequest::Singular(SingularQueryBox::FindExecutorDataModel(
                FindExecutorDataModel,
            ))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
            let mut payload = signed_query.payload;
            payload.authority = multisig_authority();
            let candidate = SignedQueryCandidate {
                signature: signed_query.signature,
                payload,
            };
            let error = match candidate.into_signed().verify_signature() {
                Ok(()) => panic!("multisig query authority must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error, SignedQueryValidationError::AuthorityNotSingleKey);
        }
    }
}
#[cfg(test)]
mod json_roundtrip_tests {
    use super::*;
    use crate::{
        account::{AccountId, MultisigMember, MultisigPolicy},
        domain::Domain,
        query::{
            executor::prelude::FindParameters,
            json_wrappers::{SignedQueryJson, query_request_from_json, query_request_to_json},
        },
    };
    use iroha_crypto::{KeyPair, Signature, SignatureOf};
    use iroha_version::codec::{DecodeVersioned, EncodeVersioned};
    use std::sync::LazyLock;
    static ALICE_ID: LazyLock<AccountId> =
        LazyLock::new(|| AccountId::new(ALICE_KEYPAIR.public_key().clone()));
    static ALICE_KEYPAIR: LazyLock<KeyPair> = LazyLock::new(|| {
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
    fn multisig_authority() -> AccountId {
        let member =
            MultisigMember::new(ALICE_KEYPAIR.public_key().clone(), 1).expect("valid member");
        let policy = MultisigPolicy::new(1, vec![member]).expect("valid multisig policy");
        AccountId::new_multisig(policy)
    }
    #[test]
    fn query_request_json_roundtrip_singular() {
        let req = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
        let json = query_request_to_json(&req);
        let back = query_request_from_json(json).expect("json->request");
        match back {
            QueryRequest::Singular(SingularQueryBox::FindParameters(_)) => {}
            _ => panic!("expected FindParameters singular query"),
        }
    }
    #[test]
    fn signed_query_versioned_roundtrip() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let bytes = signed.encode_versioned();
        let decoded =
            SignedQuery::decode_all_versioned(&bytes).expect("versioned signed query must decode");
        assert_eq!(decoded.authority(), signed.authority());
        assert_eq!(
            query_request_to_json(decoded.request()),
            query_request_to_json(signed.request())
        );
        assert_eq!(decoded.signature.0.payload(), signed.signature.0.payload());
    }
    #[test]
    fn signed_query_versioned_decode_rejects_empty_payload_without_decode_panic() {
        let err = match SignedQuery::decode_all_versioned(&[]) {
            Ok(_) => panic!("empty signed query payload must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, iroha_version::error::Error::NotVersioned));
        assert!(
            !err.to_string().contains("panic during decode"),
            "empty payloads should not surface as decode panics: {err}"
        );
    }
    #[test]
    fn signed_query_versioned_decode_rejects_version_only_payload_without_decode_panic() {
        let err = match SignedQuery::decode_all_versioned(&[1]) {
            Ok(_) => panic!("version-only signed query payload must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, iroha_version::error::Error::NoritoCodec(_)));
        assert!(
            !err.to_string().contains("panic during decode"),
            "truncated payloads should not surface as decode panics: {err}"
        );
    }
    #[test]
    fn signed_query_versioned_decode_rejects_trailing_bytes() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let mut bytes = signed.encode_versioned();
        bytes.push(0);
        let err = match SignedQuery::decode_all_versioned(&bytes) {
            Ok(_) => panic!("versioned signed query decoder must reject trailing bytes"),
            Err(err) => err,
        };
        assert!(matches!(err, iroha_version::error::Error::NoritoCodec(_)));
    }
    #[test]
    fn signed_query_versioned_decode_rejects_unsupported_version_without_decode_panic() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let mut bytes = signed.encode_versioned();
        bytes[0] = 2;
        let err = match SignedQuery::decode_all_versioned(&bytes) {
            Ok(_) => panic!("unsupported signed query version must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            iroha_version::error::Error::UnsupportedVersion(_)
        ));
        assert!(
            !err.to_string().contains("panic during decode"),
            "unsupported versions should not surface as decode panics: {err}"
        );
    }
    #[test]
    fn signed_query_versioned_decode_is_structural_then_signature_is_verified_explicitly() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let mut signature = signed.signature.0.payload().to_vec();
        let last = signature
            .last_mut()
            .expect("test signature payload is non-empty");
        *last ^= 0xFF;
        let invalid = SignedQuery {
            signature: QuerySignature(SignatureOf::from_signature(
                Signature::try_from_bytes(&signature)
                    .expect("tampered signed query signature remains structurally admissible"),
            )),
            payload: signed.payload,
        };
        let decoded = SignedQuery::decode_all_versioned(&invalid.encode_versioned())
            .expect("decoding must not spend cryptographic work");
        assert_eq!(
            decoded.verify_signature(),
            Err(SignedQueryValidationError::InvalidSignature)
        );
    }
    #[test]
    fn signed_query_decode_is_structural_then_multisig_authority_is_rejected_explicitly() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let mut payload = signed.payload;
        payload.authority = multisig_authority();
        let invalid = SignedQuery {
            signature: signed.signature,
            payload,
        };
        let encoded = norito::to_bytes(&invalid).expect("encode multisig query fixture");
        let archived =
            norito::from_bytes::<SignedQuery>(&encoded).expect("archive multisig query fixture");
        let decoded =
            <SignedQuery as norito::core::DeserializePayload<'_>>::try_deserialize(archived)
                .expect("structural archived decode must not perform authorization");
        assert_eq!(
            decoded.verify_signature(),
            Err(SignedQueryValidationError::AuthorityNotSingleKey)
        );
        let decoded = SignedQuery::decode_all_versioned(&invalid.encode_versioned())
            .expect("versioned decode must remain structural");
        assert_eq!(
            decoded.verify_signature(),
            Err(SignedQueryValidationError::AuthorityNotSingleKey)
        );
    }
    #[test]
    fn signed_query_json_rejects_malformed_ed25519_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut json = SignedQueryJson::from(&signed);
            let SignedQueryJson::Canonical(canonical) = &mut json;
            let mut signature = canonical.signature.0.payload().to_vec();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            *canonical.signature.0 = Signature::from_bytes(&signature);
            let decoded = SignedQuery::try_from(json)
                .expect("JSON conversion must remain structural before ingress admission");
            assert_eq!(
                decoded.verify_signature(),
                Err(SignedQueryValidationError::InvalidSignatureMaterial),
                "{label} signed query signature R was not rejected"
            );
        }
    }
    #[test]
    fn signed_query_json_rejects_multisig_authority_without_unwinding() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let mut json = SignedQueryJson::from(&signed);
        let SignedQueryJson::Canonical(canonical) = &mut json;
        canonical.payload.authority = multisig_authority();
        let decoded = SignedQuery::try_from(json)
            .expect("JSON conversion must remain structural before ingress admission");
        assert_eq!(
            decoded.verify_signature(),
            Err(SignedQueryValidationError::AuthorityNotSingleKey)
        );
    }

    #[test]
    fn signed_query_json_requires_every_replay_context_field() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let canonical = SignedQueryJson::from(&signed);
        let value = norito::json::to_value(&canonical).expect("serialize signed query JSON");
        for field in ["network_id", "creation_time_ms", "time_to_live_ms", "nonce"] {
            let mut missing = value.clone();
            missing
                .get_mut("content")
                .and_then(|content| content.get_mut("payload"))
                .and_then(norito::json::Value::as_object_mut)
                .expect("canonical signed-query payload object")
                .remove(field);
            assert!(
                norito::json::from_value::<SignedQueryJson>(missing).is_err(),
                "signed-query JSON without `{field}` must fail closed"
            );
        }
    }

    #[test]
    fn signed_query_json_rejects_unknown_envelope_fields_at_every_level() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let canonical = norito::json::to_value(&SignedQueryJson::from(&signed))
            .expect("serialize signed query JSON");

        let mut candidates = Vec::new();
        let mut outer = canonical.clone();
        outer
            .as_object_mut()
            .expect("signed-query version envelope")
            .insert("legacy".to_owned(), norito::json::Value::Null);
        candidates.push(("version envelope", outer));

        let mut signed_envelope = canonical.clone();
        signed_envelope
            .get_mut("content")
            .and_then(norito::json::Value::as_object_mut)
            .expect("signed-query content envelope")
            .insert("legacy".to_owned(), norito::json::Value::Null);
        candidates.push(("signed envelope", signed_envelope));

        let mut authority_envelope = canonical.clone();
        authority_envelope
            .get_mut("content")
            .and_then(|content| content.get_mut("payload"))
            .and_then(norito::json::Value::as_object_mut)
            .expect("signed-query authority envelope")
            .insert("legacy".to_owned(), norito::json::Value::Null);
        candidates.push(("authority envelope", authority_envelope));

        let mut request_envelope = canonical;
        request_envelope
            .get_mut("content")
            .and_then(|content| content.get_mut("payload"))
            .and_then(|payload| payload.get_mut("request"))
            .and_then(norito::json::Value::as_object_mut)
            .expect("signed-query request envelope")
            .insert("legacy".to_owned(), norito::json::Value::Null);
        candidates.push(("request envelope", request_envelope));

        for (label, candidate) in candidates {
            assert!(
                norito::json::from_value::<SignedQueryJson>(candidate).is_err(),
                "unknown field in {label} must fail closed"
            );
        }
    }

    #[test]
    fn signed_query_json_rejects_zero_time_to_live() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let mut value = norito::json::to_value(&SignedQueryJson::from(&signed))
            .expect("serialize signed query JSON");
        value
            .get_mut("content")
            .and_then(|content| content.get_mut("payload"))
            .and_then(norito::json::Value::as_object_mut)
            .expect("canonical signed-query payload object")
            .insert(
                "time_to_live_ms".to_owned(),
                norito::json::Value::from(0_u64),
            );
        assert!(
            norito::json::from_value::<SignedQueryJson>(value).is_err(),
            "signed-query JSON must reject a zero lifetime before admission"
        );
    }
    #[test]
    fn signed_query_decode_rejects_empty_signature_without_decode_panic() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let invalid = SignedQuery {
            signature: QuerySignature(SignatureOf::from_signature(Signature::from_bytes(&[]))),
            payload: signed.payload,
        };
        let encoded = norito::to_bytes(&invalid).expect("encode invalid signed query fixture");
        let archived =
            norito::from_bytes::<SignedQuery>(&encoded).expect("archive invalid signed query");
        let err = match <SignedQuery as norito::core::DeserializePayload<'_>>::try_deserialize(
            archived,
        ) {
            Ok(_) => panic!("empty signed query signature must fail closed"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("empty") || message.contains("length mismatch"),
            "unexpected signed query decode error: {message}"
        );
        let err = match SignedQuery::decode_all_versioned(&invalid.encode_versioned()) {
            Ok(_) => panic!("empty signed query signature must be rejected"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("empty") || message.contains("length mismatch"),
            "unexpected versioned signed query decode error: {message}"
        );
        assert!(
            !message.contains("panic during decode"),
            "empty signatures should not surface as decode panics: {message}"
        );
    }
    #[test]
    fn signed_query_decode_rejects_all_zero_signature_without_decode_panic() {
        let signed = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters))
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let invalid = SignedQuery {
            signature: QuerySignature(SignatureOf::from_signature(Signature::from_bytes(
                &[0_u8; 64],
            ))),
            payload: signed.payload,
        };
        let encoded = norito::to_bytes(&invalid).expect("encode invalid signed query fixture");
        let archived =
            norito::from_bytes::<SignedQuery>(&encoded).expect("archive invalid signed query");
        let err = match <SignedQuery as norito::core::DeserializePayload<'_>>::try_deserialize(
            archived,
        ) {
            Ok(_) => panic!("all-zero signed query signature must fail closed"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("all zero"),
            "unexpected signed query decode error: {message}"
        );
        let err = match SignedQuery::decode_all_versioned(&invalid.encode_versioned()) {
            Ok(_) => panic!("all-zero signed query signature must be rejected"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("all zero"),
            "unexpected versioned signed query decode error: {message}"
        );
        assert!(
            !message.contains("panic during decode"),
            "all-zero signatures should not surface as decode panics: {message}"
        );
    }
    #[test]
    fn signed_query_json_roundtrip_start() {
        // Construct QueryWithParams directly with payload components
        use crate::query::QueryItemKind;
        let pred = norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS);
        let sel = norito::codec::Encode::encode(&SelectorTuple::<Domain>::default());
        let qwp = QueryWithParams {
            query: (),
            query_payload: vec![1, 2, 3],
            item: QueryItemKind::Domain,
            predicate_bytes: pred,
            selector_bytes: sel,
            params: parameters::QueryParams::default(),
        };
        let signed = QueryRequest::Start(qwp)
            .with_test_authority(ALICE_ID.clone())
            .sign(&ALICE_KEYPAIR);
        let json = SignedQueryJson::from(&signed);
        let back = SignedQuery::try_from(json).expect("json->native");
        match back.request() {
            QueryRequest::Start(q) => {
                // Canonical iterable queries carry () and separate payloads.
                let _ = (&q.predicate_bytes, &q.selector_bytes, q.item);
            }
            _ => panic!("expected Start request"),
        }
    }
    #[test]
    fn query_with_params_rejects_unknown_erased_type() {
        let unknown: QueryBox<QueryOutputBatchBox> =
            Box::new(ErasedIterQuery::<QueryOutputBatchBox>::new(
                CompoundPredicate::PASS,
                SelectorTuple::default(),
                Vec::new(),
            ));
        let error = match QueryWithParams::new(&unknown, parameters::QueryParams::default()) {
            Ok(_) => panic!("an unmapped erased query type must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.type_name(),
            std::any::type_name::<ErasedIterQuery<QueryOutputBatchBox>>()
        );
    }
    #[test]
    fn query_with_params_maps_all_supported_item_kinds() {
        let repo: QueryBox<QueryOutputBatchBox> =
            Box::new(ErasedIterQuery::<crate::repo::RepoAgreement>::new(
                CompoundPredicate::PASS,
                SelectorTuple::default(),
                Vec::new(),
            ));
        let repo = QueryWithParams::new(&repo, parameters::QueryParams::default())
            .expect("repository query type has a canonical mapping");
        assert_eq!(repo.item, QueryItemKind::RepoAgreement);
        let defi: QueryBox<QueryOutputBatchBox> = Box::new(ErasedIterQuery::<
            crate::oracle::DefiOracleAttestation,
        >::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            vec![0x42],
        ));
        let defi = QueryWithParams::new(&defi, parameters::QueryParams::default())
            .expect("DeFi attestation query type has a canonical mapping");
        assert_eq!(defi.item, QueryItemKind::DefiOracleAttestation);
    }
    #[test]
    fn query_with_params_clone_preserves_canonical_parts() {
        use crate::query::QueryItemKind;
        let pred = norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS);
        let sel = norito::codec::Encode::encode(&SelectorTuple::<Domain>::default());
        let original = QueryWithParams {
            query: (),
            query_payload: vec![1, 2, 3, 4],
            item: QueryItemKind::Permission,
            predicate_bytes: pred,
            selector_bytes: sel,
            params: parameters::QueryParams::default(),
        };
        let cloned = original.clone();
        assert_eq!(cloned.item, QueryItemKind::Permission);
        assert_eq!(cloned.query_payload, vec![1, 2, 3, 4]);
        assert_eq!(cloned.predicate_bytes, original.predicate_bytes);
        assert_eq!(cloned.selector_bytes, original.selector_bytes);
        assert_eq!(cloned.params, original.params);
    }
    #[test]
    fn query_item_kind_discriminants_are_canonical() {
        let kinds = [
            QueryItemKind::Domain,
            QueryItemKind::Account,
            QueryItemKind::AccountId,
            QueryItemKind::Asset,
            QueryItemKind::AssetDefinition,
            QueryItemKind::RepoAgreement,
            QueryItemKind::Nft,
            QueryItemKind::Rwa,
            QueryItemKind::Role,
            QueryItemKind::RoleId,
            QueryItemKind::PeerId,
            QueryItemKind::TriggerId,
            QueryItemKind::Trigger,
            QueryItemKind::CommittedTransaction,
            QueryItemKind::SignedBlock,
            QueryItemKind::BlockHeader,
            QueryItemKind::ProofRecord,
            QueryItemKind::OracleFeedConfig,
            QueryItemKind::OracleFeedEventRecord,
            QueryItemKind::OracleProviderStatsRecord,
            QueryItemKind::OracleDispute,
            QueryItemKind::OracleChangeProposal,
            QueryItemKind::TwitterBindingRecord,
            QueryItemKind::DefiOracleAttestation,
            QueryItemKind::Permission,
            QueryItemKind::AssetEscrowRecord,
            QueryItemKind::FeeSponsorProgram,
            QueryItemKind::FeeSponsorProgramId,
            QueryItemKind::AssetEscrowsBySeller,
            QueryItemKind::AssetEscrowsByBuyer,
            QueryItemKind::AssetEscrowsByStatus,
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            let expected = u32::try_from(index)
                .expect("query item index fits u32")
                .to_le_bytes();
            assert_eq!(norito::codec::Encode::encode(&kind), expected);
        }
        let unknown = u32::MAX.to_le_bytes();
        let mut unknown_input = unknown.as_slice();
        assert!(
            <QueryItemKind as norito::codec::Decode>::decode(&mut unknown_input).is_err(),
            "unknown query discriminants must fail closed"
        );
    }
    #[test]
    fn escrow_query_tags_disambiguate_identical_account_payloads() {
        use crate::{
            escrow::{AssetEscrowRecord, AssetEscrowStatus},
            query::{
                Query,
                escrow::prelude::{
                    FindAssetEscrowsByBuyer, FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
                },
            },
        };
        let account = AccountId::new(ALICE_KEYPAIR.public_key().clone());
        let seller_query = FindAssetEscrowsBySeller {
            seller: account.clone(),
        };
        let buyer_query = FindAssetEscrowsByBuyer { buyer: account };
        let status_query = FindAssetEscrowsByStatus {
            status: AssetEscrowStatus::Open,
        };
        let seller_payload = norito::codec::Encode::encode(&seller_query);
        let buyer_payload = norito::codec::Encode::encode(&buyer_query);
        let status_payload = norito::codec::Encode::encode(&status_query);
        assert_eq!(
            seller_payload, buyer_payload,
            "seller and buyer bodies intentionally need an envelope discriminator"
        );
        assert_eq!(
            seller_query.query_item_kind(),
            QueryItemKind::AssetEscrowsBySeller
        );
        assert_eq!(
            buyer_query.query_item_kind(),
            QueryItemKind::AssetEscrowsByBuyer
        );
        assert_eq!(
            status_query.query_item_kind(),
            QueryItemKind::AssetEscrowsByStatus
        );
        let predicate_bytes =
            norito::codec::Encode::encode(&CompoundPredicate::<AssetEscrowRecord>::PASS);
        let selector_bytes =
            norito::codec::Encode::encode(&SelectorTuple::<AssetEscrowRecord>::default());
        let params = parameters::QueryParams::default();
        let seller_envelope = QueryWithParams {
            query: (),
            query_payload: seller_payload.clone(),
            item: QueryItemKind::AssetEscrowsBySeller,
            predicate_bytes: predicate_bytes.clone(),
            selector_bytes: selector_bytes.clone(),
            params: params.clone(),
        };
        let buyer_envelope = QueryWithParams {
            query: (),
            query_payload: buyer_payload.clone(),
            item: QueryItemKind::AssetEscrowsByBuyer,
            predicate_bytes: predicate_bytes.clone(),
            selector_bytes: selector_bytes.clone(),
            params: params.clone(),
        };
        let status_envelope = QueryWithParams {
            query: (),
            query_payload: status_payload.clone(),
            item: QueryItemKind::AssetEscrowsByStatus,
            predicate_bytes: predicate_bytes.clone(),
            selector_bytes: selector_bytes.clone(),
            params: params.clone(),
        };
        let seller_wire = norito::codec::Encode::encode(&seller_envelope);
        let buyer_wire = norito::codec::Encode::encode(&buyer_envelope);
        let status_wire = norito::codec::Encode::encode(&status_envelope);
        assert_ne!(
            seller_wire, buyer_wire,
            "the envelope discriminator must distinguish identical query payloads"
        );
        for (wire, expected_item, expected_payload) in [
            (
                seller_wire.as_slice(),
                QueryItemKind::AssetEscrowsBySeller,
                seller_payload.as_slice(),
            ),
            (
                buyer_wire.as_slice(),
                QueryItemKind::AssetEscrowsByBuyer,
                buyer_payload.as_slice(),
            ),
            (
                status_wire.as_slice(),
                QueryItemKind::AssetEscrowsByStatus,
                status_payload.as_slice(),
            ),
        ] {
            let mut input = wire;
            let decoded = <QueryWithParams as norito::codec::Decode>::decode(&mut input)
                .expect("decode escrow query envelope");
            assert!(input.is_empty());
            assert_eq!(decoded.item, expected_item);
            assert_eq!(decoded.query_payload, expected_payload);
            assert_eq!(decoded.predicate_bytes, predicate_bytes);
            assert_eq!(decoded.selector_bytes, selector_bytes);
            assert_eq!(decoded.params, params);
            assert_eq!(norito::codec::Encode::encode(&decoded), wire);
        }
    }
    #[test]
    fn query_with_params_encoding_preserves_canonical_field_order() {
        #[derive(norito::codec::Encode)]
        struct CanonicalFieldOrder {
            query: (),
            query_payload: Vec<u8>,
            item: QueryItemKind,
            predicate_bytes: Vec<u8>,
            selector_bytes: Vec<u8>,
            params: parameters::QueryParams,
        }
        let query_payload = vec![0x11, 0x22];
        let predicate_bytes = vec![0x33];
        let selector_bytes = vec![0x44, 0x55, 0x66];
        let params = parameters::QueryParams::default();
        let query = QueryWithParams {
            query: (),
            query_payload: query_payload.clone(),
            item: QueryItemKind::AssetEscrowRecord,
            predicate_bytes: predicate_bytes.clone(),
            selector_bytes: selector_bytes.clone(),
            params: params.clone(),
        };
        let canonical = CanonicalFieldOrder {
            query: (),
            query_payload: query_payload.clone(),
            item: QueryItemKind::AssetEscrowRecord,
            predicate_bytes: predicate_bytes.clone(),
            selector_bytes: selector_bytes.clone(),
            params: params.clone(),
        };
        let wire = norito::codec::Encode::encode(&query);
        assert_eq!(
            wire,
            norito::codec::Encode::encode(&canonical),
            "the envelope must retain its canonical structural field order"
        );
        let mut input = wire.as_slice();
        let decoded = <QueryWithParams as norito::codec::Decode>::decode(&mut input)
            .expect("decode canonical query envelope");
        assert!(input.is_empty());
        let (item, predicate, selector, payload) = decoded.parts();
        assert_eq!(item, QueryItemKind::AssetEscrowRecord);
        assert_eq!(predicate, predicate_bytes);
        assert_eq!(selector, selector_bytes);
        assert_eq!(payload, query_payload);
        assert_eq!(decoded.params, params);
        assert_eq!(norito::codec::Encode::encode(&decoded), wire);
    }
}
/// Use a custom syntax to implement [`Query`] for applicable types
macro_rules! impl_iter_queries {
    ($ty:ty => [$item:ty, $kind:ident] $(, $($rest:tt)*)?) => {
        impl seal::Query for $ty {}
        impl Query for $ty {
            type Item = $item;
            fn query_item_kind(&self) -> QueryItemKind {
                QueryItemKind::$kind
            }
            fn dyn_encode(&self) -> Vec<u8> {
                self.encode()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }
        $(
            impl_iter_queries!($($rest)*);
        )?
    };
    ($ty:ty => $item:ty $(, $($rest:tt)*)?) => {
        impl seal::Query for $ty {}
        impl Query for $ty {
            type Item = $item;
            fn dyn_encode(&self) -> Vec<u8> {
                self.encode()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
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
        impl seal::SingularQuery for $ty {}
        impl SingularQuery for $ty {
            type Output = $output;
            fn dyn_encode(&self) -> Vec<u8> {
                self.encode()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
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
    FindAccountIds => crate::account::AccountId,
    FindAssets => crate::asset::value::Asset,
    asset::prelude::FindAssetsByAccountId => crate::asset::value::Asset,
    FindAssetDefinitions => crate::asset::definition::AssetDefinition,
    repo::FindRepoAgreements => crate::repo::RepoAgreement,
    FindNfts => crate::nft::Nft,
    nft::prelude::FindNftsByAccountId => crate::nft::Nft,
    FindRwas => crate::rwa::Rwa,
    FindDomains => crate::domain::Domain,
    domain::prelude::FindDomainsByAccountId => crate::domain::Domain,
    FindPeers => iroha_model_base::peer::PeerId,
    FindActiveTriggerIds => crate::trigger::TriggerId,
    FindTriggers => crate::trigger::Trigger,
    escrow::FindAssetEscrows => crate::escrow::AssetEscrowRecord,
    escrow::FindAssetEscrowsBySeller => [crate::escrow::AssetEscrowRecord, AssetEscrowsBySeller],
    escrow::FindAssetEscrowsByBuyer => [crate::escrow::AssetEscrowRecord, AssetEscrowsByBuyer],
    escrow::FindAssetEscrowsByStatus => [crate::escrow::AssetEscrowRecord, AssetEscrowsByStatus],
    nexus::prelude::FindFeeSponsorPrograms => crate::nexus::FeeSponsorProgram,
    nexus::prelude::FindFeeSponsorProgramIds => crate::nexus::FeeSponsorProgramId,
    nexus::prelude::FindFeeSponsorProgramsBySponsor => crate::nexus::FeeSponsorProgram,
    FindTransactions => CommittedTransaction,
    FindAccountsWithAsset => crate::account::Account,
    FindBlockHeaders => crate::block::BlockHeader,
    FindBlocks => SignedBlock,
    proof::prelude::FindProofRecords => crate::proof::ProofRecord,
    proof::prelude::FindProofRecordsByBackend => crate::proof::ProofRecord,
    proof::prelude::FindProofRecordsByStatus => crate::proof::ProofRecord,
    oracle::prelude::FindOracleFeeds => crate::oracle::FeedConfig,
    oracle::prelude::FindOracleHistoryByFeedId => crate::events::data::oracle::FeedEventRecord,
    oracle::prelude::FindOracleProviderStatsByFeedId => crate::oracle::OracleProviderStatsRecord,
    oracle::prelude::FindOracleDisputes => crate::oracle::OracleDispute,
    oracle::prelude::FindOracleDisputesByFeedId => crate::oracle::OracleDispute,
    oracle::prelude::FindOracleChanges => crate::oracle::OracleChangeProposal,
    oracle::prelude::FindTwitterBindingsByUaid => crate::oracle::TwitterBindingRecord,
    oracle::prelude::FindDefiOracleAttestationsByKey => crate::oracle::DefiOracleAttestation,
}
impl_singular_queries! {
    nft_market::FindNftSaleOfferById => crate::nft_market::NftSaleRecordV1,
    game::FindGameSessionById => crate::game::GameSessionRecordV1,
    game::FindExecutionProofVerificationById => crate::execution_proofs::ExecutionProofVerificationV1,
    FindParameters => crate::parameter::Parameters,
    FindExecutorDataModel => crate::executor::ExecutorDataModel,
    account::prelude::FindAccountById => crate::account::Account,
    account::prelude::FindAliasesByAccountId => Vec<account::AccountAliasBindingRecord>,
    account::prelude::FindAccountRecoveryPolicyByAlias => crate::account::AccountRecoveryPolicy,
    account::prelude::FindAccountRecoveryRequestByAlias => crate::account::AccountRecoveryRequest,
    proof::prelude::FindProofRecordById => crate::proof::ProofRecord,
    smart_contract::prelude::FindContractManifestByArtifactId => crate::smart_contract::manifest::ContractManifest,
    runtime::prelude::FindAbiVersion => crate::query::runtime::AbiVersion,
    asset::prelude::FindAssetById => crate::asset::value::Asset,
    asset::prelude::FindAssetDefinitionById => crate::asset::definition::AssetDefinition,
    asset::prelude::FindAssetDefinitionDirectHome => crate::asset::AssetDefinitionDirectHomeV1,
    escrow::prelude::FindAssetEscrowById => crate::escrow::AssetEscrowRecord,
    trigger::prelude::FindTriggerById => crate::trigger::Trigger,
    oracle::FindTwitterBindingByHash => crate::oracle::TwitterBindingRecord,
    oracle::FindOracleFeedById => crate::oracle::FeedConfig,
    oracle::FindOracleDisputeById => crate::oracle::OracleDispute,
    oracle::FindOracleChangeById => crate::oracle::OracleChangeProposal,
    oracle::FindOracleProviderStatsByKey => crate::oracle::OracleProviderStats,
    oracle::FindLatestDefiOracleAttestation => crate::oracle::DefiOracleAttestation,
    endorsement::prelude::FindDomainEndorsements => Vec<crate::nexus::DomainEndorsementRecord>,
    endorsement::prelude::FindDomainEndorsementPolicy => crate::nexus::DomainEndorsementPolicy,
    endorsement::prelude::FindDomainCommittee => crate::nexus::DomainCommittee,
    da::prelude::FindDaPinIntentByTicket => crate::da::pin_intent::DaPinIntentWithLocation,
    da::prelude::FindDaPinIntentByManifest => crate::da::pin_intent::DaPinIntentWithLocation,
    da::prelude::FindDaPinIntentByAlias => crate::da::pin_intent::DaPinIntentWithLocation,
    da::prelude::FindDaPinIntentByLaneEpochSequence => crate::da::pin_intent::DaPinIntentWithLocation,
    nexus::prelude::FindFeeSponsorProgramById => crate::nexus::FeeSponsorProgram,
    settlement::prelude::FindSettlementReceiptById => crate::isi::SettlementReceipt,
    settlement::prelude::FindFxCorridorPolicyRegistry => crate::isi::settlement::FxCorridorPolicyRegistry,
    settlement::prelude::FindFxCorridorPolicyById => crate::isi::settlement::FxCorridorPolicy,
    sns::prelude::FindDataspaceNameOwnerById => crate::account::AccountId,
    musubi::prelude::FindMusubiExactPackageV1 => crate::musubi::MusubiPackageRecordV1,
    musubi::prelude::FindMusubiExactReleaseV1 => crate::musubi::MusubiExactReleaseSnapshotV1,
    musubi::prelude::FindMusubiProviderBundleAttestationV1 => crate::musubi::MusubiProviderBundleAttestationRecordV1,
    musubi::prelude::FindMusubiResolverIndexV1 => crate::musubi::MusubiResolverIndexPageV1,
    musubi::prelude::FindMusubiVersionsV1 => crate::musubi::MusubiVersionPageV1,
    musubi::prelude::FindMusubiMaintainersV1 => crate::musubi::MusubiMaintainerPageV1,
    musubi::prelude::FindMusubiArchiveLocationsV1 => crate::musubi::MusubiArchiveLocationPageV1,
    musubi::prelude::FindMusubiArchiveRetentionV1 => crate::musubi::MusubiArchiveRetentionPageV1,
    musubi::prelude::FindMusubiAliasV1 => crate::musubi::MusubiAliasRecordV1,
    musubi::prelude::FindMusubiAliasHistoryV1 => crate::musubi::MusubiAliasHistoryPageV1,
    musubi::prelude::FindMusubiOrderedPrefixV1 => crate::musubi::MusubiOrderedPackagePageV1,
    account::prelude::FindAccountByAlias => crate::account::Account,
    domain::prelude::FindDomainById => crate::domain::Domain,
    nft::prelude::FindNftById => crate::nft::Nft,
}
// NOTE: Query DSL projection traits are provided generically in dsl module now.
#[cfg(test)]
mod trait_object_tests {
    use super::*;
    use crate::query::dsl::{HasProjection, PredicateMarker, SelectorMarker};
    use norito::codec::Encode;

    fn try_bare_bytes_with_flags(
        value: &dyn norito::core::SerializePayload,
        flags: u8,
    ) -> Result<Vec<u8>, norito::core::Error> {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        let mut bytes = Vec::new();
        let mut encoder = norito::core::Encoder::for_buffer(&mut bytes);
        value.serialize(&mut encoder)?;
        Ok(bytes)
    }

    fn bare_bytes_with_flags(value: &dyn norito::core::SerializePayload, flags: u8) -> Vec<u8> {
        try_bare_bytes_with_flags(value, flags).expect("encode bare value")
    }

    #[test]
    fn query_box_streaming_wire_is_canonical_for_supported_sequence_layouts() {
        let concrete = domain::FindDomains;
        let erased = ErasedIterQuery::<Domain>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            concrete.encode(),
        );
        assert_eq!(
            norito::core::SerializePayload::encoded_len_exact(&erased.selector),
            None,
            "the fixture must exercise the count-first field path"
        );
        let query: QueryBox<QueryOutputBatchBox> = Box::new(erased);
        let expected = (
            query_wire_id(query.type_name_key())
                .expect("domain query wire identifier")
                .to_owned(),
            query.encode_bytes(),
        );
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let actual = bare_bytes_with_flags(&query, flags);
            assert_eq!(actual, bare_bytes_with_flags(&expected, flags));
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let exact = norito::core::SerializePayload::encoded_len_exact(&query);
            assert_eq!(exact, Some(actual.len()));
        }
    }

    #[test]
    fn query_box_decode_rejects_concrete_type_name_alias() {
        let erased = ErasedIterQuery::<Domain>::new(
            CompoundPredicate::PASS,
            SelectorTuple::default(),
            domain::FindDomains.encode(),
        );
        let query: QueryBox<QueryOutputBatchBox> = Box::new(erased);
        let type_name = query.type_name_key();
        let wire_id = query_wire_id(type_name).expect("domain query wire identifier");
        assert_ne!(
            type_name, wire_id,
            "fixture must exercise the alias hard cut"
        );
        let payload = query.encode_bytes();
        let flags = norito::core::default_encode_flags();

        let canonical_pair = (wire_id.to_owned(), payload.clone());
        let canonical_payload = bare_bytes_with_flags(&canonical_pair, flags);
        let canonical_frame = norito::core::frame_bare_with_header_flags::<
            QueryBox<QueryOutputBatchBox>,
        >(&canonical_payload, flags)
        .expect("frame canonical query pair");
        let decoded = norito::decode_from_bytes::<QueryBox<QueryOutputBatchBox>>(&canonical_frame)
            .expect("canonical query wire identifier decodes");
        assert_eq!(decoded.encode_bytes(), payload);

        let alias_pair = (type_name.to_owned(), payload);
        let alias_payload = bare_bytes_with_flags(&alias_pair, flags);
        let alias_frame =
            norito::core::frame_bare_with_header_flags::<QueryBox<QueryOutputBatchBox>>(
                &alias_payload,
                flags,
            )
            .expect("frame aliased query pair");
        let error = match norito::decode_from_bytes::<QueryBox<QueryOutputBatchBox>>(&alias_frame) {
            Ok(_) => panic!("concrete Rust type-name query alias must reject"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            norito::core::Error::Message(message)
                if message.contains("unknown query wire identifier")
        ));
    }

    #[test]
    fn query_box_encode_rejects_unregistered_concrete_type() {
        let query: QueryBox<QueryOutputBatchBox> =
            Box::new(ErasedIterQuery::<QueryOutputBatchBox>::new(
                CompoundPredicate::PASS,
                SelectorTuple::default(),
                vec![0xA5, 0x5A],
            ));
        assert_eq!(
            query_wire_id(query.type_name_key()),
            None,
            "fixture must remain absent from the V1 registry"
        );

        let error = try_bare_bytes_with_flags(&query, norito::core::default_encode_flags())
            .expect_err("an unregistered query type must not fall back to its Rust type name");
        assert!(matches!(
            error,
            norito::core::Error::Message(message)
                if message.contains("has no registered wire identifier")
        ));
        assert_eq!(
            norito::core::SerializePayload::encoded_len_exact(&query),
            None
        );
    }

    #[test]
    fn query_dyn_encode_matches_encode() {
        let q = domain::FindDomains;
        let expected = q.encode();
        let actual = Query::dyn_encode(&q);
        assert_eq!(actual, expected);
    }
    #[test]
    fn query_as_any_downcasts() {
        let q = domain::FindDomains;
        // Call the method in a way that avoids trait-object dispatch
        let any = <domain::FindDomains as Query>::as_any(&q);
        assert!(any.downcast_ref::<domain::FindDomains>().is_some());
    }
    #[test]
    fn query_execute_does_not_panic() {
        let q = domain::FindDomains;
        Query::execute(&q);
    }
    #[test]
    fn singular_query_dyn_encode_matches_encode() {
        let q = FindExecutorDataModel;
        let expected = q.encode();
        let actual = SingularQuery::dyn_encode(&q);
        assert_eq!(actual, expected);
    }
    #[test]
    fn singular_query_as_any_downcasts() {
        let q = FindExecutorDataModel;
        let trait_obj: &dyn SingularQuery<Output = crate::executor::ExecutorDataModel> = &q;
        assert!(
            trait_obj
                .as_any()
                .downcast_ref::<FindExecutorDataModel>()
                .is_some()
        );
    }
    #[test]
    fn singular_query_execute_does_not_panic() {
        let q = FindExecutorDataModel;
        SingularQuery::execute(&q);
    }
    #[test]
    fn find_block_headers_has_selector_projection() {
        <block::FindBlockHeaders as HasProjection<SelectorMarker>>::atom(());
    }
    fn assert_predicate<T: HasProjection<PredicateMarker>>() {}
    fn assert_selector<T: HasProjection<SelectorMarker>>() {}
    #[test]
    fn committed_transaction_has_projection_impls() {
        assert_predicate::<CommittedTransaction>();
        assert_selector::<CommittedTransaction>();
    }
    #[test]
    fn iter_queries_have_projection_impls() {
        assert_predicate::<trigger::FindTriggers>();
        assert_selector::<trigger::FindTriggers>();
        assert_predicate::<asset::FindAssetDefinitions>();
        assert_selector::<asset::FindAssetDefinitions>();
        assert_predicate::<nft::FindNfts>();
        assert_selector::<nft::FindNfts>();
        assert_predicate::<rwa::FindRwas>();
        assert_selector::<rwa::FindRwas>();
        assert_predicate::<role::FindRoles>();
        assert_selector::<role::FindRoles>();
        assert_predicate::<peer::FindPeers>();
        assert_selector::<peer::FindPeers>();
        assert_predicate::<trigger::FindActiveTriggerIds>();
        assert_selector::<trigger::FindActiveTriggerIds>();
    }
    #[test]
    fn query_with_filter_converts() {
        use crate::query::dsl::{CompoundPredicate, SelectorTuple};
        let q = QueryWithFilter::new(
            (),
            CompoundPredicate::<crate::domain::Domain>::PASS,
            SelectorTuple::<crate::domain::Domain>::default(),
        );
        let _: QueryBox<QueryOutputBatchBox> = q.into();
    }
}
/// A macro reducing boilerplate when defining query types.
/// Each item supplies its captured `norito_schema(name = "...")` identity;
/// the template derives the identity once alongside the existing codecs.
macro_rules! queries {
    ($($($meta:meta)* $item:item)+) => {
        pub use self::model::*;
        #[iroha_data_model_derive::model]
        mod model{
            use super::*;
            use norito::codec::{Decode, Encode}; $(
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
            #[derive(Decode, Encode)]
            #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
            #[derive(derive_more::Constructor)]
            #[derive(iroha_schema::IntoSchema)]
            #[derive(norito::NoritoSchema)]
            $($meta)*
            $item )+
        }
    };
}
include!("domain_queries.rs");
pub mod sns {
    //! SNS-related query definitions.
    //!
    //! Queries related to authoritative SNS-backed ownership.
    use derive_more::Display;
    use iroha_model_base::topology::DataSpaceId;
    queries! {
        /// Fetch the active SNS owner for a dataspace alias resolved from the current catalog.
        #[derive(Display)]
        #[display("Find SNS dataspace owner for `{dataspace_id}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::sns::model::FindDataspaceNameOwnerById")]
        pub struct FindDataspaceNameOwnerById {
            /// Dataspace identifier whose leased alias owner should be resolved.
            pub dataspace_id: DataSpaceId,
        }
    }
    impl FindDataspaceNameOwnerById {
        /// Return the queried dataspace identifier.
        pub fn dataspace_id(&self) -> DataSpaceId {
            self.dataspace_id
        }
    }
    /// Prelude re-exports for SNS queries.
    pub mod prelude {
        pub use super::FindDataspaceNameOwnerById;
    }
}
include!("musubi_queries.rs");
pub mod trigger {
    //! Trigger-related query definitions.
    //!
    //! Trigger-related queries.
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// Find all currently active (as in not disabled and/or expired) trigger IDs.
        #[derive(Copy, Display)]
        #[display("Find all trigger ids")]
        #[norito_schema(name = "iroha_data_model::query::trigger::model::FindActiveTriggerIds")]
        pub struct FindActiveTriggerIds;
        /// Find all currently active (as in not disabled and/or expired) triggers.
        #[derive(Copy, Display)]
        #[display("Find all triggers")]
        #[norito_schema(name = "iroha_data_model::query::trigger::model::FindTriggers")]
        pub struct FindTriggers;
        /// Find a trigger by identifier.
        #[derive(Display)]
        #[display("Find trigger `{id}`")]
        #[norito_schema(name = "iroha_data_model::query::trigger::model::FindTriggerById")]
        pub struct FindTriggerById {
            /// Trigger identifier to resolve.
            pub id: crate::trigger::TriggerId,
        }
    }
    impl FindTriggerById {
        /// Return the queried trigger identifier.
        pub fn trigger_id(&self) -> &crate::trigger::TriggerId {
            &self.id
        }
    }
    pub mod prelude {
        //! Convenient re-exports for common query types.
        pub use super::{FindActiveTriggerIds, FindTriggerById, FindTriggers};
    }
}
pub mod smart_contract {
    //! Smart-contract query definitions.
    //!
    //! Smart contract code/manifest related queries.
    use derive_more::Display;
    queries! {
        /// Find a smart contract manifest by its exact dataspace artifact identity.
        #[derive(Display)]
        #[display("Find contract manifest by `{artifact_id:?}`")]
        #[repr(transparent)]
        #[norito_schema(name = "iroha_data_model::query::smart_contract::model::FindContractManifestByArtifactId")]
        pub struct FindContractManifestByArtifactId {
            /// Exact dataspace and complete artifact content hash.
            pub artifact_id: crate::smart_contract::ContractArtifactId,
        }
    }
    pub mod prelude {
        //! Prelude re-exports for smart contract queries.
        pub use super::FindContractManifestByArtifactId;
    }
}
pub mod transaction {
    //! Transaction query definitions.
    //!
    //! Queries related to transactions.
    #![allow(clippy::missing_inline_in_public_items)]
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindTransactions`] Iroha Query lists all transactions included in a blockchain
        #[derive(Copy, Display)]
        #[display("Find all transactions")]
        #[norito_schema(name = "iroha_data_model::query::transaction::model::FindTransactions")]
        pub struct FindTransactions;
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::FindTransactions;
    }
}
pub mod block {
    //! Block query definitions.
    //!
    //! Queries related to blocks.
    #![allow(clippy::missing_inline_in_public_items)]
    use derive_more::Display;
    use std::{format, string::String, vec::Vec};
    queries! {
        /// [`FindBlocks`] Iroha Query lists all blocks sorted by height in descending order
        #[derive(Copy, Display)]
        #[display("Find all blocks")]
        #[norito_schema(name = "iroha_data_model::query::block::model::FindBlocks")]
        pub struct FindBlocks;
        /// [`FindBlockHeaders`] Iroha Query lists all block headers
        /// sorted by height in descending order
        #[derive(Copy, Display)]
        #[display("Find all block headers")]
        #[norito_schema(name = "iroha_data_model::query::block::model::FindBlockHeaders")]
        pub struct FindBlockHeaders;
    }
    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{FindBlockHeaders, FindBlocks};
    }
}
pub mod error;
/// The prelude re-exports most commonly used traits, structs and macros from this crate.
#[allow(ambiguous_glob_reexports)]
pub mod prelude {
    pub use super::{
        CommittedTransaction, QueryBox, QueryRequest, SingularQueryBox, account::prelude::*,
        asset::prelude::*, block::prelude::*, builder::prelude::*, da::prelude::*,
        domain::prelude::*, dsl::prelude::*, endorsement::prelude::*, escrow::prelude::*,
        executor::prelude::*, game::prelude::*, musubi::prelude::*, nft::prelude::*,
        nft_market::prelude::*, oracle::prelude::*, parameters::prelude::*, peer::prelude::*,
        permission::prelude::*, role::prelude::*, rwa::prelude::*, settlement::prelude::*,
        sorafs::prelude::*, transaction::prelude::*, trigger::prelude::*,
    };
}
include!("query_tail_tests.rs");

#[cfg(test)]
mod generic_identity_tests;
