//! Canonical V1 records for Kotodama's typed core-ledger queries.
//!
//! The protocol deliberately exposes only the five projections understood by the V1 core-query
//! host. Page and quantity invariants are enforced during both construction and Norito decoding so
//! untrusted contract payloads cannot manufacture values that the host itself would never return.
use iroha_data_model::prelude::{
    AccountId, AssetDefinitionId, AssetId, Json, NftId, Numeric, NumericOperationError, Quantity,
};
use iroha_model_base::domain::DomainId;
use norito::{
    Decode, DeserializePayload, Encode, SerializePayload,
    core::{self as ncore, DecodeFromSlice},
};
use std::fmt;
/// Maximum number of entities in one V1 core-query page.
pub const QUERY_PAGE_CAPACITY_V1: usize = 64;
/// Stable entity discriminator used by the V1 core-query host protocol.
///
/// The numeric values are ABI, not Rust enum ordinals.  They must never be
/// reordered or reused for a different entity family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::CoreQueryEntityTagV1")]
pub enum CoreQueryEntityTagV1 {
    /// Account projection.
    Account = 1,
    /// Asset projection.
    Asset = 2,
    /// Asset-definition projection.
    AssetDefinition = 3,
    /// Domain projection.
    Domain = 4,
    /// Non-fungible-asset projection.
    Nft = 5,
}
impl CoreQueryEntityTagV1 {
    /// Stable numeric ABI tag.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}
/// An unknown V1 core-query entity tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownCoreQueryEntityTagV1(
    /// Rejected raw ABI tag.
    pub u64,
);
impl fmt::Display for UnknownCoreQueryEntityTagV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unknown V1 core-query entity tag {} (expected 1 through 5)",
            self.0
        )
    }
}
impl std::error::Error for UnknownCoreQueryEntityTagV1 {}
impl TryFrom<u64> for CoreQueryEntityTagV1 {
    type Error = UnknownCoreQueryEntityTagV1;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Account),
            2 => Ok(Self::Asset),
            3 => Ok(Self::AssetDefinition),
            4 => Ok(Self::Domain),
            5 => Ok(Self::Nft),
            invalid => Err(UnknownCoreQueryEntityTagV1(invalid)),
        }
    }
}

impl SerializePayload for CoreQueryEntityTagV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        self.as_u64().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.as_u64().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.as_u64().encoded_len_exact()
    }
}

impl<'de> DeserializePayload<'de> for CoreQueryEntityTagV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid V1 core-query entity tag")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let pointer = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(pointer)?;
        let (value, _) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}
impl<'de> DecodeFromSlice<'de> for CoreQueryEntityTagV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (tag, used) = <u64 as DecodeFromSlice>::decode_from_slice(bytes)?;
        let tag = Self::try_from(tag).map_err(|error| ncore::Error::Message(error.to_string()))?;
        Ok((tag, used))
    }
}
/// Nominal V1 quantity, backed by the canonical nonnegative numeric domain.
///
/// The inner value is private so every constructed or decoded instance has a
/// unique decimal representation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::QuantityV1")]
pub struct QuantityV1(Quantity);
impl QuantityV1 {
    /// Construct a quantity from an already-canonical decimal payload.
    ///
    /// # Errors
    ///
    /// Returns the precise numeric-domain error for negative or noncanonical input.
    pub fn try_new(value: Numeric) -> Result<Self, NumericOperationError> {
        Quantity::from_canonical_numeric(value).map(Self)
    }
    /// Canonicalise a nonnegative decimal payload and construct a quantity.
    ///
    /// # Errors
    ///
    /// Returns the precise numeric-domain error for negative or out-of-domain input.
    pub fn canonicalize(value: Numeric) -> Result<Self, NumericOperationError> {
        Quantity::try_from_numeric(value).map(Self)
    }
    /// Borrow the nominal quantity.
    #[must_use]
    pub fn as_quantity(&self) -> &Quantity {
        &self.0
    }
    /// Borrow the canonical numeric payload.
    #[must_use]
    pub fn as_numeric(&self) -> &Numeric {
        self.0.as_numeric()
    }
    /// Consume the wrapper and return the nominal quantity.
    #[must_use]
    pub fn into_quantity(self) -> Quantity {
        self.0
    }
    /// Consume the wrapper and return its canonical numeric payload.
    #[must_use]
    pub fn into_numeric(self) -> Numeric {
        self.0.into_numeric()
    }
}
impl TryFrom<Numeric> for QuantityV1 {
    type Error = NumericOperationError;
    fn try_from(value: Numeric) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}
impl From<Quantity> for QuantityV1 {
    fn from(value: Quantity) -> Self {
        Self(value)
    }
}
impl From<QuantityV1> for Quantity {
    fn from(value: QuantityV1) -> Self {
        value.into_quantity()
    }
}
impl From<QuantityV1> for Numeric {
    fn from(value: QuantityV1) -> Self {
        value.into_numeric()
    }
}

impl SerializePayload for QuantityV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'de> DeserializePayload<'de> for QuantityV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid V1 quantity payload")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let pointer = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(pointer)?;
        let (value, _) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}
impl<'de> DecodeFromSlice<'de> for QuantityV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (quantity, used) = <Quantity as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((Self(quantity), used))
    }
}
/// Typed account projection returned by V1 core queries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::AccountView")]
pub struct AccountView {
    /// Canonical account identifier.
    pub id: AccountId,
    /// Canonical JSON representation of account metadata.
    pub metadata: Json,
}
/// Typed asset projection returned by V1 core queries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::AssetView")]
pub struct AssetView {
    /// Canonical asset identifier.
    pub id: AssetId,
    /// Canonical nonnegative quantity held by the asset.
    pub amount: QuantityV1,
}
/// Typed asset-definition projection returned by V1 core queries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::AssetDefinitionView")]
pub struct AssetDefinitionView {
    /// Canonical asset-definition identifier.
    pub id: AssetDefinitionId,
    /// Human-readable asset name.
    pub name: String,
    /// Optional human-readable asset description.
    pub description: Option<String>,
    /// Account that owns the definition.
    pub owned_by: AccountId,
    /// Canonical total quantity currently in existence.
    pub total_quantity: QuantityV1,
    /// Maximum fractional decimal places; `None` permits the full numeric domain.
    pub numeric_scale: Option<i64>,
    /// Canonical JSON representation of asset-definition metadata.
    pub metadata: Json,
}
/// Typed domain projection returned by V1 core queries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::DomainView")]
pub struct DomainView {
    /// Canonical domain identifier.
    pub id: DomainId,
    /// Account that owns the domain.
    pub owned_by: AccountId,
    /// Canonical JSON representation of domain metadata.
    pub metadata: Json,
}
/// Typed non-fungible-asset projection returned by V1 core queries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::NftView")]
pub struct NftView {
    /// Canonical NFT identifier.
    pub id: NftId,
    /// Account that owns the NFT.
    pub owned_by: AccountId,
    /// Canonical JSON representation of NFT content.
    pub content: Json,
}
/// Associates a V1 projection record with its stable entity tag.
pub trait CoreQueryProjectionV1 {
    /// Stable entity tag for this projection.
    const ENTITY_TAG: CoreQueryEntityTagV1;
}
impl CoreQueryProjectionV1 for AccountView {
    const ENTITY_TAG: CoreQueryEntityTagV1 = CoreQueryEntityTagV1::Account;
}
impl CoreQueryProjectionV1 for AssetView {
    const ENTITY_TAG: CoreQueryEntityTagV1 = CoreQueryEntityTagV1::Asset;
}
impl CoreQueryProjectionV1 for AssetDefinitionView {
    const ENTITY_TAG: CoreQueryEntityTagV1 = CoreQueryEntityTagV1::AssetDefinition;
}
impl CoreQueryProjectionV1 for DomainView {
    const ENTITY_TAG: CoreQueryEntityTagV1 = CoreQueryEntityTagV1::Domain;
}
impl CoreQueryProjectionV1 for NftView {
    const ENTITY_TAG: CoreQueryEntityTagV1 = CoreQueryEntityTagV1::Nft;
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryPageItemsV1<T>(Vec<T>);
impl<T: SerializePayload> SerializePayload for QueryPageItemsV1<T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
impl<'de, T> DeserializePayload<'de> for QueryPageItemsV1<T>
where
    T: SerializePayload
        + for<'value> DeserializePayload<'value>
        + for<'slice> DecodeFromSlice<'slice>,
{
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid bounded V1 query-page items")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let pointer = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(pointer)?;
        let (value, _) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}
impl<'de, T> DecodeFromSlice<'de> for QueryPageItemsV1<T>
where
    T: SerializePayload
        + for<'value> DeserializePayload<'value>
        + for<'slice> DecodeFromSlice<'slice>,
{
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (declared, _) = ncore::read_seq_len_slice(bytes)?;
        if declared > QUERY_PAGE_CAPACITY_V1 {
            return Err(ncore::Error::Message(format!(
                "V1 query page declares {declared} items; maximum is {QUERY_PAGE_CAPACITY_V1}"
            )));
        }
        let (items, used) = <Vec<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        if items.len() > QUERY_PAGE_CAPACITY_V1 {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok((Self(items), used))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::NonNegativeOffsetV1")]
struct NonNegativeOffsetV1(i64);

impl SerializePayload for NonNegativeOffsetV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'de> DeserializePayload<'de> for NonNegativeOffsetV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("negative V1 query-page offset")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let pointer = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(pointer)?;
        let (value, _) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}
impl<'de> DecodeFromSlice<'de> for NonNegativeOffsetV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (offset, used) = <i64 as DecodeFromSlice>::decode_from_slice(bytes)?;
        if offset < 0 {
            return Err(ncore::Error::Message(format!(
                "V1 query-page next_offset must be nonnegative, found {offset}"
            )));
        }
        Ok((Self(offset), used))
    }
}
/// Failure to construct a valid [`QueryPageV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPageErrorV1 {
    /// More than 64 items were supplied.
    TooManyItems {
        /// Supplied item count.
        actual: usize,
    },
    /// A continuation cannot follow a page that made no progress.
    EmptyPageWithContinuation,
    /// The continuation precedes the minimum offset implied by the returned items.
    NextOffsetBeforeItemCount {
        /// Rejected continuation offset.
        next_offset: i64,
        /// Number of returned items.
        item_count: usize,
    },
    /// The supplied next offset was negative.
    NegativeNextOffset(i64),
    /// Computing the next page offset overflowed `i64`.
    OffsetOverflow,
}
impl fmt::Display for QueryPageErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyItems { actual } => write!(
                formatter,
                "V1 query page contains {actual} items; maximum is {QUERY_PAGE_CAPACITY_V1}"
            ),
            Self::EmptyPageWithContinuation => formatter.write_str(
                "V1 query page cannot publish next_offset without returning at least one item",
            ),
            Self::NextOffsetBeforeItemCount {
                next_offset,
                item_count,
            } => write!(
                formatter,
                "V1 query-page next_offset {next_offset} is smaller than its {item_count} returned items"
            ),
            Self::NegativeNextOffset(offset) => write!(
                formatter,
                "V1 query-page next_offset must be nonnegative, found {offset}"
            ),
            Self::OffsetOverflow => {
                formatter.write_str("V1 query-page next_offset exceeds i64::MAX")
            }
        }
    }
}
impl std::error::Error for QueryPageErrorV1 {}
fn validate_query_page_components(
    item_count: usize,
    next_offset: Option<i64>,
) -> Result<(), QueryPageErrorV1> {
    if item_count > QUERY_PAGE_CAPACITY_V1 {
        return Err(QueryPageErrorV1::TooManyItems { actual: item_count });
    }
    let Some(next_offset) = next_offset else {
        return Ok(());
    };
    if next_offset < 0 {
        return Err(QueryPageErrorV1::NegativeNextOffset(next_offset));
    }
    if item_count == 0 {
        return Err(QueryPageErrorV1::EmptyPageWithContinuation);
    }
    let minimum_next_offset =
        i64::try_from(item_count).map_err(|_| QueryPageErrorV1::OffsetOverflow)?;
    if next_offset < minimum_next_offset {
        return Err(QueryPageErrorV1::NextOffsetBeforeItemCount {
            next_offset,
            item_count,
        });
    }
    Ok(())
}
/// One bounded page returned by a V1 plural core query.
///
/// Construction and decoding both enforce at most 64 items and a progressing,
/// nonnegative continuation offset. Fields stay private so these invariants
/// cannot be bypassed with a struct literal.
#[derive(Clone, Debug, PartialEq, Eq, Encode, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::core_query::QueryPageV1")]
pub struct QueryPageV1<T> {
    items: QueryPageItemsV1<T>,
    next_offset: Option<NonNegativeOffsetV1>,
}
#[derive(SerializePayload, DeserializePayload)]
struct QueryPageWireV1<T> {
    items: QueryPageItemsV1<T>,
    next_offset: Option<NonNegativeOffsetV1>,
}

impl<'de, T> DeserializePayload<'de> for QueryPageV1<T>
where
    T: SerializePayload
        + for<'value> DeserializePayload<'value>
        + for<'slice> DecodeFromSlice<'slice>,
{
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid V1 query page")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let pointer = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(pointer)?;
        let (value, _) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}
impl<'de, T> DecodeFromSlice<'de> for QueryPageV1<T>
where
    T: SerializePayload
        + for<'value> DeserializePayload<'value>
        + for<'slice> DecodeFromSlice<'slice>,
{
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (wire, used) = ncore::decode_field_canonical::<QueryPageWireV1<T>>(bytes)?;
        validate_query_page_components(wire.items.0.len(), wire.next_offset.map(|offset| offset.0))
            .map_err(|error| ncore::Error::Message(error.to_string()))?;
        Ok((
            Self {
                items: wire.items,
                next_offset: wire.next_offset,
            },
            used,
        ))
    }
}
impl<T> QueryPageV1<T> {
    /// Construct a page from host-projected items and an optional continuation.
    ///
    /// # Errors
    ///
    /// Returns an error for more than 64 items or an invalid continuation.
    pub fn try_new(items: Vec<T>, next_offset: Option<i64>) -> Result<Self, QueryPageErrorV1> {
        validate_query_page_components(items.len(), next_offset)?;
        Ok(Self {
            items: QueryPageItemsV1(items),
            next_offset: next_offset.map(NonNegativeOffsetV1),
        })
    }
    /// Construct a page and derive its continuation from a starting offset.
    ///
    /// `has_more` should come from a one-item lookahead performed by the host.
    /// The returned continuation is `offset + items.len()` only when another
    /// canonical page exists.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid offset, too many items, or `i64`
    /// overflow while deriving the continuation.
    pub fn from_window(
        offset: i64,
        items: Vec<T>,
        has_more: bool,
    ) -> Result<Self, QueryPageErrorV1> {
        if offset < 0 {
            return Err(QueryPageErrorV1::NegativeNextOffset(offset));
        }
        if items.len() > QUERY_PAGE_CAPACITY_V1 {
            return Err(QueryPageErrorV1::TooManyItems {
                actual: items.len(),
            });
        }
        let next_offset = if has_more {
            let item_count =
                i64::try_from(items.len()).map_err(|_| QueryPageErrorV1::OffsetOverflow)?;
            Some(
                offset
                    .checked_add(item_count)
                    .ok_or(QueryPageErrorV1::OffsetOverflow)?,
            )
        } else {
            None
        };
        Self::try_new(items, next_offset)
    }
    /// Borrow the page items in canonical query order.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items.0
    }
    /// Return the next offset only when another page exists.
    #[must_use]
    pub fn next_offset(&self) -> Option<i64> {
        self.next_offset.map(|offset| offset.0)
    }
    /// Consume the page and return its public components.
    #[must_use]
    pub fn into_parts(self) -> (Vec<T>, Option<i64>) {
        (self.items.0, self.next_offset.map(|offset| offset.0))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::prelude::{
        AccountId, AssetDefinition, AssetDefinitionId, AssetId, Registrable,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    fn bare<T: SerializePayload>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        norito::core::serialize_to_buffer(value, &mut bytes).expect("encode bare payload");
        bytes
    }
    fn account_id(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("valid deterministic key pair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn domain_id() -> DomainId {
        DomainId::try_new("wonderland", "universal").expect("valid domain id")
    }
    fn asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            domain_id(),
            "rose".parse::<Name>().expect("valid name"),
        )
    }
    fn account_view(seed: u8) -> AccountView {
        AccountView {
            id: account_id(seed),
            metadata: Json::default(),
        }
    }
    #[test]
    fn entity_tags_have_stable_values_and_reject_unknown_values() {
        let expected = [
            (CoreQueryEntityTagV1::Account, 1),
            (CoreQueryEntityTagV1::Asset, 2),
            (CoreQueryEntityTagV1::AssetDefinition, 3),
            (CoreQueryEntityTagV1::Domain, 4),
            (CoreQueryEntityTagV1::Nft, 5),
        ];
        for (tag, wire) in expected {
            assert_eq!(tag.as_u64(), wire);
            assert_eq!(
                (CoreQueryEntityTagV1::try_from(wire)).expect("expected successful fixture result"),
                tag
            );
            assert_eq!(bare(&tag), bare(&wire));
        }
        for invalid in [0, 6, u64::MAX] {
            assert_eq!(
                CoreQueryEntityTagV1::try_from(invalid),
                Err(UnknownCoreQueryEntityTagV1(invalid))
            );
            let bytes = bare(&invalid);
            assert!(CoreQueryEntityTagV1::decode_from_slice(&bytes).is_err());
        }
    }
    #[test]
    fn quantity_validation_is_strict_and_canonicalization_is_explicit() {
        let canonical = Numeric::new(125, 2);
        assert_eq!(
            QuantityV1::try_new(Numeric::new(-1, 0)),
            Err(NumericOperationError::NegativeQuantity)
        );
        let quantity = QuantityV1::canonicalize(Numeric::new(1_250, 3))
            .expect("nonnegative values canonicalize");
        assert_eq!(quantity.as_numeric(), &canonical);
        let zero = QuantityV1::canonicalize(Numeric::new(0, 28)).expect("zero canonicalizes");
        assert_eq!(zero.as_numeric(), &Numeric::zero());
    }
    #[test]
    fn quantity_decoder_rejects_negative_payloads() {
        let bytes = bare(&Numeric::new(-1, 0));
        assert!(QuantityV1::decode_from_slice(&bytes).is_err());
        let quantity = QuantityV1::from("1.25".parse::<Quantity>().expect("canonical quantity"));
        let encoded = norito::to_bytes(&quantity).expect("encode quantity");
        let decoded: QuantityV1 = norito::decode_from_bytes(&encoded).expect("decode quantity");
        assert_eq!(decoded, quantity);
    }
    #[test]
    fn query_page_construction_enforces_capacity_and_offsets() {
        let too_many = vec![account_view(1); QUERY_PAGE_CAPACITY_V1 + 1];
        assert_eq!(
            QueryPageV1::try_new(too_many, None),
            Err(QueryPageErrorV1::TooManyItems { actual: 65 })
        );
        assert_eq!(
            QueryPageV1::<AccountView>::try_new(Vec::new(), Some(-1)),
            Err(QueryPageErrorV1::NegativeNextOffset(-1))
        );
        assert_eq!(
            QueryPageV1::<AccountView>::try_new(Vec::new(), Some(0)),
            Err(QueryPageErrorV1::EmptyPageWithContinuation)
        );
        assert_eq!(
            QueryPageV1::try_new(vec![account_view(1)], Some(0)),
            Err(QueryPageErrorV1::NextOffsetBeforeItemCount {
                next_offset: 0,
                item_count: 1,
            })
        );
        assert_eq!(
            QueryPageV1::try_new(vec![account_view(1), account_view(2)], Some(1)),
            Err(QueryPageErrorV1::NextOffsetBeforeItemCount {
                next_offset: 1,
                item_count: 2,
            })
        );
        QueryPageV1::try_new(vec![account_view(1)], Some(1))
            .expect("next_offset may equal the returned item count");
        assert_eq!(
            QueryPageV1::from_window(0, Vec::<AccountView>::new(), true),
            Err(QueryPageErrorV1::EmptyPageWithContinuation)
        );
        assert_eq!(
            QueryPageV1::from_window(-1, vec![account_view(1)], true),
            Err(QueryPageErrorV1::NegativeNextOffset(-1))
        );
        assert_eq!(
            QueryPageV1::from_window(i64::MAX, vec![account_view(1)], true),
            Err(QueryPageErrorV1::OffsetOverflow)
        );
        let maximum_page = QueryPageV1::try_new(
            vec![account_view(3); QUERY_PAGE_CAPACITY_V1],
            Some(QUERY_PAGE_CAPACITY_V1 as i64),
        )
        .expect("the exact V1 capacity is valid");
        assert_eq!(maximum_page.items().len(), QUERY_PAGE_CAPACITY_V1);
        assert_eq!(maximum_page.next_offset(), Some(64));
        let page = QueryPageV1::from_window(9, vec![account_view(1), account_view(2)], true)
            .expect("valid page");
        assert_eq!(page.items().len(), 2);
        assert_eq!(page.next_offset(), Some(11));
    }
    #[test]
    fn bounded_page_decoder_rejects_oversized_and_negative_wire_values() {
        let oversized = vec![account_view(1); QUERY_PAGE_CAPACITY_V1 + 1];
        let oversized_bytes = bare(&oversized);
        assert!(QueryPageItemsV1::<AccountView>::decode_from_slice(&oversized_bytes).is_err());
        let oversized_page = QueryPageV1 {
            items: QueryPageItemsV1(oversized),
            next_offset: None,
        };
        let oversized_page_bytes = norito::to_bytes(&oversized_page).expect("encode forged page");
        assert!(
            norito::decode_from_bytes::<QueryPageV1<AccountView>>(&oversized_page_bytes).is_err()
        );
        let negative_bytes = bare(&-1_i64);
        assert!(NonNegativeOffsetV1::decode_from_slice(&negative_bytes).is_err());
        let negative_page = QueryPageV1 {
            items: QueryPageItemsV1(vec![account_view(2)]),
            next_offset: Some(NonNegativeOffsetV1(-1)),
        };
        let negative_page_bytes = norito::to_bytes(&negative_page).expect("encode forged page");
        assert!(
            norito::decode_from_bytes::<QueryPageV1<AccountView>>(&negative_page_bytes).is_err()
        );
        let nonadvancing_page = QueryPageV1::<AccountView> {
            items: QueryPageItemsV1(Vec::new()),
            next_offset: Some(NonNegativeOffsetV1(0)),
        };
        let nonadvancing_page_bytes =
            norito::to_bytes(&nonadvancing_page).expect("encode forged page");
        assert!(
            norito::decode_from_bytes::<QueryPageV1<AccountView>>(&nonadvancing_page_bytes)
                .is_err()
        );
        for (items, next_offset) in [
            (vec![account_view(3)], 0),
            (vec![account_view(3), account_view(4)], 1),
        ] {
            let regressing_page = QueryPageV1::<AccountView> {
                items: QueryPageItemsV1(items),
                next_offset: Some(NonNegativeOffsetV1(next_offset)),
            };
            let bytes = norito::to_bytes(&regressing_page).expect("encode forged page");
            assert!(
                norito::decode_from_bytes::<QueryPageV1<AccountView>>(&bytes).is_err(),
                "next_offset {next_offset} below the item count must be rejected",
            );
        }
    }
    #[test]
    fn page_roundtrip_rejects_trailing_and_malformed_bytes() {
        let page = QueryPageV1::try_new(vec![account_view(7)], Some(1)).expect("valid page");
        let encoded = norito::to_bytes(&page).expect("encode page");
        let decoded: QueryPageV1<AccountView> =
            norito::decode_from_bytes(&encoded).expect("decode page");
        assert_eq!(decoded, page);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(norito::decode_from_bytes::<QueryPageV1<AccountView>>(&trailing).is_err());
        let truncated = &encoded[..encoded.len() - 1];
        assert!(norito::decode_from_bytes::<QueryPageV1<AccountView>>(truncated).is_err());
    }
    #[test]
    fn asset_definition_projection_field_order_is_stable() {
        #[derive(SerializePayload)]
        struct FieldOrderOracle {
            id: AssetDefinitionId,
            name: String,
            description: Option<String>,
            owned_by: AccountId,
            total_quantity: QuantityV1,
            numeric_scale: Option<i64>,
            metadata: Json,
        }
        let view = AssetDefinitionView {
            id: asset_definition_id(),
            name: "Rose".to_owned(),
            description: Some("A deterministic flower".to_owned()),
            owned_by: account_id(4),
            total_quantity: QuantityV1::from(
                "1.25".parse::<Quantity>().expect("canonical quantity"),
            ),
            numeric_scale: Some(2),
            metadata: Json::default(),
        };
        let expected = FieldOrderOracle {
            id: view.id.clone(),
            name: view.name.clone(),
            description: view.description.clone(),
            owned_by: view.owned_by.clone(),
            total_quantity: view.total_quantity.clone(),
            numeric_scale: view.numeric_scale,
            metadata: view.metadata.clone(),
        };
        assert_eq!(bare(&view), bare(&expected));
    }
    #[test]
    fn declared_projection_is_smaller_than_a_full_entity_fixture() {
        let owner = account_id(6);
        let id = asset_definition_id();
        let full = AssetDefinition::numeric(
            id.clone(),
            "Rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&owner);
        let projection = AssetDefinitionView {
            id,
            name: full.name.clone(),
            description: full.description.clone(),
            owned_by: full.owned_by.clone(),
            total_quantity: full.total_quantity.clone().into(),
            numeric_scale: full.spec.scale().map(i64::from),
            metadata: Json::new(full.metadata.clone()),
        };
        let full_bytes = norito::to_bytes(&full).expect("encode full asset definition");
        let projection_bytes = norito::to_bytes(&projection).expect("encode projection");
        assert!(
            projection_bytes.len() < full_bytes.len(),
            "declared projection must be smaller than full entity: projection={} full={}",
            projection_bytes.len(),
            full_bytes.len()
        );
    }
    #[test]
    fn every_projection_roundtrips_through_a_bounded_page() {
        let owner = account_id(8);
        let definition = asset_definition_id();
        let quantity = QuantityV1::from(Quantity::from(10_u32));
        let account_page = QueryPageV1::try_new(vec![account_view(8)], None).expect("page");
        let asset_page = QueryPageV1::try_new(
            vec![AssetView {
                id: AssetId::new(definition.clone(), owner.clone()),
                amount: quantity.clone(),
            }],
            None,
        )
        .expect("page");
        let definition_page = QueryPageV1::try_new(
            vec![AssetDefinitionView {
                id: definition,
                name: "Rose".to_owned(),
                description: None,
                owned_by: owner.clone(),
                total_quantity: quantity,
                numeric_scale: None,
                metadata: Json::default(),
            }],
            None,
        )
        .expect("page");
        let domain_page = QueryPageV1::try_new(
            vec![DomainView {
                id: domain_id(),
                owned_by: owner.clone(),
                metadata: Json::default(),
            }],
            None,
        )
        .expect("page");
        let nft_page = QueryPageV1::try_new(
            vec![NftView {
                id: NftId::new(domain_id(), "rose".parse().expect("name")),
                owned_by: owner,
                content: Json::default(),
            }],
            None,
        )
        .expect("page");
        macro_rules! assert_roundtrip {
            ($page:expr, $ty:ty) => {{
                let encoded = norito::to_bytes(&$page).expect("encode projection page");
                let decoded: QueryPageV1<$ty> =
                    norito::decode_from_bytes(&encoded).expect("decode projection page");
                assert_eq!(decoded, $page);
            }};
        }
        assert_roundtrip!(account_page, AccountView);
        assert_roundtrip!(asset_page, AssetView);
        assert_roundtrip!(definition_page, AssetDefinitionView);
        assert_roundtrip!(domain_page, DomainView);
        assert_roundtrip!(nft_page, NftView);
    }
}

#[cfg(test)]
mod payload_contract_tests {
    use super::QueryPageV1;
    use norito::codec::{Decode, Encode};

    #[derive(Debug, PartialEq, norito::SerializePayload, norito::DeserializePayload)]
    #[norito(decode_from_slice)]
    struct LocalValue(u32);

    #[test]
    fn bounded_query_page_reconstructs_schema_free_fields() {
        let page = QueryPageV1::try_new(vec![LocalValue(7), LocalValue(11)], Some(2))
            .expect("valid payload page");
        let bytes = page.encode();
        let decoded = QueryPageV1::<LocalValue>::decode(&mut bytes.as_slice())
            .expect("bare decoding does not need a field frame contract");
        assert_eq!(decoded, page);
        let mut trailing = bytes;
        trailing.push(0xFF);
        assert!(QueryPageV1::<LocalValue>::decode(&mut trailing.as_slice()).is_err());
    }
}

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<super::AccountView>(
            "ivm_abi::core_query::AccountView",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::AssetView>(
            "ivm_abi::core_query::AssetView",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::AssetDefinitionView>(
            "ivm_abi::core_query::AssetDefinitionView",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::DomainView>(
            "ivm_abi::core_query::DomainView",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::NftView>(
            "ivm_abi::core_query::NftView",
        );
    }
    #[test]
    fn observed_manual_frames() {
        use super::*;
        crate::captured_identity_tests::assert_manual::<CoreQueryEntityTagV1>(
            "CoreQueryEntityTagV1",
            &(CoreQueryEntityTagV1::Account),
        );
        crate::captured_identity_tests::assert_manual::<QuantityV1>(
            "QuantityV1",
            &(QuantityV1::try_new(Numeric::new(42, 0)).unwrap()),
        );
        crate::captured_identity_tests::assert_manual::<NonNegativeOffsetV1>(
            "NonNegativeOffsetV1",
            &(NonNegativeOffsetV1(3)),
        );
        crate::captured_identity_tests::assert_manual::<QueryPageV1<u32>>(
            "QueryPageV1<u32>",
            &(QueryPageV1::try_new(vec![7_u32, 9], Some(2)).unwrap()),
        );
        crate::captured_identity_tests::assert_manual::<QueryPageV1<u64>>(
            "QueryPageV1<u64>",
            &(QueryPageV1::try_new(vec![7_u64, 9], Some(2)).unwrap()),
        );
    }
}
