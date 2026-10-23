//! Generic asset escrow records and identifiers.

pub mod control;
/// Asset-owner-scoped escrow completeness originals.
pub mod scoped;

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use crate::{account::AccountId, asset::AssetDefinitionId};
use core::num::{NonZeroU32, NonZeroU64};
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use norito::json::{self, FastJsonWrite, JsonDeserialize};
/// Domain-separation prefix for escrow ids derived from Kotodama escrow names.
pub const KOTODAMA_ESCROW_ID_PREFIX: &str = "kotodama-native-escrow:";
/// Domain separator used to bind an external 32-byte conditional-escrow evidence digest.
pub const CONDITIONAL_ESCROW_EVIDENCE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:conditional-escrow-evidence:v1\0";
/// Bind an external 32-byte evidence digest to a domain-separated Iroha hash.
#[must_use]
pub fn hash_conditional_escrow_evidence_digest(raw_digest: &[u8; Hash::LENGTH]) -> Hash {
    Hash::new_from_chunks(&[CONDITIONAL_ESCROW_EVIDENCE_DIGEST_DOMAIN_V1, raw_digest])
}
/// Stable identifier for a native asset escrow.
///
/// In the first-release V1 contract, Norito binary and JSON codecs delegate directly to [`Hash`]:
/// the binary payload is exactly 32 hash bytes and JSON is one scalar hash literal. The wrapper
/// remains a distinct nominal Rust and [`IntoSchema`] type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::escrow::EscrowId")]
pub struct EscrowId(pub Hash);
impl EscrowId {
    /// Construct an escrow identifier from a hash.
    #[must_use]
    pub const fn new(hash: Hash) -> Self {
        Self(hash)
    }
    /// Return the inner hash.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }
    /// Derive the native escrow id used by Kotodama escrow builtins.
    #[must_use]
    pub fn from_kotodama_name(name: &Name) -> Self {
        Self(Hash::new(format!("{KOTODAMA_ESCROW_ID_PREFIX}{name}")))
    }
}

impl norito::core::SerializePayload for EscrowId {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(&self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for EscrowId {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("archived escrow id must be a canonical hash")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        <Hash as norito::core::DeserializePayload>::try_deserialize(archived.cast()).map(Self)
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for EscrowId {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        <Hash as norito::core::DecodeFromSlice>::decode_from_slice(bytes)
            .map(|(hash, used)| (Self(hash), used))
    }
}

impl FastJsonWrite for EscrowId {
    fn write_json(&self, out: &mut String) {
        self.0.write_json(out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.write_json_to(out)
    }
}

impl JsonDeserialize for EscrowId {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Hash::json_deserialize(parser).map(Self)
    }
}
/// Lifecycle state for a native asset escrow.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "value")]
#[repr(u8)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::escrow::AssetEscrowStatus")]
pub enum AssetEscrowStatus {
    /// Seller has locked funds, but no buyer has accepted the offer.
    Open,
    /// Buyer accepted the offer.
    Accepted,
    /// Buyer marked the off-chain payment as sent.
    PaymentSent,
    /// Buyer or seller opened a dispute for court moderation.
    Disputed,
    /// Seller released the escrow to the buyer.
    Released,
    /// Seller cancelled and refunded the escrow before payment was marked.
    Cancelled,
    /// Court resolved the disputed escrow.
    Resolved,
    /// Generic asset lock is active and may support partial drawdown.
    Locked,
    /// Generic asset lock has been fully drawn down.
    DrawnDown,
    /// Generic asset lock expired and refunded remaining custody.
    Expired,
}
/// Native asset escrow behavior family.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[repr(u8)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::escrow::AssetEscrowKind")]
pub enum AssetEscrowKind {
    /// Seller/buyer escrow with acceptance, payment-sent, dispute, and release lifecycle.
    #[default]
    Marketplace,
    /// Generic conditional custody lock with optional release authority and expiry.
    Lock,
    /// Ordered, attestor-bound conditional custody that releases when every predicate passes.
    Conditional,
}
/// Typed value supplied by an attestor for a conditional escrow predicate.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowValue")]
pub enum ConditionalEscrowValue {
    /// Boolean value, such as whether an event occurred.
    Bool(bool),
    /// Exact UTF-8 text.
    Text(String),
    /// Non-negative numeric value.
    Quantity(Quantity),
}
/// Predicate evaluated by the ledger against a typed conditional-escrow attestation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowPredicate")]
pub enum ConditionalEscrowPredicate {
    /// Require exact typed equality.
    Equals(ConditionalEscrowValue),
    /// Require a numeric value no greater than this bound.
    QuantityAtMost(Quantity),
}
/// Attestor-bound predicate in an ordered conditional-escrow release policy.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowOracleCondition")]
pub struct ConditionalEscrowOracleCondition {
    /// Caller-selected canonical condition identifier.
    pub id: Name,
    /// Account exclusively authorized to attest this condition.
    pub attestor: AccountId,
    /// Predicate evaluated against the attested value.
    pub predicate: ConditionalEscrowPredicate,
    /// One-based attestation sequence. Every lower sequence must pass first.
    pub sequence: NonZeroU32,
}
/// Ledger-time window that bounds all attestations for one conditional escrow.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowWithinCondition")]
pub struct ConditionalEscrowWithinCondition {
    /// Caller-selected canonical condition identifier.
    pub id: Name,
    /// Maximum duration from committed escrow creation time.
    pub duration_ms: NonZeroU64,
}
/// One immutable first-class condition in a conditional escrow.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowCondition")]
pub enum ConditionalEscrowCondition {
    /// Attestor-signed predicate.
    Oracle(ConditionalEscrowOracleCondition),
    /// Ledger-time window applying to all oracle predicates.
    Within(ConditionalEscrowWithinCondition),
}
impl ConditionalEscrowCondition {
    /// Return the immutable condition identifier.
    #[must_use]
    pub const fn id(&self) -> &Name {
        match self {
            Self::Oracle(condition) => &condition.id,
            Self::Within(condition) => &condition.id,
        }
    }
}
/// Consensus-bound evidence for one satisfied oracle condition.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowAttestation")]
pub struct ConditionalEscrowAttestation {
    /// Exact account that authorized the attestation transaction.
    pub attestor: AccountId,
    /// Typed value evaluated on-chain.
    pub value: ConditionalEscrowValue,
    /// Optional external evidence digest.
    pub evidence_hash: Option<Hash>,
    /// Committed ledger timestamp in milliseconds.
    pub committed_at_ms: u64,
}
/// Query-visible satisfaction state for one conditional-escrow condition.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::escrow::ConditionalEscrowConditionState")]
pub struct ConditionalEscrowConditionState {
    /// Immutable condition definition.
    pub condition: ConditionalEscrowCondition,
    /// Attestor evidence, present only after an oracle predicate passes.
    pub attestation: Option<ConditionalEscrowAttestation>,
    /// Ledger timestamp at which this condition became satisfied.
    pub satisfied_at_ms: Option<u64>,
}
/// Court resolution details for a disputed escrow.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::escrow::AssetEscrowResolution")]
pub struct AssetEscrowResolution {
    /// Account that resolved the dispute.
    pub resolver: AccountId,
    /// Amount released to the buyer.
    pub buyer_amount: Quantity,
    /// Amount refunded to the seller.
    pub seller_amount: Quantity,
    /// Evidence or judgement hashes attached to the resolution.
    pub evidence_hashes: Vec<Hash>,
    /// Unix timestamp (milliseconds) when the resolution was recorded.
    pub resolved_at_ms: u64,
}
/// Ledger-managed numeric asset escrow.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::escrow::AssetEscrowRecord")]
pub struct AssetEscrowRecord {
    /// Escrow identifier.
    pub id: EscrowId,
    /// Seller that funded the escrow.
    pub seller: AccountId,
    /// Buyer that accepted the offer, if any.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub buyer: Option<AccountId>,
    /// Escrowed asset definition.
    pub asset_definition: AssetDefinitionId,
    /// Total amount held by the escrow.
    pub amount: Quantity,
    /// Deterministic protocol custody account holding the locked balance.
    pub custody: AccountId,
    /// Current lifecycle status.
    pub status: AssetEscrowStatus,
    /// Escrow behavior family.
    pub kind: AssetEscrowKind,
    /// Remaining amount still held in custody.
    pub remaining_amount: Quantity,
    /// Optional account required to draw down a generic lock.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub release_authority: Option<AccountId>,
    /// Optional Unix timestamp (milliseconds) after which a generic lock may expire.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Evidence hashes attached by the parties.
    pub evidence_hashes: Vec<Hash>,
    /// Immutable conditional release policy and its consensus satisfaction state.
    ///
    /// This is non-empty exactly when `kind` is [`AssetEscrowKind::Conditional`].
    pub conditions: Vec<ConditionalEscrowConditionState>,
    /// Unix timestamp (milliseconds) when the escrow was opened.
    pub created_at_ms: u64,
    /// Unix timestamp (milliseconds) when a buyer accepted.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub accepted_at_ms: Option<u64>,
    /// Unix timestamp (milliseconds) when the buyer marked payment as sent.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub payment_sent_at_ms: Option<u64>,
    /// Unix timestamp (milliseconds) when a dispute was opened.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub disputed_at_ms: Option<u64>,
    /// Unix timestamp (milliseconds) when the escrow closed.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub closed_at_ms: Option<u64>,
    /// Optional court resolution details for resolved disputed escrows.
    #[norito(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<AssetEscrowResolution>,
}
/// Prelude exports for native escrow records.
pub mod prelude {
    pub use super::{
        AssetEscrowKind, AssetEscrowRecord, AssetEscrowResolution, AssetEscrowStatus,
        CONDITIONAL_ESCROW_EVIDENCE_DIGEST_DOMAIN_V1, ConditionalEscrowAttestation,
        ConditionalEscrowCondition, ConditionalEscrowConditionState,
        ConditionalEscrowOracleCondition, ConditionalEscrowPredicate, ConditionalEscrowValue,
        ConditionalEscrowWithinCondition, EscrowId, KOTODAMA_ESCROW_ID_PREFIX,
        hash_conditional_escrow_evidence_digest,
    };
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_primitives::numeric::Numeric;
    use norito::{
        codec::{Decode, Encode},
        core::DecodeFromSlice,
    };
    #[derive(Encode)]
    struct ForgedAssetEscrowRecord {
        id: EscrowId,
        seller: AccountId,
        buyer: Option<AccountId>,
        asset_definition: AssetDefinitionId,
        amount: Numeric,
        custody: AccountId,
        status: AssetEscrowStatus,
        kind: AssetEscrowKind,
        remaining_amount: Numeric,
        release_authority: Option<AccountId>,
        expires_at_ms: Option<u64>,
        evidence_hashes: Vec<Hash>,
        conditions: Vec<ConditionalEscrowConditionState>,
        created_at_ms: u64,
        accepted_at_ms: Option<u64>,
        payment_sent_at_ms: Option<u64>,
        disputed_at_ms: Option<u64>,
        closed_at_ms: Option<u64>,
        resolution: Option<AssetEscrowResolution>,
    }
    fn checked_seed_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked escrow fixture keypair")
    }
    #[test]
    fn asset_escrow_record_roundtrips_norito() {
        let seller_keypair = checked_seed_keypair(0x51);
        let buyer_keypair = checked_seed_keypair(0x52);
        let seller = AccountId::new(seller_keypair.public_key().clone());
        let buyer = AccountId::new(buyer_keypair.public_key().clone());
        let asset_definition: AssetDefinitionId =
            "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().expect("asset id");
        let id = EscrowId::new(Hash::new("escrow-roundtrip"));
        let record = AssetEscrowRecord {
            id,
            seller: seller.clone(),
            buyer: Some(buyer.clone()),
            asset_definition,
            amount: Quantity::from(42_u32),
            custody: seller,
            status: AssetEscrowStatus::PaymentSent,
            kind: AssetEscrowKind::Marketplace,
            remaining_amount: Quantity::from(42_u32),
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: vec![Hash::new("evidence")],
            conditions: Vec::new(),
            created_at_ms: 1,
            accepted_at_ms: Some(2),
            payment_sent_at_ms: Some(3),
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        };
        let bytes = norito::to_bytes(&record).expect("encode");
        let decoded: AssetEscrowRecord = norito::decode_from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, record);
        assert_eq!(decoded.buyer, Some(buyer));
    }
    #[test]
    fn negative_numeric_payload_cannot_decode_as_durable_asset_escrow_quantity() {
        let seller = AccountId::new(checked_seed_keypair(0x53).public_key().clone());
        let asset_definition: AssetDefinitionId =
            "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().expect("asset id");
        let forged = ForgedAssetEscrowRecord {
            id: EscrowId::new(Hash::new("negative-escrow")),
            seller: seller.clone(),
            buyer: None,
            asset_definition,
            amount: Numeric::new(-1_i32, 0),
            custody: seller,
            status: AssetEscrowStatus::Open,
            kind: AssetEscrowKind::Marketplace,
            remaining_amount: Numeric::zero(),
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: Vec::new(),
            conditions: Vec::new(),
            created_at_ms: 1,
            accepted_at_ms: None,
            payment_sent_at_ms: None,
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        };
        let encoded = forged.encode();
        assert!(
            AssetEscrowRecord::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as a durable escrow quantity"
        );
    }
    #[test]
    fn kotodama_escrow_id_derivation_is_stable() {
        let name: Name = "aitai_offer".parse().expect("valid name");
        assert_eq!(
            EscrowId::from_kotodama_name(&name),
            EscrowId::new(Hash::new("kotodama-native-escrow:aitai_offer"))
        );
    }

    #[test]
    fn escrow_id_json_is_a_canonical_hash_literal() {
        let id = EscrowId::new(Hash::new("escrow-json"));
        let expected =
            norito::json::to_json(id.as_hash()).expect("serialize canonical escrow hash");
        let encoded = norito::json::to_json(&id).expect("serialize escrow id");
        assert_eq!(encoded, expected);
        assert_eq!(
            norito::json::from_str::<EscrowId>(&encoded).expect("deserialize escrow id"),
            id
        );
        assert!(
            norito::json::from_str::<EscrowId>(&format!("[{encoded}]")).is_err(),
            "the retired tuple-shaped EscrowId JSON must be rejected"
        );
    }
    #[test]
    fn escrow_id_norito_is_transparent_hash_bytes() {
        let id = EscrowId::new(Hash::new("sorafs-appeal-cancel-asset-lock-v1"));
        let encoded = id.encode();
        assert_eq!(encoded, id.0.encode());
        assert_eq!(encoded.len(), Hash::LENGTH);
        assert_eq!(encoded.as_slice(), id.as_hash().as_ref());
        let (decoded, used) =
            EscrowId::decode_from_slice(&encoded).expect("decode transparent escrow id");
        assert_eq!(decoded, id);
        assert_eq!(used, encoded.len());
    }
    #[test]
    fn escrow_id_keeps_distinct_schema_identity() {
        assert_eq!(EscrowId::type_name(), "EscrowId");
        assert_eq!(Hash::type_name(), "Hash");
        assert_ne!(EscrowId::type_name(), Hash::type_name());
        let schema = EscrowId::schema();
        assert!(schema.contains_key::<EscrowId>());
        assert!(schema.contains_key::<Hash>());
        assert!(matches!(
            schema.get::<EscrowId>(),
            Some(iroha_schema::Metadata::Tuple(fields))
                if fields.types == [core::any::TypeId::of::<Hash>()]
        ));
    }

    #[test]
    fn escrow_id_json_is_one_canonical_hash_literal() {
        let id = EscrowId::new(Hash::new("sorafs-appeal-cancel-asset-lock-v1"));
        let encoded = norito::json::to_json(&id).expect("encode escrow id JSON");
        assert_eq!(
            encoded,
            r#""hash:73CCD4E0DD69AD434DB75056B600AA4F74C8FC5556B11BDC799DFDB7EA29851F#434B""#
        );
        assert_eq!(
            norito::json::from_json::<EscrowId>(&encoded).expect("decode escrow id JSON"),
            id
        );
        let raw_hex = hex::encode_upper(id.as_hash().as_ref());
        for (label, alias) in [
            ("tuple array", format!("[{encoded}]")),
            ("nested array", format!("[[{encoded}]]")),
            ("raw hex", format!(r#""{raw_hex}""#)),
            ("lowercase literal", encoded.to_ascii_lowercase()),
            ("lowercase checksum", encoded.replace("#434B", "#434b")),
            ("Hash object", format!(r#"{{"Hash":{encoded}}}"#)),
            ("hash object", format!(r#"{{"hash":{encoded}}}"#)),
            ("EscrowId object", format!(r#"{{"EscrowId":{encoded}}}"#)),
        ] {
            assert!(
                norito::json::from_json::<EscrowId>(&alias).is_err(),
                "the {label} compatibility representation must be rejected"
            );
        }
        let nested_instruction =
            format!(r#"{{"escrow_id":[{encoded}],"expected_remaining_amount":"20"}}"#);
        assert!(
            norito::json::from_json::<crate::isi::escrow::CancelAssetLock>(&nested_instruction)
                .is_err(),
            "native CancelAssetLock JSON must reject a nested EscrowId array"
        );
    }
}

#[cfg(test)]
mod captured_escrow_schema_tests;
