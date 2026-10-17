//! Exact, bounded, network-bound atomic settlement model.
//!
//! An atomic intent may also open up to sixteen native conditional escrows from
//! exact debited buckets. Their complete terms are part of the canonical intent,
//! so every consenting owner approves the escrow coupling together with the
//! ordinary movements.
//!
//! TODO: Complete composed codec and consumer tests, then qualify the persistent
//! matched-control harness through admitted native execution.

use super::{SettlementId, settlement_decode_flags};
use crate::{
    NetworkId,
    asset::{AssetBalanceScope, AssetId},
    escrow::{ConditionalEscrowCondition, EscrowId},
    prelude::AccountId,
};
use iroha_crypto::Hash;
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::{
    DeserializePayload, SerializePayload,
    codec::{Decode, Encode},
    core::{self as ncore, DecodeFromSlice},
    derive::{JsonDeserialize, JsonSerialize},
    json,
};
use std::num::NonZeroU64;

/// Minimum number of legs (movements plus escrow legs) in an atomic settlement;
/// one ordinary payment or one escrow leg uses the same settlement owner.
pub const ATOMIC_SETTLEMENT_MIN_LEGS: usize = 1;
/// Maximum number of movements in an atomic settlement's V1 model.
pub const ATOMIC_SETTLEMENT_MAX_MOVEMENTS: usize = 255;
/// Maximum number of conditional escrow legs in one atomic settlement.
pub const ATOMIC_SETTLEMENT_MAX_ESCROWS: usize = 16;

/// One proposed movement; the containing bounded list enforces its invariants.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::AtomicSettlementMovement")]
pub struct AtomicSettlementMovement {
    /// Exact balance bucket debited, including its explicit scope.
    pub source: AssetId,
    /// Owner of the credited bucket in the same asset definition and scope.
    pub recipient: AccountId,
    /// Positive amount transferred without conversion or rounding.
    pub quantity: Quantity,
}

impl AtomicSettlementMovement {
    /// Derive the exact destination without any routing or scope inference.
    #[must_use]
    pub fn destination(&self) -> AssetId {
        AssetId::with_scope(
            self.source.definition().clone(),
            self.recipient.clone(),
            *self.source.scope(),
        )
    }
}

/// One native conditional escrow opened by the same all-or-nothing intent.
///
/// The exact `source` bucket is debited into deterministic protocol custody.
/// Its owner becomes the escrow opener and the refund recipient at expiry, so a
/// foreign source requires the same whole-intent owner consent as a movement.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::AtomicSettlementEscrow")]
pub struct AtomicSettlementEscrow {
    /// Exact global-scope bucket debited; its owner opens and is refunded by the escrow.
    pub source: AssetId,
    /// Caller-selected unused escrow identifier.
    pub escrow_id: EscrowId,
    /// Account that receives the full amount after every condition passes.
    pub beneficiary: AccountId,
    /// Positive amount moved into protocol custody without conversion or rounding.
    pub amount: Quantity,
    /// Immutable ordered all-of predicates and optional ledger-time window.
    pub conditions: Vec<ConditionalEscrowCondition>,
    /// Absolute Unix timestamp (milliseconds) at or after which anyone may trigger refund.
    pub expires_at_ms: u64,
    /// Evidence hashes attached when opening the escrow.
    pub evidence_hashes: Vec<Hash>,
}

/// One actual committed balance movement, with both fully resolved buckets.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::ResolvedSettlementMovement")]
pub struct ResolvedSettlementMovement {
    /// Exact bucket debited by the prepared transfer.
    pub source: AssetId,
    /// Exact bucket credited by the prepared transfer.
    pub destination: AssetId,
    /// Positive committed quantity.
    pub quantity: Quantity,
    /// Original per-leg metadata for bilateral settlements; empty for atomic movements.
    pub metadata: Metadata,
}

fn validate_atomic_movements(values: &[AtomicSettlementMovement]) -> Result<(), &'static str> {
    if values.len() > ATOMIC_SETTLEMENT_MAX_MOVEMENTS {
        return Err("atomic settlement allows at most 255 movements");
    }
    for value in values {
        if value.quantity.is_zero() || value.source.account() == &value.recipient {
            return Err("atomic settlement requires positive, non-self movements");
        }
    }
    if values
        .windows(2)
        .any(|pair| (&pair[0].source, &pair[0].recipient) >= (&pair[1].source, &pair[1].recipient))
    {
        return Err("atomic settlement movement keys must be strictly increasing");
    }
    Ok(())
}

fn validate_resolved_movements(values: &[ResolvedSettlementMovement]) -> Result<(), &'static str> {
    if values.len() > ATOMIC_SETTLEMENT_MAX_MOVEMENTS {
        return Err("atomic receipt allows at most 255 movements");
    }
    for value in values {
        if value.quantity.is_zero()
            || value.source.account() == value.destination.account()
            || value.source.definition() != value.destination.definition()
            || value.source.scope() != value.destination.scope()
            || !value.metadata.is_empty()
        {
            return Err(
                "atomic receipt requires positive same-definition, same-scope movements without leg metadata",
            );
        }
    }
    if values.windows(2).any(|pair| {
        (&pair[0].source, pair[0].destination.account())
            >= (&pair[1].source, pair[1].destination.account())
    }) {
        return Err("atomic receipt movement keys must be strictly increasing");
    }
    Ok(())
}

fn validate_atomic_escrows(values: &[AtomicSettlementEscrow]) -> Result<(), &'static str> {
    if values.len() > ATOMIC_SETTLEMENT_MAX_ESCROWS {
        return Err("atomic settlement allows at most 16 escrows");
    }
    for value in values {
        if value.amount.is_zero() || value.source.scope() != &AssetBalanceScope::Global {
            return Err("atomic settlement escrows require a positive amount from a global bucket");
        }
    }
    if values
        .windows(2)
        .any(|pair| pair[0].escrow_id >= pair[1].escrow_id)
    {
        return Err("atomic settlement escrow ids must be strictly increasing");
    }
    Ok(())
}

// Every bounded list shares the same decoding owner. The length is inspected
// before Vec allocation, and canonical field decoding rejects omitted AssetId
// scope fields or alternate field layouts instead of inventing a scope.
macro_rules! bounded_list {
    (
        $name:ident,
        $item:ty,
        $validate:ident,
        $min:expr,
        $max:expr,
        $decode_count_error:literal,
        $json_count_error:literal,
        $nominal:literal,
        $doc:literal
    ) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoSchema, norito::NoritoSchema,
        )]
        #[norito(reuse_archived)]
        #[norito_schema(name = $nominal)]
        pub struct $name(Vec<$item>);

        impl $name {
            /// Borrow every item in canonical order.
            #[must_use]
            pub fn as_slice(&self) -> &[$item] {
                &self.0
            }

            /// Recheck the canonical bounds and item invariants at execution entry.
            ///
            /// # Errors
            /// Returns an error for an invalid count, value, duplicate, or ordering.
            pub fn validate(&self) -> Result<(), &'static str> {
                $validate(&self.0)
            }
        }
        impl TryFrom<Vec<$item>> for $name {
            type Error = &'static str;
            fn try_from(values: Vec<$item>) -> Result<Self, Self::Error> {
                $validate(&values)?;
                Ok(Self(values))
            }
        }
        impl SerializePayload for $name {
            fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), ncore::Error> {
                self.validate()
                    .map_err(|message| ncore::Error::Message(message.into()))?;
                let len = self
                    .0
                    .encoded_len_exact()
                    .ok_or(ncore::Error::LengthMismatch)?;
                ncore::write_len(
                    writer,
                    u64::try_from(len).map_err(|_| ncore::Error::LengthMismatch)?,
                )?;
                self.0.serialize(writer)
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                let len = self.0.encoded_len_exact()?;
                ncore::len_prefix_len(len).checked_add(len)
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                self.encoded_len_exact()
            }
        }
        impl<'de> DeserializePayload<'de> for $name {
            fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
                Self::try_deserialize(archived).expect("validated canonical bounded archive")
            }
            fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
                let bytes =
                    ncore::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
                let (value, used) = Self::decode_from_slice(bytes)?;
                if used != bytes.len() {
                    return Err(ncore::Error::LengthMismatch);
                }
                Ok(value)
            }
        }
        impl<'a> DecodeFromSlice<'a> for $name {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                let (len, prefix) = ncore::read_len_dyn_slice(bytes)?;
                let end = prefix
                    .checked_add(len)
                    .ok_or(ncore::Error::LengthMismatch)?;
                if end != bytes.len() {
                    return Err(ncore::Error::LengthMismatch);
                }
                let field = bytes.get(prefix..end).ok_or(ncore::Error::LengthMismatch)?;
                let (count, _) = ncore::inspect_seq_len_slice(field)?;
                if !($min..=$max).contains(&count) {
                    return Err(ncore::Error::Message($decode_count_error.into()));
                }
                let (values, used) = ncore::decode_field_canonical::<Vec<$item>>(field)?;
                if used != field.len() {
                    return Err(ncore::Error::LengthMismatch);
                }
                let list = Self::try_from(values)
                    .map_err(|message| ncore::Error::Message(message.into()))?;
                ncore::note_payload_access(bytes, end);
                Ok((list, end))
            }
        }
        impl json::JsonSerialize for $name {
            fn json_serialize(&self, out: &mut String) {
                json::JsonSerialize::json_serialize(&self.0, out);
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn json::JsonWriteSink,
            ) -> Result<(), json::BoundedJsonError> {
                json::JsonSerialize::json_serialize_to(&self.0, out)
            }
        }
        impl json::JsonDeserialize for $name {
            fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
                parser.expect(b'[')?;
                let mut values = Vec::new();
                parser.skip_ws();
                if parser.peek() != Some(b']') {
                    loop {
                        if values.len() == $max {
                            return Err(json::Error::Message($json_count_error.into()));
                        }
                        values.push(<$item as json::JsonDeserialize>::json_deserialize(parser)?);
                        parser.skip_ws();
                        if parser.peek() == Some(b']') {
                            break;
                        }
                        parser.expect(b',')?;
                    }
                }
                parser.expect(b']')?;
                Self::try_from(values).map_err(|message| json::Error::Message(message.into()))
            }
        }
    };
}

bounded_list!(
    AtomicSettlementMovements,
    AtomicSettlementMovement,
    validate_atomic_movements,
    0,
    ATOMIC_SETTLEMENT_MAX_MOVEMENTS,
    "atomic movement count outside 0..=255",
    "atomic movement count exceeds 255",
    "iroha_data_model::isi::settlement::AtomicSettlementMovements",
    "Zero to 255 positive movements in strict (source, recipient) order; construction never sorts or coalesces. The containing intent requires at least one leg across movements and escrows."
);
bounded_list!(
    ResolvedSettlementMovements,
    ResolvedSettlementMovement,
    validate_resolved_movements,
    0,
    ATOMIC_SETTLEMENT_MAX_MOVEMENTS,
    "atomic movement count outside 0..=255",
    "atomic movement count exceeds 255",
    "iroha_data_model::isi::settlement::ResolvedSettlementMovements",
    "The canonical bounded resolved movements retained by a successful atomic settlement receipt."
);
bounded_list!(
    AtomicSettlementEscrows,
    AtomicSettlementEscrow,
    validate_atomic_escrows,
    0,
    ATOMIC_SETTLEMENT_MAX_ESCROWS,
    "atomic escrow count outside 0..=16",
    "atomic escrow count exceeds 16",
    "iroha_data_model::isi::settlement::AtomicSettlementEscrows",
    "Zero to sixteen conditional escrow legs in strictly increasing escrow-id order; construction never sorts."
);

impl AtomicSettlementEscrows {
    /// Construct the canonical empty escrow list.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Return every escrow identifier in the signed canonical order.
    #[must_use]
    pub fn escrow_ids(&self) -> Vec<EscrowId> {
        self.0.iter().map(|escrow| escrow.escrow_id).collect()
    }
}

impl AtomicSettlementMovements {
    /// Resolve every destination exactly, preserving the signed order and quantities.
    ///
    /// # Errors
    /// Returns an error if the signed movement list is invalid.
    pub fn resolve(&self) -> Result<ResolvedSettlementMovements, &'static str> {
        self.validate()?;
        ResolvedSettlementMovements::try_from(
            self.0
                .iter()
                .map(|movement| ResolvedSettlementMovement {
                    source: movement.source.clone(),
                    destination: movement.destination(),
                    quantity: movement.quantity.clone(),
                    metadata: Metadata::default(),
                })
                .collect::<Vec<_>>(),
        )
    }
}

isi! {
    #[derive(JsonSerialize, JsonDeserialize)]
    #[norito(deny_unknown_fields, validate = "Self::checked")]
    /// Execute one network-bound all-or-nothing batch under exact debit-owner consent.
    #[norito_schema(name = "iroha_data_model::isi::settlement::SettleAtomic")]
    pub struct SettleAtomic {
        /// Genesis-derived network identity approved by every debited owner.
        pub network_id: NetworkId,
        /// One-shot business identifier used as the successful receipt's map key.
        pub settlement_id: SettlementId,
        /// Complete canonical movement vector approved by every debited owner.
        pub movements: AtomicSettlementMovements,
        /// Conditional escrows opened from exact buckets by the same intent.
        pub escrows: AtomicSettlementEscrows,
        /// Last block height at which execution is permitted, inclusive.
        pub expires_at_height: NonZeroU64,
        /// Complete signed settlement metadata.
        pub metadata: Metadata,
    }
}
impl SettleAtomic {
    fn checked(self) -> Result<Self, norito::Error> {
        self.validate()
            .map_err(|message| norito::Error::Message(message.into()))?;
        Ok(self)
    }

    /// Concrete operation label; wire dispatch uses the registered settlement box.
    pub const WIRE_ID: &'static str = "iroha.settlement.atomic";
    /// Domain for the complete canonical V1 instruction frame.
    pub const INTENT_HASH_DOMAIN: &'static [u8] = b"iroha:settlement:atomic-intent:v1\0";

    /// Construct the complete intent from already validated movement and escrow lists.
    #[must_use]
    pub fn new(
        network_id: NetworkId,
        settlement_id: SettlementId,
        movements: AtomicSettlementMovements,
        escrows: AtomicSettlementEscrows,
        expires_at_height: NonZeroU64,
        metadata: Metadata,
    ) -> Self {
        Self {
            network_id,
            settlement_id,
            movements,
            escrows,
            expires_at_height,
            metadata,
        }
    }

    /// Revalidate direct Rust values before authorizing any balance mutation.
    ///
    /// Core additionally checks exact network identity, expiry against the current
    /// block, unused business identifier, every debit owner's consent and all
    /// balance/permission/routing policies in the same `StateTransaction`.
    ///
    /// # Errors
    /// Returns an error for a noncanonical or invalid movement or escrow vector,
    /// when the intent has no movement or escrow leg, or when the settlement ID
    /// owner debits none of its movements or escrow legs.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.movements.validate()?;
        self.escrows.validate()?;
        if self.movements.as_slice().len() + self.escrows.as_slice().len()
            < ATOMIC_SETTLEMENT_MIN_LEGS
        {
            return Err("atomic settlement requires at least one movement or escrow leg");
        }
        let owner = self.settlement_id.owner();
        if !self
            .movements
            .as_slice()
            .iter()
            .any(|movement| movement.source.account() == owner)
            && !self
                .escrows
                .as_slice()
                .iter()
                .any(|escrow| escrow.source.account() == owner)
        {
            return Err("settlement id owner must participate as an authorized debit owner");
        }
        Ok(())
    }

    /// Commit the exact network, business identifier, movements, escrows, expiry and metadata.
    ///
    /// # Errors
    /// Returns an error for an invalid value or failed canonical Norito encoding.
    pub fn intent_hash(&self) -> Result<iroha_crypto::Hash, norito::Error> {
        self.validate()
            .map_err(|message| norito::Error::Message(message.into()))?;
        let frame = norito::encode_canonical(self)?;
        Ok(iroha_crypto::Hash::new_from_chunks(&[
            Self::INTENT_HASH_DOMAIN,
            &frame,
        ]))
    }
}
impl core::fmt::Display for SettleAtomic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SETTLE ATOMIC `{}` ({} movements, {} escrows)",
            self.settlement_id,
            self.movements.as_slice().len(),
            self.escrows.as_slice().len()
        )
    }
}
impl crate::seal::Instruction for SettleAtomic {}
impl<'a> DecodeFromSlice<'a> for SettleAtomic {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let flags = settlement_decode_flags();
        let mut offset = 0;
        macro_rules! field {
            ($ty:ty) => {
                super::super::decode_aos_canonical_field::<$ty>(
                    super::super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?
            };
        }
        let value = Self {
            network_id: field!(NetworkId),
            settlement_id: field!(SettlementId),
            movements: field!(AtomicSettlementMovements),
            escrows: field!(AtomicSettlementEscrows),
            expires_at_height: field!(NonZeroU64),
            metadata: field!(Metadata),
        };
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        value
            .validate()
            .map_err(|message| ncore::Error::Message(message.into()))?;
        ncore::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}

#[cfg(test)]
#[path = "atomic_tests.rs"]
mod tests;
