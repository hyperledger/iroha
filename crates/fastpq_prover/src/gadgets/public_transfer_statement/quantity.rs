//! Canonical full-domain public quantity values and their SMT commitment domain.
//!
//! The nominal V1 frame binds the exact common scale and all 19 limbs. It is a
//! public transition-value encoding, not an admitted proof profile. Its schema
//! and value-hash domain differ from the existing eight-byte narrow values.

use iroha_crypto::Hash;
use iroha_data_model::fastpq::{FASTPQ_QUANTITY_UNIT_LIMBS, FastpqQuantityUnits};
use iroha_primitives::numeric::Quantity;
use norito::{NoritoDeserialize, NoritoSerialize};

use super::{LEAF_DOMAIN, TransferValue, invariant};
use crate::Result;

/// Maximum complete canonical Norito frame for one V1 quantity value.
/// This cap is checked before decoding; inherited Norito budgets also apply.
pub const QUANTITY_VALUE_MAX_BYTES_V1: usize = 512;

const VALUE_DOMAIN: &[u8] = b"fastpq:quantity:v1:smt:value|";

#[derive(NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::gadgets::public_transfer_statement::quantity::QuantityValueV1",
    frame = "fastpq_prover::public_transfer::QuantityValueV1"
)]
pub(super) struct QuantityValueV1 {
    scale: u32,
    limbs: [u32; FASTPQ_QUANTITY_UNIT_LIMBS],
}

/// Borrow-free fixed-size canonical value used by both buffered and funded writers.
pub(super) fn quantity_value_frame(value: &FastpqQuantityUnits) -> QuantityValueV1 {
    QuantityValueV1 {
        scale: value.scale(),
        limbs: *value.limbs(),
    }
}

/// Encode the exact normalized quantity in its canonical nominal V1 frame.
/// The complete scale and fixed limbs are retained, including high zero limbs.
///
/// # Errors
/// Returns an error if canonical bounded Norito encoding fails. Underlying Norito
/// resource errors are retained so callers can recognize terminal budget refusals.
pub fn encode_quantity_units_v1(value: &FastpqQuantityUnits) -> Result<Vec<u8>> {
    let frame = quantity_value_frame(value);
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::to_bytes_bounded(&frame, QUANTITY_VALUE_MAX_BYTES_V1).map_err(|error| match error
    {
        norito::core::BoundedEncodeError::Serialization(error) => error.into(),
        error => invariant(&format!("quantity value encoding failed: {error}")),
    })
}

/// Decode an exact canonical V1 frame and validate its full ledger quantity.
/// Trailing bytes, other schemas/layouts and narrow raw values are rejected.
///
/// # Errors
/// Rejects oversized frames before decoding, malformed canonical encodings,
/// scales above 28, and limbs that cannot reconstruct a ledger quantity.
pub fn decode_quantity_units_v1(bytes: &[u8]) -> Result<FastpqQuantityUnits> {
    if bytes.len() > QUANTITY_VALUE_MAX_BYTES_V1 {
        return Err(invariant("quantity value exceeds its fixed wire limit"));
    }
    let frame: QuantityValueV1 = norito::decode_canonical_with_limits(
        bytes,
        norito::canonical_decode_limits(QUANTITY_VALUE_MAX_BYTES_V1),
    )?;
    FastpqQuantityUnits::from_limbs(frame.limbs, frame.scale)
        .ok_or_else(|| invariant("quantity value is outside the ledger domain"))
}

impl TransferValue for FastpqQuantityUnits {
    type Key = (u32, [u32; FASTPQ_QUANTITY_UNIT_LIMBS]);

    fn row_key(self) -> Self::Key {
        (self.scale(), *self.limbs())
    }

    fn normalize(quantity: &Quantity, scale: u32) -> Option<Self> {
        Self::from_quantity(quantity, scale)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        decode_quantity_units_v1(bytes)
    }

    fn add(self, rhs: Self) -> Option<Self> {
        self.checked_add(&rhs)
    }

    fn sub(self, rhs: Self) -> Option<Self> {
        self.checked_sub(&rhs)
    }

    fn leaf(key_hash: &[u8; 32], value: Self) -> Result<[u8; 32]> {
        let frame = encode_quantity_units_v1(&value)?;
        let value_hash = Hash::new_from_chunks(&[VALUE_DOMAIN, &frame]);
        Ok(Hash::new_from_chunks(&[LEAF_DOMAIN, key_hash, value_hash.as_ref()]).into())
    }
}

#[cfg(test)]
mod tests;
