//! State-free canonical pointer encoding for Kotodama V1 exact numbers.
use crate::{VMError, pointer_abi::PointerType};
use iroha_primitives::{
    bigint::BigInt,
    numeric::{Numeric, Quantity},
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
const OUTER_HEADER_BYTES: usize = 7;
const OUTER_HASH_BYTES: usize = iroha_crypto::Hash::LENGTH;
/// Encode an exact V1 pointer envelope around a prevalidated numeric or private-input frame.
///
/// # Errors
/// Returns [`VMError::GasCostOverflow`] when header length or allocation size overflows.
pub fn encode_envelope(pointer_type: PointerType, frame: &[u8]) -> Result<Vec<u8>, VMError> {
    let length = u32::try_from(frame.len()).map_err(|_| VMError::GasCostOverflow)?;
    let capacity = OUTER_HEADER_BYTES
        .checked_add(frame.len())
        .and_then(|bytes| bytes.checked_add(OUTER_HASH_BYTES))
        .ok_or(VMError::GasCostOverflow)?;
    let mut envelope = Vec::with_capacity(capacity);
    envelope.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(&length.to_be_bytes());
    envelope.extend_from_slice(frame);
    envelope.extend_from_slice(iroha_crypto::Hash::new(frame).as_ref());
    Ok(envelope)
}
/// Encode a canonical V1 integer pointer envelope.
///
/// # Errors
/// Returns the exact numeric pointer fault for invalid frames or a checked length overflow.
pub fn encode_int(value: &BigInt) -> Result<Vec<u8>, VMError> {
    let frame = IntValueV1::prepare_frame(value)
        .map_err(VMError::from)?
        .encode_frame()
        .map_err(VMError::from)?;
    encode_envelope(PointerType::Int, &frame)
}
/// Encode a canonical V1 decimal pointer envelope.
///
/// # Errors
/// Returns the exact numeric pointer fault for invalid frames or a checked length overflow.
pub fn encode_decimal(value: &Numeric) -> Result<Vec<u8>, VMError> {
    let frame = DecimalValueV1::prepare_frame(value)
        .encode_frame()
        .map_err(VMError::from)?;
    encode_envelope(PointerType::Decimal, &frame)
}
/// Encode a canonical V1 quantity pointer envelope.
///
/// # Errors
/// Returns the exact numeric pointer fault for invalid frames or a checked length overflow.
pub fn encode_quantity(value: &Quantity) -> Result<Vec<u8>, VMError> {
    let frame = QuantityValueV1::prepare_frame(value)
        .encode_frame()
        .map_err(VMError::from)?;
    encode_envelope(PointerType::Quantity, &frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integer_encoding_rejects_both_signed_domain_overflows() {
        use crate::numeric::PointerAbiFaultV1;
        use iroha_primitives::numeric::MAX_MANTISSA_BYTES;

        let mut above = [0; MAX_MANTISSA_BYTES + 1];
        above[MAX_MANTISSA_BYTES - 1] = 0x80;
        let mut below = [0xff; MAX_MANTISSA_BYTES + 1];
        below[MAX_MANTISSA_BYTES - 1] = 0x7f;
        for bytes in [&above, &below] {
            let value = BigInt::from_twos_bytes(bytes).expect("arbitrary-width integer");
            assert!(
                matches!(encode_int(&value), Err(VMError::PointerAbiFault(__actual_error_field)) if __actual_error_field == (PointerAbiFaultV1::NonCanonical))
            );
        }
    }
    #[test]
    fn all_shared_numeric_envelopes_match_the_cross_sdk_golden_bytes() {
        let fixture =
            norito::json::parse_value(include_str!("../../../fixtures/numeric_v1_golden.json"))
                .expect("numeric golden document");
        assert_eq!(
            fixture
                .get("generator")
                .and_then(norito::json::Value::as_str),
            Some("ivm_abi::numeric_tlv + iroha_primitives::numeric_abi")
        );
        for vector in fixture
            .get("valid")
            .and_then(norito::json::Value::as_array)
            .expect("valid vectors")
        {
            let text = vector
                .get("canonical")
                .and_then(norito::json::Value::as_str)
                .expect("canonical number");
            let envelope = match vector
                .get("kind")
                .and_then(norito::json::Value::as_str)
                .expect("numeric kind")
            {
                "int" => encode_int(&text.parse().expect("integer")),
                "decimal" => encode_decimal(&text.parse().expect("decimal")),
                "quantity" => encode_quantity(&text.parse().expect("quantity")),
                other => panic!("unexpected fixture kind {other}"),
            }
            .expect("encode canonical numeric envelope");
            let expected = hex::decode(
                vector
                    .get("envelope_hex")
                    .and_then(norito::json::Value::as_str)
                    .expect("exact envelope"),
            )
            .expect("envelope hex");
            assert_eq!(envelope, expected);
            let tlv = crate::pointer_abi::validate_tlv_bytes(&envelope)
                .expect("authenticate exact envelope");
            assert_eq!(
                hex::encode(tlv.payload),
                vector
                    .get("frame_hex")
                    .and_then(norito::json::Value::as_str)
                    .expect("exact frame")
            );
            let mut substituted = envelope.clone();
            let last = substituted.len() - 1;
            substituted[last] ^= 1;
            assert!(crate::pointer_abi::validate_tlv_bytes(&substituted).is_err());
        }
    }
}
