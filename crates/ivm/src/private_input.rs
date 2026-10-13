//! Runtime validation and commitment helpers for typed private inputs.
//!
//! Private-input records are bounded before Norito decoding. Successful
//! decoding yields an opaque private numeric TLV; only the explicitly approved
//! full-width commitment path below may declassify it.
use crate::{PointerType, VMError, pointer_abi};
use blstrs::Scalar;
use crypto_bigint::{
    Encoding, U256,
    subtle::{ConditionallySelectable, ConstantTimeLess},
};
use iroha_crypto::Hash;
use iroha_primitives::{
    bigint::BigInt,
    numeric::{Numeric, Quantity},
    numeric_abi::{
        DecimalValueV1, IntValueV1, MAX_DECIMAL_FRAME_BYTES_V1, MAX_INT_FRAME_BYTES_V1,
        MAX_QUANTITY_FRAME_BYTES_V1, QuantityValueV1,
    },
};
use ivm_abi::private_input::{
    MAX_PRIVATE_INPUT_RECORD_BYTES_V1, PRIVATE_INPUT_ABI_VERSION_V1,
    PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1, PRIVATE_NUMERIC_VALCOM_DOMAIN_V1, PrivateInputKindV1,
    PrivateInputRecordV1,
};
const BLS_SCALAR_MODULUS: U256 =
    U256::from_be_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
/// A fully validated private input ready to be published into opaque VM memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPrivateInput {
    /// Exact nominal numeric kind.
    pub kind: PrivateInputKindV1,
    /// Complete canonical pointer-ABI envelope.
    pub envelope: Vec<u8>,
}
fn canonical_record_bytes(record: &PrivateInputRecordV1) -> Result<Vec<u8>, VMError> {
    norito::encode_canonical(record).map_err(|_| VMError::NoritoInvalid)
}
/// Encode a canonical integer private-input record.
pub fn int_record(value: BigInt) -> Result<PrivateInputRecordV1, VMError> {
    let payload = IntValueV1::try_new(value)
        .map_err(|_| VMError::NoritoInvalid)?
        .encode_frame()
        .map_err(|_| VMError::NoritoInvalid)?;
    Ok(PrivateInputRecordV1::new(PrivateInputKindV1::Int, payload))
}
/// Encode a canonical decimal private-input record.
pub fn decimal_record(value: Numeric) -> Result<PrivateInputRecordV1, VMError> {
    let payload = DecimalValueV1::try_from_numeric(value)
        .map_err(|_| VMError::NoritoInvalid)?
        .encode_frame()
        .map_err(|_| VMError::NoritoInvalid)?;
    Ok(PrivateInputRecordV1::new(
        PrivateInputKindV1::Decimal,
        payload,
    ))
}
/// Encode a canonical quantity private-input record.
pub fn quantity_record(value: Quantity) -> Result<PrivateInputRecordV1, VMError> {
    let payload = QuantityValueV1::new(value)
        .encode_frame()
        .map_err(|_| VMError::NoritoInvalid)?;
    Ok(PrivateInputRecordV1::new(
        PrivateInputKindV1::Quantity,
        payload,
    ))
}
/// Encode a typed record into the canonical outer Norito frame accepted by the host.
pub fn encode_record(record: &PrivateInputRecordV1) -> Result<Vec<u8>, VMError> {
    // This check must precede Norito serialization: an untrusted typed record
    // may already contain an attacker-sized `Vec`, and serializing it merely
    // to discover that the outer record is too large would allocate and copy
    // that payload a second time.
    let max_payload_bytes = match record.kind {
        PrivateInputKindV1::Int => MAX_INT_FRAME_BYTES_V1,
        PrivateInputKindV1::Decimal => MAX_DECIMAL_FRAME_BYTES_V1,
        PrivateInputKindV1::Quantity => MAX_QUANTITY_FRAME_BYTES_V1,
    };
    if record.payload.len() > max_payload_bytes {
        return Err(VMError::NoritoInvalid);
    }
    let encoded = canonical_record_bytes(record)?;
    if encoded.len() > MAX_PRIVATE_INPUT_RECORD_BYTES_V1 {
        return Err(VMError::NoritoInvalid);
    }
    Ok(encoded)
}
fn validate_frame(kind: PrivateInputKindV1, frame: &[u8]) -> Result<(), VMError> {
    let canonical = match kind {
        PrivateInputKindV1::Int => {
            if frame.len() > MAX_INT_FRAME_BYTES_V1 {
                return Err(VMError::NoritoInvalid);
            }
            IntValueV1::decode_frame(frame)
                .and_then(|value| value.encode_frame())
                .map_err(|_| VMError::NoritoInvalid)?
        }
        PrivateInputKindV1::Decimal => {
            if frame.len() > MAX_DECIMAL_FRAME_BYTES_V1 {
                return Err(VMError::NoritoInvalid);
            }
            DecimalValueV1::decode_frame(frame)
                .and_then(|value| value.encode_frame())
                .map_err(|_| VMError::NoritoInvalid)?
        }
        PrivateInputKindV1::Quantity => {
            if frame.len() > MAX_QUANTITY_FRAME_BYTES_V1 {
                return Err(VMError::NoritoInvalid);
            }
            QuantityValueV1::decode_frame(frame)
                .and_then(|value| value.encode_frame())
                .map_err(|_| VMError::NoritoInvalid)?
        }
    };
    if canonical != frame {
        return Err(VMError::NoritoInvalid);
    }
    Ok(())
}
/// Decode and validate one untrusted outer record for an exact requested kind.
///
/// Callers must debit the fixed private-input quote before invoking this
/// function. The raw bound is checked before Norito can allocate the payload.
pub(crate) fn decode_record(
    raw: &[u8],
    expected: PrivateInputKindV1,
) -> Result<ValidatedPrivateInput, VMError> {
    if raw.is_empty() || raw.len() > MAX_PRIVATE_INPUT_RECORD_BYTES_V1 {
        return Err(VMError::NoritoInvalid);
    }
    let record: PrivateInputRecordV1 =
        norito::decode_canonical(raw).map_err(|_| VMError::NoritoInvalid)?;
    if record.kind != expected {
        return Err(VMError::NoritoInvalid);
    }
    validate_frame(record.kind, &record.payload)?;
    let envelope =
        ivm_abi::numeric_tlv::encode_envelope(record.kind.pointer_type(), &record.payload)?;
    Ok(ValidatedPrivateInput {
        kind: record.kind,
        envelope,
    })
}
/// Validate a complete opaque numeric TLV snapshot after the host quote is debited.
pub(crate) fn validate_private_numeric_envelope(
    envelope: &[u8],
) -> Result<PrivateInputKindV1, VMError> {
    let tlv = pointer_abi::validate_tlv_bytes(envelope)?;
    let kind = match tlv.type_id {
        PointerType::Int => PrivateInputKindV1::Int,
        PointerType::Decimal => PrivateInputKindV1::Decimal,
        PointerType::Quantity => PrivateInputKindV1::Quantity,
        _ => return Err(VMError::NoritoInvalid),
    };
    validate_frame(kind, tlv.payload)?;
    Ok(kind)
}
/// Compute the canonical full-width, still-private numeric projection.
///
/// This value is not a public commitment and must never be returned to guest
/// code. It binds the operation-independent domain, explicit ABI version,
/// nominal kind, exact envelope length, and every byte of the canonical TLV.
#[must_use]
pub(crate) fn private_numeric_projection_v1(
    kind: PrivateInputKindV1,
    canonical_envelope: &[u8],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(
        PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1.len() + 2 + 8 + 8 + canonical_envelope.len(),
    );
    material.extend_from_slice(PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1);
    material.extend_from_slice(&PRIVATE_INPUT_ABI_VERSION_V1.to_le_bytes());
    material.extend_from_slice(&kind.tag().to_le_bytes());
    material.extend_from_slice(
        &u64::try_from(canonical_envelope.len())
            .expect("bounded private numeric envelope length fits u64")
            .to_le_bytes(),
    );
    material.extend_from_slice(canonical_envelope);
    Hash::new(&material).into()
}
/// Reduce one 256-bit digest modulo the BLS12-381 scalar order with a fixed operation count.
///
/// The modulus is greater than `2^254`, so every 256-bit input is below three
/// moduli. Two unconditional subtract-and-select rounds therefore produce the
/// canonical residue without secret-dependent division, loops, or branches.
fn reduce_bls_scalar(integer: U256) -> U256 {
    let subtract_once = |value: U256| {
        let difference = value.wrapping_sub(&BLS_SCALAR_MODULUS);
        let at_least_modulus = !value.ct_lt(&BLS_SCALAR_MODULUS);
        U256::conditional_select(&value, &difference, at_least_modulus)
    };
    subtract_once(subtract_once(integer))
}
fn valcom_scalar(role: u8, kind: PrivateInputKindV1, envelope: &[u8]) -> Scalar {
    let projection = private_numeric_projection_v1(kind, envelope);
    let mut material = Vec::with_capacity(PRIVATE_NUMERIC_VALCOM_DOMAIN_V1.len() + 2 + 1 + 32);
    material.extend_from_slice(PRIVATE_NUMERIC_VALCOM_DOMAIN_V1);
    material.extend_from_slice(&PRIVATE_INPUT_ABI_VERSION_V1.to_le_bytes());
    material.push(role);
    material.extend_from_slice(&projection);
    let digest: [u8; 32] = Hash::new(&material).into();
    let integer = U256::from_le_bytes(digest);
    let reduced = reduce_bls_scalar(integer);
    Scalar::from_bytes_le(&reduced.to_le_bytes())
        .into_option()
        .expect("modular reduction produces a canonical BLS scalar")
}
/// Commit two complete canonical private numeric envelopes without truncation.
///
/// Both domain-separated projections remain private. Only the full compressed
/// Pedersen point returned as a non-negative Kotodama `int` is declassified.
pub(crate) fn valcom(
    value_kind: PrivateInputKindV1,
    value_envelope: &[u8],
    blind_kind: PrivateInputKindV1,
    blind_envelope: &[u8],
) -> Result<BigInt, VMError> {
    let value = valcom_scalar(0, value_kind, value_envelope);
    let blind = valcom_scalar(1, blind_kind, blind_envelope);
    let mut unsigned_be = crate::pedersen::pedersen_commit_scalars(value, blind);
    unsigned_be.reverse();
    let mut unsigned_le = unsigned_be.to_vec();
    if unsigned_le.last().is_some_and(|byte| byte & 0x80 != 0) {
        unsigned_le.push(0);
    }
    BigInt::from_twos_bytes(&unsigned_le).map_err(|_| VMError::NoritoInvalid)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn envelope(record: PrivateInputRecordV1) -> Vec<u8> {
        let raw = encode_record(&record).expect("encode private record");
        decode_record(&raw, record.kind)
            .expect("decode private record")
            .envelope
    }
    #[test]
    fn kind_and_complete_payload_are_bound_into_projection() {
        let int = envelope(int_record(BigInt::from(1_u64)).unwrap());
        let decimal = envelope(decimal_record("1".parse().unwrap()).unwrap());
        let quantity = envelope(quantity_record(Quantity::from(1_u32)).unwrap());
        let int_projection = private_numeric_projection_v1(PrivateInputKindV1::Int, &int);
        let decimal_projection =
            private_numeric_projection_v1(PrivateInputKindV1::Decimal, &decimal);
        let quantity_projection =
            private_numeric_projection_v1(PrivateInputKindV1::Quantity, &quantity);
        assert_ne!(int_projection, decimal_projection);
        assert_ne!(int_projection, quantity_projection);
        assert_ne!(decimal_projection, quantity_projection);
        let other = envelope(int_record(BigInt::from(2_u64)).unwrap());
        assert_ne!(
            int_projection,
            private_numeric_projection_v1(PrivateInputKindV1::Int, &other)
        );
    }
    #[test]
    fn wrong_kind_fails_before_an_envelope_is_returned() {
        let raw = encode_record(&decimal_record("1.5".parse().unwrap()).unwrap()).unwrap();
        assert!(decode_record(&raw, PrivateInputKindV1::Int).is_err());
    }
    #[test]
    fn private_input_boundary_is_canonical_and_ambient_independent() {
        let record = quantity_record(Quantity::from(17_u32)).expect("valid quantity record");
        let canonical = encode_record(&record).expect("encode canonical private input");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&record).expect("encode alternate-layout private input")
        };
        assert_ne!(
            alternate, canonical,
            "fixture must exercise a non-canonical outer layout"
        );
        assert!(matches!(
            decode_record(&alternate, PrivateInputKindV1::Quantity),
            Err(VMError::NoritoInvalid)
        ));
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_eq!(
            encode_record(&record).expect("encode under alternate ambient layout"),
            canonical
        );
        assert!(
            decode_record(&canonical, PrivateInputKindV1::Quantity).is_ok(),
            "canonical admission must ignore the caller's ambient layout"
        );
    }
    #[test]
    fn negative_quantity_frame_is_rejected() {
        let negative_decimal = DecimalValueV1::new("-1".parse().unwrap())
            .encode_frame()
            .unwrap();
        let record = PrivateInputRecordV1::new(PrivateInputKindV1::Quantity, negative_decimal);
        let raw = encode_record(&record).unwrap();
        assert!(decode_record(&raw, PrivateInputKindV1::Quantity).is_err());
    }
    #[test]
    fn typed_record_payload_is_rejected_before_outer_serialization() {
        let oversized = PrivateInputRecordV1::new(
            PrivateInputKindV1::Int,
            vec![0_u8; MAX_PRIVATE_INPUT_RECORD_BYTES_V1 * 2],
        );
        assert!(
            oversized.payload.len() > MAX_INT_FRAME_BYTES_V1,
            "fixture must exercise the pre-serialization payload bound"
        );
        assert!(matches!(
            encode_record(&oversized),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn commitment_preserves_the_full_compressed_point() {
        let value = envelope(int_record(BigInt::from(7_u64)).unwrap());
        let blind = envelope(quantity_record(Quantity::from(11_u32)).unwrap());
        let commitment = valcom(
            PrivateInputKindV1::Int,
            &value,
            PrivateInputKindV1::Quantity,
            &blind,
        )
        .unwrap();
        assert!(
            commitment.bit_len() > 64,
            "commitment must not be truncated"
        );
        assert!(commitment.bit_len() <= 384);
    }
    #[test]
    fn fixed_operation_scalar_reduction_matches_reference_boundaries() {
        let q_minus_one = BLS_SCALAR_MODULUS.wrapping_sub(&U256::ONE);
        let twice_q = BLS_SCALAR_MODULUS.wrapping_add(&BLS_SCALAR_MODULUS);
        let twice_q_minus_one = twice_q.wrapping_sub(&U256::ONE);
        let modulus = crypto_bigint::NonZero::new(BLS_SCALAR_MODULUS)
            .expect("BLS scalar modulus is non-zero");
        for input in [
            U256::ZERO,
            q_minus_one,
            BLS_SCALAR_MODULUS,
            twice_q_minus_one,
            twice_q,
            U256::MAX,
        ] {
            let reference = U256::rem_wide_vartime((input, U256::ZERO), &modulus);
            assert_eq!(reduce_bls_scalar(input), reference, "input={input:?}");
        }
    }
}
