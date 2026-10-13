//! Schema-bound pointer envelopes for Kotodama V1 exact numbers.
//!
//! Staged decoding charges bounded public work before each read, snapshots the
//! complete envelope once, authenticates that snapshot, and then performs
//! strict schema/canonical decoding. This ordering is consensus-visible.
use crate::{
    IVM, PointerType, VMError, numeric::PointerAbiFaultV1, numeric_gas,
    syscall_metering::SyscallMeteringPhase,
};
pub use iroha_primitives::numeric_abi::MAX_QUANTITY_ENVELOPE_BYTES_V1;
#[cfg(test)]
use iroha_primitives::numeric_abi::NUMERIC_FRAME_HEADER_BYTES_V1;
use iroha_primitives::{
    bigint::BigInt,
    numeric::{Numeric, NumericWorkStep, Quantity},
    numeric_abi::{
        DecimalValueV1, IntValueV1, MAX_DECIMAL_FRAME_BYTES_V1, MAX_INT_FRAME_BYTES_V1,
        MAX_QUANTITY_FRAME_BYTES_V1, NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1, NumericAbiWorkStep,
        ObservedNumericAbiError, QuantityValueV1,
    },
};
use ivm_abi::numeric_tlv::encode_envelope;
const OUTER_HEADER_BYTES: usize = 7;
const OUTER_HASH_BYTES: usize = iroha_crypto::Hash::LENGTH;
fn pointer_fault(fault: PointerAbiFaultV1) -> VMError {
    VMError::PointerAbiFault(fault)
}
fn decode_envelope_bytes(
    envelope: &[u8],
    expected: PointerType,
    maximum_frame: usize,
) -> Result<&[u8], VMError> {
    if envelope.len() < OUTER_HEADER_BYTES {
        return Err(pointer_fault(PointerAbiFaultV1::TruncatedEnvelope));
    }
    let raw_type = u16::from_be_bytes([envelope[0], envelope[1]]);
    let pointer_type = PointerType::from_u16(raw_type)
        .ok_or_else(|| pointer_fault(PointerAbiFaultV1::UnknownType))?;
    if !crate::pointer_abi::is_type_allowed_for_policy(crate::SyscallPolicy::AbiV1, pointer_type) {
        return Err(pointer_fault(PointerAbiFaultV1::TypeNotAllowed));
    }
    if pointer_type != expected {
        return Err(pointer_fault(PointerAbiFaultV1::WrongType));
    }
    if envelope[2] != 1 {
        return Err(pointer_fault(PointerAbiFaultV1::InvalidEnvelopeVersion));
    }
    let frame_len = usize::try_from(u32::from_be_bytes([
        envelope[3],
        envelope[4],
        envelope[5],
        envelope[6],
    ]))
    .map_err(|_| pointer_fault(PointerAbiFaultV1::OversizedLength))?;
    if frame_len > maximum_frame {
        return Err(pointer_fault(PointerAbiFaultV1::OversizedLength));
    }
    let expected_len = OUTER_HEADER_BYTES
        .checked_add(frame_len)
        .and_then(|bytes| bytes.checked_add(OUTER_HASH_BYTES))
        .ok_or_else(|| pointer_fault(PointerAbiFaultV1::OversizedLength))?;
    if expected_len != envelope.len() {
        return Err(pointer_fault(PointerAbiFaultV1::TruncatedEnvelope));
    }
    let frame = &envelope[OUTER_HEADER_BYTES..OUTER_HEADER_BYTES + frame_len];
    let expected_hash = &envelope[OUTER_HEADER_BYTES + frame_len..];
    if iroha_crypto::Hash::new(frame).as_ref() != expected_hash {
        return Err(pointer_fault(PointerAbiFaultV1::PayloadHashMismatch));
    }
    Ok(frame)
}
struct AuthenticatedFrame {
    envelope: Vec<u8>,
    frame_len: usize,
}
impl AuthenticatedFrame {
    fn frame(&self) -> &[u8] {
        &self.envelope[OUTER_HEADER_BYTES..OUTER_HEADER_BYTES + self.frame_len]
    }
}
fn snapshot_metered(
    vm: &mut IVM,
    pointer: u64,
    expected: PointerType,
    maximum_frame: usize,
) -> Result<AuthenticatedFrame, VMError> {
    vm.charge_syscall_stage(
        SyscallMeteringPhase::PointerHeader,
        numeric_gas::POINTER_HEADER_BYTES,
    )?;
    vm.ensure_owned_public_tlv_range(pointer, OUTER_HEADER_BYTES as u64)
        .map_err(|_| pointer_fault(PointerAbiFaultV1::InvalidAddress))?;
    let header: [u8; OUTER_HEADER_BYTES] = vm
        .memory
        .load_region(pointer, OUTER_HEADER_BYTES as u64)
        .map_err(|error| {
            crate::error::preserve_execution_deferral(
                error,
                pointer_fault(PointerAbiFaultV1::InvalidAddress),
            )
        })?
        .try_into()
        .expect("fixed header range has the requested length");
    let raw_type = u16::from_be_bytes([header[0], header[1]]);
    let pointer_type = PointerType::from_u16(raw_type)
        .ok_or_else(|| pointer_fault(PointerAbiFaultV1::UnknownType))?;
    if !crate::pointer_abi::is_type_allowed_for_policy(vm.syscall_policy(), pointer_type) {
        return Err(pointer_fault(PointerAbiFaultV1::TypeNotAllowed));
    }
    if pointer_type != expected {
        return Err(pointer_fault(PointerAbiFaultV1::WrongType));
    }
    if header[2] != 1 {
        return Err(pointer_fault(PointerAbiFaultV1::InvalidEnvelopeVersion));
    }
    let frame_len = usize::try_from(u32::from_be_bytes([
        header[3], header[4], header[5], header[6],
    ]))
    .map_err(|_| pointer_fault(PointerAbiFaultV1::OversizedLength))?;
    if frame_len > maximum_frame {
        return Err(pointer_fault(PointerAbiFaultV1::OversizedLength));
    }
    let total = OUTER_HEADER_BYTES
        .checked_add(frame_len)
        .and_then(|bytes| bytes.checked_add(OUTER_HASH_BYTES))
        .ok_or_else(|| pointer_fault(PointerAbiFaultV1::OversizedLength))?;
    // Both bounded tail charges happen before the VM checks or reads the tail.
    // The frame bytes belong to the envelope-snapshot phase; the fixed digest
    // bytes belong to payload authentication. Malformed/truncated inputs
    // therefore cannot perform free range probes or hash work.
    vm.charge_syscall_stage(
        SyscallMeteringPhase::PointerEnvelope,
        numeric_gas::checked_bytes(frame_len)?,
    )?;
    vm.charge_syscall_stage(
        SyscallMeteringPhase::PayloadHash,
        numeric_gas::payload_hash_gas(frame_len)?,
    )?;
    let total_u64 = u64::try_from(total).map_err(|_| VMError::GasCostOverflow)?;
    vm.ensure_owned_tlv_range(pointer, total_u64)
        .map_err(|_| pointer_fault(PointerAbiFaultV1::TruncatedEnvelope))?;
    // Read only the tail here: the authenticated execution snapshot reuses
    // the already charged/copied header instead of traversing those seven
    // bytes a second time.
    let tail_pointer = pointer
        .checked_add(OUTER_HEADER_BYTES as u64)
        .ok_or_else(|| pointer_fault(PointerAbiFaultV1::InvalidAddress))?;
    let tail_len = total - OUTER_HEADER_BYTES;
    vm.ensure_public_memory(
        tail_pointer,
        u64::try_from(tail_len).map_err(|_| VMError::GasCostOverflow)?,
    )
    .map_err(|_| pointer_fault(PointerAbiFaultV1::TruncatedEnvelope))?;
    let tail = vm
        .memory
        .load_region(
            tail_pointer,
            u64::try_from(tail_len).map_err(|_| VMError::GasCostOverflow)?,
        )
        .map_err(|error| {
            crate::error::preserve_execution_deferral(
                error,
                pointer_fault(PointerAbiFaultV1::TruncatedEnvelope),
            )
        })?
        .to_vec();
    let mut snapshot = Vec::with_capacity(total);
    snapshot.extend_from_slice(&header);
    snapshot.extend_from_slice(&tail);
    // Authenticate exactly the bytes that subsequent stages decode.
    let frame = &snapshot[OUTER_HEADER_BYTES..OUTER_HEADER_BYTES + frame_len];
    let supplied_hash = &snapshot[OUTER_HEADER_BYTES + frame_len..];
    if iroha_crypto::Hash::new(frame).as_ref() != supplied_hash {
        return Err(pointer_fault(PointerAbiFaultV1::PayloadHashMismatch));
    }
    // Structural validation scans the complete frame (including its Norito
    // CRC). Canonical value decoding scans the body. Debit the structural pass
    // now; after structure succeeds, the typed decoder separately debits the
    // body scan and any scaled-mantissa canonicality probe immediately before
    // each begins.
    let (decode_work, _) = numeric_gas::numeric_frame_validation_phase_work(frame_len)?;
    vm.charge_syscall_stage(
        SyscallMeteringPhase::NoritoDecode,
        numeric_gas::work_gas(decode_work)?,
    )?;
    Ok(AuthenticatedFrame {
        envelope: snapshot,
        frame_len,
    })
}
fn charge_abi_work(vm: &mut IVM, step: NumericAbiWorkStep) -> Result<(), VMError> {
    let gas = match step {
        NumericAbiWorkStep::CanonicalBody { body_bytes } => numeric_gas::work_gas(
            numeric_gas::numeric_frame_body_validation_work(usize::from(body_bytes))?,
        )?,
        NumericAbiWorkStep::CanonicalityProbe {
            mantissa_limbs,
            scale,
        } => numeric_gas::work_step_gas(NumericWorkStep::CanonicalityProbe {
            mantissa_limbs,
            scale,
        })?,
    };
    vm.charge_syscall_stage(SyscallMeteringPhase::CanonicalValidation, gas)
}
fn finish_observed_decode<T>(
    result: Result<T, ObservedNumericAbiError<VMError>>,
) -> Result<T, VMError> {
    match result {
        Ok(value) => Ok(value),
        Err(ObservedNumericAbiError::Abi(error)) => Err(VMError::from(error)),
        Err(ObservedNumericAbiError::Observer(error)) => Err(error),
    }
}
// Independent length reference retained for the original boundary assertions.
#[cfg(test)]
fn exact_int_frame_len(value: &BigInt) -> Result<usize, VMError> {
    NUMERIC_FRAME_HEADER_BYTES_V1
        .checked_add(4)
        .and_then(|bytes| bytes.checked_add(value.twos_byte_len()))
        .ok_or(VMError::GasCostOverflow)
}
fn exact_envelope_len(frame_len: usize) -> Result<usize, VMError> {
    frame_len
        .checked_add(NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1)
        .ok_or(VMError::GasCostOverflow)
}
fn charge_output_length_probe(vm: &mut IVM, value: &BigInt) -> Result<(), VMError> {
    let magnitude_bits = u64::try_from(value.bit_len()).map_err(|_| VMError::GasCostOverflow)?;
    // One conservative sign bit covers every minimal two's-complement length,
    // including positive sign-extension boundaries. Negative powers of two
    // may need one limb less, which is a deliberate bounded overcharge.
    let limbs = numeric_gas::limbs_for_bits(numeric_gas::checked_add(magnitude_bits, 1)?);
    vm.charge_syscall_stage(
        SyscallMeteringPhase::OutputSerialization,
        numeric_gas::work_gas(numeric_gas::finalization_work(limbs))?,
    )
}
fn charge_output(vm: &mut IVM, envelope_len: usize, frame_len: usize) -> Result<(), VMError> {
    vm.charge_syscall_stage(
        SyscallMeteringPhase::OutputSerialization,
        numeric_gas::output_serialization_gas(envelope_len, frame_len)?,
    )
}
/// Strictly decode an integer from a complete pointer envelope snapshot.
pub fn decode_int_bytes(envelope: &[u8]) -> Result<BigInt, VMError> {
    let frame = decode_envelope_bytes(envelope, PointerType::Int, MAX_INT_FRAME_BYTES_V1)?;
    IntValueV1::decode_frame(frame)
        .map(IntValueV1::into_int)
        .map_err(VMError::from)
}
/// Strictly decode a decimal from a complete pointer envelope snapshot.
pub fn decode_decimal_bytes(envelope: &[u8]) -> Result<Numeric, VMError> {
    let frame = decode_envelope_bytes(envelope, PointerType::Decimal, MAX_DECIMAL_FRAME_BYTES_V1)?;
    DecimalValueV1::decode_frame(frame)
        .map(DecimalValueV1::into_numeric)
        .map_err(VMError::from)
}
/// Strictly decode a quantity from a complete pointer envelope snapshot.
pub fn decode_quantity_bytes(envelope: &[u8]) -> Result<Quantity, VMError> {
    let frame =
        decode_envelope_bytes(envelope, PointerType::Quantity, MAX_QUANTITY_FRAME_BYTES_V1)?;
    QuantityValueV1::decode_frame(frame)
        .map(QuantityValueV1::into_quantity)
        .map_err(VMError::from)
}
/// Validate canonical numeric frames carried by generic pointer transport.
///
/// The pointer TLV header and hash are checked by the caller. This validates
/// the nominal numeric payload before a guest can publish or consume it.
pub(crate) fn validate_numeric_frame_if_needed(
    pointer_type: PointerType,
    frame: &[u8],
) -> Result<(), VMError> {
    match pointer_type {
        PointerType::Int => IntValueV1::decode_frame(frame)
            .map(|_| ())
            .map_err(VMError::from),
        PointerType::Decimal => DecimalValueV1::decode_frame(frame)
            .map(|_| ())
            .map_err(VMError::from),
        PointerType::Quantity => QuantityValueV1::decode_frame(frame)
            .map(|_| ())
            .map_err(VMError::from),
        _ => Ok(()),
    }
}
/// Strictly decode a staged integer operand.
pub fn decode_int_metered(vm: &mut IVM, pointer: u64) -> Result<BigInt, VMError> {
    let snapshot = snapshot_metered(vm, pointer, PointerType::Int, MAX_INT_FRAME_BYTES_V1)?;
    let result =
        IntValueV1::decode_frame_observed(snapshot.frame(), |step| charge_abi_work(vm, step));
    finish_observed_decode(result).map(IntValueV1::into_int)
}
/// Strictly decode a staged decimal operand.
pub fn decode_decimal_metered(vm: &mut IVM, pointer: u64) -> Result<Numeric, VMError> {
    let snapshot = snapshot_metered(
        vm,
        pointer,
        PointerType::Decimal,
        MAX_DECIMAL_FRAME_BYTES_V1,
    )?;
    let result =
        DecimalValueV1::decode_frame_observed(snapshot.frame(), |step| charge_abi_work(vm, step));
    finish_observed_decode(result).map(DecimalValueV1::into_numeric)
}
/// Strictly decode a staged quantity operand.
pub fn decode_quantity_metered(vm: &mut IVM, pointer: u64) -> Result<Quantity, VMError> {
    let snapshot = snapshot_metered(
        vm,
        pointer,
        PointerType::Quantity,
        MAX_QUANTITY_FRAME_BYTES_V1,
    )?;
    let result =
        QuantityValueV1::decode_frame_observed(snapshot.frame(), |step| charge_abi_work(vm, step));
    finish_observed_decode(result).map(QuantityValueV1::into_quantity)
}
/// Debit, serialize, and allocate a staged integer result.
pub fn allocate_int_metered(vm: &mut IVM, value: &BigInt) -> Result<u64, VMError> {
    charge_output_length_probe(vm, value)?;
    let prepared = IntValueV1::prepare_frame(value).map_err(VMError::from)?;
    let frame_len = prepared.frame_len();
    let envelope_len = exact_envelope_len(frame_len)?;
    charge_output(vm, envelope_len, frame_len)?;
    let frame = prepared.encode_frame().map_err(VMError::from)?;
    let envelope = encode_envelope(PointerType::Int, &frame)?;
    debug_assert_eq!(envelope.len(), envelope_len);
    vm.alloc_host_tlv(&envelope)
}
/// Debit, serialize, and allocate a staged decimal result.
pub fn allocate_decimal_metered(vm: &mut IVM, value: &Numeric) -> Result<u64, VMError> {
    charge_output_length_probe(vm, value.mantissa())?;
    let prepared = DecimalValueV1::prepare_frame(value);
    let frame_len = prepared.frame_len();
    let envelope_len = exact_envelope_len(frame_len)?;
    charge_output(vm, envelope_len, frame_len)?;
    let frame = prepared.encode_frame().map_err(VMError::from)?;
    let envelope = encode_envelope(PointerType::Decimal, &frame)?;
    debug_assert_eq!(envelope.len(), envelope_len);
    vm.alloc_host_tlv(&envelope)
}
/// Debit, serialize, and allocate a staged quantity result.
pub fn allocate_quantity_metered(vm: &mut IVM, value: &Quantity) -> Result<u64, VMError> {
    charge_output_length_probe(vm, value.mantissa())?;
    let prepared = QuantityValueV1::prepare_frame(value);
    let frame_len = prepared.frame_len();
    let envelope_len = exact_envelope_len(frame_len)?;
    charge_output(vm, envelope_len, frame_len)?;
    let frame = prepared.encode_frame().map_err(VMError::from)?;
    let envelope = encode_envelope(PointerType::Quantity, &frame)?;
    debug_assert_eq!(envelope.len(), envelope_len);
    vm.alloc_host_tlv(&envelope)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ivm_abi::numeric_tlv::{encode_decimal, encode_int, encode_quantity};
    #[test]
    fn pointer_transport_validates_numeric_frames_before_publication() {
        let integer = BigInt::from_twos_bytes(&[0x7f; 64]).expect("signed 512-bit value");
        let int_envelope = encode_int(&integer).expect("canonical Int envelope");
        let int_frame = &int_envelope[OUTER_HEADER_BYTES..int_envelope.len() - OUTER_HASH_BYTES];
        assert!(matches!(
            validate_numeric_frame_if_needed(PointerType::Int, int_frame),
            Ok(())
        ));
        assert!(matches!(
            validate_numeric_frame_if_needed(
                PointerType::Int,
                &norito::to_bytes(&17_i64).expect("retired i64 carrier")
            ),
            Err(VMError::PointerAbiFault(_))
        ));
        let mut oversized_body = vec![0_u8; 4 + 65];
        oversized_body[..4].copy_from_slice(&65_u32.to_le_bytes());
        oversized_body[4 + 64] = 1;
        let oversized_frame =
            norito::core::frame_bare_with_header_flags::<IntValueV1>(&oversized_body, 0)
                .expect("well-framed out-of-domain Int");
        assert!(matches!(
            validate_numeric_frame_if_needed(PointerType::Int, &oversized_frame),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::OversizedLength))
        ));
        assert!(matches!(
            validate_numeric_frame_if_needed(PointerType::Blob, b"untyped"),
            Ok(())
        ));
    }
    #[test]
    fn all_three_envelopes_roundtrip_and_cross_types_fail() {
        let integer = BigInt::from_i128(-129);
        let decimal = Numeric::new(-125, 2);
        let quantity: Quantity = "1.25".parse().expect("quantity");
        let int_envelope = encode_int(&integer).expect("int envelope");
        let decimal_envelope = encode_decimal(&decimal).expect("decimal envelope");
        let quantity_envelope = encode_quantity(&quantity).expect("quantity envelope");
        assert_eq!(
            (decode_int_bytes(&int_envelope)).expect("expected successful fixture result"),
            integer
        );
        assert_eq!(
            (decode_decimal_bytes(&decimal_envelope)).expect("expected successful fixture result"),
            decimal
        );
        assert_eq!(
            (decode_quantity_bytes(&quantity_envelope))
                .expect("expected successful fixture result"),
            quantity
        );
        assert!(matches!(
            decode_decimal_bytes(&int_envelope),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::WrongType))
        ));
    }
    #[test]
    fn outer_envelope_attacks_have_stable_precedence() {
        let envelope = encode_int(&BigInt::one()).expect("envelope");
        assert!(matches!(
            decode_int_bytes(&envelope[..OUTER_HEADER_BYTES - 1]),
            Err(VMError::PointerAbiFault(
                PointerAbiFaultV1::TruncatedEnvelope
            ))
        ));
        let mut unknown = envelope.clone();
        unknown[..2].copy_from_slice(&0xffff_u16.to_be_bytes());
        assert!(matches!(
            decode_int_bytes(&unknown),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::UnknownType))
        ));
        let mut unassigned = envelope.clone();
        unassigned[..2].copy_from_slice(&0x000C_u16.to_be_bytes());
        assert!(matches!(
            decode_int_bytes(&unassigned),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::UnknownType))
        ));
        let quantity = encode_quantity(&"1".parse().expect("quantity")).expect("quantity");
        assert!(matches!(
            decode_int_bytes(&quantity),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::WrongType))
        ));
        let mut bad_version = envelope.clone();
        bad_version[2] = 2;
        assert!(matches!(
            decode_int_bytes(&bad_version),
            Err(VMError::PointerAbiFault(
                PointerAbiFaultV1::InvalidEnvelopeVersion
            ))
        ));
        let mut oversized = envelope.clone();
        oversized[3..7].copy_from_slice(
            &u32::try_from(MAX_INT_FRAME_BYTES_V1 + 1)
                .expect("bounded oversized length")
                .to_be_bytes(),
        );
        assert!(matches!(
            decode_int_bytes(&oversized),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::OversizedLength))
        ));
        let mut trailing = envelope.clone();
        trailing.push(0);
        assert!(matches!(
            decode_int_bytes(&trailing),
            Err(VMError::PointerAbiFault(
                PointerAbiFaultV1::TruncatedEnvelope
            ))
        ));
        let mut bad_hash = envelope;
        let last = bad_hash.len() - 1;
        bad_hash[last] ^= 1;
        assert!(matches!(
            decode_int_bytes(&bad_hash),
            Err(VMError::PointerAbiFault(
                PointerAbiFaultV1::PayloadHashMismatch
            ))
        ));
    }
    #[test]
    fn exact_lengths_cover_empty_zero_and_signed_boundaries() {
        let zero = encode_int(&BigInt::zero()).expect("zero");
        assert_eq!(zero.len(), NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1 + 44);
        for value in [127_i128, 128, -128, -129] {
            let value = BigInt::from_i128(value);
            assert_eq!(
                encode_int(&value).expect("boundary envelope").len(),
                exact_envelope_len(exact_int_frame_len(&value).expect("frame length"))
                    .expect("envelope length")
            );
        }
    }
}
