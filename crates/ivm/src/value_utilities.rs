//! Deterministic, bounded public value encoding and UTF-8/byte operations.

use std::io::Cursor;

use crate::{IVM, PointerType, VMError, syscalls, value_record};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_data_model::smart_contract::entrypoint::{
    EntrypointReturnRecordV1, EntrypointValueAtomV1 as Atom, EntrypointValueKindV1 as Kind,
    EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1, MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
};

const MAX_SCHEMA_BYTES: usize = 64 * 1024;
const BASE_GAS: u64 = 32;
const ENVELOPE: usize = 39;

fn unavailable() -> VMError {
    VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable)
}
fn codec_error(error: norito::Error) -> VMError {
    match error {
        norito::Error::AllocationFailed { .. } => unavailable(),
        _ => VMError::NoritoInvalid,
    }
}

// Byte backing is destroyed before its original physical reservation. Standalone
// VMs stay standalone; a funded VM never substitutes a new allocation pool.
struct Scratch {
    bytes: Vec<u8>,
    _reservation: Option<AllocationReservation>,
}
impl Scratch {
    fn new(length: usize, pool: Option<&AllocationBudget>) -> Result<Self, VMError> {
        let reservation = pool
            .map(|pool| pool.try_reserve_bytes(length))
            .transpose()
            .map_err(VMError::AllocationDeferred)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| unavailable())?;
        bytes.resize(length, 0);
        Ok(Self {
            bytes,
            _reservation: reservation,
        })
    }
}

fn preflight(vm: &IVM, gas: u64) -> Result<(), VMError> {
    crate::host::preflight_reserved_syscall_gas(vm, gas)?;
    if vm.syscall_reserved_gas() == 0 && vm.remaining_gas() < gas {
        return Err(VMError::OutOfGas);
    }
    Ok(())
}
fn payload(vm: &IVM, pointer: u64, kind: PointerType) -> Result<&[u8], VMError> {
    let tlv = vm.validate_tlv(pointer)?;
    if tlv.type_id != kind {
        return Err(VMError::NoritoInvalid);
    }
    Ok(tlv.payload)
}
fn quote_payload(
    vm: &IVM,
    register: usize,
    kind: PointerType,
    maximum: usize,
) -> Result<usize, VMError> {
    vm.ensure_public_register(register)?;
    let size = crate::host::quote_tlv_payload_len_at(vm, vm.register(register), kind)?;
    if size > maximum {
        return Err(VMError::NoritoInvalid);
    }
    Ok(size)
}

// Decode within a physically prepaid, protocol-bounded allowance. The exact
// decoded graph dies inside the closure before the original allowance refunds.
fn with_decoded<T, R>(
    pool: Option<&AllocationBudget>,
    bytes: &[u8],
    use_value: impl FnOnce(&T) -> Result<R, VMError>,
) -> Result<R, VMError>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    let limits = norito::canonical_decode_limits(bytes.len());
    let mut reservation = pool
        .map(|pool| {
            pool.try_reserve_bytes(
                limits
                    .max_total_allocated_bytes()
                    .saturating_add(norito::core::DecodeBudgetContext::allocation_layout().size()),
            )
        })
        .transpose()
        .map_err(VMError::AllocationDeferred)?;
    let context = match reservation.as_mut() {
        Some(reservation) => {
            norito::core::DecodeBudgetContext::from_reservation(limits, reservation)
                .map_err(|_| unavailable())?
        }
        None => norito::core::DecodeBudgetContext::new(limits),
    };
    let value = context
        .with(|| norito::decode_canonical_with_limits::<T>(bytes, limits).map_err(codec_error))?;
    use_value(&value)
}

fn blob_envelope(bytes: &[u8], pool: Option<&AllocationBudget>) -> Result<Scratch, VMError> {
    let mut output = Scratch::new(
        bytes
            .len()
            .checked_add(ENVELOPE)
            .ok_or(VMError::NoritoInvalid)?,
        pool,
    )?;
    output.bytes[..2].copy_from_slice(&(PointerType::Blob as u16).to_be_bytes());
    output.bytes[2] = 1;
    output.bytes[3..7].copy_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| VMError::NoritoInvalid)?
            .to_be_bytes(),
    );
    output.bytes[7..7 + bytes.len()].copy_from_slice(bytes);
    output.bytes[7 + bytes.len()..].copy_from_slice(iroha_crypto::Hash::new(bytes).as_ref());
    Ok(output)
}

/// Dispatch the four pure utility syscalls shared by every production host.
///
/// # Errors
/// Rejects private/malformed values and protocol bounds before publishing output;
/// local allocation refusals retain their original pool and do not become traps.
pub fn execute(number: u32, vm: &mut IVM) -> Result<u64, VMError> {
    let mut gas = BASE_GAS;
    let result = match number {
        syscalls::SYSCALL_BLOB_CONCAT => concat(vm, &mut gas),
        syscalls::SYSCALL_UTF8_VALIDATE => utf8(vm, &mut gas),
        syscalls::SYSCALL_VALUE_ENCODE => encode(vm, false, &mut gas),
        syscalls::SYSCALL_VALUE_TO_STRING => encode(vm, true, &mut gas),
        _ => return Err(VMError::UnknownSyscall(number)),
    };
    result.map(|()| gas).map_err(|error| {
        if error.metered_gas().is_some() {
            error
        } else {
            VMError::metered(gas, error)
        }
    })
}

fn concat(vm: &mut IVM, gas: &mut u64) -> Result<(), VMError> {
    let left_len = quote_payload(
        vm,
        10,
        PointerType::Blob,
        MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
    )?;
    let right_len = quote_payload(
        vm,
        11,
        PointerType::Blob,
        MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
    )?;
    let length = left_len
        .checked_add(right_len)
        .filter(|length| *length <= MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
        .ok_or(VMError::NoritoInvalid)?;
    *gas = BASE_GAS + 2 * length as u64;
    preflight(vm, *gas)?;
    let left = payload(vm, vm.register(10), PointerType::Blob)?;
    let right = payload(vm, vm.register(11), PointerType::Blob)?;
    let mut bytes = Scratch::new(length, vm.memory.allocation_budget())?;
    bytes.bytes[..left_len].copy_from_slice(left);
    bytes.bytes[left_len..].copy_from_slice(right);
    let envelope = blob_envelope(&bytes.bytes, vm.memory.allocation_budget())?;
    let pointer = vm.alloc_host_tlv(&envelope.bytes)?;
    vm.set_register(10, pointer);
    Ok(())
}
fn utf8(vm: &mut IVM, gas: &mut u64) -> Result<(), VMError> {
    let length = quote_payload(
        vm,
        10,
        PointerType::Blob,
        MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
    )?;
    *gas = BASE_GAS + length as u64;
    preflight(vm, *gas)?;
    let valid = std::str::from_utf8(payload(vm, vm.register(10), PointerType::Blob)?).is_ok();
    if !valid {
        vm.set_register(10, 0);
    }
    Ok(())
}

enum Captured {
    Funded(value_record::CapturedValueRecord),
    Standalone(EntrypointReturnRecordV1),
}
impl Captured {
    fn get(&self) -> &EntrypointReturnRecordV1 {
        match self {
            Self::Funded(record) => record.get(),
            Self::Standalone(record) => record,
        }
    }
}
fn encode(vm: &mut IVM, text: bool, gas: &mut u64) -> Result<(), VMError> {
    let schema_bytes = quote_payload(vm, 10, PointerType::NoritoBytes, MAX_SCHEMA_BYTES)?;
    for register in 11..=12 {
        vm.ensure_public_register(register)?;
    }
    *gas = BASE_GAS + schema_bytes as u64;
    preflight(vm, *gas)?;
    let pool = vm.memory.allocation_budget().cloned();
    // The schema's input borrow ends before publishing the output into this VM.
    let output = with_decoded::<EntrypointValueTypeV1, _>(
        pool.as_ref(),
        payload(vm, vm.register(10), PointerType::NoritoBytes)?,
        |schema| {
            if !schema.validate()
                || schema
                    .nodes
                    .iter()
                    .any(|node| matches!(node, Node::StateCursor(_)))
            {
                return Err(VMError::DecodeError);
            }
            if text && !matches!(schema.nodes.as_slice(), [Node::Leaf(kind)] if scalar_kind(*kind))
            {
                return Err(VMError::DecodeError);
            }
            let words = usize::try_from(vm.register(12)).map_err(|_| VMError::DecodeError)?;
            let available = if vm.syscall_reserved_gas() == 0 {
                vm.remaining_gas()
            } else {
                vm.syscall_reserved_gas()
            };
            let quote = value_record::quote_value_record(
                vm,
                schema,
                vm.register(11),
                words,
                available.saturating_sub(*gas),
            )
            .map_err(|error| VMError::metered(*gas, error))?;
            *gas = gas.checked_add(quote.gas).ok_or(VMError::OutOfGas)?;
            preflight(vm, *gas)?;
            let captured = match pool.as_ref() {
                Some(pool) => Captured::Funded(value_record::capture_value_record_funded(
                    vm,
                    schema,
                    vm.register(11),
                    words,
                    pool,
                )?),
                None => Captured::Standalone(value_record::capture_value_record(
                    vm,
                    schema,
                    vm.register(11),
                    words,
                )?),
            };
            if text {
                scalar_text(schema, captured.get(), pool.as_ref(), vm, gas)
            } else {
                let length = norito::canonical_frame_len(captured.get()).map_err(codec_error)?;
                if length > MAX_ENTRYPOINT_RETURN_RECORD_BYTES {
                    return Err(VMError::NoritoInvalid);
                }
                *gas = gas.checked_add(length as u64).ok_or(VMError::OutOfGas)?;
                preflight(vm, *gas)?;
                let mut bytes = Scratch::new(length, pool.as_ref())?;
                let mut writer = Cursor::new(bytes.bytes.as_mut_slice());
                norito::core::write_canonical_to_writer(captured.get(), &mut writer)
                    .map_err(codec_error)?;
                if writer.position() != length as u64 {
                    return Err(VMError::NoritoInvalid);
                }
                blob_envelope(&bytes.bytes, pool.as_ref())
            }
        },
    )?;
    let pointer = vm.alloc_host_tlv(&output.bytes)?;
    vm.set_register(10, pointer);
    Ok(())
}
fn scalar_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Bool | Kind::Int | Kind::Decimal | Kind::Quantity | Kind::String | Kind::Name
    )
}
fn scalar_text(
    schema: &EntrypointValueTypeV1,
    record: &EntrypointReturnRecordV1,
    pool: Option<&AllocationBudget>,
    vm: &IVM,
    gas: &mut u64,
) -> Result<Scratch, VMError> {
    let [Node::Leaf(kind)] = schema.nodes.as_slice() else {
        return Err(VMError::DecodeError);
    };
    if let (Kind::Bool, [Atom::Bool(value)]) = (kind, record.atoms.as_slice()) {
        return format_value(value, pool, vm, gas);
    }
    let [Atom::Pointer(envelope)] = record.atoms.as_slice() else {
        return Err(VMError::DecodeError);
    };
    let tlv = crate::pointer_abi::validate_tlv_bytes(envelope)?;
    macro_rules! display {
        ($ty:ty) => {
            with_decoded::<$ty, _>(pool, tlv.payload, |value| {
                format_value(value, pool, vm, gas)
            })
        };
    }
    match kind {
        Kind::String => format_value(
            &std::str::from_utf8(tlv.payload).map_err(|_| VMError::NoritoInvalid)?,
            pool,
            vm,
            gas,
        ),
        Kind::Name => display!(iroha_model_base::name::Name),
        Kind::Int => with_decoded::<iroha_primitives::numeric_abi::IntValueV1, _>(
            pool,
            tlv.payload,
            |value| format_value(&StackInt(value.as_int()), pool, vm, gas),
        ),
        Kind::Decimal => with_decoded::<iroha_primitives::numeric_abi::DecimalValueV1, _>(
            pool,
            tlv.payload,
            |value| format_value(value.as_numeric(), pool, vm, gas),
        ),
        Kind::Quantity => with_decoded::<iroha_primitives::numeric_abi::QuantityValueV1, _>(
            pool,
            tlv.payload,
            |value| format_value(value.as_quantity(), pool, vm, gas),
        ),
        _ => Err(VMError::DecodeError),
    }
}
// Public Int is signed 512-bit. Decimal digits and division scratch are fixed
// stack arrays, so Display cannot allocate through num-bigint's formatter.
struct StackInt<'a>(&'a iroha_primitives::bigint::BigInt);
impl std::fmt::Display for StackInt<'_> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const LIMBS: usize = iroha_primitives::numeric::MAX_MANTISSA_BITS / 32;
        let mut limbs = [0_u32; LIMBS];
        let mut count = 0_usize;
        for limb in self.0.magnitude_u32_digits() {
            *limbs.get_mut(count).ok_or(std::fmt::Error)? = limb;
            count += 1;
        }
        // ceil(512 * log10(2)); includes the largest signed magnitude.
        let mut digits = [0_u8; 155];
        let mut start = digits.len();
        while count != 0 {
            let mut remainder = 0_u64;
            for limb in limbs[..count].iter_mut().rev() {
                let dividend = (remainder << 32) | u64::from(*limb);
                *limb = u32::try_from(dividend / 10).map_err(|_| std::fmt::Error)?;
                remainder = dividend % 10;
            }
            while count != 0 && limbs[count - 1] == 0 {
                count -= 1;
            }
            start = start.checked_sub(1).ok_or(std::fmt::Error)?;
            digits[start] = b'0' + u8::try_from(remainder).map_err(|_| std::fmt::Error)?;
        }
        if start == digits.len() {
            start -= 1;
            digits[start] = b'0';
        }
        if self.0.is_negative() {
            output.write_str("-")?;
        }
        output.write_str(std::str::from_utf8(&digits[start..]).map_err(|_| std::fmt::Error)?)
    }
}

fn format_value(
    value: &impl std::fmt::Display,
    pool: Option<&AllocationBudget>,
    vm: &IVM,
    gas: &mut u64,
) -> Result<Scratch, VMError> {
    use std::fmt::Write as _;
    struct Count(usize);
    impl std::fmt::Write for Count {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0 = self
                .0
                .checked_add(value.len())
                .filter(|length| *length <= MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
                .ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut count = Count(0);
    write!(&mut count, "{value}").map_err(|_| VMError::NoritoInvalid)?;
    *gas = gas.checked_add(count.0 as u64).ok_or(VMError::OutOfGas)?;
    preflight(vm, *gas)?;
    let mut bytes = Scratch::new(count.0, pool)?;
    struct Writer<'a> {
        bytes: &'a mut [u8],
        position: usize,
    }
    impl std::fmt::Write for Writer<'_> {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let end = self
                .position
                .checked_add(value.len())
                .ok_or(std::fmt::Error)?;
            self.bytes
                .get_mut(self.position..end)
                .ok_or(std::fmt::Error)?
                .copy_from_slice(value.as_bytes());
            self.position = end;
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: &mut bytes.bytes,
        position: 0,
    };
    write!(&mut writer, "{value}").map_err(|_| VMError::NoritoInvalid)?;
    if writer.position != count.0 {
        return Err(VMError::NoritoInvalid);
    }
    blob_envelope(&bytes.bytes, pool)
}

#[cfg(test)]
mod tests;
