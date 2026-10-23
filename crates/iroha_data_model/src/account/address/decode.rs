//! One I105 radix, prefix and controller grammar with selectable allocation destinations.
//!
//! Ordinary decoding and original-pool ingress share every syntax and arithmetic step.
//! The finite destination funds scratch before use and retains each final controller leaf.
//! Retained output shares the radix kernel through a scratch-only destination; it cannot
//! decode controllers and does not debit inbound resource quotas.

use super::*;
use iroha_allocation::{AllocationCharge, ChargedBuffer};
use std::ops::{Deref, DerefMut};

/// Scratch storage; the actual backing is destroyed before its optional pool credit.
/// No buffer can grow after its exact destination capacity has been selected.
pub(in crate::account) struct Work<T> {
    pub(super) values: Vec<T>,
    _charge: Option<AllocationCharge>,
    capacity: usize,
}
impl<T> Work<T> {
    pub(in crate::account) fn ordinary(capacity: usize) -> Result<Self, AccountAddressError> {
        let layout = std::alloc::Layout::array::<T>(capacity)
            .map_err(|_| AccountAddressError::DecodeResourceLimit)?;
        ncore::reserve_decode_allocation(layout.size())
            .map_err(AccountAddressError::from_decode_error)?;
        Self::output(capacity)
    }
    /// Retained output allocates fallibly without spending inbound decoder quota.
    fn output(capacity: usize) -> Result<Self, AccountAddressError> {
        let mut values = Vec::new();
        reserve_address_vec(&mut values, capacity)?;
        Ok(Self {
            values,
            _charge: None,
            capacity,
        })
    }
    #[allow(unsafe_code)]
    pub(in crate::account) fn admitted(buffer: ChargedBuffer<T>) -> Self {
        let capacity = buffer.capacity();
        // SAFETY: move both exact backing and its charge into one value-first
        // private scratch owner; no extraction, growth or replacement is exposed.
        let (values, charge) = unsafe { buffer.into_allocation_parts() };
        Self {
            values,
            _charge: Some(charge),
            capacity,
        }
    }
    fn push(&mut self, value: T) {
        assert!(self.values.len() < self.capacity);
        self.values.push(value);
    }
    fn extend(&mut self, values: impl IntoIterator<Item = T>) {
        for value in values {
            self.push(value);
        }
    }
    fn discard_prefix(&mut self, count: usize) {
        self.values.drain(..count);
    }
}
impl<T: Copy> Work<T> {
    fn resize(&mut self, length: usize, fill: T) {
        assert!(length <= self.capacity);
        self.values.resize(length, fill);
    }
    fn extend_from_slice(&mut self, values: &[T]) {
        assert!(values.len() <= self.capacity - self.values.len());
        self.values.extend_from_slice(values);
    }
}
impl<T> Deref for Work<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T> DerefMut for Work<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

/// Allocation destination shared by the sole radix arithmetic implementation.
pub(in crate::account) trait BufferDestination {
    type Error: From<AccountAddressError>;
    fn buffer<T>(&self, capacity: usize) -> Result<Work<T>, Self::Error>;
}

pub(in crate::account) trait Destination: BufferDestination {
    type Key;
    type Members;
    type Controller;
    fn is_resource(error: &Self::Error) -> bool;
    fn encoded_error(error: Self::Error) -> Self::Error;
    fn key(&self, algorithm: Algorithm, payload: &[u8]) -> Result<Self::Key, Self::Error>;
    fn members(&self, count: usize) -> Result<Self::Members, Self::Error>;
    fn push(
        &self,
        members: &mut Self::Members,
        curve: CurveId,
        weight: u16,
        key: Self::Key,
    ) -> Result<(), Self::Error>;
    fn single(&self, curve: CurveId, key: Self::Key) -> Result<Self::Controller, Self::Error>;
    fn multisig(
        &self,
        version: u8,
        threshold: u16,
        members: Self::Members,
    ) -> Result<Self::Controller, Self::Error>;
}

pub(super) struct Ordinary;
impl BufferDestination for Ordinary {
    type Error = AccountAddressError;
    fn buffer<T>(&self, capacity: usize) -> Result<Work<T>, Self::Error> {
        Work::ordinary(capacity)
    }
}

/// Output cannot be passed to controller/prefix decoding: it only funds radix scratch.
pub(super) struct RetainedOutput;
impl BufferDestination for RetainedOutput {
    type Error = AccountAddressError;
    fn buffer<T>(&self, capacity: usize) -> Result<Work<T>, Self::Error> {
        Work::output(capacity)
    }
}

impl Destination for Ordinary {
    type Key = PublicKey;
    type Members = Vec<MultisigMemberPayload>;
    type Controller = ControllerPayload;
    fn is_resource(error: &Self::Error) -> bool {
        error.is_decode_resource_limit()
    }
    fn encoded_error(error: Self::Error) -> Self::Error {
        match error {
            AccountAddressError::MissingI105Sentinel => {
                AccountAddressError::UnsupportedAddressFormat
            }
            other => other,
        }
    }
    fn key(&self, algorithm: Algorithm, payload: &[u8]) -> Result<Self::Key, Self::Error> {
        decode_public_key(algorithm, payload)
    }
    fn members(&self, count: usize) -> Result<Self::Members, Self::Error> {
        allocate_multisig_members(count)
    }
    fn push(
        &self,
        members: &mut Self::Members,
        curve: CurveId,
        weight: u16,
        public_key: Self::Key,
    ) -> Result<(), Self::Error> {
        // Both destinations reject the same invalid member before any further member.
        if weight == 0 {
            return Err(AccountAddressError::InvalidMultisigPolicy(
                MultisigPolicyError::MemberWeightZero,
            ));
        }
        members.push(MultisigMemberPayload {
            curve,
            weight,
            public_key,
        });
        Ok(())
    }
    fn single(
        &self,
        curve: CurveId,
        public_key: Self::Key,
    ) -> Result<Self::Controller, Self::Error> {
        Ok(ControllerPayload::SingleKey { curve, public_key })
    }
    fn multisig(
        &self,
        version: u8,
        threshold: u16,
        members: Self::Members,
    ) -> Result<Self::Controller, Self::Error> {
        MultisigPolicy::validate_canonical_members(
            version,
            threshold,
            members.iter().map(|m| (&m.public_key, m.weight)),
        )
        .map_err(AccountAddressError::InvalidMultisigPolicy)?;
        Ok(ControllerPayload::MultiSig(MultisigPayload {
            version,
            threshold,
            members,
        }))
    }
}

/// Validate all fixed header/controller fields using the same destination grammar.
pub(in crate::account) fn canonical<D: Destination>(
    bytes: &[u8],
    destination: &D,
) -> Result<D::Controller, D::Error> {
    let first = *bytes.first().ok_or(AccountAddressError::InvalidLength)?;
    let header = AddressHeader::decode(first)?;
    let mut cursor = 1;
    let (class, controller) = controller(bytes, &mut cursor, destination)?;
    if cursor != bytes.len() {
        return Err(AccountAddressError::UnexpectedTrailingBytes.into());
    }
    if header.class != class {
        return Err(AccountAddressError::UnsupportedAddressFormat.into());
    }
    Ok(controller)
}

/// Strict AccountId literal entry; never accepts an alternate identity envelope.
pub(in crate::account) fn account_literal<D: Destination>(
    input: &str,
    destination: &D,
) -> Result<D::Controller, D::Error> {
    if input.is_empty() || input.trim() != input || input.contains('@') {
        return Err(AccountAddressError::UnsupportedAddressFormat.into());
    }
    encoded_literal(input, Some(chain_discriminant()), destination)
}

/// Address parsing may explicitly accept an embedded chain independently of the local default.
pub(in crate::account) fn encoded_literal<D: Destination>(
    input: &str,
    expected: Option<u16>,
    destination: &D,
) -> Result<D::Controller, D::Error> {
    if input.trim().is_empty() {
        return Err(AccountAddressError::InvalidLength.into());
    }
    if input.trim() != input || input.starts_with("0x") || input.starts_with("0X") {
        return Err(AccountAddressError::UnsupportedAddressFormat.into());
    }
    // Map only the missing envelope diagnostic; a real resource/capability cause
    // stays terminal in the shared prefix search and is never restaged.
    let (found, bytes) =
        decode_i105_literal(input, expected, destination).map_err(D::encoded_error)?;
    let controller = canonical(&bytes, destination)?;
    ensure_literal(input, found, &bytes, destination)?;
    Ok(controller)
}

/// Compare the canonical re-encoding without creating a rendered string.
fn ensure_literal<D: Destination>(
    input: &str,
    discriminant: u16,
    canonical: &[u8],
    destination: &D,
) -> Result<(), D::Error> {
    let digits = encode_base_n(canonical, I105_BASE, destination)?;
    let checksum = i105_checksum_digits(canonical);
    let mut numeric = [0; 6];
    let sentinel = write_i105_sentinel(discriminant, &mut numeric);
    let mut remaining = input.as_bytes();
    let Some(rest) = remaining.strip_prefix(sentinel) else {
        return Err(AccountAddressError::UnsupportedAddressFormat.into());
    };
    remaining = rest;
    for &digit in digits.iter().chain(checksum.iter()) {
        let symbol = i105_digit_symbol(digit)?;
        let Some(rest) = remaining.strip_prefix(symbol.as_bytes()) else {
            return Err(AccountAddressError::UnsupportedAddressFormat.into());
        };
        remaining = rest;
    }
    if !remaining.is_empty() {
        return Err(AccountAddressError::UnsupportedAddressFormat.into());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn controller<D: Destination>(
    bytes: &[u8],
    cursor: &mut usize,
    destination: &D,
) -> Result<(AddressClass, D::Controller), D::Error> {
    let tag = *bytes
        .get(*cursor)
        .ok_or(AccountAddressError::InvalidLength)?;
    *cursor += 1;
    match tag {
        CONTROLLER_SINGLE_KEY_TAG => {
            let curve_raw = *bytes
                .get(*cursor)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += 1;
            let curve = CurveId::try_from(curve_raw).map_err(AccountAddressError::from)?;
            let len = *bytes
                .get(*cursor)
                .ok_or(AccountAddressError::InvalidLength)? as usize;
            *cursor += 1;
            let payload = bytes
                .get(*cursor..*cursor + len)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += len;
            let public_key = destination.key(curve.algorithm(), payload)?;
            destination
                .single(curve, public_key)
                .map(|controller| (AddressClass::SingleKey, controller))
        }
        CONTROLLER_SINGLE_KEY_EXTENDED_TAG => {
            let curve_raw = *bytes
                .get(*cursor)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += 1;
            let curve = CurveId::try_from(curve_raw).map_err(AccountAddressError::from)?;
            let len_bytes = bytes
                .get(*cursor..*cursor + 2)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += 2;
            let len = u16::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
            if u8::try_from(len).is_ok() {
                return Err(AccountAddressError::InvalidLength.into());
            }
            let payload = bytes
                .get(*cursor..*cursor + len)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += len;
            let public_key = destination.key(curve.algorithm(), payload)?;
            destination
                .single(curve, public_key)
                .map(|controller| (AddressClass::SingleKey, controller))
        }
        CONTROLLER_MULTISIG_TAG => {
            let version = *bytes
                .get(*cursor)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += 1;
            let threshold_bytes = bytes
                .get(*cursor..*cursor + 2)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += 2;
            let threshold = u16::from_be_bytes(threshold_bytes.try_into().unwrap());
            let member_count_bytes = bytes
                .get(*cursor..*cursor + 2)
                .ok_or(AccountAddressError::InvalidLength)?;
            *cursor += 2;
            let member_count = u16::from_be_bytes(member_count_bytes.try_into().unwrap());
            let member_count = usize::from(member_count);
            if member_count > CONTROLLER_MULTISIG_MEMBER_MAX {
                return Err(AccountAddressError::MultisigMemberOverflow(member_count).into());
            }
            preflight_multisig_members(bytes, *cursor, member_count)?;
            let mut members = destination.members(member_count)?;
            for _ in 0..member_count {
                let curve_raw = *bytes
                    .get(*cursor)
                    .ok_or(AccountAddressError::InvalidLength)?;
                *cursor += 1;
                let curve = CurveId::try_from(curve_raw).map_err(AccountAddressError::from)?;
                let weight_bytes = bytes
                    .get(*cursor..*cursor + 2)
                    .ok_or(AccountAddressError::InvalidLength)?;
                *cursor += 2;
                let weight = u16::from_be_bytes(weight_bytes.try_into().unwrap());
                let key_len_bytes = bytes
                    .get(*cursor..*cursor + 2)
                    .ok_or(AccountAddressError::InvalidLength)?;
                *cursor += 2;
                let key_len = u16::from_be_bytes(key_len_bytes.try_into().unwrap()) as usize;
                let payload = bytes
                    .get(*cursor..*cursor + key_len)
                    .ok_or(AccountAddressError::InvalidLength)?;
                *cursor += key_len;
                let public_key = destination.key(curve.algorithm(), payload)?;
                destination.push(&mut members, curve, weight, public_key)?;
            }
            destination
                .multisig(version, threshold, members)
                .map(|controller| (AddressClass::MultiSig, controller))
        }
        other => Err(AccountAddressError::UnknownControllerTag(other).into()),
    }
}

pub(super) fn decode_i105_literal<D: Destination>(
    input: &str,
    expected_discriminant: Option<u16>,
    destination: &D,
) -> Result<(u16, Work<u8>), D::Error> {
    match decode_i105_literal_with_embedded_discriminant(input, destination) {
        Ok((found, canonical)) => {
            if let Some(expected) = expected_discriminant
                && found != expected
            {
                return Err(
                    AccountAddressError::UnexpectedNetworkPrefix { expected, found }.into(),
                );
            }
            Ok((found, canonical))
        }
        Err(error) => {
            // Format diagnostics may inspect the expected payload; a resource
            // refusal is terminal and must retain its original observer.
            if D::is_resource(&error) && !cfg!(all(test, sumeragi_model_mutation = "DM24")) {
                return Err(error);
            }
            let Some(expected) = expected_discriminant else {
                return Err(error);
            };
            let mut numeric = [0; 6];
            let sentinel = core::str::from_utf8(write_i105_sentinel(expected, &mut numeric))
                .map_err(|_| AccountAddressError::UnsupportedAddressFormat)?;
            let Some(payload) = input.strip_prefix(sentinel) else {
                return Err(error);
            };
            match decode_i105_payload(payload, destination) {
                Err(exact_error) => Err(exact_error),
                Ok(_) => Err(error),
            }
        }
    }
}
pub(super) fn decode_i105_literal_with_embedded_discriminant<D: Destination>(
    input: &str,
    destination: &D,
) -> Result<(u16, Work<u8>), D::Error> {
    for (discriminant, sentinel) in [
        (CHAIN_DISCRIMINANT_SORA, I105_SENTINEL_SORA),
        (CHAIN_DISCRIMINANT_TEST, I105_SENTINEL_TEST),
        (CHAIN_DISCRIMINANT_DEV, I105_SENTINEL_DEV),
    ] {
        if let Some(payload) = input.strip_prefix(sentinel) {
            return decode_i105_payload(payload, destination)
                .map(|canonical| (discriminant, canonical));
        }
    }
    let Some(rest) = input.strip_prefix(I105_SENTINEL_FALLBACK_PREFIX) else {
        return Err(AccountAddressError::MissingI105Sentinel.into());
    };
    let mut decoded = None;
    let mut first_err = None;
    let mut structural_err = None;
    for sentinel_len in 1..=5 {
        let Some((candidate, payload)) = numeric_i105_sentinel_candidate(rest, sentinel_len) else {
            continue;
        };
        match decode_i105_payload(payload, destination) {
            Ok(canonical) => {
                let controller = match self::canonical(&canonical, destination) {
                    Ok(address) => address,
                    Err(err) => {
                        if D::is_resource(&err)
                            && !cfg!(all(test, sumeragi_model_mutation = "DM23"))
                        {
                            return Err(err);
                        }
                        structural_err.get_or_insert(err);
                        continue;
                    }
                };
                if let Err(err) = ensure_literal(input, candidate, &canonical, destination) {
                    if D::is_resource(&err) && !cfg!(all(test, sumeragi_model_mutation = "DM23")) {
                        return Err(err);
                    }
                    structural_err.get_or_insert(err);
                    continue;
                }
                drop(controller);
                if decoded.replace((candidate, canonical)).is_some() {
                    return Err(AccountAddressError::UnsupportedAddressFormat.into());
                }
            }
            Err(err) => {
                if D::is_resource(&err) && !cfg!(all(test, sumeragi_model_mutation = "DM23")) {
                    return Err(err);
                }
                first_err.get_or_insert(err);
            }
        }
    }
    decoded.ok_or_else(|| {
        structural_err
            .or(first_err)
            .unwrap_or_else(|| AccountAddressError::MissingI105Sentinel.into())
    })
}
pub(super) fn encode_base_n<D: BufferDestination>(
    bytes: &[u8],
    base: u32,
    destination: &D,
) -> Result<Work<u8>, D::Error> {
    if !(2..=256).contains(&base) {
        return Err(AccountAddressError::InvalidI105Base.into());
    }
    if bytes.is_empty() {
        let mut digits = destination.buffer(1)?;
        digits.push(0);
        return Ok(digits);
    }
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = &bytes[leading_zeros..];
    if significant.is_empty() {
        let mut digits = destination.buffer(leading_zeros)?;
        digits.resize(leading_zeros, 0);
        return Ok(digits);
    }

    let maximum_limbs = significant.len().div_ceil(8);
    let mut limbs: Work<u64> = destination.buffer(maximum_limbs)?;
    let first = significant.len() % 8;
    let mut cursor = 0_usize;
    while cursor < significant.len() {
        let width = if cursor == 0 && first != 0 { first } else { 8 };
        let mut limb = 0_u64;
        for &byte in &significant[cursor..cursor + width] {
            limb = (limb << 8) | u64::from(byte);
        }
        limbs.push(limb);
        cursor += width;
    }

    let base = u64::from(base);
    let mut group_radix = base;
    let mut group_width = 1_usize;
    while let Some(next) = group_radix.checked_mul(base) {
        group_radix = next;
        group_width += 1;
    }
    // The generic helper accepts every radix in 2..=256. Use its actual
    // information bound so a smaller radix cannot outgrow admitted storage.
    let bits_per_digit = usize::try_from(u64::BITS - base.leading_zeros() - 1)
        .expect("bounded radix bit width fits usize");
    let maximum_digits = bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(bits_per_digit - 1))
        .map(|bits| bits / bits_per_digit)
        .and_then(|digits| digits.checked_add(leading_zeros))
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let mut digits = destination.buffer(maximum_digits)?;
    while !limbs.is_empty() {
        let mut remainder = 0_u128;
        for limb in limbs.iter_mut() {
            let value = (remainder << 64) | u128::from(*limb);
            *limb = u64::try_from(value / u128::from(group_radix))
                .expect("division by a non-zero u64 radix leaves one u64 quotient limb");
            remainder = value % u128::from(group_radix);
        }
        let first_nonzero = limbs
            .iter()
            .position(|&limb| limb != 0)
            .unwrap_or(limbs.len());
        if first_nonzero != 0 {
            limbs.discard_prefix(first_nonzero);
        }
        let emitted_width = if limbs.is_empty() {
            let mut value = remainder;
            let mut width = 1;
            while value >= u128::from(base) {
                value /= u128::from(base);
                width += 1;
            }
            width
        } else {
            group_width
        };
        for _ in 0..emitted_width {
            digits.push(
                u8::try_from(remainder % u128::from(base))
                    .expect("radix remainder digit fits in u8"),
            );
            remainder /= u128::from(base);
        }
    }
    digits.extend(std::iter::repeat_n(0, leading_zeros));
    digits.reverse();
    Ok(digits)
}
pub(super) fn decode_base_n<D: Destination>(
    digits: &[u8],
    base: u32,
    destination: &D,
) -> Result<Work<u8>, D::Error> {
    if !(2..=256).contains(&base) {
        return Err(AccountAddressError::InvalidI105Base.into());
    }
    if digits.is_empty() {
        return Err(AccountAddressError::InvalidLength.into());
    }
    validate_base_n_digits(digits, base)?;
    let leading_zeros = digits.iter().take_while(|&&d| d == 0).count();
    let significant = &digits[leading_zeros..];
    if significant.is_empty() {
        let mut bytes = destination.buffer(leading_zeros)?;
        bytes.resize(leading_zeros, 0);
        return Ok(bytes);
    }

    // Consume several source digits per big-integer pass. The former repeated
    // division walked almost the complete digit vector once per output byte,
    // making malformed long I105 literals quadratic with a large constant.
    // Base-105 admits nine digits in one u64 limb, reducing the same exact
    // conversion to grouped u128 multiply-add operations.
    let base = u64::from(base);
    let mut group_digits = 1_usize;
    let mut group_radix = base;
    while let Some(next) = group_radix.checked_mul(base) {
        group_radix = next;
        group_digits += 1;
    }
    let bits_per_digit =
        usize::try_from(u64::BITS - (base - 1).leading_zeros()).expect("u64 bit width fits usize");
    let maximum_limbs = significant
        .len()
        .checked_mul(bits_per_digit)
        .and_then(|bits| bits.checked_add(63))
        .map(|bits| bits / 64)
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let mut limbs: Work<u64> = destination.buffer(maximum_limbs)?;

    let first_group = significant.len() % group_digits;
    let mut cursor = 0_usize;
    while cursor < significant.len() {
        let width = if cursor == 0 && first_group != 0 {
            first_group
        } else {
            group_digits
        };
        let end = cursor + width;
        let mut chunk = 0_u64;
        let mut multiplier = 1_u64;
        for &digit in &significant[cursor..end] {
            chunk = chunk
                .checked_mul(base)
                .and_then(|value| value.checked_add(u64::from(digit)))
                .ok_or(AccountAddressError::DecodeResourceLimit)?;
            multiplier = multiplier
                .checked_mul(base)
                .ok_or(AccountAddressError::DecodeResourceLimit)?;
        }
        if limbs.is_empty() {
            limbs.push(chunk);
        } else {
            let mut carry = u128::from(chunk);
            for limb in limbs.iter_mut() {
                let product = u128::from(*limb) * u128::from(multiplier) + carry;
                *limb = u64::try_from(product & u128::from(u64::MAX))
                    .expect("masked base-N product limb fits in u64");
                carry = product >> 64;
            }
            if carry != 0 {
                limbs.push(u64::try_from(carry).expect("u64 radix leaves at most one carry limb"));
            }
        }
        cursor = end;
    }

    let most_significant = *limbs
        .last()
        .expect("a non-zero leading source digit creates one limb");
    let significant_bytes = limbs
        .len()
        .checked_mul(8)
        .and_then(|bytes| {
            bytes.checked_sub(usize::try_from(most_significant.leading_zeros() / 8).ok()?)
        })
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let output_bytes = leading_zeros
        .checked_add(significant_bytes)
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let mut bytes = destination.buffer(output_bytes)?;
    bytes.resize(leading_zeros, 0);
    let top = most_significant.to_be_bytes();
    let top_start =
        usize::try_from(most_significant.leading_zeros() / 8).expect("u32 byte count fits usize");
    bytes.extend_from_slice(&top[top_start..]);
    for limb in limbs[..limbs.len() - 1].iter().rev() {
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    debug_assert_eq!(bytes.len(), output_bytes);
    Ok(bytes)
}
pub(super) fn decode_i105_payload<D: Destination>(
    payload: &str,
    destination: &D,
) -> Result<Work<u8>, D::Error> {
    let digits = i105_payload_digits(payload, destination)?;
    if digits.len() <= I105_CHECKSUM_LEN {
        return Err(AccountAddressError::I105TooShort.into());
    }
    let split_at = digits.len() - I105_CHECKSUM_LEN;
    let canonical = decode_base_n(&digits[..split_at], I105_BASE, destination)?;
    let expected = i105_checksum_digits(&canonical);
    if digits[split_at..] != expected {
        return Err(AccountAddressError::ChecksumMismatch.into());
    }
    Ok(canonical)
}
pub(super) fn i105_payload_digits<D: Destination>(
    payload: &str,
    destination: &D,
) -> Result<Work<u8>, D::Error> {
    let digit_count = payload.chars().count();
    let mut digits = destination.buffer(digit_count)?;
    for ch in payload.chars() {
        let mut symbol = [0_u8; 4];
        let encoded = ch.encode_utf8(&mut symbol);
        let Some(digit) = lookup_i105_digit(encoded) else {
            return Err(AccountAddressError::InvalidI105Char(ch).into());
        };
        digits.push(digit);
    }
    Ok(digits)
}

#[cfg(test)]
mod tests;
