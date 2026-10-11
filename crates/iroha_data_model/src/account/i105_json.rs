//! Allocation-bounded canonical I105 JSON output for account identifiers.
use super::{AccountController, AccountId, curve::CurveId};
use iroha_crypto::PublicKey;
use norito::json::{BoundedJsonError, JsonWriteSink};
use std::{alloc::Layout, mem::MaybeUninit, ptr::NonNull};
const ADDRESS_HEADER_SINGLE_V1: u8 = 0b0000_0010;
const ADDRESS_HEADER_MULTISIG_V1: u8 = 0b0000_1010;
const CONTROLLER_SINGLE_KEY_TAG: u8 = 0;
const CONTROLLER_SINGLE_KEY_EXTENDED_TAG: u8 = 2;
const CONTROLLER_MULTISIG_TAG: u8 = 1;
const I105_BASE: u64 = 105;
const I105_LIMB_DIGITS: usize = 8;
const I105_LIMB_BASE: u64 = 14_774_554_437_890_625; // 105^8
const I105_CHECKSUM_LEN: usize = 6;
/// Write one canonical `AccountId` JSON string without constructing an
/// `AccountAddress` or staging the rendered string.
///
/// The sole attacker-sized scratch object is an exact-layout boxed slice of base-105^8 limbs. For
/// an `N`-byte canonical address, `ceil(4N/3)` base-105 digits suffice because every digit carries
/// more than six bits. The non-zero V1 header also means the emitted numeral contains at least `N`
/// digits. Accounting for the partially occupied final limb, the reserved scratch is therefore at
/// most twice the complete emitted JSON body. Allocation is attempted fallibly before any unchecked
/// vector push. The exact scratch layout is charged to any active Norito resource scope before
/// requesting native storage.
pub(super) fn write_bounded(
    account: &AccountId,
    output: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    let prepared = PreparedI105::new(account)?;
    output.push('"')?;
    prepared.write_to(output)?;
    output.push('"')
}

/// Visit canonical I105 text without staging the complete account literal.
pub(super) fn visit_key_text(
    account: &AccountId,
    mut visitor: impl FnMut(&str) -> Result<(), BoundedJsonError>,
) -> Result<(), BoundedJsonError> {
    struct VisitorSink<'a, F> {
        visitor: &'a mut F,
    }

    impl<F> JsonWriteSink for VisitorSink<'_, F>
    where
        F: FnMut(&str) -> Result<(), BoundedJsonError>,
    {
        fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
            let mut bytes = [0_u8; 4];
            (self.visitor)(value.encode_utf8(&mut bytes))
        }

        fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
            (self.visitor)(value)
        }
    }

    let prepared = PreparedI105::new(account)?;
    prepared.write_to(&mut VisitorSink {
        visitor: &mut visitor,
    })
}

struct PreparedI105 {
    limbs: Box<[MaybeUninit<u64>]>,
    initialized_limbs: usize,
    checksum: [u8; I105_CHECKSUM_LEN],
}

impl PreparedI105 {
    fn new(account: &AccountId) -> Result<Self, BoundedJsonError> {
        let canonical_len = canonical_address_len(account)?;
        let maximum_limbs = maximum_base105_limbs(canonical_len)?;
        let limbs = try_allocate_exact_limbs(maximum_limbs)?;
        let mut encoder = I105Encoder::new(limbs);
        emit_canonical_address(account, |byte| encoder.push_canonical_byte(byte))?;
        if encoder.canonical_bytes != canonical_len || encoder.initialized_limbs().is_empty() {
            return Err(BoundedJsonError::LengthMismatch);
        }
        let I105Encoder {
            limbs,
            initialized_limbs,
            checksum,
            ..
        } = encoder;
        Ok(Self {
            limbs,
            initialized_limbs,
            checksum: checksum.finish(),
        })
    }

    fn write_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_sentinel(super::address::chain_discriminant(), output)?;
        write_base105_limbs(self.initialized_limbs(), output)?;
        for &digit in &self.checksum {
            write_i105_symbol(digit, output)?;
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn initialized_limbs(&self) -> &[u64] {
        // SAFETY: `PreparedI105::new` moves the initialized prefix out of an
        // `I105Encoder` together with its exact initialized length.
        unsafe {
            core::slice::from_raw_parts(self.limbs.as_ptr().cast::<u64>(), self.initialized_limbs)
        }
    }
}
#[allow(unsafe_code)]
fn try_allocate_exact_limbs(length: usize) -> Result<Box<[MaybeUninit<u64>]>, BoundedJsonError> {
    let layout = Layout::array::<MaybeUninit<u64>>(length)
        .map_err(|_| BoundedJsonError::AllocationFailed)?;
    if layout.size() == 0 {
        return Err(BoundedJsonError::Unsupported);
    }
    norito::core::reserve_decode_allocation(layout.size())
        .map_err(BoundedJsonError::from_decode_resource)?;
    // SAFETY: `layout` is non-zero and was constructed for exactly `length`
    // `MaybeUninit<u64>` values. `Box::from_raw` receives that same slice
    // layout and therefore deallocates it with the matching request size.
    let allocation = NonNull::new(unsafe { std::alloc::alloc(layout) })
        .ok_or(BoundedJsonError::AllocationFailed)?;
    // `Layout::array::<MaybeUninit<u64>>` guarantees the alignment required by this typed view.
    let allocation = allocation.cast::<MaybeUninit<u64>>();
    let slice = core::ptr::slice_from_raw_parts_mut(allocation.as_ptr(), length);
    Ok(unsafe { Box::from_raw(slice) })
}
fn canonical_address_len(account: &AccountId) -> Result<usize, BoundedJsonError> {
    let controller_len = match account.controller() {
        AccountController::Single(key) => {
            let (_, payload) = key_parts(key)?;
            let prefix = if u8::try_from(payload.len()).is_ok() {
                3_usize
            } else {
                u16::try_from(payload.len()).map_err(|_| BoundedJsonError::Unsupported)?;
                4_usize
            };
            prefix
                .checked_add(payload.len())
                .ok_or(BoundedJsonError::Unsupported)?
        }
        AccountController::Multisig(policy) => {
            u16::try_from(policy.members().len()).map_err(|_| BoundedJsonError::Unsupported)?;
            policy
                .members()
                .iter()
                .try_fold(6_usize, |length, member| {
                    let (_, payload) = key_parts(member.public_key())?;
                    u16::try_from(payload.len()).map_err(|_| BoundedJsonError::Unsupported)?;
                    length
                        .checked_add(5)
                        .and_then(|length| length.checked_add(payload.len()))
                        .ok_or(BoundedJsonError::Unsupported)
                })?
        }
    };
    controller_len
        .checked_add(1)
        .ok_or(BoundedJsonError::Unsupported)
}
fn maximum_base105_digits(canonical_len: usize) -> Result<usize, BoundedJsonError> {
    if canonical_len == 0 {
        return Err(BoundedJsonError::Unsupported);
    }
    canonical_len
        .checked_mul(4)
        .map(|digits| digits.div_ceil(3))
        .ok_or(BoundedJsonError::Unsupported)
}
fn maximum_base105_limbs(canonical_len: usize) -> Result<usize, BoundedJsonError> {
    Ok(maximum_base105_digits(canonical_len)?.div_ceil(I105_LIMB_DIGITS))
}
fn key_parts(key: &PublicKey) -> Result<(u8, &[u8]), BoundedJsonError> {
    let (algorithm, payload) = key
        .try_to_bytes()
        .map_err(|_| BoundedJsonError::Unsupported)?;
    let curve = CurveId::try_from_algorithm(algorithm)
        .map(CurveId::as_u8)
        .map_err(|_| BoundedJsonError::Unsupported)?;
    Ok((curve, payload))
}
fn emit_canonical_address(
    account: &AccountId,
    mut emit: impl FnMut(u8) -> Result<(), BoundedJsonError>,
) -> Result<(), BoundedJsonError> {
    match account.controller() {
        AccountController::Single(key) => {
            emit(ADDRESS_HEADER_SINGLE_V1)?;
            let (curve, payload) = key_parts(key)?;
            if let Ok(length) = u8::try_from(payload.len()) {
                for byte in [CONTROLLER_SINGLE_KEY_TAG, curve, length] {
                    emit(byte)?;
                }
            } else {
                let length =
                    u16::try_from(payload.len()).map_err(|_| BoundedJsonError::Unsupported)?;
                for byte in [CONTROLLER_SINGLE_KEY_EXTENDED_TAG, curve] {
                    emit(byte)?;
                }
                for byte in length.to_be_bytes() {
                    emit(byte)?;
                }
            }
            for &byte in payload {
                emit(byte)?;
            }
        }
        AccountController::Multisig(policy) => {
            for byte in [
                ADDRESS_HEADER_MULTISIG_V1,
                CONTROLLER_MULTISIG_TAG,
                policy.version(),
            ] {
                emit(byte)?;
            }
            for byte in policy.threshold().to_be_bytes() {
                emit(byte)?;
            }
            let member_count =
                u16::try_from(policy.members().len()).map_err(|_| BoundedJsonError::Unsupported)?;
            for byte in member_count.to_be_bytes() {
                emit(byte)?;
            }
            for member in policy.members() {
                let (curve, payload) = key_parts(member.public_key())?;
                emit(curve)?;
                for byte in member.weight().to_be_bytes() {
                    emit(byte)?;
                }
                let length =
                    u16::try_from(payload.len()).map_err(|_| BoundedJsonError::Unsupported)?;
                for byte in length.to_be_bytes() {
                    emit(byte)?;
                }
                for &byte in payload {
                    emit(byte)?;
                }
            }
        }
    }
    Ok(())
}
struct I105Encoder {
    limbs: Box<[MaybeUninit<u64>]>,
    initialized_limbs: usize,
    canonical_bytes: usize,
    checksum: I105Checksum,
}
impl I105Encoder {
    fn new(limbs: Box<[MaybeUninit<u64>]>) -> Self {
        Self {
            limbs,
            initialized_limbs: 0,
            canonical_bytes: 0,
            checksum: I105Checksum::new(),
        }
    }
    fn push_canonical_byte(&mut self, byte: u8) -> Result<(), BoundedJsonError> {
        self.canonical_bytes = self
            .canonical_bytes
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        self.checksum.push_byte(byte);
        let mut carry = u64::from(byte);
        for limb in self.initialized_limbs_mut() {
            let accumulator = *limb * 256 + carry;
            *limb = accumulator % I105_LIMB_BASE;
            carry = accumulator / I105_LIMB_BASE;
        }
        while carry != 0 {
            self.push_limb(carry % I105_LIMB_BASE)?;
            carry /= I105_LIMB_BASE;
        }
        Ok(())
    }
    fn push_limb(&mut self, limb: u64) -> Result<(), BoundedJsonError> {
        if self.initialized_limbs >= self.limbs.len() {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.limbs[self.initialized_limbs].write(limb);
        self.initialized_limbs += 1;
        Ok(())
    }
    #[allow(unsafe_code)]
    fn initialized_limbs(&self) -> &[u64] {
        // SAFETY: `push_limb` initializes every slot below
        // `initialized_limbs`, and no initialized value is subsequently moved
        // out of the backing slice.
        unsafe {
            core::slice::from_raw_parts(self.limbs.as_ptr().cast::<u64>(), self.initialized_limbs)
        }
    }
    #[allow(unsafe_code)]
    fn initialized_limbs_mut(&mut self) -> &mut [u64] {
        // SAFETY: identical initialization invariant to
        // `initialized_limbs`; the mutable borrow of `self` is exclusive.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.limbs.as_mut_ptr().cast::<u64>(),
                self.initialized_limbs,
            )
        }
    }
}
struct I105Checksum {
    value: u32,
    accumulator: u32,
    bits: u32,
}
impl I105Checksum {
    fn new() -> Self {
        let mut checksum = Self {
            value: 1,
            accumulator: 0,
            bits: 0,
        };
        for &byte in b"snx" {
            checksum.step(byte >> 5);
        }
        checksum.step(0);
        for &byte in b"snx" {
            checksum.step(byte & 0x1f);
        }
        checksum
    }
    fn push_byte(&mut self, byte: u8) {
        self.accumulator = (self.accumulator << 8) | u32::from(byte);
        self.bits += 8;
        while self.bits >= 5 {
            self.bits -= 5;
            let word = u8::try_from((self.accumulator >> self.bits) & 0x1f)
                .expect("five-bit checksum word fits in one byte");
            self.step(word);
        }
        // Only the low `bits` are carried into the next byte. Masking the
        // already-consumed prefix keeps the fixed-width accumulator bounded
        // for arbitrarily long multisig controllers without changing the
        // emitted five-bit stream.
        self.accumulator &= (1_u32 << self.bits) - 1;
    }
    fn finish(mut self) -> [u8; I105_CHECKSUM_LEN] {
        if self.bits > 0 {
            let word = u8::try_from((self.accumulator << (5 - self.bits)) & 0x1f)
                .expect("five-bit checksum word fits in one byte");
            self.step(word);
        }
        for _ in 0..I105_CHECKSUM_LEN {
            self.step(0);
        }
        self.value ^= 0x2bc8_30a3;
        let mut result = [0_u8; I105_CHECKSUM_LEN];
        for (index, slot) in result.iter_mut().enumerate() {
            let shift = 5 * (I105_CHECKSUM_LEN - 1 - index);
            *slot = u8::try_from((self.value >> shift) & 0x1f)
                .expect("five-bit checksum word fits in one byte");
        }
        result
    }
    fn step(&mut self, word: u8) {
        const GENERATORS: [u32; 5] = [
            0x3b6a_57b2,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ];
        let top = self.value >> 25;
        self.value = ((self.value & 0x01ff_ffff) << 5) ^ u32::from(word);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                self.value ^= generator;
            }
        }
    }
}
fn write_sentinel(
    discriminant: u16,
    output: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    match discriminant {
        0x02f1 => output.push_str("sora"),
        0x0171 => output.push_str("test"),
        0 => output.push_str("dev"),
        discriminant => {
            output.push('n')?;
            write_u16_decimal(discriminant, output)
        }
    }
}
fn write_u16_decimal(
    mut value: u16,
    output: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    let mut digits = [0_u8; 5];
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(value % 10).expect("decimal digit fits in one byte");
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.push_str(
        core::str::from_utf8(&digits[cursor..]).expect("decimal digit buffer is valid UTF-8"),
    )
}
fn write_base105_limbs(
    limbs: &[u64],
    output: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    let Some((&most_significant, remaining)) = limbs.split_last() else {
        return Err(BoundedJsonError::LengthMismatch);
    };
    let mut digits = [0_u8; I105_LIMB_DIGITS];
    let significant_start = expand_base105_limb(most_significant, &mut digits, false);
    for &digit in &digits[significant_start..] {
        write_i105_symbol(digit, output)?;
    }
    for &limb in remaining.iter().rev() {
        expand_base105_limb(limb, &mut digits, true);
        for &digit in &digits {
            write_i105_symbol(digit, output)?;
        }
    }
    Ok(())
}
fn expand_base105_limb(mut limb: u64, digits: &mut [u8; I105_LIMB_DIGITS], pad: bool) -> usize {
    let mut cursor = digits.len();
    while limb != 0 {
        cursor -= 1;
        digits[cursor] = u8::try_from(limb % I105_BASE).expect("base-105 digit fits in one byte");
        limb /= I105_BASE;
    }
    if pad {
        digits[..cursor].fill(0);
        0
    } else if cursor == digits.len() {
        digits[digits.len() - 1] = 0;
        digits.len() - 1
    } else {
        cursor
    }
}
fn write_i105_symbol(digit: u8, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
    super::address::i105_symbol(digit)
        .ok_or(BoundedJsonError::Unsupported)
        .and_then(|symbol| output.push_str(symbol))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{MultisigMember, MultisigPolicy, address::ChainDiscriminantGuard};
    use iroha_crypto::{Algorithm, KeyPair};
    fn keypair(seed: u64) -> KeyPair {
        let mut bytes = vec![0xA5; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        KeyPair::try_from_seed(bytes, Algorithm::Ed25519)
            .expect("derive checked AccountId JSON fixture keypair")
    }
    fn assert_bounded_parity(account: &AccountId) {
        for discriminant in [0x02f1, 0x0171, 0, 42] {
            let _guard = ChainDiscriminantGuard::enter(discriminant);
            let ordinary = norito::json::to_json(account).expect("ordinary JSON serialization");
            let exact = norito::json::to_json_bounded(account, ordinary.len())
                .expect("exact bounded JSON serialization");
            assert_eq!(exact, ordinary);
            assert_eq!(
                norito::json::to_json_bounded(account, ordinary.len() - 1),
                Err(BoundedJsonError::BodyTooLarge)
            );
            let canonical_len = canonical_address_len(account).expect("canonical address length");
            let scratch = maximum_base105_limbs(canonical_len)
                .expect("scratch bound")
                .saturating_mul(core::mem::size_of::<u64>());
            assert!(
                scratch <= canonical_len.saturating_mul(2),
                "every valid account controller keeps I105 scratch within two decoded canonical units"
            );
            assert!(scratch <= ordinary.len().saturating_mul(2));
        }
    }
    #[test]
    fn bounded_account_json_matches_ordinary_for_single_controller() {
        assert_bounded_parity(&AccountId::new(keypair(1).public_key().clone()));
    }
    #[test]
    fn bounded_account_json_matches_ordinary_for_large_multisig_controller() {
        let members = (0..=u8::MAX)
            .map(|index| {
                MultisigMember::new(keypair(u64::from(index) + 2).public_key().clone(), 1)
                    .expect("valid multisig member")
            })
            .collect();
        let policy = MultisigPolicy::new(1, members).expect("valid multisig policy");
        assert_bounded_parity(&AccountId::new_multisig(policy));
    }
    #[test]
    fn base105_digit_capacity_covers_every_byte_width() {
        for canonical_len in 1..=4096 {
            let digits = maximum_base105_digits(canonical_len).expect("bounded digit capacity");
            let scratch = maximum_base105_limbs(canonical_len)
                .expect("bounded limb capacity")
                .saturating_mul(core::mem::size_of::<u64>());
            assert!(digits >= canonical_len);
            assert!(scratch <= canonical_len.saturating_mul(2).saturating_add(7));
        }
    }
    #[test]
    fn limb_scratch_uses_the_requested_exact_layout() {
        for length in [1, 2, 17, 257] {
            let storage = try_allocate_exact_limbs(length).expect("allocate exact limb scratch");
            assert_eq!(storage.len(), length);
            assert_eq!(
                core::mem::size_of_val(storage.as_ref()),
                length * core::mem::size_of::<u64>()
            );
        }
    }
    #[test]
    fn checked_i105_scratch_is_charged_before_any_visitor_output() {
        fn visit_without_destination(
            account: &AccountId,
            expected: &str,
        ) -> (Result<(), BoundedJsonError>, usize) {
            let mut offset = 0;
            let result = visit_key_text(account, |chunk| {
                let end = offset + chunk.len();
                assert_eq!(expected.get(offset..end), Some(chunk));
                offset = end;
                Ok(())
            });
            (result, offset)
        }

        let _guard = ChainDiscriminantGuard::enter(0x02f1);
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let members = (0..2)
            .map(|index| {
                MultisigMember::new(keypair(index + 10).public_key().clone(), 1)
                    .expect("valid multisig member")
            })
            .collect();
        // Independent V1 fixture widths: a single controller is header(1) +
        // tag/curve/length(3) + Ed25519 key(32) = 36 bytes. Two multisig members
        // are header(1) + tag/version/threshold/count(6) + 2 * (curve/weight/
        // length/key)(37) = 81 bytes. Their exact limb requests are 48 and 112.
        let accounts = [
            (AccountId::new(keypair(9).public_key().clone()), 36, 48),
            (
                AccountId::new_multisig(
                    MultisigPolicy::new(2, members).expect("valid multisig policy"),
                ),
                81,
                112,
            ),
        ];
        for (account, expected_canonical, expected_scratch) in accounts {
            let expected = account.canonical_i105().expect("canonical account literal");
            assert_eq!(
                canonical_address_len(&account).expect("canonical address length"),
                expected_canonical,
            );

            // The visitor borrows its expected bytes and has no destination allocation.
            // A zero budget must therefore refuse the native limb allocation itself.
            let ((rejected, emitted), usage) =
                norito::core::with_decode_limits_measured(limits(0), || {
                    visit_without_destination(&account, &expected)
                });
            assert_eq!(
                rejected,
                Err(BoundedJsonError::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded {
                        attempted: u64::try_from(expected_scratch).unwrap(),
                        limit: 0,
                    },
                ))
            );
            assert_eq!(
                emitted, 0,
                "no account chunk may escape a refused allocation"
            );
            assert_eq!(usage.total_allocated_bytes(), 0);

            let ((accepted, emitted), usage) =
                norito::core::with_decode_limits_measured(limits(expected_scratch), || {
                    visit_without_destination(&account, &expected)
                });
            assert_eq!(accepted, Ok(()));
            assert_eq!(emitted, expected.len());
            assert_eq!(usage.total_allocated_bytes(), expected_scratch);

            let ((rejected, emitted), usage) =
                norito::core::with_decode_limits_measured(limits(expected_scratch - 1), || {
                    visit_without_destination(&account, &expected)
                });
            assert_eq!(
                rejected,
                Err(BoundedJsonError::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded {
                        attempted: u64::try_from(expected_scratch).unwrap(),
                        limit: u64::try_from(expected_scratch - 1).unwrap(),
                    },
                ))
            );
            assert_eq!(emitted, 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(
                visit_without_destination(&account, &expected),
                (Ok(()), expected.len())
            );
        }
    }
}
