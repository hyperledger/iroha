//! Address encoding utilities for accounts.
use super::{
    AccountController, AccountId, MultisigMember, MultisigPolicy, MultisigPolicyError,
    curve::{CurveId, CurveRegistryError},
};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
    str::FromStr,
};
use iroha_crypto::{Algorithm, PublicKey};
use iroha_schema::{Ident, IntoSchema, MetaMap, Metadata, TypeId, VecMeta};

use norito::json::{self, JsonDeserialize, JsonSerialize};
use norito::{
    DeserializePayload, SerializePayload,
    core::{self as ncore, Archived},
};
use std::{
    cell::Cell,
    sync::{
        LazyLock,
        atomic::{AtomicU16, Ordering},
    },
};
use thiserror::Error;
#[cfg(test)]
#[path = "address/canonical_multisig_tests.rs"]
mod canonical_multisig_tests;
#[cfg(test)]
#[path = "address/retained_output_tests.rs"]
mod retained_output_tests;

pub mod compliance_vectors;
/// Obtain the currently configured chain discriminant for i105 literal encoding,
/// honoring any thread-local override.
#[must_use]
pub fn chain_discriminant() -> u16 {
    CHAIN_DISCRIMINANT_OVERRIDE.with(|cell| {
        cell.get()
            .unwrap_or_else(|| CHAIN_DISCRIMINANT.load(Ordering::Relaxed))
    })
}
/// Set the global chain discriminant used by i105 addresses, returning the previous value.
pub fn set_chain_discriminant(discriminant: u16) -> u16 {
    CHAIN_DISCRIMINANT.swap(discriminant, Ordering::Relaxed)
}
const HEADER_VERSION_V1: u8 = 0;
const HEADER_NORM_VERSION_V1: u8 = 1;
const I105_SENTINEL_SORA: &str = "sora";
const I105_SENTINEL_TEST: &str = "test";
const I105_SENTINEL_DEV: &str = "dev";
const I105_SENTINEL_FALLBACK_PREFIX: &str = "n";
const I105_CHECKSUM_LEN: usize = 6;
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const I105_BASE_U8: u8 = 105;
const I105_BASE: u32 = I105_BASE_U8 as u32;
const CHAIN_DISCRIMINANT_SORA: u16 = 0x02F1;
const CHAIN_DISCRIMINANT_TEST: u16 = 0x0171;
const CHAIN_DISCRIMINANT_DEV: u16 = 0x0000;
const DEFAULT_CHAIN_DISCRIMINANT: u16 = CHAIN_DISCRIMINANT_SORA;
static CHAIN_DISCRIMINANT: AtomicU16 = AtomicU16::new(DEFAULT_CHAIN_DISCRIMINANT);
thread_local! {
    static CHAIN_DISCRIMINANT_OVERRIDE: Cell<Option<u16>> = const { Cell::new(None) };
}
/// Scoped chain discriminant override for the current thread.
#[derive(Debug)]
pub struct ChainDiscriminantGuard(Option<u16>);
impl ChainDiscriminantGuard {
    /// Override the chain discriminant for the current thread.
    pub fn enter(discriminant: u16) -> Self {
        let previous = CHAIN_DISCRIMINANT_OVERRIDE.with(|cell| {
            let prev = cell.get();
            cell.set(Some(discriminant));
            prev
        });
        Self(previous)
    }
}
impl Drop for ChainDiscriminantGuard {
    fn drop(&mut self) {
        CHAIN_DISCRIMINANT_OVERRIDE.with(|cell| cell.set(self.0));
    }
}
/// Canonical representation of an account address payload.
#[derive(Clone, Debug, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::address::AccountAddress")]
pub struct AccountAddress {
    header: AddressHeader,
    controller: ControllerPayload,
}
impl AccountAddress {
    /// Construct from an [`AccountId`] assuming a single-key controller.
    ///
    /// Construct the canonical byte representation of the address payload.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the account cannot be represented with the
    /// supported address header or controller payload variants.
    pub fn from_account_id(account: &AccountId) -> Result<Self, AccountAddressError> {
        let (class, controller) = ControllerPayload::from_account_controller(account.controller())?;
        let header = AddressHeader::new(HEADER_VERSION_V1, class, HEADER_NORM_VERSION_V1)?;
        Ok(Self { header, controller })
    }
    /// Encode the payload as a canonical I105 literal using the active chain discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if canonical payload construction or i105 encoding fails.
    pub fn to_i105(&self) -> Result<String, AccountAddressError> {
        self.to_i105_for_discriminant(chain_discriminant())
    }
    /// Encode the payload as a canonical I105 literal with a specific chain discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if canonical payload construction or i105 encoding fails.
    pub fn to_i105_for_discriminant(
        &self,
        discriminant: u16,
    ) -> Result<String, AccountAddressError> {
        let canonical = self.canonical_bytes()?;
        encode_i105_literal(discriminant, &canonical)
    }
    /// Render an existing account without crossing an inbound key ownership boundary.
    pub(super) fn retained_account_i105(
        account: &AccountId,
        discriminant: u16,
    ) -> Result<String, AccountAddressError> {
        encode_i105_literal(discriminant, &canonical_output_bytes(account)?)
    }

    /// Render the same retained canonical bytes through the shared hexadecimal sink.
    pub(super) fn retained_account_hex(account: &AccountId) -> Result<String, AccountAddressError> {
        canonical_output_hex(account)
    }

    /// Parse an address payload from its canonical byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the byte slice does not contain a valid
    /// canonical representation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AccountAddressError> {
        if bytes.is_empty() {
            return Err(AccountAddressError::InvalidLength);
        }
        let header = AddressHeader::decode(bytes[0])?;
        let mut controller_cursor = 1usize;
        let controller = ControllerPayload::decode(bytes, &mut controller_cursor)?;
        if controller_cursor != bytes.len() {
            return Err(AccountAddressError::UnexpectedTrailingBytes);
        }
        let controller_class = match &controller {
            ControllerPayload::SingleKey { .. } => AddressClass::SingleKey,
            ControllerPayload::MultiSig(_) => AddressClass::MultiSig,
        };
        if header.class != controller_class {
            return Err(AccountAddressError::UnsupportedAddressFormat);
        }
        Ok(Self { header, controller })
    }
    /// Decode the canonical I105 representation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the string contains symbols outside the canonical I105
    /// alphabet, carries a mismatching chain discriminant, or fails checksum validation.
    pub fn from_i105(encoded: &str) -> Result<Self, AccountAddressError> {
        let expected = chain_discriminant();
        let address = Self::from_i105_for_discriminant(encoded, Some(expected))?;
        address.ensure_canonical_i105_literal(encoded, expected)?;
        Ok(address)
    }
    /// Decode the i105 representation, optionally enforcing an expected chain discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the string carries a mismatching discriminant, has
    /// symbols outside the canonical I105 alphabet, or fails checksum validation.
    pub fn from_i105_for_discriminant(
        encoded: &str,
        expected_discriminant: Option<u16>,
    ) -> Result<Self, AccountAddressError> {
        let (_, canonical) = decode_i105_literal(encoded, expected_discriminant)?;
        Self::from_canonical_bytes(&canonical)
    }
    /// Return the chain discriminant embedded in a canonical I105 literal.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if the string is not a valid I105 literal.
    pub fn i105_discriminant(encoded: &str) -> Result<u16, AccountAddressError> {
        if encoded.is_empty() || encoded.trim() != encoded {
            return Err(AccountAddressError::UnsupportedAddressFormat);
        }
        let (discriminant, canonical) = decode_i105_literal(encoded, None)?;
        let address = Self::from_canonical_bytes(&canonical)?;
        address.ensure_canonical_i105_literal(encoded, discriminant)?;
        Ok(discriminant)
    }
    fn ensure_canonical_i105_literal(
        &self,
        encoded: &str,
        discriminant: u16,
    ) -> Result<(), AccountAddressError> {
        let canonical = self.to_i105_for_discriminant(discriminant)?;
        if canonical == encoded {
            Ok(())
        } else {
            Err(AccountAddressError::UnsupportedAddressFormat)
        }
    }
    /// Parse an address string in strict encoded i105 form.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError::UnsupportedAddressFormat`] for unsupported
    /// non-i105 literals (including canonical-hex parser input). Once an i105
    /// sentinel is present, semantic i105 decode errors are preserved.
    ///
    /// Preserves semantic decode failures such as checksum and discriminant mismatches.
    pub fn parse_encoded(
        input: &str,
        expected_discriminant: Option<u16>,
    ) -> Result<Self, AccountAddressError> {
        if input.trim().is_empty() {
            return Err(AccountAddressError::InvalidLength);
        }
        if input.trim() != input || input.starts_with("0x") || input.starts_with("0X") {
            return Err(AccountAddressError::UnsupportedAddressFormat);
        }
        let address = Self::from_i105_for_discriminant(input, expected_discriminant).map_err(
            |err| match err {
                AccountAddressError::MissingI105Sentinel => {
                    AccountAddressError::UnsupportedAddressFormat
                }
                other => other,
            },
        )?;
        let expected = match expected_discriminant {
            Some(discriminant) => discriminant,
            None => Self::i105_discriminant(input)?,
        };
        address.ensure_canonical_i105_literal(input, expected)?;
        Ok(address)
    }
    /// Encode the canonical byte representation that [`Self::from_canonical_bytes`] parses
    /// (the SCCP codec-3 account bytes).
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if encoding the controller payload fails.
    ///
    /// Canonical payloads are domain-agnostic and therefore do not include a
    /// serialized domain selector segment.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AccountAddressError> {
        canonical_output_bytes(self)
    }

    fn emit_canonical_bytes<E>(
        &self,
        mut emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), CanonicalEmissionError<E>> {
        emit(&[self.header.encode()]).map_err(CanonicalEmissionError::Sink)?;
        self.controller.emit_into(&mut emit)
    }

    /// Return the canonical bytes encoded as a lowercase hex string with `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] if canonical byte construction fails.
    pub fn canonical_hex(&self) -> Result<String, AccountAddressError> {
        canonical_output_hex(self)
    }

    /// Convert this address into a domainless [`AccountId`].
    ///
    /// # Errors
    ///
    /// Returns [`AccountAddressError`] when the controller payload cannot be decoded.
    pub fn to_account_id(&self) -> Result<AccountId, AccountAddressError> {
        let controller = self.to_account_controller()?;
        Ok(AccountId { controller })
    }
    pub(crate) fn to_account_controller(&self) -> Result<AccountController, AccountAddressError> {
        self.controller.to_account_controller()
    }
}
impl FromStr for AccountAddress {
    type Err = AccountAddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_encoded(s, None)
    }
}
impl TypeId for AccountAddress {
    fn id() -> Ident {
        "iroha_data_model::account::address::AccountAddress".to_owned()
    }
}
impl IntoSchema for AccountAddress {
    fn type_name() -> Ident {
        "AccountAddress".to_owned()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.insert::<Self>(Metadata::Vec(VecMeta {
            ty: core::any::TypeId::of::<u8>(),
        })) {
            return;
        }
        <u8 as IntoSchema>::update_schema_map(map);
    }
}
fn account_address_norito_error(err: AccountAddressError) -> ncore::Error {
    match err {
        AccountAddressError::DecodeResourceLimit => {
            ncore::Error::Json(json::Error::DecodeResourceLimit)
        }
        AccountAddressError::DecodeResource(resource) => resource.into(),
        AccountAddressError::ScopedDecodeResource(origin) => {
            ncore::Error::ScopedDecodeResource(origin)
        }
        other => ncore::Error::Message(other.to_string()),
    }
}

fn push_lower_hex_byte(out: &mut String, byte: u8) {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(ALPHABET[usize::from(byte >> 4)]));
    out.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
}

enum CanonicalEmissionError<E> {
    Account(AccountAddressError),
    Sink(E),
}
impl CanonicalEmissionError<core::convert::Infallible> {
    fn into_account(self) -> AccountAddressError {
        match self {
            Self::Account(error) => error,
            Self::Sink(never) => match never {},
        }
    }
}

fn write_lower_hex_byte_to(
    out: &mut dyn json::JsonWriteSink,
    byte: u8,
) -> Result<(), json::BoundedJsonError> {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(ALPHABET[usize::from(byte >> 4)]))?;
    out.push(char::from(ALPHABET[usize::from(byte & 0x0f)]))
}

#[allow(unsafe_code)]
fn visit_lower_hex_byte(
    byte: u8,
    visitor: &mut impl FnMut(&str) -> Result<(), json::BoundedJsonError>,
) -> Result<(), json::BoundedJsonError> {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let encoded = [
        ALPHABET[usize::from(byte >> 4)],
        ALPHABET[usize::from(byte & 0x0f)],
    ];
    // SAFETY: both bytes are selected from the ASCII hexadecimal alphabet.
    visitor(unsafe { core::str::from_utf8_unchecked(&encoded) })
}

impl SerializePayload for AccountAddress {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        let canonical = self
            .canonical_bytes()
            .map_err(account_address_norito_error)?;
        <Vec<u8> as SerializePayload>::serialize(&canonical, writer)
    }
}

impl<'de> DeserializePayload<'de> for AccountAddress {
    fn deserialize(archived: &'de Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("archived AccountAddress must contain canonical bytes")
    }
    fn try_deserialize(archived: &'de Archived<Self>) -> Result<Self, ncore::Error> {
        let bytes = <Vec<u8> as DeserializePayload>::try_deserialize(archived.cast())?;
        AccountAddress::from_canonical_bytes(&bytes).map_err(account_address_norito_error)
    }
}

impl JsonSerialize for AccountAddress {
    fn json_serialize(&self, out: &mut String) {
        let canonical = self
            .canonical_hex()
            .expect("AccountAddress must produce canonical hex");
        json::write_json_string(&canonical, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.push('"')?;
        out.push_str("0x")?;
        self.emit_canonical_bytes(|chunk| {
            for &byte in chunk {
                write_lower_hex_byte_to(out, byte)?;
            }
            Ok(())
        })
        .map_err(|error| match error {
            CanonicalEmissionError::Account(_) => json::BoundedJsonError::Unsupported,
            CanonicalEmissionError::Sink(error) => error,
        })?;
        out.push('"')
    }
}

impl JsonDeserialize for AccountAddress {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let literal = parser.parse_string()?;
        account_address_from_json_str(&literal)
    }

    fn json_from_value(value: &json::Value) -> Result<Self, json::Error> {
        let json::Value::String(value) = value else {
            return Err(invalid_account_address_json());
        };
        account_address_from_json_str(value)
    }
}

impl json::JsonObjectKey for AccountAddress {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        let canonical = self
            .canonical_hex()
            .expect("AccountAddress must produce canonical hex");
        visitor(&canonical)
    }

    fn visit_json_key_text_checked(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), json::BoundedJsonError>,
    ) -> Result<(), json::BoundedJsonError> {
        visitor("0x")?;
        self.emit_canonical_bytes(|chunk| {
            for &byte in chunk {
                visit_lower_hex_byte(byte, &mut visitor)?;
            }
            Ok(())
        })
        .map_err(|error| match error {
            CanonicalEmissionError::Account(_) => json::BoundedJsonError::Unsupported,
            CanonicalEmissionError::Sink(error) => error,
        })
    }
}

impl json::JsonObjectKeyOwned for AccountAddress {
    fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
        account_address_from_json_str(key)
    }
}

fn account_address_from_json_str(literal: &str) -> Result<AccountAddress, json::Error> {
    super::reserve_account_literal_json_decode(literal.len())?;
    match AccountAddress::from_str(literal) {
        Ok(address) => Ok(address),
        Err(AccountAddressError::UnsupportedAddressFormat) => {
            let canonical_hex = literal
                .strip_prefix("0x")
                .or_else(|| literal.strip_prefix("0X"))
                .unwrap_or(literal);
            let canonical_bytes = decode_account_address_hex_for_json(canonical_hex)?;
            AccountAddress::from_canonical_bytes(&canonical_bytes)
                .map_err(map_account_address_json_error)
        }
        Err(error) => Err(map_account_address_json_error(error)),
    }
}

pub(super) fn map_account_address_json_error(error: AccountAddressError) -> json::Error {
    match error {
        AccountAddressError::DecodeResourceLimit => json::Error::DecodeResourceLimit,
        AccountAddressError::DecodeResource(resource) => json::Error::DecodeResource(resource),
        AccountAddressError::ScopedDecodeResource(origin) => {
            json::Error::ScopedDecodeResource(origin)
        }
        _ => invalid_account_address_json(),
    }
}

fn invalid_account_address_json() -> json::Error {
    json::Error::Message("invalid account address".to_owned())
}

#[allow(unsafe_code)]
fn decode_account_address_hex_for_json(encoded: &str) -> Result<Vec<u8>, json::Error> {
    if !encoded.len().is_multiple_of(2) {
        return Err(json::Error::Message("invalid account address".to_owned()));
    }
    let bytes = encoded.len() / 2;
    if bytes == 0 {
        return Ok(Vec::new());
    }
    let layout =
        std::alloc::Layout::array::<u8>(bytes).map_err(|_| json::Error::DecodeResourceLimit)?;
    // The source-derived account-literal precharge covers this exact decoded
    // destination before entry. Null is rejected before ownership.
    let allocation = unsafe { std::alloc::alloc(layout) };
    let allocation = core::ptr::NonNull::new(allocation).ok_or(json::Error::AllocationFailed)?;
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let Some(byte) = nibble(pair[0])
            .zip(nibble(pair[1]))
            .map(|(high, low)| (high << 4) | low)
        else {
            // SAFETY: `allocation` still owns the exact `layout` above.
            unsafe { std::alloc::dealloc(allocation.as_ptr(), layout) };
            return Err(json::Error::Message("invalid account address".to_owned()));
        };
        // SAFETY: one byte is written to each disjoint in-bounds slot.
        unsafe { allocation.as_ptr().add(index).write(byte) };
    }
    // SAFETY: every byte is initialized and the allocation has exact capacity.
    Ok(unsafe { Vec::from_raw_parts(allocation.as_ptr(), bytes, bytes) })
}
const CONTROLLER_SINGLE_KEY_TAG: u8 = 0x00;
const CONTROLLER_MULTISIG_TAG: u8 = 0x01;
const CONTROLLER_SINGLE_KEY_EXTENDED_TAG: u8 = 0x02;
const CONTROLLER_MULTISIG_MEMBER_MAX: usize = u16::MAX as usize;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AddressHeader {
    version: u8,
    class: AddressClass,
    norm_version: u8,
    ext_flag: bool,
}
impl AddressHeader {
    fn new(
        version: u8,
        class: AddressClass,
        norm_version: u8,
    ) -> Result<Self, AccountAddressError> {
        if version != HEADER_VERSION_V1 {
            return Err(AccountAddressError::InvalidHeaderVersion(version));
        }
        if norm_version != HEADER_NORM_VERSION_V1 {
            return Err(AccountAddressError::InvalidNormVersion(norm_version));
        }
        Ok(Self {
            version,
            class,
            norm_version,
            ext_flag: false,
        })
    }
    fn encode(self) -> u8 {
        let class_bits = (self.class as u8) & 0b11;
        (self.version << 5)
            | (class_bits << 3)
            | ((self.norm_version & 0b11) << 1)
            | u8::from(self.ext_flag)
    }
    fn decode(byte: u8) -> Result<Self, AccountAddressError> {
        let version = byte >> 5;
        let class_bits = (byte >> 3) & 0b11;
        let norm_version = (byte >> 1) & 0b11;
        let ext_flag = (byte & 1) == 1;
        if ext_flag {
            return Err(AccountAddressError::UnexpectedExtensionFlag);
        }
        let class = match class_bits {
            0 => AddressClass::SingleKey,
            1 => AddressClass::MultiSig,
            other => return Err(AccountAddressError::UnknownAddressClass(other)),
        };
        Self::new(version, class, norm_version)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressClass {
    SingleKey = 0,
    MultiSig = 1,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum ControllerPayload {
    SingleKey {
        curve: CurveId,
        public_key: PublicKey,
    },
    MultiSig(MultisigPayload),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct MultisigPayload {
    version: u8,
    threshold: u16,
    members: Vec<MultisigMemberPayload>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct MultisigMemberPayload {
    curve: CurveId,
    weight: u16,
    public_key: PublicKey,
}
trait CanonicalAccountOutput {
    fn emit_canonical_bytes<E>(
        &self,
        emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), CanonicalEmissionError<E>>;
}

impl CanonicalAccountOutput for AccountAddress {
    fn emit_canonical_bytes<E>(
        &self,
        emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), CanonicalEmissionError<E>> {
        AccountAddress::emit_canonical_bytes(self, emit)
    }
}

impl CanonicalAccountOutput for AccountId {
    fn emit_canonical_bytes<E>(
        &self,
        mut emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), CanonicalEmissionError<E>> {
        let class = match self.controller() {
            AccountController::Single(_) => AddressClass::SingleKey,
            AccountController::Multisig(policy) => {
                if policy.members().len() > CONTROLLER_MULTISIG_MEMBER_MAX {
                    return Err(CanonicalEmissionError::Account(
                        AccountAddressError::MultisigMemberOverflow(policy.members().len()),
                    ));
                }
                AddressClass::MultiSig
            }
        };
        let header = AddressHeader::new(HEADER_VERSION_V1, class, HEADER_NORM_VERSION_V1)
            .map_err(CanonicalEmissionError::Account)?;
        emit(&[header.encode()]).map_err(CanonicalEmissionError::Sink)?;
        match self.controller() {
            AccountController::Single(public_key) => {
                let (algorithm, _) = public_key.try_to_bytes().map_err(|_| {
                    CanonicalEmissionError::Account(AccountAddressError::InvalidPublicKey)
                })?;
                let curve = CurveId::try_from_algorithm(algorithm)
                    .map_err(AccountAddressError::from)
                    .map_err(CanonicalEmissionError::Account)?;
                emit_single_controller(curve, public_key, &mut emit)
            }
            AccountController::Multisig(policy) => emit_multisig_controller(
                policy.version(),
                policy.threshold(),
                policy.members(),
                &mut emit,
            ),
        }
    }
}

fn address_allocation_failure(layout: std::alloc::Layout) -> AccountAddressError {
    u64::try_from(layout.size()).map_or_else(
        |_| AccountAddressError::DecodeResourceLimit,
        |bytes| {
            AccountAddressError::DecodeResource(ncore::DecodeResourceError::AllocationFailed {
                bytes,
            })
        },
    )
}

fn reserve_address_vec<T>(
    output: &mut Vec<T>,
    additional: usize,
) -> Result<(), AccountAddressError> {
    let length = output
        .len()
        .checked_add(additional)
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let layout = std::alloc::Layout::array::<T>(length)
        .map_err(|_| AccountAddressError::DecodeResourceLimit)?;
    output
        .try_reserve_exact(additional)
        .map_err(|_| address_allocation_failure(layout))
}

fn reserve_address_string(
    output: &mut String,
    additional: usize,
) -> Result<(), AccountAddressError> {
    let length = output
        .len()
        .checked_add(additional)
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let layout = std::alloc::Layout::array::<u8>(length)
        .map_err(|_| AccountAddressError::DecodeResourceLimit)?;
    output
        .try_reserve_exact(additional)
        .map_err(|_| address_allocation_failure(layout))
}

fn canonical_output_bytes(
    output: &impl CanonicalAccountOutput,
) -> Result<Vec<u8>, AccountAddressError> {
    let mut canonical_len = 0_usize;
    output
        .emit_canonical_bytes(|chunk| {
            canonical_len = canonical_len
                .checked_add(chunk.len())
                .ok_or(AccountAddressError::DecodeResourceLimit)?;
            Ok::<_, AccountAddressError>(())
        })
        .map_err(|error| match error {
            CanonicalEmissionError::Account(error) | CanonicalEmissionError::Sink(error) => error,
        })?;
    let mut bytes = Vec::new();
    reserve_address_vec(&mut bytes, canonical_len)?;
    output
        .emit_canonical_bytes(|chunk| {
            bytes.extend_from_slice(chunk);
            Ok::<_, core::convert::Infallible>(())
        })
        .map_err(CanonicalEmissionError::into_account)?;
    Ok(bytes)
}

fn canonical_output_hex(
    output: &impl CanonicalAccountOutput,
) -> Result<String, AccountAddressError> {
    let mut canonical_bytes = 0_usize;
    output
        .emit_canonical_bytes(|chunk| {
            canonical_bytes = canonical_bytes
                .checked_add(chunk.len())
                .ok_or(AccountAddressError::DecodeResourceLimit)?;
            Ok::<_, AccountAddressError>(())
        })
        .map_err(|error| match error {
            CanonicalEmissionError::Account(error) | CanonicalEmissionError::Sink(error) => error,
        })?;
    let encoded_bytes = canonical_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let mut canonical = String::new();
    reserve_address_string(&mut canonical, encoded_bytes)?;
    canonical.push_str("0x");
    output
        .emit_canonical_bytes(|chunk| {
            for &byte in chunk {
                push_lower_hex_byte(&mut canonical, byte);
            }
            Ok::<_, core::convert::Infallible>(())
        })
        .map_err(CanonicalEmissionError::into_account)?;
    Ok(canonical)
}

trait CanonicalMultisigMember {
    fn canonical_coordinates(&self) -> Result<(CurveId, u16, &PublicKey), AccountAddressError>;
}

impl CanonicalMultisigMember for MultisigMemberPayload {
    fn canonical_coordinates(&self) -> Result<(CurveId, u16, &PublicKey), AccountAddressError> {
        Ok((self.curve, self.weight, &self.public_key))
    }
}

impl CanonicalMultisigMember for MultisigMember {
    fn canonical_coordinates(&self) -> Result<(CurveId, u16, &PublicKey), AccountAddressError> {
        let (algorithm, _) = self
            .public_key()
            .try_to_bytes()
            .map_err(|_| AccountAddressError::InvalidPublicKey)?;
        let curve = CurveId::try_from_algorithm(algorithm).map_err(AccountAddressError::from)?;
        Ok((curve, self.weight(), self.public_key()))
    }
}

fn emit_single_controller<E>(
    curve: CurveId,
    public_key: &PublicKey,
    emit: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), CanonicalEmissionError<E>> {
    let (_alg, payload) = public_key
        .try_to_bytes()
        .map_err(|_| CanonicalEmissionError::Account(AccountAddressError::InvalidPublicKey))?;
    if let Ok(length) = u8::try_from(payload.len()) {
        emit(&[CONTROLLER_SINGLE_KEY_TAG, curve.as_u8(), length])
            .map_err(CanonicalEmissionError::Sink)?;
    } else {
        let length = u16::try_from(payload.len()).map_err(|_| {
            CanonicalEmissionError::Account(AccountAddressError::KeyPayloadTooLong(u16::MAX))
        })?;
        emit(&[CONTROLLER_SINGLE_KEY_EXTENDED_TAG, curve.as_u8()])
            .map_err(CanonicalEmissionError::Sink)?;
        emit(&length.to_be_bytes()).map_err(CanonicalEmissionError::Sink)?;
    }
    emit(payload).map_err(CanonicalEmissionError::Sink)?;
    Ok(())
}

fn emit_multisig_controller<E>(
    version: u8,
    threshold: u16,
    members: &[impl CanonicalMultisigMember],
    emit: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), CanonicalEmissionError<E>> {
    let member_count = u16::try_from(members.len()).map_err(|_| {
        CanonicalEmissionError::Account(AccountAddressError::MultisigMemberOverflow(members.len()))
    })?;
    emit(&[CONTROLLER_MULTISIG_TAG, version]).map_err(CanonicalEmissionError::Sink)?;
    emit(&threshold.to_be_bytes()).map_err(CanonicalEmissionError::Sink)?;
    emit(&member_count.to_be_bytes()).map_err(CanonicalEmissionError::Sink)?;
    for member in members {
        let (curve, weight, public_key) = member
            .canonical_coordinates()
            .map_err(CanonicalEmissionError::Account)?;
        let (_alg, key_bytes) = public_key
            .try_to_bytes()
            .map_err(|_| CanonicalEmissionError::Account(AccountAddressError::InvalidPublicKey))?;
        let length = u16::try_from(key_bytes.len()).map_err(|_| {
            CanonicalEmissionError::Account(AccountAddressError::KeyPayloadTooLong(u16::MAX))
        })?;
        emit(&[curve.as_u8()]).map_err(CanonicalEmissionError::Sink)?;
        emit(&weight.to_be_bytes()).map_err(CanonicalEmissionError::Sink)?;
        emit(&length.to_be_bytes()).map_err(CanonicalEmissionError::Sink)?;
        emit(key_bytes).map_err(CanonicalEmissionError::Sink)?;
    }
    Ok(())
}

impl ControllerPayload {
    fn from_account_controller(
        controller: &AccountController,
    ) -> Result<(AddressClass, Self), AccountAddressError> {
        match controller {
            AccountController::Single(key) => {
                let (algorithm, _) = key
                    .try_to_bytes()
                    .map_err(|_| AccountAddressError::InvalidPublicKey)?;
                let curve =
                    CurveId::try_from_algorithm(algorithm).map_err(AccountAddressError::from)?;
                Ok((
                    AddressClass::SingleKey,
                    Self::SingleKey {
                        curve,
                        public_key: key
                            .try_clone_for_admission()
                            .map_err(AccountAddressError::from_decode_error)?,
                    },
                ))
            }
            AccountController::Multisig(policy) => {
                if policy.members().len() > CONTROLLER_MULTISIG_MEMBER_MAX {
                    return Err(AccountAddressError::MultisigMemberOverflow(
                        policy.members().len(),
                    ));
                }
                let mut members = Vec::new();
                reserve_address_vec(&mut members, policy.members().len())?;
                for member in policy.members() {
                    let (algorithm, _) = member
                        .public_key()
                        .try_to_bytes()
                        .map_err(|_| AccountAddressError::InvalidPublicKey)?;
                    let curve = CurveId::try_from_algorithm(algorithm)
                        .map_err(AccountAddressError::from)?;
                    members.push(MultisigMemberPayload {
                        curve,
                        weight: member.weight(),
                        public_key: member
                            .public_key()
                            .try_clone_for_admission()
                            .map_err(AccountAddressError::from_decode_error)?,
                    });
                }
                Ok((
                    AddressClass::MultiSig,
                    Self::MultiSig(MultisigPayload {
                        version: policy.version(),
                        threshold: policy.threshold(),
                        members,
                    }),
                ))
            }
        }
    }
    fn emit_into<E>(
        &self,
        emit: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), CanonicalEmissionError<E>> {
        match self {
            Self::SingleKey { curve, public_key } => {
                emit_single_controller(*curve, public_key, emit)
            }
            Self::MultiSig(payload) => {
                emit_multisig_controller(payload.version, payload.threshold, &payload.members, emit)
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    fn decode(bytes: &[u8], cursor: &mut usize) -> Result<Self, AccountAddressError> {
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
                let public_key = decode_public_key(curve.algorithm(), payload)?;
                Ok(Self::SingleKey { curve, public_key })
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
                    return Err(AccountAddressError::InvalidLength);
                }
                let payload = bytes
                    .get(*cursor..*cursor + len)
                    .ok_or(AccountAddressError::InvalidLength)?;
                *cursor += len;
                let public_key = decode_public_key(curve.algorithm(), payload)?;
                Ok(Self::SingleKey { curve, public_key })
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
                    return Err(AccountAddressError::MultisigMemberOverflow(member_count));
                }
                preflight_multisig_members(bytes, *cursor, member_count)?;
                let mut members = allocate_multisig_members(member_count)?;
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
                    let public_key = decode_public_key(curve.algorithm(), payload)?;
                    members.push(MultisigMemberPayload {
                        curve,
                        weight,
                        public_key,
                    });
                }
                MultisigPolicy::validate_canonical_members(
                    version,
                    threshold,
                    members
                        .iter()
                        .map(|member| (&member.public_key, member.weight)),
                )
                .map_err(AccountAddressError::InvalidMultisigPolicy)?;
                Ok(Self::MultiSig(MultisigPayload {
                    version,
                    threshold,
                    members,
                }))
            }
            other => Err(AccountAddressError::UnknownControllerTag(other)),
        }
    }
    fn to_account_controller(&self) -> Result<AccountController, AccountAddressError> {
        match self {
            Self::SingleKey { public_key, .. } => Ok(AccountController::single(
                public_key
                    .try_clone_for_admission()
                    .map_err(AccountAddressError::from_decode_error)?,
            )),
            Self::MultiSig(payload) => {
                let member_bytes = payload
                    .members
                    .len()
                    .checked_mul(core::mem::size_of::<MultisigMember>())
                    .ok_or(AccountAddressError::DecodeResourceLimit)?;
                norito::core::reserve_decode_allocation(member_bytes)
                    .map_err(AccountAddressError::from_decode_error)?;
                let mut members = Vec::new();
                reserve_address_vec(&mut members, payload.members.len())?;
                for member in &payload.members {
                    members.push(
                        MultisigMember::new(
                            member
                                .public_key
                                .try_clone_for_admission()
                                .map_err(AccountAddressError::from_decode_error)?,
                            member.weight,
                        )
                        .map_err(AccountAddressError::InvalidMultisigPolicy)?,
                    );
                }
                let policy =
                    MultisigPolicy::from_serialized(payload.version, payload.threshold, members)
                        .map_err(AccountAddressError::InvalidMultisigPolicy)?;
                Ok(AccountController::multisig(policy))
            }
        }
    }
}
fn preflight_multisig_members(
    bytes: &[u8],
    mut cursor: usize,
    member_count: usize,
) -> Result<(), AccountAddressError> {
    for _ in 0..member_count {
        let curve_raw = *bytes
            .get(cursor)
            .ok_or(AccountAddressError::InvalidLength)?;
        CurveId::try_from(curve_raw).map_err(AccountAddressError::from)?;
        cursor = cursor
            .checked_add(3)
            .ok_or(AccountAddressError::InvalidLength)?;
        let key_len_end = cursor
            .checked_add(2)
            .ok_or(AccountAddressError::InvalidLength)?;
        let key_len_bytes = bytes
            .get(cursor..key_len_end)
            .ok_or(AccountAddressError::InvalidLength)?;
        cursor = key_len_end;
        let key_len = usize::from(u16::from_be_bytes(key_len_bytes.try_into().unwrap()));
        cursor = cursor
            .checked_add(key_len)
            .filter(|end| *end <= bytes.len())
            .ok_or(AccountAddressError::InvalidLength)?;
    }
    Ok(())
}
fn decode_public_key(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<PublicKey, AccountAddressError> {
    PublicKey::from_bytes_for_decode(algorithm, payload)
        .map_err(AccountAddressError::from_decode_error)
}
#[allow(unsafe_code)]
fn allocate_multisig_members(
    member_count: usize,
) -> Result<Vec<MultisigMemberPayload>, AccountAddressError> {
    if member_count == 0 {
        return Ok(Vec::new());
    }
    let layout = std::alloc::Layout::array::<MultisigMemberPayload>(member_count)
        .map_err(|_| AccountAddressError::DecodeResourceLimit)?;
    norito::core::reserve_decode_allocation(layout.size())
        .map_err(AccountAddressError::from_decode_error)?;
    // SAFETY: the exact non-zero layout was admitted before allocation. The
    // returned Vec starts empty and initializes elements only through `push`.
    let allocation = unsafe { std::alloc::alloc(layout) };
    let allocation =
        core::ptr::NonNull::new(allocation).ok_or_else(|| address_allocation_failure(layout))?;
    Ok(unsafe { Vec::from_raw_parts(allocation.as_ptr().cast(), 0, member_count) })
}
fn i105_sentinel_for_discriminant(discriminant: u16) -> String {
    match discriminant {
        CHAIN_DISCRIMINANT_SORA => I105_SENTINEL_SORA.to_owned(),
        CHAIN_DISCRIMINANT_TEST => I105_SENTINEL_TEST.to_owned(),
        CHAIN_DISCRIMINANT_DEV => I105_SENTINEL_DEV.to_owned(),
        _ => format!("{I105_SENTINEL_FALLBACK_PREFIX}{discriminant}"),
    }
}
/// Write the I105 chain sentinel for `discriminant` without allocating.
///
/// Named chains use their fixed sentinel; any other discriminant is `n` followed by its decimal
/// value, which always fits the six-byte scratch buffer.
#[doc(hidden)]
pub fn write_i105_sentinel(discriminant: u16, numeric: &mut [u8; 6]) -> &[u8] {
    match discriminant {
        CHAIN_DISCRIMINANT_SORA => I105_SENTINEL_SORA.as_bytes(),
        CHAIN_DISCRIMINANT_TEST => I105_SENTINEL_TEST.as_bytes(),
        CHAIN_DISCRIMINANT_DEV => I105_SENTINEL_DEV.as_bytes(),
        discriminant => {
            numeric[0] = I105_SENTINEL_FALLBACK_PREFIX.as_bytes()[0];
            let mut reversed = [0_u8; 5];
            let mut value = discriminant;
            let mut digits = 0_usize;
            loop {
                reversed[digits] = b'0'
                    + u8::try_from(value % 10).expect("decimal sentinel digit fits in one byte");
                digits += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            for index in 0..digits {
                numeric[index + 1] = reversed[digits - 1 - index];
            }
            &numeric[..=digits]
        }
    }
}
/// Stable error codes surfaced by address encoders/decoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountAddressErrorCode {
    /// Unsupported signing algorithm requested.
    UnsupportedAlgorithm,
    /// Key payload exceeds supported length.
    KeyPayloadTooLong,
    /// Address header version outside supported range.
    InvalidHeaderVersion,
    /// Normalisation version outside supported range.
    InvalidNormVersion,
    /// Payload length invalid for the requested operation.
    InvalidLength,
    /// i105 checksum validation failed.
    ChecksumMismatch,
    /// Canonical hexadecimal payload failed to decode.
    InvalidHexAddress,
    /// Chain discriminant prefix did not match expectation.
    UnexpectedNetworkPrefix,
    /// Unknown address class encountered.
    UnknownAddressClass,
    /// Reserved extension flag set unexpectedly.
    UnexpectedExtensionFlag,
    /// Unknown controller payload tag encountered.
    UnknownControllerTag,
    /// Public key payload failed validation.
    InvalidPublicKey,
    /// An active decode allocation budget was exhausted.
    DecodeResourceLimit,
    /// Unknown curve identifier encountered.
    UnknownCurve,
    /// Canonical payload contained trailing bytes.
    UnexpectedTrailingBytes,
    /// i105 form missing the expected chain-discriminant sentinel.
    MissingI105Sentinel,
    /// i105 form shorter than minimal payload.
    I105TooShort,
    /// Invalid character in i105 alphabet.
    InvalidI105Char,
    /// Invalid i105 alphabet base requested.
    InvalidI105Base,
    /// Digit outside i105 alphabet bounds.
    InvalidI105Digit,
    /// Address string format unsupported.
    UnsupportedAddressFormat,
    /// Multisig controller declares too many members.
    MultisigMemberOverflow,
    /// Multisig policy payload failed validation.
    InvalidMultisigPolicy,
}
impl AccountAddressErrorCode {
    /// Stable string representation suitable for telemetry/logging.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm => "ERR_UNSUPPORTED_ALGORITHM",
            Self::KeyPayloadTooLong => "ERR_KEY_PAYLOAD_TOO_LONG",
            Self::InvalidHeaderVersion => "ERR_INVALID_HEADER_VERSION",
            Self::InvalidNormVersion => "ERR_INVALID_NORM_VERSION",
            Self::InvalidLength => "ERR_INVALID_LENGTH",
            Self::ChecksumMismatch => "ERR_CHECKSUM_MISMATCH",
            Self::InvalidHexAddress => "ERR_INVALID_HEX_ADDRESS",
            Self::UnexpectedNetworkPrefix => "ERR_UNEXPECTED_NETWORK_PREFIX",
            Self::UnknownAddressClass => "ERR_UNKNOWN_ADDRESS_CLASS",
            Self::UnexpectedExtensionFlag => "ERR_UNEXPECTED_EXTENSION_FLAG",
            Self::UnknownControllerTag => "ERR_UNKNOWN_CONTROLLER_TAG",
            Self::InvalidPublicKey => "ERR_INVALID_PUBLIC_KEY",
            Self::DecodeResourceLimit => "ERR_DECODE_RESOURCE_LIMIT",
            Self::UnknownCurve => "ERR_UNKNOWN_CURVE",
            Self::UnexpectedTrailingBytes => "ERR_UNEXPECTED_TRAILING_BYTES",
            Self::MissingI105Sentinel => "ERR_MISSING_I105_SENTINEL",
            Self::I105TooShort => "ERR_I105_TOO_SHORT",
            Self::InvalidI105Char => "ERR_INVALID_I105_CHAR",
            Self::InvalidI105Base => "ERR_INVALID_I105_BASE",
            Self::InvalidI105Digit => "ERR_INVALID_I105_DIGIT",
            Self::UnsupportedAddressFormat => "ERR_UNSUPPORTED_ADDRESS_FORMAT",
            Self::MultisigMemberOverflow => "ERR_MULTISIG_MEMBER_OVERFLOW",
            Self::InvalidMultisigPolicy => "ERR_INVALID_MULTISIG_POLICY",
        }
    }
}
/// Errors raised during address construction or encoding.
#[derive(Clone, Debug, Error)]
pub enum AccountAddressError {
    /// Requested signing algorithm is not supported by the encoder.
    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(Algorithm),
    /// The signing key payload exceeds the supported length.
    #[error("key payload too long: {0} bytes")]
    KeyPayloadTooLong(u16),
    /// Address header version is outside the supported range.
    #[error("invalid address header version: {0}")]
    InvalidHeaderVersion(u8),
    /// Normalisation version flag is outside the supported range.
    #[error("invalid normalization version: {0}")]
    InvalidNormVersion(u8),
    /// Data length is invalid for the requested operation.
    #[error("invalid length for address payload")]
    InvalidLength,
    /// i105 checksum validation failed.
    #[error("i105 checksum mismatch")]
    ChecksumMismatch,
    /// Canonical hexadecimal payload could not be decoded.
    #[error("invalid canonical hex account address")]
    InvalidHexAddress,
    /// Chain discriminant prefix did not match expectations.
    #[error("unexpected i105 chain discriminant: expected {expected}, found {found}")]
    UnexpectedNetworkPrefix {
        /// Chain discriminant we expected to decode.
        expected: u16,
        /// Chain discriminant decoded from the prefix bytes.
        found: u16,
    },
    /// Encountered an unknown address class.
    #[error("unknown address class: {0}")]
    UnknownAddressClass(u8),
    /// Address header sets the reserved extension flag.
    #[error("address header reserves extension flag but it was set")]
    UnexpectedExtensionFlag,
    /// Encountered an unknown controller tag.
    #[error("unknown controller payload tag: {0}")]
    UnknownControllerTag(u8),
    /// Public key payload could not be parsed for the declared curve.
    #[error("invalid public key payload for declared curve")]
    InvalidPublicKey,
    /// A size calculation or fallible reserve failed without recorded resource fields.
    #[error("account address decode resource limit exceeded")]
    DecodeResourceLimit,
    /// Exact decoder resource fields without original observer provenance.
    #[error("{0}")]
    DecodeResource(#[source] ncore::DecodeResourceError),
    /// Original decoder refusal, including its private budget and attempt identity.
    #[error("{0}")]
    ScopedDecodeResource(#[source] ncore::ScopedDecodeResourceError),
    /// Curve identifier is not recognised.
    #[error("unknown curve identifier: {0}")]
    UnknownCurve(u8),
    /// Address contains trailing bytes beyond the expected payload.
    #[error("unexpected trailing bytes in canonical payload")]
    UnexpectedTrailingBytes,
    /// i105 form is missing the expected chain-discriminant sentinel.
    #[error("i105 address is missing the expected chain-discriminant sentinel")]
    MissingI105Sentinel,
    /// i105 form is too short to contain payload and checksum.
    #[error("i105 address too short")]
    I105TooShort,
    /// Encountered a character outside of the i105 alphabet.
    #[error("invalid character `{0}` in i105 address")]
    InvalidI105Char(char),
    /// The i105 alphabet base is invalid or unsupported.
    #[error("invalid i105 alphabet base")]
    InvalidI105Base,
    /// Encountered a digit value outside of the i105 alphabet size.
    #[error("invalid i105 digit value: {0}")]
    InvalidI105Digit(u8),
    /// Address string is not in a recognised format.
    #[error("unsupported account address format")]
    UnsupportedAddressFormat,
    /// Multisignature controller declares more members than supported.
    #[error("multisig controller has too many members: {0}")]
    MultisigMemberOverflow(usize),
    /// Multisignature controller payload failed validation.
    #[error("invalid multisig policy: {0}")]
    InvalidMultisigPolicy(#[from] MultisigPolicyError),
}
impl From<CurveRegistryError> for AccountAddressError {
    fn from(error: CurveRegistryError) -> Self {
        match error {
            CurveRegistryError::UnsupportedAlgorithm(algorithm) => {
                Self::UnsupportedAlgorithm(algorithm)
            }
            CurveRegistryError::UnknownCurveId(curve) => Self::UnknownCurve(curve),
        }
    }
}
impl AccountAddressError {
    fn from_decode_error(error: ncore::Error) -> Self {
        if cfg!(all(test, sumeragi_model_mutation = "DM21"))
            && error.decode_resource_error().is_some()
        {
            return Self::DecodeResourceLimit;
        }
        match error {
            ncore::Error::ScopedDecodeResource(origin) => Self::ScopedDecodeResource(origin),
            ncore::Error::Json(json::Error::ScopedDecodeResource(origin)) => {
                Self::ScopedDecodeResource(origin)
            }
            ncore::Error::Json(json::Error::DecodeResource(resource)) => {
                Self::DecodeResource(resource)
            }
            ncore::Error::Json(json::Error::DecodeResourceLimit) => Self::DecodeResourceLimit,
            error => error
                .decode_resource_error()
                .map_or(Self::InvalidPublicKey, Self::DecodeResource),
        }
    }

    /// Whether canonical address work was refused by a decode bound or allocator.
    #[must_use]
    pub const fn is_decode_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::DecodeResourceLimit | Self::DecodeResource(_) | Self::ScopedDecodeResource(_)
        )
    }

    /// Stable error code attached to this failure.
    #[must_use]
    pub const fn code(&self) -> AccountAddressErrorCode {
        match self {
            Self::UnsupportedAlgorithm(_) => AccountAddressErrorCode::UnsupportedAlgorithm,
            Self::KeyPayloadTooLong(_) => AccountAddressErrorCode::KeyPayloadTooLong,
            Self::InvalidHeaderVersion(_) => AccountAddressErrorCode::InvalidHeaderVersion,
            Self::InvalidNormVersion(_) => AccountAddressErrorCode::InvalidNormVersion,
            Self::InvalidLength => AccountAddressErrorCode::InvalidLength,
            Self::ChecksumMismatch => AccountAddressErrorCode::ChecksumMismatch,
            Self::InvalidHexAddress => AccountAddressErrorCode::InvalidHexAddress,
            Self::UnexpectedNetworkPrefix { .. } => {
                AccountAddressErrorCode::UnexpectedNetworkPrefix
            }
            Self::UnknownAddressClass(_) => AccountAddressErrorCode::UnknownAddressClass,
            Self::UnexpectedExtensionFlag => AccountAddressErrorCode::UnexpectedExtensionFlag,
            Self::UnknownControllerTag(_) => AccountAddressErrorCode::UnknownControllerTag,
            Self::InvalidPublicKey => AccountAddressErrorCode::InvalidPublicKey,
            Self::DecodeResourceLimit | Self::DecodeResource(_) | Self::ScopedDecodeResource(_) => {
                AccountAddressErrorCode::DecodeResourceLimit
            }
            Self::UnknownCurve(_) => AccountAddressErrorCode::UnknownCurve,
            Self::UnexpectedTrailingBytes => AccountAddressErrorCode::UnexpectedTrailingBytes,
            Self::MissingI105Sentinel => AccountAddressErrorCode::MissingI105Sentinel,
            Self::I105TooShort => AccountAddressErrorCode::I105TooShort,
            Self::InvalidI105Char(_) => AccountAddressErrorCode::InvalidI105Char,
            Self::InvalidI105Base => AccountAddressErrorCode::InvalidI105Base,
            Self::InvalidI105Digit(_) => AccountAddressErrorCode::InvalidI105Digit,
            Self::UnsupportedAddressFormat => AccountAddressErrorCode::UnsupportedAddressFormat,
            Self::MultisigMemberOverflow(_) => AccountAddressErrorCode::MultisigMemberOverflow,
            Self::InvalidMultisigPolicy(_) => AccountAddressErrorCode::InvalidMultisigPolicy,
        }
    }
    /// Stable string identifier for this failure.
    #[must_use]
    pub const fn code_str(&self) -> &'static str {
        self.code().as_str()
    }
}
impl fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_hex().map_err(|_| fmt::Error)?)
    }
}
fn encode_i105_literal(prefix: u16, canonical: &[u8]) -> Result<String, AccountAddressError> {
    let digits = encode_base_n(canonical, I105_BASE)?;
    let checksum = i105_checksum_digits(canonical);
    let mut output = i105_sentinel_for_discriminant(prefix);
    let encoded_bytes =
        digits
            .iter()
            .chain(checksum.iter())
            .try_fold(0_usize, |length, digit| {
                i105_digit_symbol(*digit).and_then(|symbol| {
                    length
                        .checked_add(symbol.len())
                        .ok_or(AccountAddressError::DecodeResourceLimit)
                })
            })?;
    reserve_address_string(&mut output, encoded_bytes)?;
    for digit in digits.iter().chain(checksum.iter()) {
        output.push_str(i105_digit_symbol(*digit)?);
    }
    Ok(output)
}
fn decode_i105_literal(
    input: &str,
    expected_discriminant: Option<u16>,
) -> Result<(u16, Vec<u8>), AccountAddressError> {
    match decode_i105_literal_with_embedded_discriminant(input) {
        Ok((found, canonical)) => {
            if let Some(expected) = expected_discriminant
                && found != expected
            {
                return Err(AccountAddressError::UnexpectedNetworkPrefix { expected, found });
            }
            Ok((found, canonical))
        }
        Err(error) => {
            // Format diagnostics may inspect the expected payload; a resource
            // refusal is terminal and must retain its original observer.
            if error.is_decode_resource_limit()
                && !cfg!(all(test, sumeragi_model_mutation = "DM24"))
            {
                return Err(error);
            }
            let Some(expected) = expected_discriminant else {
                return Err(error);
            };
            let sentinel = i105_sentinel_for_discriminant(expected);
            let Some(payload) = input.strip_prefix(sentinel.as_str()) else {
                return Err(error);
            };
            match decode_i105_payload(payload) {
                Err(exact_error) => Err(exact_error),
                Ok(_) => Err(error),
            }
        }
    }
}
fn decode_i105_literal_with_embedded_discriminant(
    input: &str,
) -> Result<(u16, Vec<u8>), AccountAddressError> {
    for (discriminant, sentinel) in [
        (CHAIN_DISCRIMINANT_SORA, I105_SENTINEL_SORA),
        (CHAIN_DISCRIMINANT_TEST, I105_SENTINEL_TEST),
        (CHAIN_DISCRIMINANT_DEV, I105_SENTINEL_DEV),
    ] {
        if let Some(payload) = input.strip_prefix(sentinel) {
            return decode_i105_payload(payload).map(|canonical| (discriminant, canonical));
        }
    }
    let Some(rest) = input.strip_prefix(I105_SENTINEL_FALLBACK_PREFIX) else {
        return Err(AccountAddressError::MissingI105Sentinel);
    };
    let mut decoded = None;
    let mut first_err = None;
    let mut structural_err = None;
    for sentinel_len in 1..=5 {
        let Some((candidate, payload)) = numeric_i105_sentinel_candidate(rest, sentinel_len) else {
            continue;
        };
        match decode_i105_payload(payload) {
            Ok(canonical) => {
                let address = match AccountAddress::from_canonical_bytes(&canonical) {
                    Ok(address) => address,
                    Err(err) => {
                        if err.is_decode_resource_limit()
                            && !cfg!(all(test, sumeragi_model_mutation = "DM23"))
                        {
                            return Err(err);
                        }
                        structural_err.get_or_insert(err);
                        continue;
                    }
                };
                if let Err(err) = address.ensure_canonical_i105_literal(input, candidate) {
                    if err.is_decode_resource_limit()
                        && !cfg!(all(test, sumeragi_model_mutation = "DM23"))
                    {
                        return Err(err);
                    }
                    structural_err.get_or_insert(err);
                    continue;
                }
                if decoded.replace((candidate, canonical)).is_some() {
                    return Err(AccountAddressError::UnsupportedAddressFormat);
                }
            }
            Err(err) => {
                if err.is_decode_resource_limit()
                    && !cfg!(all(test, sumeragi_model_mutation = "DM23"))
                {
                    return Err(err);
                }
                first_err.get_or_insert(err);
            }
        }
    }
    decoded.ok_or_else(|| {
        structural_err
            .or(first_err)
            .unwrap_or(AccountAddressError::MissingI105Sentinel)
    })
}
fn numeric_i105_sentinel_candidate(rest: &str, len: usize) -> Option<(u16, &str)> {
    let mut end = 0;
    for (index, ch) in rest.char_indices().take(len) {
        if !ch.is_ascii_digit() {
            return None;
        }
        end = index + ch.len_utf8();
    }
    if end == 0 || rest[..end].chars().count() != len {
        return None;
    }
    let discriminant = rest[..end].parse::<u16>().ok()?;
    let sentinel = i105_sentinel_for_discriminant(discriminant);
    if sentinel.strip_prefix(I105_SENTINEL_FALLBACK_PREFIX)? != &rest[..end] {
        return None;
    }
    Some((discriminant, &rest[end..]))
}
fn encode_base_n(bytes: &[u8], base: u32) -> Result<Vec<u8>, AccountAddressError> {
    if !(2..=256).contains(&base) {
        return Err(AccountAddressError::InvalidI105Base);
    }
    if bytes.is_empty() {
        return Ok(vec![0]);
    }
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = &bytes[leading_zeros..];
    if significant.is_empty() {
        let mut digits = Vec::new();
        reserve_address_vec(&mut digits, leading_zeros)?;
        digits.resize(leading_zeros, 0);
        return Ok(digits);
    }

    let maximum_limbs = significant.len().div_ceil(8);
    let mut limbs = Vec::<u64>::new();
    reserve_address_vec(&mut limbs, maximum_limbs)?;
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
    let maximum_digits = bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(5))
        .map(|bits| bits / 6)
        .and_then(|digits| digits.checked_add(leading_zeros))
        .ok_or(AccountAddressError::DecodeResourceLimit)?;
    let mut digits = Vec::new();
    reserve_address_vec(&mut digits, maximum_digits)?;
    while !limbs.is_empty() {
        let mut remainder = 0_u128;
        for limb in &mut limbs {
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
            limbs.drain(..first_nonzero);
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
fn decode_base_n(digits: &[u8], base: u32) -> Result<Vec<u8>, AccountAddressError> {
    if !(2..=256).contains(&base) {
        return Err(AccountAddressError::InvalidI105Base);
    }
    if digits.is_empty() {
        return Err(AccountAddressError::InvalidLength);
    }
    validate_base_n_digits(digits, base)?;
    let leading_zeros = digits.iter().take_while(|&&d| d == 0).count();
    let significant = &digits[leading_zeros..];
    if significant.is_empty() {
        let mut bytes = Vec::new();
        reserve_address_vec(&mut bytes, leading_zeros)?;
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
    let mut limbs = Vec::<u64>::new();
    reserve_address_vec(&mut limbs, maximum_limbs)?;

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
            for limb in &mut limbs {
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
    let mut bytes = Vec::new();
    reserve_address_vec(&mut bytes, output_bytes)?;
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
fn validate_base_n_digits(digits: &[u8], base: u32) -> Result<(), AccountAddressError> {
    for &digit in digits {
        if u32::from(digit) >= base {
            return Err(AccountAddressError::InvalidI105Digit(digit));
        }
    }
    Ok(())
}
/// Bech32m-style checksum digits over the `snx` domain for a canonical account payload.
#[doc(hidden)]
#[must_use]
pub fn i105_checksum_digits(canonical: &[u8]) -> [u8; I105_CHECKSUM_LEN] {
    let mut chk = 1_u32;
    for byte in "snx".bytes() {
        chk = bech32_polymod_step(chk, byte >> 5);
    }
    chk = bech32_polymod_step(chk, 0);
    for byte in "snx".bytes() {
        chk = bech32_polymod_step(chk, byte & 0x1f);
    }
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for &byte in canonical {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chk = bech32_polymod_step(chk, u8::try_from((acc >> bits) & 0x1f).unwrap());
        }
    }
    if bits > 0 {
        chk = bech32_polymod_step(
            chk,
            u8::try_from((acc << (5 - bits)) & 0x1f).expect("base32 limb fits in u8"),
        );
    }
    for _ in 0..I105_CHECKSUM_LEN {
        chk = bech32_polymod_step(chk, 0);
    }
    let polymod = chk ^ BECH32M_CONST;
    let mut result = [0_u8; I105_CHECKSUM_LEN];
    for (index, slot) in result.iter_mut().enumerate() {
        let shift = 5 * (I105_CHECKSUM_LEN - 1 - index);
        *slot = u8::try_from((polymod >> shift) & 0x1f).expect("checksum limb fits in u8");
    }
    result
}
#[cfg(test)]
fn convert_to_base32(data: &[u8]) -> Vec<u8> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(5));
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let value = u8::try_from((acc >> bits) & 0x1f).expect("base32 limb fits in u8");
            out.push(value);
        }
    }
    if bits > 0 {
        let value = u8::try_from((acc << (5 - bits)) & 0x1f).expect("base32 limb fits in u8");
        out.push(value);
    }
    out
}
fn bech32_polymod_step(mut chk: u32, value: u8) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let top = chk >> 25;
    chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(value);
    for (index, generator) in GEN.iter().enumerate() {
        if (top >> index) & 1 == 1 {
            chk ^= generator;
        }
    }
    chk
}
#[cfg(test)]
fn expand_hrp(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for byte in hrp.bytes() {
        out.push(byte >> 5);
    }
    out.push(0);
    out.extend(hrp.bytes().map(|byte| byte & 0x1f));
    out
}
fn decode_i105_payload(payload: &str) -> Result<Vec<u8>, AccountAddressError> {
    let digits = i105_payload_digits(payload)?;
    if digits.len() <= I105_CHECKSUM_LEN {
        return Err(AccountAddressError::I105TooShort);
    }
    let split_at = digits.len() - I105_CHECKSUM_LEN;
    let canonical = decode_base_n(&digits[..split_at], I105_BASE)?;
    let expected = i105_checksum_digits(&canonical);
    if digits[split_at..] != expected {
        return Err(AccountAddressError::ChecksumMismatch);
    }
    Ok(canonical)
}
fn i105_payload_digits(payload: &str) -> Result<Vec<u8>, AccountAddressError> {
    let digit_count = payload.chars().count();
    let mut digits = Vec::new();
    reserve_address_vec(&mut digits, digit_count)?;
    for ch in payload.chars() {
        let mut symbol = [0_u8; 4];
        let encoded = ch.encode_utf8(&mut symbol);
        let Some(digit) = lookup_i105_digit(encoded) else {
            return Err(AccountAddressError::InvalidI105Char(ch));
        };
        digits.push(digit);
    }
    Ok(digits)
}
fn lookup_i105_digit(symbol: &str) -> Option<u8> {
    I105_DIGIT_TABLE
        .iter()
        .find_map(|(candidate, value)| (*candidate == symbol).then_some(*value))
}
fn i105_digit_symbol(digit: u8) -> Result<&'static str, AccountAddressError> {
    i105_symbol(digit).ok_or(AccountAddressError::InvalidI105Digit(digit))
}
/// Symbol for one I105 digit, or `None` outside the 105-digit alphabet.
#[doc(hidden)]
#[inline]
#[must_use]
pub fn i105_symbol(digit: u8) -> Option<&'static str> {
    I105_SYMBOLS.get(usize::from(digit)).copied()
}
const BASE58_ALPHABET: [&str; 58] = [
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "J", "K",
    "L", "M", "N", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e",
    "f", "g", "h", "i", "j", "k", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y",
    "z",
];
const IROHA_POEM_KANA_HALFWIDTH: [&str; 47] = [
    "ｲ", "ﾛ", "ﾊ", "ﾆ", "ﾎ", "ﾍ", "ﾄ", "ﾁ", "ﾘ", "ﾇ", "ﾙ", "ｦ", "ﾜ", "ｶ", "ﾖ", "ﾀ", "ﾚ", "ｿ", "ﾂ",
    "ﾈ", "ﾅ", "ﾗ", "ﾑ", "ｳ", "ヰ", "ﾉ", "ｵ", "ｸ", "ﾔ", "ﾏ", "ｹ", "ﾌ", "ｺ", "ｴ", "ﾃ", "ｱ", "ｻ", "ｷ",
    "ﾕ", "ﾒ", "ﾐ", "ｼ", "ヱ", "ﾋ", "ﾓ", "ｾ", "ｽ",
];
const fn i105_symbols() -> [&'static str; I105_BASE_U8 as usize] {
    let mut table = [""; I105_BASE_U8 as usize];
    let mut index = 0;
    while index < BASE58_ALPHABET.len() {
        table[index] = BASE58_ALPHABET[index];
        index += 1;
    }
    let mut kana = 0;
    while kana < IROHA_POEM_KANA_HALFWIDTH.len() {
        table[BASE58_ALPHABET.len() + kana] = IROHA_POEM_KANA_HALFWIDTH[kana];
        kana += 1;
    }
    table
}
/// The I105 digit alphabet in digit order: Base58 followed by the half-width Iroha poem kana.
#[doc(hidden)]
pub const I105_SYMBOLS: [&str; I105_BASE_U8 as usize] = i105_symbols();
static I105_DIGIT_TABLE: LazyLock<Vec<(&'static str, u8)>> = LazyLock::new(|| {
    let mut table = Vec::with_capacity(usize::from(I105_BASE_U8));
    for (index, symbol) in I105_SYMBOLS.iter().enumerate() {
        table.push((
            *symbol,
            u8::try_from(index).expect("I105 alphabet length fits within u8"),
        ));
    }
    table
});
#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use iroha_crypto::{Algorithm, KeyPair, PublicKey};
    use std::collections::BTreeSet;
    fn ed25519_pk() -> PublicKey {
        PublicKey::from_hex(
            Algorithm::Ed25519,
            "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf",
        )
        .expect("valid ed25519 payload")
    }
    fn ed25519_pk_with(byte: u8) -> PublicKey {
        let mut seed = vec![0xA5; 32];
        seed[0] = byte;
        let (public_key, _) = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("derive checked account-address fixture keypair")
            .into_parts();
        public_key
    }
    fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
            panic!("{algorithm:?} account-address fixture key generation should succeed: {err}")
        })
    }
    const ED25519_SMALL_ORDER_POINT: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const ED25519_ALL_ZERO_PUBLIC_KEY: [u8; 32] = [0_u8; 32];
    const ED25519_NON_CANONICAL_IDENTITY: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn account_address_for_seed(seed: u8) -> AccountAddress {
        let account = AccountId::new(ed25519_pk_with(seed));
        AccountAddress::from_account_id(&account).expect("account id encodes into an address")
    }
    const NONCANONICAL_IROHA_POEM_KANA_FULLWIDTH: [&str; 47] = [
        "イ", "ロ", "ハ", "ニ", "ホ", "ヘ", "ト", "チ", "リ", "ヌ", "ル", "ヲ", "ワ", "カ", "ヨ",
        "タ", "レ", "ソ", "ツ", "ネ", "ナ", "ラ", "ム", "ウ", "ヰ", "ノ", "オ", "ク", "ヤ", "マ",
        "ケ", "フ", "コ", "エ", "テ", "ア", "サ", "キ", "ユ", "メ", "ミ", "シ", "ヱ", "ヒ", "モ",
        "セ", "ス",
    ];
    fn fullwidth_sentinel_literal(canonical: &str) -> String {
        for (sentinel, fullwidth) in [
            (I105_SENTINEL_SORA, "ｓｏｒａ"),
            (I105_SENTINEL_TEST, "ｔｅｓｔ"),
            (I105_SENTINEL_DEV, "ｄｅｖ"),
        ] {
            if let Some(rest) = canonical.strip_prefix(sentinel) {
                return format!("{fullwidth}{rest}");
            }
        }
        if let Some(rest) = canonical.strip_prefix(I105_SENTINEL_FALLBACK_PREFIX) {
            return format!("ｎ{rest}");
        }
        canonical.to_owned()
    }
    fn fullwidth_payload_literal(canonical: &str) -> String {
        let mut literal = canonical.to_owned();
        for (halfwidth, fullwidth) in IROHA_POEM_KANA_HALFWIDTH
            .iter()
            .zip(NONCANONICAL_IROHA_POEM_KANA_FULLWIDTH.iter())
        {
            literal = literal.replace(halfwidth, fullwidth);
        }
        literal
    }

    #[test]
    fn account_address_json_roundtrip_supports_canonical_hex_literals() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("account address");
        let json_literal = norito::json::to_json(&address).expect("serialize account address");
        let decoded: AccountAddress =
            norito::json::from_str(&json_literal).expect("deserialize account address");
        assert_eq!(decoded, address);
    }

    #[test]
    fn account_address_value_and_map_key_json_decoders_are_borrowed_and_measured() {
        use norito::json::JsonDeserialize as _;

        let address = account_address_for_seed(0x35);
        let literal = address.canonical_hex().expect("canonical hex address");
        let value = norito::json::Value::String(literal.clone());
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (_, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            AccountAddress::json_from_value(&value)
        });
        let exact = usage.total_allocated_bytes();
        for decode in [
            norito::core::with_decode_limits_measured(limits(exact), || {
                AccountAddress::json_from_value(&value)
            }),
            norito::core::with_decode_limits_measured(limits(exact), || {
                <AccountAddress as json::JsonObjectKeyOwned>::from_json_key_text(&literal)
            }),
        ] {
            assert_eq!(decode.0.expect("exact AccountAddress budget"), address);
            assert_eq!(decode.1.total_allocated_bytes(), exact);
        }
        let mut key_text = String::new();
        json::JsonObjectKey::visit_json_key_text_checked(&address, |chunk| {
            key_text.push_str(chunk);
            Ok(())
        })
        .expect("stream canonical AccountAddress key");
        assert_eq!(key_text, literal);
        let mut accepted = 0_usize;
        let error = json::JsonObjectKey::visit_json_key_text_checked(&address, |chunk| {
            let next = accepted
                .checked_add(chunk.len())
                .ok_or(json::BoundedJsonError::BodyTooLarge)?;
            if next > literal.len() - 1 {
                return Err(json::BoundedJsonError::BodyTooLarge);
            }
            accepted = next;
            Ok(())
        })
        .expect_err("one-byte-short key sink must reject AccountAddress");
        assert_eq!(error, json::BoundedJsonError::BodyTooLarge);
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
            <AccountAddress as json::JsonObjectKeyOwned>::from_json_key_text(&literal)
        });
        assert!(matches!(
            decoded,
            Err(json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert!(usage.total_allocated_bytes() < exact);
    }
    #[test]
    fn chain_discriminant_guard_scopes_override() {
        let _outer = ChainDiscriminantGuard::enter(42);
        let original = chain_discriminant();
        {
            let _guard = ChainDiscriminantGuard::enter(original.wrapping_add(1));
            assert_eq!(chain_discriminant(), original.wrapping_add(1));
        }
        assert_eq!(chain_discriminant(), original);
    }
    #[test]
    fn chain_discriminant_guard_is_thread_local() {
        let original = chain_discriminant();
        let scoped = original.wrapping_add(17);
        let _guard = ChainDiscriminantGuard::enter(scoped);
        assert_eq!(chain_discriminant(), scoped);
        let thread_seen = std::thread::spawn(chain_discriminant)
            .join()
            .expect("thread should report its chain discriminant");
        assert_eq!(
            thread_seen, original,
            "thread-local override must not mutate the process-global discriminant"
        );
    }
    #[test]
    fn i105_discriminant_decoding_covers_known_numeric_and_invalid_prefixes() {
        assert_eq!(
            i105_sentinel_for_discriminant(CHAIN_DISCRIMINANT_SORA),
            I105_SENTINEL_SORA
        );
        assert_eq!(
            i105_sentinel_for_discriminant(CHAIN_DISCRIMINANT_TEST),
            I105_SENTINEL_TEST
        );
        assert_eq!(
            i105_sentinel_for_discriminant(CHAIN_DISCRIMINANT_DEV),
            I105_SENTINEL_DEV
        );
        assert_eq!(i105_sentinel_for_discriminant(42), "n42");
        let mut numeric = [0_u8; 6];
        for discriminant in [
            CHAIN_DISCRIMINANT_SORA,
            CHAIN_DISCRIMINANT_TEST,
            CHAIN_DISCRIMINANT_DEV,
            42,
            u16::MAX,
        ] {
            assert_eq!(
                write_i105_sentinel(discriminant, &mut numeric),
                i105_sentinel_for_discriminant(discriminant).as_bytes()
            );
        }
        assert_eq!(i105_symbol(0), Some("1"));
        assert_eq!(i105_symbol(58), Some(IROHA_POEM_KANA_HALFWIDTH[0]));
        assert_eq!(i105_symbol(I105_BASE_U8), None);
        let address = AccountAddress::from_account_id(&AccountId::new(ed25519_pk()))
            .expect("address encoding");
        for discriminant in [
            CHAIN_DISCRIMINANT_SORA,
            CHAIN_DISCRIMINANT_TEST,
            CHAIN_DISCRIMINANT_DEV,
            42,
        ] {
            let literal = address
                .to_i105_for_discriminant(discriminant)
                .expect("i105 encoding");
            assert_eq!(
                AccountAddress::i105_discriminant(&literal).expect("valid i105 discriminant"),
                discriminant
            );
        }
        assert!(matches!(
            AccountAddress::i105_discriminant("x42payload"),
            Err(AccountAddressError::MissingI105Sentinel)
        ));
        assert!(AccountAddress::i105_discriminant("n").is_err());
        assert!(AccountAddress::i105_discriminant("nabc").is_err());
        assert!(AccountAddress::i105_discriminant("n65536payload").is_err());
        let invalid_header_literal =
            encode_i105_literal(42, &[0b0001_0000]).expect("encode checksum-valid invalid header");
        assert!(matches!(
            AccountAddress::from_i105_for_discriminant(&invalid_header_literal, Some(42)),
            Err(AccountAddressError::UnknownAddressClass(2))
        ));
        assert!(matches!(
            AccountAddress::i105_discriminant(&invalid_header_literal),
            Err(AccountAddressError::UnknownAddressClass(2))
        ));
    }
    #[test]
    fn base_n_helpers_cover_empty_leading_zero_and_error_paths() {
        assert_eq!(
            encode_base_n(&[], I105_BASE).expect("empty encode"),
            vec![0]
        );
        let bytes = [0, 0, 1, 2, 255];
        let digits = encode_base_n(&bytes, I105_BASE).expect("base105 encode");
        assert_eq!(
            decode_base_n(&digits, I105_BASE).expect("base105 decode"),
            bytes
        );
        assert!(matches!(
            encode_base_n(&bytes, 1),
            Err(AccountAddressError::InvalidI105Base)
        ));
        assert!(matches!(
            decode_base_n(&digits, 1),
            Err(AccountAddressError::InvalidI105Base)
        ));
        assert!(matches!(
            decode_base_n(&[], I105_BASE),
            Err(AccountAddressError::InvalidLength)
        ));
        assert!(matches!(
            decode_base_n(&[2], 2),
            Err(AccountAddressError::InvalidI105Digit(2))
        ));
        assert!(matches!(
            i105_digit_symbol(I105_BASE_U8),
            Err(AccountAddressError::InvalidI105Digit(I105_BASE_U8))
        ));
    }

    #[test]
    fn grouped_base105_decode_roundtrips_large_payload() {
        let mut bytes = Vec::with_capacity(1_024);
        for index in 0..1_024_u16 {
            bytes.push(index.wrapping_mul(73).wrapping_add(19).to_le_bytes()[0]);
        }
        bytes[0] = 0;
        bytes[1] = 0;
        let digits = encode_base_n(&bytes, I105_BASE).expect("large base105 encode");
        assert!(
            digits.len() > 1_000,
            "fixture must exercise many digit groups"
        );
        assert_eq!(
            decode_base_n(&digits, I105_BASE).expect("grouped base105 decode"),
            bytes
        );
    }

    #[test]
    fn base32_and_checksum_helpers_cover_empty_and_partial_bytes() {
        assert_eq!(convert_to_base32(&[]), Vec::<u8>::new());
        assert_eq!(convert_to_base32(&[0x00]), vec![0, 0]);
        assert_eq!(convert_to_base32(&[0xff]), vec![31, 28]);
        assert_eq!(expand_hrp("snx"), vec![3, 3, 3, 0, 19, 14, 24]);
        let checksum = i105_checksum_digits(&[0x02, 0x00, 0x01]);
        assert_eq!(checksum.len(), I105_CHECKSUM_LEN);
        assert!(
            checksum.iter().all(|digit| u32::from(*digit) < 32),
            "bech32m checksum digits must be base32 limbs"
        );
    }
    #[test]
    fn truncated_selector_prefixed_payloads_are_rejected() {
        let mut canonical =
            hex::decode("0201b18fe9c1abbac45b3e38fc5d0001208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
                .expect("selector-prefixed fixture");
        let digest_start = 2; // header (0) + tag (1) + digest payload
        canonical.drain(digest_start + 8..digest_start + 12);
        let err = AccountAddress::from_canonical_bytes(&canonical)
            .expect_err("selector-prefixed payload rejected");
        let literal = format!("0x{}", hex::encode(&canonical));
        let parse_err = AccountId::parse_encoded(&literal).expect_err("account parsing fails");
        assert_eq!(
            parse_err.code_str(),
            "AccountId must use a canonical I105 literal"
        );
        assert_eq!(
            err.code_str(),
            AccountAddressErrorCode::UnknownCurve.as_str()
        );
    }
    #[test]
    fn malformed_selector_prefixed_payloads_are_rejected() {
        let mut canonical =
            hex::decode("0201b18fe9c1abbac45b3e38fc5d0001208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
                .expect("selector-prefixed fixture");
        canonical.drain(10..15);
        let err = AccountAddress::from_canonical_bytes(&canonical)
            .expect_err("selector-prefixed payload rejected");
        let literal = format!("0x{}", hex::encode(&canonical));
        let parse_err = AccountId::parse_encoded(&literal).expect_err("account parsing fails");
        assert_eq!(
            parse_err.code_str(),
            "AccountId must use a canonical I105 literal"
        );
        assert_eq!(
            err.code_str(),
            AccountAddressErrorCode::UnknownCurve.as_str()
        );
    }
    #[test]
    fn selector_prefixed_payloads_are_rejected() {
        let canonical = hex::decode(
            "0201b18fe9c1abbac45b3e38fc5d0001208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        )
        .expect("selector-prefixed fixture");
        AccountAddress::from_canonical_bytes(&canonical)
            .expect_err("selector-prefixed payload must be rejected");
    }
    #[test]
    fn iroha_poem_kana_matches_expected_order() {
        const EXPECTED: [&str; 47] = [
            "ｲ", "ﾛ", "ﾊ", "ﾆ", "ﾎ", "ﾍ", "ﾄ", "ﾁ", "ﾘ", "ﾇ", "ﾙ", "ｦ", "ﾜ", "ｶ", "ﾖ", "ﾀ", "ﾚ",
            "ｿ", "ﾂ", "ﾈ", "ﾅ", "ﾗ", "ﾑ", "ｳ", "ヰ", "ﾉ", "ｵ", "ｸ", "ﾔ", "ﾏ", "ｹ", "ﾌ", "ｺ", "ｴ",
            "ﾃ", "ｱ", "ｻ", "ｷ", "ﾕ", "ﾒ", "ﾐ", "ｼ", "ヱ", "ﾋ", "ﾓ", "ｾ", "ｽ",
        ];
        assert_eq!(IROHA_POEM_KANA_HALFWIDTH, EXPECTED);
    }
    #[test]
    fn i105_alphabet_has_unique_canonical_symbols() {
        let mut symbols = BTreeSet::new();
        for symbol in BASE58_ALPHABET {
            assert!(symbols.insert(symbol), "duplicate Base58 symbol {symbol}");
        }
        for symbol in IROHA_POEM_KANA_HALFWIDTH {
            assert!(
                symbols.insert(symbol),
                "duplicate Iroha poem symbol {symbol}"
            );
        }
        assert_eq!(
            symbols.len(),
            I105_SYMBOLS.len(),
            "unexpected I105 alphabet length"
        );
    }
    #[test]
    fn i105_golden_vectors_roundtrip() {
        let vectors = [
            ("default", 0_u8),
            ("treasury", 1_u8),
            ("wonderland", 2_u8),
            ("iroha", 3_u8),
            ("alpha", 4_u8),
            ("omega", 5_u8),
            ("governance", 6_u8),
            ("validators", 7_u8),
            ("explorer", 8_u8),
            ("soranet", 9_u8),
            ("kitsune", 10_u8),
            ("da", 11_u8),
        ];
        for (label, seed_byte) in vectors {
            let account = AccountId::new(ed25519_pk_with(seed_byte));
            let address = AccountAddress::from_account_id(&account).expect("address encoding");
            let canonical = address
                .canonical_hex()
                .expect("canonical encoding must succeed");
            let literal = address
                .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
                .expect("i105 encoding must succeed");
            assert!(
                canonical.starts_with("0x020001"),
                "canonical payloads must not include a domain selector byte: label={label} seed={seed_byte} canonical={canonical}"
            );
            let decoded =
                AccountAddress::from_i105_for_discriminant(&literal, Some(CHAIN_DISCRIMINANT_SORA))
                    .expect("i105 decode");
            assert_eq!(
                decoded.canonical_hex().expect("canonical"),
                canonical,
                "label={label} seed={seed_byte}"
            );
        }
    }
    #[test]
    fn canonical_payload_omits_domain_selector_bytes() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let canonical = address.canonical_bytes().expect("bytes");
        assert_eq!(canonical[0] >> 5, HEADER_VERSION_V1);
        assert_eq!(canonical[1], CONTROLLER_SINGLE_KEY_TAG);
        let mut selector_prefixed = canonical.clone();
        selector_prefixed.insert(1, 0x00);
        AccountAddress::from_canonical_bytes(&selector_prefixed)
            .expect_err("selector-prefixed payloads are rejected");
    }

    #[test]
    fn canonical_byte_emitter_preserves_single_and_multisig_outputs() {
        let single = AccountAddress::from_account_id(&AccountId::new(ed25519_pk()))
            .expect("single-key address");
        let members = vec![
            MultisigMember::new(ed25519_pk_with(1), 1).expect("first member"),
            MultisigMember::new(ed25519_pk_with(2), 2).expect("second member"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("multisig policy");
        let multisig = AccountAddress::from_account_id(&AccountId::new_multisig(policy))
            .expect("multisig address");

        for address in [&single, &multisig] {
            let bytes = address.canonical_bytes().expect("canonical bytes");
            let canonical_hex = format!("0x{}", hex::encode(bytes));
            assert_eq!(
                address.canonical_hex().expect("canonical hex"),
                canonical_hex
            );
            assert_eq!(address.to_string(), canonical_hex);

            {
                let expected = format!("\"{canonical_hex}\"");
                assert_eq!(
                    norito::json::to_json(address).expect("ordinary JSON"),
                    expected
                );
                assert_eq!(
                    norito::json::to_json_bounded(address, expected.len())
                        .expect("exact checked JSON"),
                    expected
                );
                assert!(matches!(
                    norito::json::to_json_bounded(address, expected.len() - 1),
                    Err(norito::json::BoundedJsonError::BodyTooLarge)
                ));
            }
        }
    }

    #[test]
    fn norito_try_deserialize_rejects_malformed_vec_without_panicking() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let mut payload = vec![0_u8; core::mem::size_of::<AccountAddress>().max(8)];
        payload[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        let archived = norito::core::archived_from_slice::<AccountAddress>(&payload)
            .expect("sized archived marker");
        let _flags = norito::core::DecodeFlagsGuard::enter(0);
        let _context = norito::core::PayloadCtxGuard::enter(archived.bytes());
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            <AccountAddress as DeserializePayload<'_>>::try_deserialize(archived.as_ref())
        }));
        let result = attempt.expect("fallible AccountAddress decode must not panic");
        assert!(result.is_err(), "malformed Vec framing must fail closed");
    }

    #[test]
    fn norito_address_preserves_nested_decode_resource_classification() {
        let error = account_address_norito_error(AccountAddressError::DecodeResourceLimit);
        assert!(
            matches!(error, ncore::Error::Json(json::Error::DecodeResourceLimit)),
            "an anonymous address bound must not invent allocator fields or an observer",
        );
    }

    #[test]
    fn canonical_byte_emitter_stops_at_the_first_sink_error() {
        #[derive(Debug, PartialEq, Eq)]
        struct Stop;

        let members = vec![
            MultisigMember::new(ed25519_pk_with(1), 1).expect("first member"),
            MultisigMember::new(ed25519_pk_with(2), 1).expect("second member"),
        ];
        let policy = MultisigPolicy::new(1, members).expect("multisig policy");
        let address = AccountAddress::from_account_id(&AccountId::new_multisig(policy))
            .expect("multisig address");
        let mut calls = 0;
        let error = address
            .emit_canonical_bytes(|_| {
                calls += 1;
                Err(Stop)
            })
            .expect_err("sink rejection must stop canonical emission");
        assert!(matches!(error, CanonicalEmissionError::Sink(Stop)));
        assert_eq!(
            calls, 1,
            "no controller/member may be visited after sink failure"
        );
    }

    #[test]
    fn canonical_address_bytes_depend_only_on_account_controller() {
        let key = ed25519_pk();
        let first_account = AccountId::new(key.clone());
        let second_account = AccountId::new(key);
        let first_address = AccountAddress::from_account_id(&first_account).expect("encode");
        let second_address = AccountAddress::from_account_id(&second_account).expect("encode");
        assert_eq!(
            first_address.canonical_bytes().expect("first bytes"),
            second_address.canonical_bytes().expect("second bytes"),
            "only the universal account controller may influence canonical bytes"
        );
    }
    #[test]
    fn i105_encoding_respects_chain_discriminant() {
        let _chain = ChainDiscriminantGuard::enter(42);
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let encoded = address.to_i105().expect("i105");
        assert_eq!(
            encoded,
            address
                .to_i105_for_discriminant(42)
                .expect("explicit discriminant")
        );
        assert_ne!(
            encoded,
            address
                .to_i105_for_discriminant(DEFAULT_CHAIN_DISCRIMINANT)
                .expect("default discriminant"),
            "changing the chain discriminant must change the encoded prefix bytes"
        );
    }
    #[test]
    fn i105_known_discriminants_roundtrip() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let sora = address
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("sora");
        let taira = address
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_TEST)
            .expect("test");
        let dev = address
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_DEV)
            .expect("dev");
        assert_ne!(sora, taira);
        assert_ne!(sora, dev);
        assert_ne!(taira, dev);
        assert!(!sora.contains(':'));
        assert!(!taira.contains(':'));
        assert!(!dev.contains(':'));
        for (literal, discriminant) in [
            (sora, CHAIN_DISCRIMINANT_SORA),
            (taira, CHAIN_DISCRIMINANT_TEST),
            (dev, CHAIN_DISCRIMINANT_DEV),
        ] {
            let decoded = AccountAddress::from_i105_for_discriminant(&literal, Some(discriminant))
                .expect("decode succeeds with discriminant");
            assert_eq!(
                decoded.canonical_bytes().unwrap(),
                address.canonical_bytes().unwrap()
            );
        }
    }
    #[test]
    fn parse_encoded_without_expected_discriminant_accepts_literal_prefix() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let testnet = address
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_TEST)
            .expect("testnet i105");
        let parsed = AccountAddress::parse_encoded(&testnet, None)
            .expect("omitted expected prefix accepts literal sentinel");
        assert_eq!(
            parsed.canonical_bytes().unwrap(),
            address.canonical_bytes().unwrap()
        );
        let err = AccountAddress::parse_encoded(&testnet, Some(CHAIN_DISCRIMINANT_SORA))
            .expect_err("explicit mainnet prefix still rejects testnet literal");
        assert!(matches!(
            err,
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: CHAIN_DISCRIMINANT_SORA,
                found: CHAIN_DISCRIMINANT_TEST
            }
        ));
    }
    #[test]
    fn parse_encoded_rejects_fullwidth_sentinel_literals() {
        let account = AccountId::new(ed25519_pk());
        let canonical = AccountAddress::from_account_id(&account)
            .expect("encode")
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("canonical I105");
        let noncanonical = fullwidth_sentinel_literal(&canonical);
        let err = AccountAddress::parse_encoded(&noncanonical, Some(CHAIN_DISCRIMINANT_SORA))
            .expect_err("fullwidth sentinel must be rejected");
        assert_eq!(
            err.code_str(),
            AccountAddressErrorCode::UnsupportedAddressFormat.as_str()
        );
    }
    #[test]
    fn i105_canonical_payload_uses_base58_and_iroha_kana() {
        let account = AccountId::new(ed25519_pk());
        let literal = AccountAddress::from_account_id(&account)
            .expect("encode")
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("i105");
        let payload = literal
            .strip_prefix(I105_SENTINEL_SORA)
            .expect("sora sentinel must prefix canonical literal");
        assert!(
            !payload.is_empty(),
            "canonical literal must contain payload symbols"
        );
        assert!(
            payload.chars().any(|ch| ch.is_ascii_alphanumeric()),
            "canonical I105 payload must expose Base58 symbols: {literal}"
        );
        assert!(
            payload.chars().any(|ch| {
                let mut symbol = [0_u8; 4];
                let encoded = ch.encode_utf8(&mut symbol);
                IROHA_POEM_KANA_HALFWIDTH
                    .iter()
                    .any(|candidate| *candidate == encoded)
            }),
            "canonical I105 payload must expose Iroha-poem katakana: {literal}"
        );
    }
    #[test]
    fn account_address_encodes_secp256k1_controller() {
        let (public_key, _) =
            checked_random_keypair_with_algorithm(Algorithm::Secp256k1).into_parts();
        let account = AccountId::new(public_key.clone());
        let address = AccountAddress::from_account_id(&account).expect("encode secp256k1");
        let controller = address
            .to_account_controller()
            .expect("decode secp256k1 controller");
        assert_eq!(controller.single_signatory(), Some(&public_key));
    }
    #[test]
    fn account_address_encodes_mldsa_controller_with_extended_length() {
        let (public_key, _) = checked_random_keypair_with_algorithm(Algorithm::MlDsa).into_parts();
        let (_algorithm, key_payload) = public_key
            .try_to_bytes()
            .expect("fixture ML-DSA public key must be well-formed");
        assert!(
            key_payload.len() > u8::MAX as usize,
            "ML-DSA public keys must exercise extended single-key encoding"
        );
        let account = AccountId::new(public_key.clone());
        let address = AccountAddress::from_account_id(&account).expect("encode mldsa");
        let canonical = address.canonical_bytes().expect("canonical bytes");
        assert_eq!(canonical[1], CONTROLLER_SINGLE_KEY_EXTENDED_TAG);
        assert_eq!(canonical[2], CurveId::MLDSA.as_u8());
        assert_eq!(
            usize::from(u16::from_be_bytes([canonical[3], canonical[4]])),
            key_payload.len()
        );
        let roundtrip = AccountAddress::from_canonical_bytes(&canonical)
            .expect("extended single-key address decodes")
            .to_account_id()
            .expect("extended single-key account id decodes");
        assert_eq!(roundtrip, account);
    }
    #[test]
    fn canonical_decode_rejects_reserved_headers_and_controller_class_mismatches() {
        let single = AccountAddress::from_account_id(&AccountId::new(ed25519_pk()))
            .expect("single-key address")
            .canonical_bytes()
            .expect("single-key canonical bytes");

        for version in 1_u8..=0b111 {
            let mut reserved = single.clone();
            reserved[0] = (version << 5) | (HEADER_NORM_VERSION_V1 << 1);
            let error = AccountAddress::from_canonical_bytes(&reserved)
                .expect_err("reserved address versions must be rejected");
            assert!(
                matches!(error, AccountAddressError::InvalidHeaderVersion(found) if found == version)
            );
        }
        for norm_version in [0_u8, 2, 3] {
            let mut reserved = single.clone();
            reserved[0] = norm_version << 1;
            let error = AccountAddress::from_canonical_bytes(&reserved)
                .expect_err("reserved normalization versions must be rejected");
            assert!(
                matches!(error, AccountAddressError::InvalidNormVersion(found) if found == norm_version)
            );
        }

        let mut compact_single_under_multisig = single;
        compact_single_under_multisig[0] = 0x0a;
        assert!(matches!(
            AccountAddress::from_canonical_bytes(&compact_single_under_multisig),
            Err(AccountAddressError::UnsupportedAddressFormat)
        ));

        let (mldsa_key, _) = checked_random_keypair_with_algorithm(Algorithm::MlDsa).into_parts();
        let mut extended_single_under_multisig =
            AccountAddress::from_account_id(&AccountId::new(mldsa_key))
                .expect("ML-DSA single-key address")
                .canonical_bytes()
                .expect("ML-DSA canonical bytes");
        assert_eq!(
            extended_single_under_multisig[1],
            CONTROLLER_SINGLE_KEY_EXTENDED_TAG
        );
        extended_single_under_multisig[0] = 0x0a;
        assert!(matches!(
            AccountAddress::from_canonical_bytes(&extended_single_under_multisig),
            Err(AccountAddressError::UnsupportedAddressFormat)
        ));

        let policy = MultisigPolicy::new(
            1,
            vec![MultisigMember::new(ed25519_pk_with(1), 1).expect("member")],
        )
        .expect("multisig policy");
        let mut multisig_under_single =
            AccountAddress::from_account_id(&AccountId::new_multisig(policy))
                .expect("multisig address")
                .canonical_bytes()
                .expect("multisig canonical bytes");
        multisig_under_single[0] = 0x02;
        assert!(matches!(
            AccountAddress::from_canonical_bytes(&multisig_under_single),
            Err(AccountAddressError::UnsupportedAddressFormat)
        ));
    }
    #[test]
    fn account_address_rejects_extended_encoding_for_short_single_key() {
        let account = AccountId::new(ed25519_pk());
        let canonical = AccountAddress::from_account_id(&account)
            .expect("encode")
            .canonical_bytes()
            .expect("canonical bytes");
        let key_len = canonical[3];
        let mut extended = Vec::with_capacity(canonical.len() + 1);
        extended.extend_from_slice(&canonical[..1]);
        extended.push(CONTROLLER_SINGLE_KEY_EXTENDED_TAG);
        extended.push(canonical[2]);
        extended.extend_from_slice(&u16::from(key_len).to_be_bytes());
        extended.extend_from_slice(&canonical[4..]);
        let err = AccountAddress::from_canonical_bytes(&extended)
            .expect_err("short keys must use canonical compact length");
        assert!(matches!(err, AccountAddressError::InvalidLength));
    }
    #[test]
    fn account_address_to_account_id_roundtrip() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode account id");
        let roundtrip = address.to_account_id().expect("decode account id");
        assert_eq!(roundtrip, account);
    }
    #[test]
    fn i105_round_trip_recovers_canonical_payload() {
        let account = AccountId::new(ed25519_pk());
        let original = AccountAddress::from_account_id(&account).expect("encode");
        let encoded = original.to_i105_for_discriminant(73).expect("i105");
        let decoded = AccountAddress::from_i105_for_discriminant(&encoded, Some(73))
            .expect("decode succeeds with discriminant");
        assert_eq!(
            decoded.canonical_bytes().unwrap(),
            original.canonical_bytes().unwrap()
        );
    }
    #[test]
    fn i105_discriminant_mismatch_fails() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let encoded = address.to_i105_for_discriminant(10).expect("i105");
        let err = AccountAddress::from_i105_for_discriminant(&encoded, Some(11))
            .expect_err("discriminant mismatch");
        assert!(matches!(
            err,
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: 11,
                found: 10
            }
        ));
    }
    #[test]
    fn from_i105_validates_scoped_chain_discriminant() {
        let _chain = ChainDiscriminantGuard::enter(73);
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let encoded = address.to_i105_for_discriminant(42).expect("i105");
        let err = AccountAddress::from_i105(&encoded).expect_err("foreign discriminant rejected");
        assert!(matches!(
            err,
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: 73,
                found: 42
            }
        ));
    }
    #[test]
    fn from_i105_without_expected_discriminant_accepts_literal_prefix() {
        let account = AccountId::new(ed25519_pk());
        let original = AccountAddress::from_account_id(&account).expect("encode");
        let literal = original.to_i105_for_discriminant(42).expect("i105");
        let decoded = AccountAddress::from_i105_for_discriminant(&literal, None)
            .expect("omitted expected discriminant should use literal prefix");
        assert_eq!(
            decoded.canonical_bytes().unwrap(),
            original.canonical_bytes().unwrap()
        );
    }
    #[test]
    fn i105_round_trip() {
        let _chain = ChainDiscriminantGuard::enter(42);
        let account = AccountId::new(ed25519_pk());
        let original = AccountAddress::from_account_id(&account).expect("encode");
        let literal = original.to_i105().expect("i105 encode");
        assert!(
            literal.starts_with("n42"),
            "scoped discriminant must drive canonical i105 encoding"
        );
        let decoded = AccountAddress::from_i105(&literal).expect("i105 decode");
        assert_eq!(
            decoded.canonical_bytes().unwrap(),
            original.canonical_bytes().unwrap()
        );
    }
    #[test]
    fn i105_rejects_fullwidth_iroha_kana_inputs() {
        let account = AccountId::new(ed25519_pk());
        let original = AccountAddress::from_account_id(&account).expect("encode");
        let canonical = original
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("i105 encode");
        let fullwidth = fullwidth_payload_literal(&canonical);
        assert_ne!(canonical, fullwidth);
        let err =
            AccountAddress::from_i105_for_discriminant(&fullwidth, Some(CHAIN_DISCRIMINANT_SORA))
                .expect_err("fullwidth kana must be rejected");
        assert!(matches!(err, AccountAddressError::InvalidI105Char(_)));
        let parse_err = AccountAddress::parse_encoded(&fullwidth, Some(CHAIN_DISCRIMINANT_SORA))
            .expect_err("strict parse rejects fullwidth kana");
        assert!(matches!(parse_err, AccountAddressError::InvalidI105Char(_)));
    }
    #[test]
    fn i105_invalid_char_rejected() {
        let account = AccountId::new(ed25519_pk());
        let mut chars = AccountAddress::from_account_id(&account)
            .expect("encode")
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("i105 encode")
            .chars()
            .collect::<Vec<_>>();
        let last = chars.len() - 1;
        chars[last] = '!';
        let literal = chars.into_iter().collect::<String>();
        let err =
            AccountAddress::from_i105_for_discriminant(&literal, Some(CHAIN_DISCRIMINANT_SORA))
                .expect_err("invalid char should fail");
        assert!(matches!(err, AccountAddressError::InvalidI105Char('!')));
    }
    #[test]
    fn i105_checksum_mismatch_detected() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let mut tampered = address
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("i105 encode")
            .chars()
            .collect::<Vec<_>>();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == '1' { '2' } else { '1' };
        let tampered = tampered.into_iter().collect::<String>();
        let err =
            AccountAddress::from_i105_for_discriminant(&tampered, Some(CHAIN_DISCRIMINANT_SORA))
                .expect_err("checksum mismatch");
        assert!(matches!(err, AccountAddressError::ChecksumMismatch));
    }
    #[test]
    fn i105_checksum_corruption_detected_for_deterministic_cases() {
        let seeds = [0_u8, 1, 2, 7, 31, 63, 127, 128, 191, 255];
        for &seed in &seeds {
            let address = account_address_for_seed(seed);
            let literal = address
                .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
                .expect("i105 encode");
            let sentinel_len = i105_sentinel_for_discriminant(CHAIN_DISCRIMINANT_SORA)
                .chars()
                .count();
            let payload_len = literal.chars().count() - sentinel_len;
            let offsets = [0, 1, 2, payload_len / 2, payload_len - 1];
            for offset in offsets {
                let mut chars = literal.chars().collect::<Vec<_>>();
                let index = sentinel_len + offset;
                chars[index] = match chars[index] {
                    '1' => '2',
                    _ => '1',
                };
                let tampered = chars.into_iter().collect::<String>();
                let err = AccountAddress::from_i105_for_discriminant(
                    &tampered,
                    Some(CHAIN_DISCRIMINANT_SORA),
                )
                .expect_err("checksum mismatch");
                assert!(matches!(err, AccountAddressError::ChecksumMismatch));
            }
        }
    }
    #[test]
    fn canonical_decode_rejects_small_order_public_key() {
        let account = AccountId::new(ed25519_pk());
        let mut canonical = AccountAddress::from_account_id(&account)
            .expect("encode")
            .canonical_bytes()
            .expect("bytes");
        let offset = canonical.len() - ED25519_SMALL_ORDER_POINT.len();
        canonical[offset..].copy_from_slice(&ED25519_SMALL_ORDER_POINT);
        let err = AccountAddress::from_canonical_bytes(&canonical).unwrap_err();
        assert!(matches!(err, AccountAddressError::InvalidPublicKey));
    }
    #[test]
    fn canonical_decode_rejects_all_zero_public_key() {
        let account = AccountId::new(ed25519_pk());
        let mut canonical = AccountAddress::from_account_id(&account)
            .expect("encode")
            .canonical_bytes()
            .expect("bytes");
        let offset = canonical.len() - ED25519_ALL_ZERO_PUBLIC_KEY.len();
        canonical[offset..].copy_from_slice(&ED25519_ALL_ZERO_PUBLIC_KEY);
        let err = AccountAddress::from_canonical_bytes(&canonical).unwrap_err();
        assert!(matches!(err, AccountAddressError::InvalidPublicKey));
    }
    #[test]
    fn canonical_decode_rejects_non_canonical_public_key() {
        let account = AccountId::new(ed25519_pk());
        let mut canonical = AccountAddress::from_account_id(&account)
            .expect("encode")
            .canonical_bytes()
            .expect("bytes");
        let offset = canonical.len() - ED25519_NON_CANONICAL_IDENTITY.len();
        canonical[offset..].copy_from_slice(&ED25519_NON_CANONICAL_IDENTITY);
        let err = AccountAddress::from_canonical_bytes(&canonical).unwrap_err();
        assert!(matches!(err, AccountAddressError::InvalidPublicKey));
    }
    #[test]
    fn canonical_decode_rejects_forged_multisig_count_before_allocation() {
        let header = AddressHeader::new(
            HEADER_VERSION_V1,
            AddressClass::MultiSig,
            HEADER_NORM_VERSION_V1,
        )
        .expect("canonical multisig header")
        .encode();
        // Reject truncated member inventories before charging or allocating their counts.
        for count in [u16::MAX, 1_u16, 2_u16] {
            let [high, low] = count.to_be_bytes();
            let canonical = [header, CONTROLLER_MULTISIG_TAG, 1, 0, 1, high, low];
            let (result, usage) = norito::core::with_decode_limits_measured(
                norito::core::DecodeLimits::new(64, 256, 64, 0, 8),
                || AccountAddress::from_canonical_bytes(&canonical),
            );
            assert!(matches!(result, Err(AccountAddressError::InvalidLength)));
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }

    #[test]
    fn parse_encoded_accepts_i105_format() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let literal = address
            .to_i105_for_discriminant(42)
            .expect("i105 with explicit discriminant");
        let decoded = AccountAddress::parse_encoded(&literal, Some(42)).expect("parse i105");
        assert_eq!(
            decoded.canonical_bytes().unwrap(),
            address.canonical_bytes().unwrap()
        );
    }
    #[test]
    fn parse_encoded_accepts_numeric_i105_without_global_discriminant() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let literal = address.to_i105_for_discriminant(42).expect("i105");
        assert_eq!(
            AccountAddress::i105_discriminant(&literal).expect("decode discriminant"),
            42
        );
        let inferred = AccountAddress::parse_encoded(&literal, None)
            .expect("embedded discriminant should parse");
        let explicit = AccountAddress::parse_encoded(&literal, Some(42))
            .expect("explicit discriminant should parse");
        assert_eq!(
            inferred.canonical_bytes().unwrap(),
            address.canonical_bytes().unwrap()
        );
        assert_eq!(
            explicit.canonical_bytes().unwrap(),
            address.canonical_bytes().unwrap()
        );
    }
    #[test]
    fn parse_encoded_rejects_padded_i105_literal() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let literal = address.to_i105_for_discriminant(42).expect("i105");
        let padded = format!(" \n{literal}\t ");
        let error = AccountAddress::parse_encoded(&padded, Some(42))
            .expect_err("padded i105 is not the canonical first-release literal");
        assert!(matches!(
            error,
            AccountAddressError::UnsupportedAddressFormat
        ));
        let error = AccountAddress::i105_discriminant(&padded)
            .expect_err("discriminant inspection must reject padded i105");
        assert!(matches!(
            error,
            AccountAddressError::UnsupportedAddressFormat
        ));
    }
    #[test]
    fn parse_encoded_rejects_whitespace_only_input() {
        let err = AccountAddress::parse_encoded(" \n\t ", None)
            .expect_err("whitespace-only input is empty after trimming");
        assert!(matches!(err, AccountAddressError::InvalidLength));
    }
    #[test]
    fn parse_encoded_rejects_noncanonical_numeric_sentinel() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let canonical = address.to_i105_for_discriminant(42).expect("i105");
        let noncanonical = canonical.replacen("n42", "n00042", 1);
        let err = AccountAddress::parse_encoded(&noncanonical, None)
            .expect_err("numeric sentinel must use canonical decimal form");
        assert!(matches!(err, AccountAddressError::UnsupportedAddressFormat));
    }
    #[test]
    fn parse_encoded_rejects_wrong_expected_numeric_discriminant() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let literal = address.to_i105_for_discriminant(42).expect("i105");
        let foreign = literal.replacen("n42", "n43", 1);
        let inferred = AccountAddress::parse_encoded(&foreign, None)
            .expect("foreign embedded discriminant is valid when no prefix is expected");
        assert_eq!(
            inferred.canonical_bytes().unwrap(),
            address.canonical_bytes().unwrap()
        );
        let err = AccountAddress::parse_encoded(&foreign, Some(42))
            .expect_err("explicit expected discriminant must reject foreign prefix");
        assert!(matches!(
            err,
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: 42,
                found: 43
            }
        ));
    }
    #[test]
    fn parse_encoded_rejects_foreign_numeric_discriminant_that_extends_expected_prefix() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let foreign = address
            .to_i105_for_discriminant(421)
            .expect("foreign i105 with longer numeric sentinel");
        assert!(
            foreign.starts_with("n421"),
            "fixture must extend the expected n42 sentinel"
        );
        let inferred = AccountAddress::parse_encoded(&foreign, None)
            .expect("foreign embedded discriminant is valid when no prefix is expected");
        assert_eq!(
            inferred.canonical_bytes().unwrap(),
            address.canonical_bytes().unwrap()
        );
        let err = AccountAddress::parse_encoded(&foreign, Some(42))
            .expect_err("expected n42 must reject foreign n421 prefix");
        assert!(matches!(
            err,
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: 42,
                found: 421
            }
        ));
    }
    #[test]
    fn parse_encoded_rejects_numeric_i105_payload_tampering() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let literal = address.to_i105_for_discriminant(42).expect("i105");
        let mut chars = literal.chars().collect::<Vec<_>>();
        let last = chars.len().saturating_sub(1);
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let tampered = chars.into_iter().collect::<String>();
        let err = AccountAddress::parse_encoded(&tampered, None)
            .expect_err("payload/checksum tampering must be rejected");
        assert!(matches!(
            err,
            AccountAddressError::ChecksumMismatch | AccountAddressError::InvalidI105Char(_)
        ));
    }
    #[test]
    fn parse_encoded_rejects_unknown_format() {
        let err = AccountAddress::parse_encoded("alice@banka.dataspace", None)
            .expect_err("alias literal rejected");
        assert!(matches!(err, AccountAddressError::UnsupportedAddressFormat));
    }
    #[test]
    fn parse_encoded_rejects_garbage_literal_as_unsupported_format() {
        let err = AccountAddress::parse_encoded("invalid-address", None)
            .expect_err("garbage literal rejected");
        assert!(matches!(err, AccountAddressError::UnsupportedAddressFormat));
    }
    #[test]
    fn parse_encoded_preserves_malformed_i105_errors() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let mut chars = address
            .to_i105_for_discriminant(CHAIN_DISCRIMINANT_SORA)
            .expect("i105")
            .chars()
            .collect::<Vec<_>>();
        let last = chars.len().saturating_sub(1);
        chars[last] = '0';
        let invalid = chars.into_iter().collect::<String>();
        let err = AccountAddress::parse_encoded(&invalid, Some(CHAIN_DISCRIMINANT_SORA))
            .expect_err("i105 invalid char must preserve semantic error");
        assert!(matches!(err, AccountAddressError::InvalidI105Char('0')));
        let short = i105_sentinel_for_discriminant(CHAIN_DISCRIMINANT_SORA);
        let err = AccountAddress::parse_encoded(&short, Some(CHAIN_DISCRIMINANT_SORA))
            .expect_err("i105 sentinel-only literal must preserve semantic error");
        assert!(matches!(err, AccountAddressError::I105TooShort));
    }
    #[test]
    fn parse_encoded_accepts_only_i105() {
        let account = AccountId::new(ed25519_pk());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let i105 = address.to_i105_for_discriminant(42).expect("i105");
        let canonical = address.canonical_hex().expect("canonical");
        AccountAddress::parse_encoded(&i105, Some(42)).expect("parse i105");
        let err = AccountAddress::parse_encoded(&canonical, None)
            .expect_err("canonical must be rejected");
        assert!(matches!(err, AccountAddressError::UnsupportedAddressFormat));
    }
    #[test]
    fn multisig_address_round_trip_preserves_policy() {
        let members = vec![
            MultisigMember::new(ed25519_pk_with(1), 1).expect("member"),
            MultisigMember::new(ed25519_pk_with(2), 2).expect("member"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let account = AccountId::new_multisig(policy.clone());
        let address = AccountAddress::from_account_id(&account).expect("encode");
        let controller = address.to_account_controller().expect("controller");
        assert_eq!(controller.multisig_policy().expect("multisig"), &policy);
        let canonical = address.canonical_bytes().expect("bytes");
        assert_eq!((canonical[0] >> 3) & 0b11, 1, "multisig class tag");
        let i105 = address.to_i105_for_discriminant(42).expect("i105");
        let parsed = AccountAddress::parse_encoded(&i105, Some(42)).expect("parse i105");
        let decoded = parsed.to_account_controller().expect("controller");
        assert_eq!(decoded.multisig_policy().expect("multisig"), &policy);
    }
    #[test]
    fn multisig_address_rejects_inert_member_public_key() {
        let members = vec![
            MultisigMember::new(ed25519_pk_with(1), 1).expect("member"),
            MultisigMember::new(ed25519_pk_with(2), 2).expect("member"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let account = AccountId::new_multisig(policy);
        for (label, public_key) in [
            ("all-zero", ED25519_ALL_ZERO_PUBLIC_KEY),
            ("small-order", ED25519_SMALL_ORDER_POINT),
            ("noncanonical", ED25519_NON_CANONICAL_IDENTITY),
        ] {
            let mut canonical = AccountAddress::from_account_id(&account)
                .expect("encode")
                .canonical_bytes()
                .expect("bytes");
            let offset = canonical.len() - public_key.len();
            canonical[offset..].copy_from_slice(&public_key);
            let err = AccountAddress::from_canonical_bytes(&canonical).unwrap_err();
            assert!(
                matches!(err, AccountAddressError::InvalidPublicKey),
                "{label} multisig member key must fail at public-key admission"
            );
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn account_address_error_codes_are_stable() {
        macro_rules! assert_code {
            ($error:expr, $code_variant:ident, $code_str:literal) => {{
                let err: AccountAddressError = $error;
                assert_eq!(err.code(), AccountAddressErrorCode::$code_variant);
                assert_eq!(err.code_str(), $code_str);
            }};
        }
        assert_code!(
            AccountAddressError::UnsupportedAlgorithm(Algorithm::Secp256k1),
            UnsupportedAlgorithm,
            "ERR_UNSUPPORTED_ALGORITHM"
        );
        assert_code!(
            AccountAddressError::KeyPayloadTooLong(1024),
            KeyPayloadTooLong,
            "ERR_KEY_PAYLOAD_TOO_LONG"
        );
        assert_code!(
            AccountAddressError::InvalidHeaderVersion(5),
            InvalidHeaderVersion,
            "ERR_INVALID_HEADER_VERSION"
        );
        assert_code!(
            AccountAddressError::InvalidNormVersion(3),
            InvalidNormVersion,
            "ERR_INVALID_NORM_VERSION"
        );
        assert_code!(
            AccountAddressError::InvalidLength,
            InvalidLength,
            "ERR_INVALID_LENGTH"
        );
        assert_code!(
            AccountAddressError::ChecksumMismatch,
            ChecksumMismatch,
            "ERR_CHECKSUM_MISMATCH"
        );
        assert_code!(
            AccountAddressError::InvalidHexAddress,
            InvalidHexAddress,
            "ERR_INVALID_HEX_ADDRESS"
        );
        assert_code!(
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: 0x1200,
                found: 0x3400
            },
            UnexpectedNetworkPrefix,
            "ERR_UNEXPECTED_NETWORK_PREFIX"
        );
        assert_code!(
            AccountAddressError::UnknownAddressClass(7),
            UnknownAddressClass,
            "ERR_UNKNOWN_ADDRESS_CLASS"
        );
        assert_code!(
            AccountAddressError::UnexpectedExtensionFlag,
            UnexpectedExtensionFlag,
            "ERR_UNEXPECTED_EXTENSION_FLAG"
        );
        assert_code!(
            AccountAddressError::UnknownControllerTag(11),
            UnknownControllerTag,
            "ERR_UNKNOWN_CONTROLLER_TAG"
        );
        assert_code!(
            AccountAddressError::InvalidPublicKey,
            InvalidPublicKey,
            "ERR_INVALID_PUBLIC_KEY"
        );
        assert_code!(
            AccountAddressError::DecodeResourceLimit,
            DecodeResourceLimit,
            "ERR_DECODE_RESOURCE_LIMIT"
        );
        assert_code!(
            AccountAddressError::UnknownCurve(4),
            UnknownCurve,
            "ERR_UNKNOWN_CURVE"
        );
        assert_code!(
            AccountAddressError::UnexpectedTrailingBytes,
            UnexpectedTrailingBytes,
            "ERR_UNEXPECTED_TRAILING_BYTES"
        );
        assert_code!(
            AccountAddressError::MissingI105Sentinel,
            MissingI105Sentinel,
            "ERR_MISSING_I105_SENTINEL"
        );
        assert_code!(
            AccountAddressError::I105TooShort,
            I105TooShort,
            "ERR_I105_TOO_SHORT"
        );
        assert_code!(
            AccountAddressError::InvalidI105Char('!'),
            InvalidI105Char,
            "ERR_INVALID_I105_CHAR"
        );
        assert_code!(
            AccountAddressError::InvalidI105Base,
            InvalidI105Base,
            "ERR_INVALID_I105_BASE"
        );
        assert_code!(
            AccountAddressError::InvalidI105Digit(105),
            InvalidI105Digit,
            "ERR_INVALID_I105_DIGIT"
        );
        assert_code!(
            AccountAddressError::UnsupportedAddressFormat,
            UnsupportedAddressFormat,
            "ERR_UNSUPPORTED_ADDRESS_FORMAT"
        );
        assert_code!(
            AccountAddressError::MultisigMemberOverflow(32),
            MultisigMemberOverflow,
            "ERR_MULTISIG_MEMBER_OVERFLOW"
        );
        assert_code!(
            AccountAddressError::InvalidMultisigPolicy(MultisigPolicyError::EmptyMembers),
            InvalidMultisigPolicy,
            "ERR_INVALID_MULTISIG_POLICY"
        );
    }

    #[test]
    fn canonical_address_json_preserves_original_refusal_fields_scope_and_retry() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };
        use norito::json::{JsonDeserialize as _, JsonObjectKeyOwned as _};

        let expected = account_address_for_seed(0x6b);
        let literal = expected.canonical_hex().unwrap();
        let value = norito::json::Value::String(literal.clone());
        let wire = norito::json::to_json(&literal).unwrap();
        let source_pointer = value.as_str().unwrap().as_ptr();
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let decode = |mode| match mode {
            0 => AccountAddress::json_from_value(&value),
            1 => AccountAddress::from_json_key_text(&literal),
            2 => norito::json::from_json::<AccountAddress>(&wire),
            _ => unreachable!("three actual canonical JSON API owners"),
        };
        let demands = [0, 1, 2].map(|mode| {
            let (decoded, usage) =
                norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(mode));
            assert_eq!(decoded.unwrap(), expected);
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            demand
        });
        let context_limit = demands
            .iter()
            .try_fold(0_usize, |total, demand| total.checked_add(*demand))
            .unwrap()
            .checked_mul(2)
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(context_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        // The original pool owns the decoder counters. These ordinary JSON controls do not
        // claim physical admission of the returned account graph.
        for (mode, demand) in demands.into_iter().enumerate() {
            let decode = || decode(mode);
            let mut observed = None;
            let before = original.consumed_allocated_bytes();
            let refusal = original.with(|| norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let error = decode().expect_err("one-byte-short canonical decoder must refuse");
                    let norito::json::Error::ScopedDecodeResource(origin) = &error else {
                        panic!("canonical AccountAddress JSON must retain the original scoped refusal: {error:?}");
                    };
                    observed = Some(origin.clone());
                    Err::<(), _>(error.into_core_error())
                })
            })).unwrap_err();
            assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            let refusal = refusal.into_error();
            assert_eq!(
                refusal.decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(demand).unwrap(),
                    limit: u64::try_from(demand - 1).unwrap(),
                })
            );
            let norito::Error::ScopedDecodeResource(returned) = refusal else {
                panic!("canonical JSON must return its exact original observer");
            };
            assert_eq!(returned, observed.unwrap());
            drop(returned);
            assert_eq!(pool.reserved_bytes(), baseline);
            let after_refusal = original.consumed_allocated_bytes();
            assert!(after_refusal >= before);
            // The original outer context records the attempted charge before the
            // narrower inner ceiling refuses it. Its counters are cumulative and
            // must not be refunded or replaced by the failed inner operation.
            assert_eq!(after_refusal - before, u64::try_from(demand).unwrap());
            let retry = original
                .with(decode)
                .expect("same input and original context retry");
            assert_eq!(retry, expected);
            assert_eq!(
                original.consumed_allocated_bytes() - after_refusal,
                u64::try_from(demand).unwrap()
            );
            drop(retry);
            assert_eq!(pool.reserved_bytes(), baseline);

            let (error, usage) =
                norito::core::with_decode_limits_measured(limits(demand - 1), decode);
            let error = error
                .expect_err("same input unscoped quota refusal")
                .into_core_error();
            assert_eq!(
                error.decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(demand).unwrap(),
                    limit: u64::try_from(demand - 1).unwrap(),
                })
            );
            assert!(!matches!(error, norito::Error::ScopedDecodeResource(_)));
            assert!(usage.total_allocated_bytes() < demand);
        }
        let invalid =
            AccountAddress::json_from_value(&norito::json::Value::Bool(false)).unwrap_err();
        assert!(matches!(invalid, norito::json::Error::Message(_)));
        assert_eq!(value.as_str().unwrap().as_ptr(), source_pointer);
        assert_eq!(value.as_str(), Some(literal.as_str()));
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn address_resource_conversions_preserve_fields_and_anonymous_bounds_without_minting_scope() {
        let resource = ncore::DecodeResourceError::AllocationFailed { bytes: 97 };
        let error = AccountAddressError::from_decode_error(resource.into());
        assert!(error.is_decode_resource_limit());
        assert_eq!(
            error.code_str(),
            AccountAddressErrorCode::DecodeResourceLimit.as_str()
        );
        let error = account_address_norito_error(error);
        assert_eq!(error.decode_resource_error(), Some(resource));
        assert!(!matches!(error, ncore::Error::ScopedDecodeResource(_)));
        let error = map_account_address_json_error(AccountAddressError::from_decode_error(
            ncore::Error::Json(json::Error::DecodeResource(resource)),
        ));
        assert_eq!(
            error.into_core_error().decode_resource_error(),
            Some(resource)
        );
        assert!(matches!(
            AccountAddressError::from_decode_error(ncore::Error::InvalidValue {
                context: "public key"
            }),
            AccountAddressError::InvalidPublicKey
        ));
        let mut vector = Vec::<u64>::new();
        assert!(reserve_address_vec(&mut vector, 2).is_ok());
        assert!(vector.capacity() >= 2);
        assert!(matches!(
            reserve_address_vec(&mut vector, usize::MAX),
            Err(AccountAddressError::DecodeResourceLimit)
        ));
        assert!(vector.is_empty());
        let mut string = String::from("sora");
        assert!(reserve_address_string(&mut string, 6).is_ok());
        assert_eq!(string, "sora");
        assert!(matches!(
            reserve_address_string(&mut string, usize::MAX),
            Err(AccountAddressError::DecodeResourceLimit)
        ));
        assert_eq!(string, "sora");
        assert!(matches!(
            map_account_address_json_error(AccountAddressError::DecodeResourceLimit),
            json::Error::DecodeResourceLimit
        ));
        assert!(matches!(
            account_address_norito_error(AccountAddressError::DecodeResourceLimit),
            ncore::Error::Json(json::Error::DecodeResourceLimit)
        ));
        let layout = std::alloc::Layout::array::<MultisigMemberPayload>(2).unwrap();
        assert_eq!(
            account_address_norito_error(address_allocation_failure(layout))
                .decode_resource_error(),
            Some(ncore::DecodeResourceError::AllocationFailed {
                bytes: u64::try_from(layout.size()).unwrap()
            })
        );
    }
    fn observed_i105_terminal_refusal(
        original: &norito::core::DecodeBudgetContext,
        decode: impl FnOnce() -> Result<AccountAddress, AccountAddressError>,
    ) -> (norito::core::DecodeResourceError, [usize; 3]) {
        use norito::core::{DecodeAttemptErrorKind, classify_decode_attempt};
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let before = original.consumed_allocated_bytes();
        let mut observed = None;
        let (refusal, requests) = crate::amx_prepare_streaming_allocations::measured(|| {
            original.with(|| norito::with_decode_limits_scope(limits, || {
                classify_decode_attempt(|| {
                    let error = decode().expect_err("original zero quota must refuse controller admission");
                    let AccountAddressError::ScopedDecodeResource(origin) = &error else {
                        panic!("public I105 parsing must retain the original scoped refusal: {error:?}");
                    };
                    observed = Some(origin.clone());
                    Err::<AccountAddress, _>(account_address_norito_error(error))
                })
            }))
        });
        let refusal = refusal.unwrap_err();
        assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let refusal = refusal.into_error();
        let resource = refusal
            .decode_resource_error()
            .expect("original typed fields");
        let norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted,
            limit: 0,
        } = resource
        else {
            panic!("the genuine first controller request must refuse the zero inner quota");
        };
        assert!(attempted > 0);
        // Existing admission debits the original outer layer before the narrower
        // inner layer refuses. Refusal does not refund cumulative decoder work.
        assert_eq!(original.consumed_allocated_bytes() - before, attempted);
        let norito::Error::ScopedDecodeResource(returned) = refusal else {
            panic!("original scoped observer must survive the public return");
        };
        assert_eq!(returned, observed.unwrap());
        drop(returned);
        (resource, requests)
    }

    fn first_i105_controller_charge(expected: &AccountAddress) -> usize {
        let canonical = expected.canonical_bytes().unwrap();
        let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let error = norito::with_decode_limits_scope(zero, || {
            AccountAddress::from_canonical_bytes(&canonical)
        })
        .unwrap_err();
        let AccountAddressError::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted,
                limit: 0,
            },
        ) = error
        else {
            panic!(
                "independent canonical controller admission must report its first actual request"
            );
        };
        usize::try_from(attempted).unwrap()
    }

    fn numeric_candidate_refusal_fixture() -> (AccountAddress, String) {
        let members = (0..6)
            .map(|index| MultisigMember::new(ed25519_pk_with(0x80 + index), 1).unwrap())
            .collect();
        let account = AccountId::new_multisig(MultisigPolicy::new(3, members).unwrap());
        let address = AccountAddress::from_account_id(&account).unwrap();
        let literal = address.to_i105_for_discriminant(1).unwrap();
        let rest = literal.strip_prefix(I105_SENTINEL_FALLBACK_PREFIX).unwrap();
        let (candidate, payload) = numeric_i105_sentinel_candidate(rest, 1).unwrap();
        assert_eq!(candidate, 1);
        assert!(payload.starts_with(|character: char| character.is_ascii_digit()));
        assert!(numeric_i105_sentinel_candidate(rest, 2).is_some());
        assert_eq!(
            AccountAddress::from_i105_for_discriminant(&literal, None).unwrap(),
            address
        );
        (address, literal)
    }

    #[test]
    fn numeric_i105_resource_refusal_stops_at_original_candidate_without_later_allocations() {
        use norito::core::DecodeBudgetContext;
        let (expected, literal) = numeric_candidate_refusal_fixture();
        let source_pointer = literal.as_ptr();
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                AccountAddress::from_i105_for_discriminant(&literal, None)
            });
        assert_eq!(decoded.unwrap(), expected);
        let demand = usage.total_allocated_bytes();
        assert!(demand > 0);
        let first_charge = first_i105_controller_charge(&expected);
        let original_limit = first_charge
            .checked_mul(2)
            .unwrap()
            .checked_add(demand)
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(original_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        // The reference stops at the first genuine candidate's admitted controller
        // refusal, using the same canonical kernels and original observer. It includes
        // the required numeric-sentinel formatting and all pre-refusal payload buffers.
        let (expected_resource, expected_requests) =
            observed_i105_terminal_refusal(&original, || {
                let rest = literal.strip_prefix(I105_SENTINEL_FALLBACK_PREFIX).unwrap();
                let (candidate, payload) = numeric_i105_sentinel_candidate(rest, 1).unwrap();
                assert_eq!(candidate, 1);
                let canonical = decode_i105_payload(payload)?;
                AccountAddress::from_canonical_bytes(&canonical)
            });
        let (resource, actual_requests) = observed_i105_terminal_refusal(&original, || {
            AccountAddress::from_i105_for_discriminant(&literal, None)
        });
        assert_eq!(resource, expected_resource);
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(
            actual_requests, expected_requests,
            "a numeric I105 resource refusal must terminate before later candidate allocations"
        );
        let before_retry = original.consumed_allocated_bytes();
        assert_eq!(
            before_retry,
            u64::try_from(first_charge.checked_mul(2).unwrap()).unwrap()
        );
        assert_eq!(
            original
                .with(|| AccountAddress::from_i105_for_discriminant(&literal, None))
                .unwrap(),
            expected
        );
        assert_eq!(
            original.consumed_allocated_bytes() - before_retry,
            u64::try_from(demand).unwrap()
        );
        assert_eq!(
            original.consumed_allocated_bytes(),
            u64::try_from(original_limit).unwrap()
        );
        assert_eq!(literal.as_ptr(), source_pointer);
        assert_eq!(expected.to_i105_for_discriminant(1).unwrap(), literal);
        assert_eq!(pool.reserved_bytes(), baseline);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn expected_i105_prefix_diagnostics_do_not_retry_original_resource_refusal() {
        use norito::core::DecodeBudgetContext;
        let (expected, literal) = numeric_candidate_refusal_fixture();
        let source_pointer = literal.as_ptr();
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                AccountAddress::from_i105_for_discriminant(&literal, Some(1))
            });
        assert_eq!(decoded.unwrap(), expected);
        let demand = usage.total_allocated_bytes();
        assert!(demand > 0);
        let first_charge = first_i105_controller_charge(&expected);
        let original_limit = first_charge
            .checked_mul(2)
            .unwrap()
            .checked_add(demand)
            .unwrap();
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(limits(original_limit), &pool).unwrap();
        let baseline = pool.reserved_bytes();
        let (expected_resource, expected_requests) =
            observed_i105_terminal_refusal(&original, || {
                AccountAddress::from_i105_for_discriminant(&literal, None)
            });
        let (resource, actual_requests) = observed_i105_terminal_refusal(&original, || {
            AccountAddress::from_i105_for_discriminant(&literal, Some(1))
        });
        assert_eq!(resource, expected_resource);
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(
            actual_requests, expected_requests,
            "expected I105 prefix diagnostics must not allocate another payload after resource refusal"
        );
        let before_retry = original.consumed_allocated_bytes();
        assert_eq!(
            before_retry,
            u64::try_from(first_charge.checked_mul(2).unwrap()).unwrap()
        );
        assert_eq!(
            original
                .with(|| AccountAddress::from_i105_for_discriminant(&literal, Some(1)))
                .unwrap(),
            expected
        );
        assert_eq!(
            original.consumed_allocated_bytes() - before_retry,
            u64::try_from(demand).unwrap()
        );
        assert_eq!(
            original.consumed_allocated_bytes(),
            u64::try_from(original_limit).unwrap()
        );
        let wrong_prefix =
            AccountAddress::from_i105_for_discriminant(&literal, Some(2)).unwrap_err();
        assert!(matches!(
            wrong_prefix,
            AccountAddressError::UnexpectedNetworkPrefix {
                expected: 2,
                found: 1
            }
        ));
        let mut corrupt = literal.clone();
        let last = corrupt.pop().unwrap();
        corrupt.push(if last == '1' { '2' } else { '1' });
        assert!(matches!(
            AccountAddress::from_i105_for_discriminant(&corrupt, Some(1)),
            Err(AccountAddressError::ChecksumMismatch)
        ));
        assert!(matches!(
            AccountAddress::from_i105_for_discriminant("sora!", Some(CHAIN_DISCRIMINANT_SORA)),
            Err(AccountAddressError::InvalidI105Char('!'))
        ));
        assert_eq!(literal.as_ptr(), source_pointer);
        assert_eq!(expected.to_i105_for_discriminant(1).unwrap(), literal);
        assert_eq!(pool.reserved_bytes(), baseline);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
