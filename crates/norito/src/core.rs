//! Norito core serialization library.
//!
//! This crate provides deterministic serialization and zero-copy deserialization for common Rust
//! data structures including primitives, strings, vectors, maps, and simple structs.
//!
//! The format begins with a small metadata header followed by a byte buffer
//! containing archived values. Every value has a corresponding [`Archived`] type
//! which represents the layout in the buffer.
#[cfg(feature = "schema-structural")]
use crate::json;
use crate::{ArchiveSlice, guarded_try_deserialize};
pub use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::convert::TryFrom;
pub use norito_derive::{DeserializePayload, NoritoDeserialize, NoritoSerialize};
use sha2::{Digest, Sha256};
use std::{
    alloc::Layout,
    any::TypeId,
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque},
    hash::Hash,
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
mod encoder;
#[cfg(test)]
#[path = "core/encoder_tests.rs"]
mod encoder_tests;
pub use encoder::Encoder;
mod encode_frames;
mod encode_writers;
mod fixed_frame;
mod heap_payload;
mod nominal_text;
use encode_frames::write_frame_to_writer_with_flags;
#[doc(hidden)]
pub use encode_frames::write_frame_with_prefix;
pub(crate) use encode_writers::ExactSliceWriter;
use encode_writers::{ExactLengthWriter, LengthCountingWriter};
pub use fixed_frame::FixedFrameLayout;
pub use nominal_text::{NominalText, borrow_canonical_text, borrow_text_payload};
mod budget_scope;
mod field_destination;
mod prepared_option;
mod prepared_scope;
mod prepared_sequence;
mod prepared_string;
use budget_scope::CounterOwner;
pub use field_destination::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields, FieldDestination,
    OwnedFields, PreparedRecordDestination, framed_byte_array_field, framed_field,
    with_context_fields,
};
pub use prepared_scope::{PreparedDecodeError, PreparedDecodeScopeError, PreparedDecodeWorkspace};
pub use prepared_sequence::{
    ChargedElementSequence, PreparedElementSequence, RetainedElementSequence,
    RetainedSequenceError, SequenceAdmissionError, SequenceDestinationError,
    decode_raw_byte_sequence_into, inspect_element_sequence, prepare_element_sequence,
};
pub use prepared_string::{StringDestinationError, borrow_canonical_string, decode_string_into};
mod decode_attempt;
pub use decode_attempt::classify_decode_attempt;
pub use decode_attempt::{
    DecodeAttemptError, DecodeAttemptErrorKind, DecodeLocalRefusal, DecodeLocalRefusalKind,
    ScopedDecodeResourceError,
};
mod byte_sequence;
#[doc(hidden)]
pub use byte_sequence::{decode_byte_element_sequence_into, visit_binary_sequence_with_count};
mod sequence_length;
pub use sequence_length::SequencePayloadLength;
mod payload_ref;
pub use payload_ref::PayloadRef;
#[cfg(test)]
#[path = "core/counting_tests.rs"]
mod counting_tests;
#[cfg(test)]
#[path = "core/element_sequence_tests.rs"]
mod element_sequence_tests;
pub mod heuristics;
pub mod hw;
#[cfg(test)]
mod ordered_map_projection_tests;
#[cfg(test)]
#[path = "core/payload_decode_tests.rs"]
mod payload_decode_tests;
#[cfg(test)]
#[path = "core/payload_tests.rs"]
mod payload_tests;
pub mod simd_crc64;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub use simd_crc64::crc64_neon;
#[cfg(all(target_arch = "x86_64", target_feature = "sse4.2"))]
pub use simd_crc64::crc64_sse42;
pub use simd_crc64::{crc64_fallback, hardware_crc64};
#[cfg(feature = "gpu-compression")]
pub mod gpu_zstd;
/// Default upper bound on Norito archive length (bytes) when hosts do not
/// provide an explicit configuration.
const DEFAULT_MAX_ARCHIVE_LEN: u64 = 64 * 1024 * 1024; // 64 MiB
/// Maximum nesting depth for recursively encoded or decoded Norito values.
///
/// Owned containers such as `Box`, `Rc`, and `Arc` make a finite Rust type recursively shaped at
/// runtime. The shared ceiling also covers derive-generated encoders, so hostile values cannot
/// exhaust the native stack before a codec guard executes. Thirty-two levels leave a deterministic
/// margin on the smallest supported test and worker stacks.
pub const MAX_VALUE_NESTING_DEPTH: usize = 32;
static MAX_ARCHIVE_LEN: AtomicU64 = AtomicU64::new(DEFAULT_MAX_ARCHIVE_LEN);
/// Per-decode resource limits for attacker-controlled archives.
///
/// Per-value sequence and field limits are enforced before allocation. The cumulative limits apply
/// across the complete synchronous decode, including Norito-managed parallel workers and bounded
/// streaming iterators. They are deliberately separate from the archive byte limit: a small archive
/// can otherwise advertise large collection counts or field bodies, while a deeply nested archive
/// can amplify modest individual allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    max_sequence_elements: usize,
    max_field_bytes: usize,
    max_total_elements: usize,
    max_total_allocated_bytes: usize,
    max_nesting_depth: usize,
}
impl DecodeLimits {
    /// Construct a complete resource budget for one decode operation.
    ///
    /// `max_sequence_elements` and `max_field_bytes` apply independently to every decoded sequence
    /// and length-delimited field. The two total limits are shared across nested scopes and
    /// Norito-managed worker threads. `max_nesting_depth` counts nested length-delimited value
    /// decodes; a value of zero permits only roots that require no nested field decoding.
    #[must_use]
    pub const fn new(
        max_sequence_elements: usize,
        max_field_bytes: usize,
        max_total_elements: usize,
        max_total_allocated_bytes: usize,
        max_nesting_depth: usize,
    ) -> Self {
        Self {
            max_sequence_elements,
            max_field_bytes,
            max_total_elements,
            max_total_allocated_bytes,
            max_nesting_depth,
        }
    }
    /// Maximum number of elements permitted in any one decoded sequence.
    #[must_use]
    pub const fn max_sequence_elements(self) -> usize {
        self.max_sequence_elements
    }
    /// Maximum byte length permitted for one length-delimited field or blob.
    #[must_use]
    pub const fn max_field_bytes(self) -> usize {
        self.max_field_bytes
    }
    /// Maximum cumulative sequence elements permitted across the decode tree.
    #[must_use]
    pub const fn max_total_elements(self) -> usize {
        self.max_total_elements
    }
    /// Maximum cumulative allocation budget in bytes.
    #[must_use]
    pub const fn max_total_allocated_bytes(self) -> usize {
        self.max_total_allocated_bytes
    }
    /// Maximum permitted nested value-decode depth.
    #[must_use]
    pub const fn max_nesting_depth(self) -> usize {
        self.max_nesting_depth
    }
}
fn serialize_owned<T: SerializePayload>(writer: &mut Encoder<'_>, value: &T) -> Result<(), Error> {
    let _flags_guard = if decode_flags_active() {
        None
    } else {
        Some(DecodeFlagsGuard::enter(default_encode_flags()))
    };
    let flags = effective_layout_flags();
    // Count a real serialization pass instead of trusting an optional length
    // hint or retaining a second payload-sized `Vec`. The counted write below
    // also detects a stateful serializer that changes between passes.
    let exact_len = encoded_payload_len(value)?;
    let len = u64::try_from(exact_len).map_err(|_| Error::LengthMismatch)?;
    write_len_with_flags(writer, len, flags)?;
    // An error from this point leaves the prefix and at most `exact_len`
    // payload bytes in `writer`; the caller propagates it and discards the
    // incomplete enclosing serialization.
    write_counted_payload(value, writer, exact_len)
}
#[cfg(test)]
mod serialize_owned_tests {
    include!("core/serialize_owned_tests.rs");
}
fn owned_bytes_from_ctx<A>(archived: &Archived<A>) -> Result<&[u8], Error> {
    let ptr = archived as *const _ as *const u8;
    let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
    let offset = (ptr as usize)
        .checked_sub(base)
        .ok_or(Error::LengthMismatch)?;
    if offset > total {
        return Err(Error::LengthMismatch);
    }
    let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
    Ok(&payload[offset..])
}
fn parse_owned_payload(bytes: &[u8]) -> Result<(&[u8], usize), Error> {
    // The wrapper decoder borrows this field directly and charges only the
    // allocation it actually constructs (`Box`, `Rc`, or `Arc`) below.
    let (len, hdr) = inspect_len_from_slice(bytes)?;
    let end = hdr.checked_add(len).ok_or(Error::LengthMismatch)?;
    if end > bytes.len() {
        return Err(Error::LengthMismatch);
    }
    Ok((&bytes[hdr..end], end))
}
/// Override the maximum allowed Norito archive length (bytes).
///
/// Hosts should call this during initialization using the configured limit. A value of `0` disables
/// the explicit cap and falls back to the platform pointer width (`usize::MAX`).
pub fn set_max_archive_len(limit: u64) {
    let resolved = if limit == 0 { u64::MAX } else { limit };
    let capped = resolved.min(usize::MAX as u64);
    MAX_ARCHIVE_LEN.store(capped, Ordering::Relaxed);
}
/// Effective maximum Norito archive length in bytes.
#[inline]
pub fn max_archive_len() -> u64 {
    MAX_ARCHIVE_LEN
        .load(Ordering::Relaxed)
        .min(usize::MAX as u64)
}
/// Convert a header-declared length into a `usize`, enforcing the configured cap.
pub(crate) fn payload_len_to_usize(length: u64) -> Result<usize, Error> {
    let limit = max_archive_len();
    if length > limit {
        return Err(Error::ArchiveLengthExceeded { length, limit });
    }
    usize::try_from(length).map_err(|_| Error::ArchiveLengthExceeded { length, limit })
}
#[inline]
pub(crate) fn len_u64_to_usize(length: u64) -> Result<usize, Error> {
    usize::try_from(length).map_err(|_| Error::LengthMismatch)
}
/// Maximum padding (bytes) allowed between a Norito header and the payload when
/// the target type's alignment is unknown.
const MAX_HEADER_PADDING: usize = 64;
/// Strip alignment padding that was inserted between the header and the payload.
///
/// Rejects inputs whose leading bytes exceed `max_padding` to prevent accepting
/// arbitrarily padded archives.
pub(crate) fn payload_without_leading_padding(
    slice: &[u8],
    payload_len: usize,
    max_padding: usize,
) -> Result<&[u8], Error> {
    if slice.len() < payload_len {
        return Err(Error::LengthMismatch);
    }
    let padding = slice.len() - payload_len;
    if padding > max_padding {
        return Err(Error::LengthMismatch);
    }
    if padding != 0 && slice[..padding].iter().any(|&b| b != 0) {
        return Err(Error::LengthMismatch);
    }
    Ok(match padding {
        0 => slice,
        _ => &slice[padding..],
    })
}
/// Strip alignment padding between the header and payload, requiring an exact
/// padding length and zero-filled padding bytes.
pub(crate) fn payload_without_leading_padding_exact(
    slice: &[u8],
    payload_len: usize,
    padding: usize,
) -> Result<&[u8], Error> {
    let expected = padding
        .checked_add(payload_len)
        .ok_or(Error::LengthMismatch)?;
    if slice.len() != expected {
        return Err(Error::LengthMismatch);
    }
    if padding != 0 && slice[..padding].iter().any(|&b| b != 0) {
        return Err(Error::LengthMismatch);
    }
    Ok(&slice[padding..])
}
const TYPE_NAME_SCHEMA_HASH_DOMAIN: &[u8] = b"norito:v1:type-name\0";
#[cfg(feature = "schema-structural")]
const STRUCTURAL_SCHEMA_HASH_DOMAIN: &[u8] = b"norito:v1:structural-schema\0";
/// Header flags stored in the final padding byte.
pub mod header_flags {
    /// Compact varint lengths are used for per-field/element length prefixes (including string/blob
    /// lengths). Does not affect the fixed u64 sequence count header.
    pub const COMPACT_LEN: u8 = 0x02;
}
fn schema_hash_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}
fn type_name_schema_hash_from_bytes(bytes: &[u8]) -> [u8; 16] {
    schema_hash_with_domain(TYPE_NAME_SCHEMA_HASH_DOMAIN, bytes)
}
#[cfg(feature = "schema-structural")]
fn structural_schema_hash_from_bytes(bytes: &[u8]) -> [u8; 16] {
    schema_hash_with_domain(STRUCTURAL_SCHEMA_HASH_DOMAIN, bytes)
}
/// Inspect the domain-separated hash of Rust's compiler type name.
///
/// This diagnostic helper does not select frame identities. Typed readers and
/// writers use [`crate::schema::identity::frame_hash`] exclusively.
pub fn type_name_schema_hash<T>() -> [u8; 16] {
    schema_hash_for_name(core::any::type_name::<T>())
}
/// Compute a type-name-based schema hash for an arbitrary type name string.
pub fn schema_hash_for_name(name: &str) -> [u8; 16] {
    type_name_schema_hash_from_bytes(name.as_bytes())
}
#[cfg(feature = "schema-structural")]
/// Compute a structural schema hash using `iroha_schema`'s canonical serialization.
pub fn schema_hash_structural<T: iroha_schema::IntoSchema>() -> [u8; 16] {
    let map = <T as iroha_schema::IntoSchema>::schema();
    schema_hash_from_json_serializable(&map)
}
#[cfg(feature = "schema-structural")]
fn schema_hash_from_json_serializable<T>(value: &T) -> [u8; 16]
where
    T: json::JsonSerialize + ?Sized,
{
    let mut out = String::new();
    json::JsonSerialize::json_serialize(value, &mut out);
    structural_schema_hash_from_bytes(out.as_bytes())
}
#[cfg(feature = "schema-structural")]
/// Compute a structural schema hash from a pre-built Norito JSON [`Value`].
///
/// The `Value` is serialized using Norito's canonical writer to guarantee the
/// same byte representation as other language bindings (Python, Java).
pub fn schema_hash_structural_value(value: &json::Value) -> [u8; 16] {
    schema_hash_from_json_serializable(value)
}
#[cfg(feature = "schema-structural")]
/// Compute a structural schema hash from a JSON string descriptor.
///
/// The descriptor is parsed using Norito's native JSON parser and then
/// canonicalized using the same writer as [`schema_hash_structural_value`].
pub fn schema_hash_structural_from_json_str(input: &str) -> Result<[u8; 16], json::Error> {
    let value = json::parse_value(input)?;
    Ok(schema_hash_structural_value(&value))
}
#[cfg(feature = "schema-structural")]
/// Compute a structural schema hash from UTF-8 JSON bytes.
pub fn schema_hash_structural_from_json_bytes(bytes: &[u8]) -> Result<[u8; 16], json::Error> {
    let input = std::str::from_utf8(bytes).map_err(|_| json::Error::InvalidUtf8)?;
    schema_hash_structural_from_json_str(input)
}
/// Compute the CRC64-XZ checksum over `data` using the ECMA polynomial.
fn crc64(data: &[u8]) -> u64 {
    simd_crc64::hardware_crc64(data)
}
const MAX_VARINT_BYTES: usize = 10;
/// Number of bytes used to encode a length prefix for `value`.
///
/// Honors the active `COMPACT_LEN` layout flag so callers can pre-compute
/// per-value length prefix sizes accurately.
pub fn len_prefix_len(value: usize) -> usize {
    len_prefix_len_with_flags(value, effective_layout_flags())
}
/// Number of bytes used to encode a length prefix for `value` under `flags`.
///
/// This is the flag-explicit variant of [`len_prefix_len`] for tight loops
/// that have already captured the active Norito layout.
#[doc(hidden)]
pub fn len_prefix_len_with_flags(value: usize, flags: u8) -> usize {
    if compact_len_enabled_for_flags(flags) {
        varint_encoded_len(value as u64)
    } else {
        8
    }
}
#[inline]
fn len_prefixed_payload_len_with_flags(payload_len: usize, flags: u8) -> Option<usize> {
    len_prefix_len_with_flags(payload_len, flags).checked_add(payload_len)
}
#[inline]
fn len_prefixed_payload_len(payload_len: usize) -> Option<usize> {
    len_prefixed_payload_len_with_flags(payload_len, effective_layout_flags())
}
#[inline]
fn tagged_len_prefixed_payload_len_with_flags(payload_len: usize, flags: u8) -> Option<usize> {
    1usize
        .checked_add(len_prefix_len_with_flags(payload_len, flags))?
        .checked_add(payload_len)
}
#[inline]
fn tagged_len_prefixed_payload_len(payload_len: usize) -> Option<usize> {
    tagged_len_prefixed_payload_len_with_flags(payload_len, effective_layout_flags())
}
/// Number of bytes used to encode a sequence length prefix for `value`.
///
/// Sequence length headers are fixed-width in v1.
pub fn seq_len_prefix_len(value: usize) -> usize {
    let _ = value;
    8
}
/// Number of bytes used to encode a compact varint length prefix.
pub fn varint_len_prefix_len(value: usize) -> usize {
    varint_encoded_len(value as u64)
}
#[inline]
/// Return the set of Norito header layout flags supported by this build.
///
/// Only [`header_flags::COMPACT_LEN`] may be set in a v1 header. A flag byte of
/// `0x00` selects fixed-width (8-byte) per-value length prefixes; every other
/// bit is reserved, rejected by decoders and never emitted.
pub const fn supported_header_flags() -> u8 {
    header_flags::COMPACT_LEN
}
#[inline]
/// Validate that a Norito header flag byte uses only supported v1 layout bits.
pub fn validate_header_flags(flags: u8) -> Result<(), Error> {
    if flags & !supported_header_flags() != 0 {
        return Err(Error::UnsupportedFeature("layout flag"));
    }
    Ok(())
}
#[inline]
fn sanitize_layout_flags(flags: u8) -> u8 {
    flags & supported_header_flags()
}
/// Return the default v1 encode layout flags.
///
/// The v1 minor byte remains fixed at [`VERSION_MINOR`]; payloads advertise layout selections
/// through header flags. Compact per-value lengths are the default because they reduce wire size
/// without changing collection offsets or sequence length headers.
#[inline]
pub const fn default_encode_flags() -> u8 {
    header_flags::COMPACT_LEN
}
#[derive(Clone)]
struct PayloadCtxState {
    base: usize,
    len: usize,
    schema: Option<[u8; 16]>,
    max_access: usize,
    flags: u8,
    flags_active: bool,
}
// Decode context managed per-thread; set based on header flags.
thread_local! {
    static DECODE_FLAGS: Cell<u8> = const { Cell::new(0) };
}
thread_local! {
    static DECODE_FLAGS_ACTIVE: Cell<bool> = const { Cell::new(false) };
}
thread_local! {
    static ENCODE_CONTEXT_ACTIVE: Cell<bool> = const { Cell::new(false) };
}
thread_local! {
    static ENCODE_COMPACT_LEN_USED: Cell<bool> = const { Cell::new(false) };
}
thread_local! {
    static ENCODE_VALUE_NESTING_DEPTH: Cell<usize> = const { Cell::new(0) };
}
#[derive(Debug, Default)]
struct DecodeBudgetCounters {
    attempt: AtomicU64,
    total_elements: AtomicU64,
    total_allocated_bytes: AtomicU64,
}
#[derive(Clone)]
struct DecodeBudgetLayer {
    limits: DecodeLimits,
    counters: CounterOwner,
}
impl DecodeBudgetLayer {
    fn new(limits: DecodeLimits) -> Self {
        let layer = Self {
            limits,
            counters: CounterOwner::Owned(Arc::new(DecodeBudgetCounters::default())),
        };
        decode_attempt::note_fresh_budget(&layer.counters);
        layer
    }
}
#[derive(Clone)]
struct ActiveDecodeBudgetLayer {
    budget: DecodeBudgetLayer,
    base_depth: usize,
}
/// Cloneable cumulative codec accounting context for synchronous physical work.
/// The context owns one original layer; cloning shares its cumulative counters
/// without allocating a one-element collection. Active scope layers borrow stack
/// nodes; the shared counter control remains an independent owned allocation.
/// Limits provide accounting only: an actual execution or query owner must separately
/// admit and retain the physical source, graph, destination and counter backing.
#[derive(Clone)]
pub struct DecodeBudgetContext {
    layer: ActiveDecodeBudgetLayer,
    depth: usize,
}
impl DecodeBudgetContext {
    /// Create cumulative accounting without granting physical allocation authority.
    /// Physical producers fund the original counter control with [`Self::try_new_owned`]
    /// or [`Self::from_reservation`].
    pub fn new(limits: DecodeLimits) -> Self {
        let depth = DECODE_NESTING_DEPTH.with(Cell::get);
        Self {
            layer: ActiveDecodeBudgetLayer {
                budget: DecodeBudgetLayer::new(limits),
                base_depth: depth,
            },
            depth,
        }
    }

    /// Exact native shared-counter layout required by an owned context.
    pub fn allocation_layout() -> Layout {
        iroha_allocation::ChargedShared::<DecodeBudgetCounters>::allocation_layout()
    }

    /// Admit the original cumulative counter backing before allocating it.
    /// Clones retain the same physical pool and counters; they grant no new credit.
    ///
    /// # Errors
    /// Refuses when the original pool cannot own the counter layout or allocation fails.
    pub fn try_new_owned(
        limits: DecodeLimits,
        pool: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, Error> {
        let layout = Self::allocation_layout();
        let refused = || Error::AllocationFailed {
            bytes: limit_to_u64(layout.size()),
        };
        let mut reservation = pool.try_reserve(layout).map_err(|_| refused())?;
        Self::from_reservation(limits, &mut reservation).map_err(|_| refused())
    }

    /// Construct the cumulative counter backing from its original prepaid reservation.
    /// No new pool admission occurs. Clones retain the same counters and physical charge.
    ///
    /// # Errors
    /// A short original remainder is unchanged and returns its exact typed shortage.
    /// Physical allocation refusal refunds only the split control charge; the unused
    /// remainder stays with the original reservation.
    pub fn from_reservation(
        limits: DecodeLimits,
        reservation: &mut iroha_allocation::AllocationReservation,
    ) -> Result<Self, iroha_allocation::PrepaidSharedError> {
        let counters = iroha_allocation::ChargedShared::from_reservation(
            DecodeBudgetCounters::default(),
            reservation,
        )
        .map_err(|(_, error)| error)?;
        let counters = CounterOwner::Prepared(counters);
        decode_attempt::note_fresh_budget(&counters);
        let depth = DECODE_NESTING_DEPTH.with(Cell::get);
        Ok(Self {
            layer: ActiveDecodeBudgetLayer {
                budget: DecodeBudgetLayer { limits, counters },
                base_depth: depth,
            },
            depth,
        })
    }

    /// Cumulative native allocation charges retained across all scopes and clones.
    pub fn consumed_allocated_bytes(&self) -> u64 {
        self.layer
            .budget
            .counters
            .total_allocated_bytes
            .load(Ordering::Relaxed)
    }
}
thread_local! {
    static DECODE_NESTING_DEPTH: Cell<usize> = const { Cell::new(0) };
}
impl DecodeBudgetContext {
    /// Install this original context only for a synchronous physical operation.
    /// Prior thread state is restored on return and unwind; no guard escapes the closure.
    pub fn with<R>(&self, body: impl FnOnce() -> R) -> R {
        budget_scope::with_layers(core::slice::from_ref(&self.layer), self.depth, body)
    }
}
pub(crate) fn with_optional_decode_budget<R>(
    context: Option<&DecodeBudgetContext>,
    body: impl FnOnce() -> R,
) -> R {
    match context {
        Some(context) => context.with(body),
        None => body(),
    }
}
/// Return whether the current thread is inside at least one decode-limit scope.
#[inline]
#[doc(hidden)]
pub fn decode_limits_active() -> bool {
    budget_scope::with_active(|layers| !layers.is_empty())
}
/// Check whether an original decoder error names a still-active resource ceiling.
///
/// Call this after the inner decoder's scopes have unwound and before projecting the error.
/// A wider surviving scope cannot claim an inner format limit. The global archive cap and
/// canonical nesting limits are not local capacity refusals. A narrower caller's decode-budget
/// depth is local only while that exact ceiling survives. This does not supply an allocation-pool
/// owner or a release notification.
#[doc(hidden)]
pub fn decode_error_matches_active_limits(error: &Error) -> bool {
    if let Error::ScopedDecodeResource(origin) = error {
        return origin.matches_enclosing_scope();
    }
    budget_scope::with_active(|layers| {
        layers.iter().any(|layer| {
            let limits = layer.budget.limits;
            match error {
                Error::SequenceLengthExceeded { length, limit } => {
                    length > limit && *limit == limit_to_u64(limits.max_sequence_elements())
                }
                Error::FieldLengthExceeded { length, limit } => {
                    length > limit && *limit == limit_to_u64(limits.max_field_bytes())
                }
                Error::TotalElementsExceeded { attempted, limit } => {
                    attempted > limit && *limit == limit_to_u64(limits.max_total_elements())
                }
                Error::TotalAllocationExceeded { attempted, limit } => {
                    attempted > limit && *limit == limit_to_u64(limits.max_total_allocated_bytes())
                }
                Error::NestingDepthExceeded {
                    depth,
                    limit,
                    context,
                } => {
                    *context == "decode budget"
                        && depth > limit
                        && *limit < MAX_VALUE_NESTING_DEPTH
                        && *limit == limits.max_nesting_depth()
                }
                _ => false,
            }
        })
    })
}
#[inline]
fn limit_to_u64(limit: usize) -> u64 {
    u64::try_from(limit).unwrap_or(u64::MAX)
}
fn charge_atomic_budget(counter: &AtomicU64, amount: u64, limit: u64) -> Result<u64, u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(amount).filter(|next| *next <= limit)
        })
        .map(|previous| previous.saturating_add(amount))
        .map_err(|current| current.saturating_add(amount))
}
/// Guard representing one nested length-delimited value decode.
pub(crate) struct DecodeDepthGuard {
    previous_depth: usize,
    _not_send: PhantomData<Rc<()>>,
}
impl DecodeDepthGuard {
    pub(crate) fn enter() -> Result<Self, Error> {
        let previous_depth = DECODE_NESTING_DEPTH.with(Cell::get);
        let depth = previous_depth
            .checked_add(1)
            .ok_or(Error::NestingDepthExceeded {
                depth: usize::MAX,
                limit: usize::MAX,
                context: "decode budget",
            })?;
        budget_scope::with_active(|layers| {
            for (index, layer) in decode_attempt::layers_in_order(layers) {
                let relative_depth = depth.saturating_sub(layer.base_depth);
                if relative_depth > layer.budget.limits.max_nesting_depth() {
                    return Err(decode_attempt::budget_error(
                        index,
                        &layer.budget.counters,
                        Error::NestingDepthExceeded {
                            depth: relative_depth,
                            limit: layer.budget.limits.max_nesting_depth(),
                            context: "decode budget",
                        },
                    ));
                }
            }
            Ok(())
        })?;
        DECODE_NESTING_DEPTH.with(|slot| slot.set(depth));
        Ok(Self {
            previous_depth,
            _not_send: PhantomData,
        })
    }
}
impl Drop for DecodeDepthGuard {
    fn drop(&mut self) {
        DECODE_NESTING_DEPTH.with(|slot| slot.set(self.previous_depth));
    }
}
/// Guard one nested encode or encoded-length operation.
///
/// Derive-generated implementations enter this guard before evaluating fields. This makes
/// recursive owned values fail with a typed error before Rust exhausts the native stack.
#[doc(hidden)]
pub struct EncodeValueDepthGuard {
    previous_depth: usize,
}
impl EncodeValueDepthGuard {
    /// Enter one value level in the current encode operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NestingDepthExceeded`] when the canonical nesting ceiling is exceeded.
    pub fn enter() -> Result<Self, Error> {
        let previous_depth = ENCODE_VALUE_NESTING_DEPTH.with(Cell::get);
        let depth = previous_depth.saturating_add(1);
        if depth > MAX_VALUE_NESTING_DEPTH {
            return Err(Error::NestingDepthExceeded {
                depth,
                limit: MAX_VALUE_NESTING_DEPTH,
                context: "encode budget",
            });
        }
        ENCODE_VALUE_NESTING_DEPTH.with(|slot| slot.set(depth));
        Ok(Self { previous_depth })
    }
}
impl Drop for EncodeValueDepthGuard {
    fn drop(&mut self) {
        ENCODE_VALUE_NESTING_DEPTH.with(|slot| slot.set(self.previous_depth));
    }
}
/// Run a decode operation with limits scoped to the current thread.
///
/// Nested scopes compose by taking the stricter limit, so a decoder invoked by an already-bounded
/// decoder cannot raise the outer sequence limit. The prior scope is restored even when `decode`
/// returns an error or unwinds. Decoding must complete before the closure returns; a lazy decoder
/// returned from the closure does not retain the scope.
///
/// # Errors
///
/// Returns an error produced by `decode`, or a resource-limit error when the
/// decode exceeds any member of `limits`.
pub fn with_decode_limits<T>(
    limits: DecodeLimits,
    decode: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    with_decode_limits_scope(limits, decode)
}
/// Run an operation under decode limits without constraining its return type.
///
/// This is the scope primitive for versioned or layered codecs whose public
/// error type wraps [`Error`]. Every nested Norito decoder on the current
/// thread still observes `limits`; the caller retains its exact outer result
/// and error type. The closure must finish decoding before it returns.
pub fn with_decode_limits_scope<T>(limits: DecodeLimits, decode: impl FnOnce() -> T) -> T {
    DecodeBudgetContext::new(limits).with(decode)
}
#[inline]
pub(crate) fn enforce_decode_sequence_length(length: u64) -> Result<(), Error> {
    budget_scope::with_active(|layers| {
        for (index, layer) in decode_attempt::layers_in_order(layers) {
            let limit = limit_to_u64(layer.budget.limits.max_sequence_elements());
            if length > limit {
                return Err(decode_attempt::budget_error(
                    index,
                    &layer.budget.counters,
                    Error::SequenceLengthExceeded { length, limit },
                ));
            }
        }
        for (index, layer) in decode_attempt::layers_in_order(layers) {
            let limit = limit_to_u64(layer.budget.limits.max_total_elements());
            if let Err(attempted) =
                charge_atomic_budget(&layer.budget.counters.total_elements, length, limit)
            {
                return Err(decode_attempt::budget_error(
                    index,
                    &layer.budget.counters,
                    Error::TotalElementsExceeded { attempted, limit },
                ));
            }
        }
        Ok(())
    })?;
    // Every decoded element requires at least one unit of container or planning
    // metadata. Type-specific bodies and temporary aligned copies are charged
    // separately when their field lengths are read or buffers are allocated.
    reserve_decode_allocation_u64(length)
}
#[inline]
pub(crate) fn check_decode_sequence_length(length: u64) -> Result<(), Error> {
    budget_scope::with_active(|layers| {
        for (index, layer) in decode_attempt::layers_in_order(layers) {
            let limit = limit_to_u64(layer.budget.limits.max_sequence_elements());
            if length > limit {
                return Err(decode_attempt::budget_error(
                    index,
                    &layer.budget.counters,
                    Error::SequenceLengthExceeded { length, limit },
                ));
            }
        }
        Ok(())
    })
}
#[inline]
pub(crate) fn enforce_decode_field_length(length: u64) -> Result<(), Error> {
    check_decode_field_length(length)?;
    reserve_decode_allocation_u64(length)
}
#[inline]
fn check_decode_field_length(length: u64) -> Result<(), Error> {
    budget_scope::with_active(|layers| {
        for (index, layer) in decode_attempt::layers_in_order(layers) {
            let limit = limit_to_u64(layer.budget.limits.max_field_bytes());
            if length > limit {
                return Err(decode_attempt::budget_error(
                    index,
                    &layer.budget.counters,
                    Error::FieldLengthExceeded { length, limit },
                ));
            }
        }
        Ok(())
    })
}
#[inline]
#[doc(hidden)]
pub fn reserve_decode_allocation(length: usize) -> Result<(), Error> {
    reserve_decode_allocation_u64(limit_to_u64(length))
}
fn reserve_decode_allocation_u64(length: u64) -> Result<(), Error> {
    budget_scope::with_active(|layers| {
        for (index, layer) in decode_attempt::layers_in_order(layers) {
            let limit = limit_to_u64(layer.budget.limits.max_total_allocated_bytes());
            if let Err(attempted) =
                charge_atomic_budget(&layer.budget.counters.total_allocated_bytes, length, limit)
            {
                return Err(decode_attempt::budget_error(
                    index,
                    &layer.budget.counters,
                    Error::TotalAllocationExceeded { attempted, limit },
                ));
            }
        }
        Ok(())
    })
}
pub(crate) struct EncodeContextGuard {
    prev_active: bool,
    prev_compact_len_used: bool,
}
impl EncodeContextGuard {
    pub(crate) fn enter() -> Self {
        let prev_active = ENCODE_CONTEXT_ACTIVE.with(|cell| {
            let prev = cell.get();
            cell.set(true);
            prev
        });
        let prev_compact_len_used = ENCODE_COMPACT_LEN_USED.with(|cell| {
            let prev = cell.get();
            cell.set(false);
            prev
        });
        Self {
            prev_active,
            prev_compact_len_used,
        }
    }
}
impl Drop for EncodeContextGuard {
    fn drop(&mut self) {
        ENCODE_CONTEXT_ACTIVE.with(|cell| cell.set(self.prev_active));
        ENCODE_COMPACT_LEN_USED.with(|cell| cell.set(self.prev_compact_len_used));
    }
}
fn mark_compact_len_used_if_encoding() {
    ENCODE_CONTEXT_ACTIVE.with(|active| {
        if active.get() {
            ENCODE_COMPACT_LEN_USED.with(|flag| flag.set(true));
        }
    });
}
/// Record that a compact length prefix was emitted in the current encode pass.
pub fn note_compact_len_emitted() {
    mark_compact_len_used_if_encoding();
    #[cfg(debug_assertions)]
    if crate::debug_trace_enabled() {
        eprintln!(
            "note_compact_len_emitted compact_len_used={}",
            ENCODE_COMPACT_LEN_USED.with(|flag| flag.get())
        );
    }
}
pub(crate) fn compact_len_used() -> bool {
    ENCODE_COMPACT_LEN_USED.with(|flag| flag.get())
}
#[inline]
pub(crate) fn finalized_encode_flags(base_flags: u8, compact_len_used: bool) -> u8 {
    debug_assert!(validate_header_flags(base_flags).is_ok());
    if compact_len_used {
        base_flags | header_flags::COMPACT_LEN
    } else {
        base_flags & !header_flags::COMPACT_LEN
    }
}
// Thread-local payload context: base pointer, length, and optional schema hash.
thread_local! {
    static DECODE_PAYLOAD_CTX: RefCell<Option<PayloadCtxState>> = const { RefCell::new(None) };
    static DECODE_ROOT_SPAN: RefCell<Option<(usize, usize)>> = const { RefCell::new(None) };
    static OWNED_VALUE_DECODE_DEPTH: Cell<usize> = const { Cell::new(0) };
}
struct OwnedValueDecodeDepthGuard;
impl OwnedValueDecodeDepthGuard {
    fn enter() -> Result<Self, Error> {
        OWNED_VALUE_DECODE_DEPTH.with(|depth| {
            let next = depth.get().saturating_add(1);
            if next > MAX_VALUE_NESTING_DEPTH {
                return Err(Error::NestingDepthExceeded {
                    depth: next,
                    limit: MAX_VALUE_NESTING_DEPTH,
                    context: "owned Norito value",
                });
            }
            depth.set(next);
            Ok(Self)
        })
    }
}
impl Drop for OwnedValueDecodeDepthGuard {
    fn drop(&mut self) {
        OWNED_VALUE_DECODE_DEPTH.with(|depth| {
            debug_assert!(depth.get() > 0, "owned-value decode depth underflow");
            depth.set(depth.get().saturating_sub(1));
        });
    }
}
/// Record the root payload span for the current thread.
pub fn set_decode_root(bytes: &[u8]) {
    DECODE_ROOT_SPAN.with(|slot| *slot.borrow_mut() = Some((bytes.as_ptr() as usize, bytes.len())));
}
/// Clear the root payload span for the current thread.
pub fn clear_decode_root() {
    DECODE_ROOT_SPAN.with(|slot| *slot.borrow_mut() = None);
}
/// Fetch the currently recorded root payload span, if any.
pub fn payload_root_span() -> Option<(usize, usize)> {
    DECODE_ROOT_SPAN.with(|slot| *slot.borrow())
}
// Per-thread payload context (base pointer, length, and optional schema hash).
fn set_payload_ctx_state(bytes: &[u8], schema: Option<[u8; 16]>, flags: Option<u8>) {
    set_payload_ctx_state_with_len(bytes, bytes.len(), schema, flags);
}
fn set_payload_ctx_state_with_len(
    bytes: &[u8],
    len: usize,
    schema: Option<[u8; 16]>,
    flags: Option<u8>,
) {
    let len = len.min(bytes.len());
    DECODE_PAYLOAD_CTX.with(|c| {
        let flags_value = flags.unwrap_or(0);
        *c.borrow_mut() = Some(PayloadCtxState {
            base: bytes.as_ptr() as usize,
            len,
            schema,
            max_access: 0,
            flags: flags_value,
            flags_active: flags.is_some(),
        });
    });
}
/// Set the current payload context for slice-based decoders.
pub fn set_payload_ctx(bytes: &[u8]) {
    set_payload_ctx_state(bytes, None, None);
}
/// Clear the payload context.
pub fn clear_payload_ctx() {
    DECODE_PAYLOAD_CTX.with(|c| *c.borrow_mut() = None);
}
pub fn payload_ctx() -> Option<(usize, usize)> {
    payload_ctx_state().map(|state| (state.base, state.len))
}
fn payload_ctx_flags() -> Option<u8> {
    payload_ctx_state().and_then(|state| {
        if state.flags_active {
            Some(state.flags)
        } else {
            None
        }
    })
}

fn enter_field_codec_flags() -> Option<DecodeFlagsGuard> {
    if decode_flags_active() {
        return None;
    }
    let flags = payload_ctx_flags().unwrap_or_else(default_encode_flags);
    Some(DecodeFlagsGuard::enter(flags))
}

fn payload_ctx_state() -> Option<PayloadCtxState> {
    DECODE_PAYLOAD_CTX.with(|c| c.borrow().clone())
}
fn payload_ctx_state_mut<R>(f: impl FnOnce(&mut PayloadCtxState) -> R) -> Option<R> {
    DECODE_PAYLOAD_CTX.with(|c| {
        let mut guard = c.borrow_mut();
        guard.as_mut().map(f)
    })
}
struct DecodeStateSnapshot {
    flags: u8,
    flags_active: bool,
    field_boundary: FieldDecodeBoundary,
    payload_ctx: Option<PayloadCtxState>,
    root_span: Option<(usize, usize)>,
}
impl DecodeStateSnapshot {
    fn capture() -> Self {
        Self {
            flags: get_decode_flags(),
            flags_active: decode_flags_active(),
            field_boundary: FIELD_DECODE_BOUNDARY.with(Cell::get),
            payload_ctx: payload_ctx_state(),
            root_span: payload_root_span(),
        }
    }
    fn restore(self) {
        set_decode_flags_raw(self.flags);
        set_decode_flags_active(self.flags_active);
        FIELD_DECODE_BOUNDARY.with(|slot| slot.set(self.field_boundary));
        DECODE_PAYLOAD_CTX.with(|slot| *slot.borrow_mut() = self.payload_ctx);
        DECODE_ROOT_SPAN.with(|slot| *slot.borrow_mut() = self.root_span);
    }
}
struct IsolatedDecodeGuard {
    snapshot: Option<DecodeStateSnapshot>,
}
impl IsolatedDecodeGuard {
    fn enter() -> Self {
        let snapshot = DecodeStateSnapshot::capture();
        reset_decode_state();
        clear_decode_root();
        FIELD_DECODE_BOUNDARY.with(|slot| slot.set(FieldDecodeBoundary::Canonical));
        Self {
            snapshot: Some(snapshot),
        }
    }
}
impl Drop for IsolatedDecodeGuard {
    fn drop(&mut self) {
        if let Some(snapshot) = self.snapshot.take() {
            snapshot.restore();
        }
    }
}
fn record_payload_access(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    payload_ctx_state_mut(|state| {
        let base = state.base;
        let ptr_us = ptr as usize;
        if ptr_us < base {
            return;
        }
        let rel = ptr_us - base;
        let end = rel.saturating_add(len);
        if end > state.len {
            state.max_access = state.len;
        } else if end > state.max_access {
            state.max_access = end;
        }
    });
}
pub(crate) fn payload_ctx_max_access() -> Option<usize> {
    payload_ctx_state().map(|state| state.max_access)
}
fn record_slice_access(bytes: &[u8], len: usize) {
    let cap = bytes.len();
    let used = len.min(cap);
    if used == 0 {
        return;
    }
    record_payload_access(bytes.as_ptr(), used);
}
/// Record that `len` bytes of `bytes` were accessed while decoding within an active payload
/// context.
///
/// This is intended for custom `NoritoDeserialize` implementations that can validate full
/// consumption without re-encoding, allowing `decode_field_canonical` to skip its canonical byte
/// comparison fallback.
pub fn note_payload_access(bytes: &[u8], len: usize) {
    record_slice_access(bytes, len);
}
#[inline]
fn payload_bytes_with_offset(ptr: *const u8) -> Result<(&'static [u8], usize), Error> {
    let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
    let ptr_us = ptr as usize;
    let base_end = base.checked_add(total).ok_or(Error::LengthMismatch)?;
    if ptr_us >= base && ptr_us <= base_end {
        let offset = ptr_us - base;
        let payload = unsafe { core::slice::from_raw_parts(base as *const u8, total) };
        return Ok((payload, offset));
    }
    Err(Error::LengthMismatch)
}
#[inline]
pub fn payload_slice_from_ptr(ptr: *const u8) -> Result<&'static [u8], Error> {
    let (payload, offset) = payload_bytes_with_offset(ptr)?;
    Ok(&payload[offset..])
}
/// Return an exact, bounds-checked range from the active decode payload.
///
/// Generated decoders use this instead of constructing slices directly from
/// pointers supplied by an archived value.
#[doc(hidden)]
#[inline]
pub fn payload_range_from_ptr(ptr: *const u8, len: usize) -> Result<&'static [u8], Error> {
    let (payload, offset) = payload_bytes_with_offset(ptr)?;
    let end = offset.checked_add(len).ok_or(Error::LengthMismatch)?;
    if end > payload.len() {
        return Err(Error::LengthMismatch);
    }
    record_payload_access(ptr, len);
    Ok(&payload[offset..end])
}
#[inline]
fn ensure_len_within_remaining(len: usize, remaining: usize) -> Result<(), Error> {
    if len > remaining {
        return Err(Error::LengthMismatch);
    }
    Ok(())
}
#[cfg(test)]
#[inline]
fn btreemap_entry_slices<'a>(
    key_bytes: &'a [u8],
    value_bytes: &'a [u8],
    ks: usize,
    ke: usize,
    vs: usize,
    ve: usize,
    index: usize,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    let Some(key_slice) = key_bytes.get(ks..ke) else {
        #[cfg(debug_assertions)]
        eprintln!(
            "norito: BTreeMap slice_oob key i={index} ks={ks} ke={ke} len={}",
            key_bytes.len()
        );
        return Err(Error::LengthMismatch);
    };
    let Some(value_slice) = value_bytes.get(vs..ve) else {
        #[cfg(debug_assertions)]
        eprintln!(
            "norito: BTreeMap slice_oob val i={index} vs={vs} ve={ve} len={}",
            value_bytes.len()
        );
        return Err(Error::LengthMismatch);
    };
    if crate::debug_trace_enabled() {
        eprintln!(
            "norito: BTreeMap entry[{index}] ks={ks} ke={ke} vs={vs} ve={ve} key_len={} val_len={}",
            key_slice.len(),
            value_slice.len()
        );
    }
    record_slice_access(key_slice, key_slice.len());
    record_slice_access(value_slice, value_slice.len());
    Ok((key_slice, value_slice))
}
#[inline]
#[allow(dead_code)]
fn safe_read_u64_from_ctx(ptr: *const u8, offset: usize) -> Option<u64> {
    let (base, total) = payload_ctx()?;
    let ptr_us = ptr as usize;
    if ptr_us < base {
        return None;
    }
    let base_offset = ptr_us - base;
    let off = base_offset.checked_add(offset)?;
    let slice_end = off.checked_add(8)?;
    if slice_end > total {
        return None;
    }
    let payload = unsafe { core::slice::from_raw_parts(base as *const u8, total) };
    let mut lb = [0u8; 8];
    lb.copy_from_slice(&payload[off..slice_end]);
    Some(u64::from_le_bytes(lb))
}
/// Read a dynamic length header at a given pointer using the current payload context.
/// Returns (value, bytes_consumed).
fn read_len_dyn_at_ptr(ptr: *const u8) -> Result<(usize, usize), Error> {
    let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
    let ptr_us = ptr as usize;
    let base_end = base.checked_add(total).ok_or(Error::LengthMismatch)?;
    if ptr_us < base || ptr_us >= base_end {
        #[cfg(debug_assertions)]
        if crate::debug_trace_enabled() {
            eprintln!(
                "read_len_dyn_at_ptr: ptr={ptr:?} base=0x{base:016x} total={total} base_end=0x{base_end:016x}"
            );
        }
        return Err(Error::LengthMismatch);
    }
    let off = ptr_us - base;
    debug_assert!(off <= total);
    let head_slice = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
    let head = &head_slice[off..];
    let (len, used) = read_len_dyn_slice(head)?;
    record_payload_access(ptr, used);
    Ok((len, used))
}
/// Allocate a raw buffer for `layout` without invoking the process-wide OOM handler.
///
/// Returns a pair of `(ptr, needs_dealloc)` where `needs_dealloc` indicates whether
/// the pointer must be passed to `dealloc` when it is no longer needed.
#[inline]
unsafe fn alloc_checked(layout: Layout) -> Result<(*mut u8, bool), Error> {
    reserve_decode_allocation(layout.size())?;
    if layout.size() == 0 {
        let align = layout.align();
        // For ZSTs, return an arbitrary non-null pointer that satisfies the
        // required alignment so downstream casts remain well-formed.
        let ptr = align as *mut u8;
        debug_assert_eq!((ptr as usize) & (align - 1), 0);
        return Ok((ptr, false));
    }
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() {
        return Err(Error::AllocationFailed {
            bytes: limit_to_u64(layout.size()),
        });
    }
    Ok((ptr, true))
}
#[inline]
unsafe fn dealloc_checked(ptr: *mut u8, layout: Layout, needs_dealloc: bool) {
    if needs_dealloc {
        unsafe { std::alloc::dealloc(ptr, layout) };
    }
}
fn reserve_decode_sequence_storage<T>(capacity: usize) -> Result<usize, Error> {
    let bytes = capacity
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(Error::LengthMismatch)?;
    reserve_decode_allocation(bytes)?;
    Ok(bytes)
}
fn try_decode_vec_with_capacity<T>(capacity: usize) -> Result<Vec<T>, Error> {
    let bytes = reserve_decode_sequence_storage::<T>(capacity)?;
    let mut values = Vec::new();
    values
        .try_reserve(capacity)
        .map_err(|_| Error::AllocationFailed {
            bytes: limit_to_u64(bytes),
        })?;
    Ok(values)
}
#[inline]
unsafe fn copy_from_payload(src: *const u8, dst: *mut u8, len: usize) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    let slice = payload_range_from_ptr(src, len)?;
    record_payload_access(src, len);
    let dst_slice = unsafe { core::slice::from_raw_parts_mut(dst, len) };
    dst_slice.copy_from_slice(slice);
    Ok(())
}
/// RAII guard to set and restore the current payload context.
pub struct PayloadCtxGuard {
    prev: Option<PayloadCtxState>,
    flags_guard: Option<DecodeFlagsGuard>,
}
impl PayloadCtxGuard {
    fn install(
        bytes: &[u8],
        logical_len: usize,
        schema: Option<[u8; 16]>,
        flags: Option<u8>,
    ) -> Self {
        let prev = payload_ctx_state();
        set_payload_ctx_state_with_len(bytes, logical_len, schema, flags);
        let flags_guard = flags
            .filter(|flags| !decode_flags_active() || get_decode_flags() != *flags)
            .map(DecodeFlagsGuard::enter);
        PayloadCtxGuard { prev, flags_guard }
    }

    pub fn enter(bytes: &[u8]) -> Self {
        let prev = payload_ctx_state();
        let schema = prev.as_ref().and_then(|state| state.schema);
        // An explicit decode guard is authoritative over a restored outer
        // payload context. This matches `effective_decode_flags()` and avoids
        // silently reverting nested field decoders to stale layout flags.
        let flags = current_decode_flags_effective();
        Self::install(bytes, bytes.len(), schema, flags)
    }
    /// Install a payload context with an explicit logical length while preserving
    /// any active schema/flag state from the current decode context.
    pub fn enter_with_len(bytes: &[u8], logical_len: usize) -> Self {
        let prev = payload_ctx_state();
        let schema = prev.as_ref().and_then(|state| state.schema);
        let flags = current_decode_flags_effective();
        Self::install(bytes, logical_len, schema, flags)
    }
    pub fn enter_with_schema(bytes: &[u8], schema: [u8; 16]) -> Self {
        Self::install(bytes, bytes.len(), Some(schema), None)
    }
    pub fn enter_with_flags(bytes: &[u8], flags: u8) -> Self {
        Self::install(bytes, bytes.len(), None, Some(flags))
    }
    pub fn enter_with_schema_and_flags(bytes: &[u8], schema: [u8; 16], flags: u8) -> Self {
        Self::install(bytes, bytes.len(), Some(schema), Some(flags))
    }
    /// Install a payload context using `logical_len` bytes from `bytes` while tracking
    /// decode flags.
    pub fn enter_with_flags_len(bytes: &[u8], logical_len: usize, flags: u8) -> Self {
        Self::install(bytes, logical_len, None, Some(flags))
    }
}
impl Drop for PayloadCtxGuard {
    fn drop(&mut self) {
        // Drop the decode flags guard first so the previous decode state is restored before
        // we reconcile the payload context stack.
        self.flags_guard.take();
        DECODE_PAYLOAD_CTX.with(|cell| {
            let mut slot = cell.borrow_mut();
            let current = slot.take();
            let restored = match (&self.prev, current) {
                (Some(prev_state), Some(curr_state)) => {
                    let mut merged = prev_state.clone();
                    if curr_state.max_access > 0 {
                        if curr_state.base == merged.base && curr_state.len == merged.len {
                            if curr_state.max_access > merged.max_access {
                                merged.max_access = curr_state.max_access;
                            }
                        } else if curr_state.base >= merged.base
                            && curr_state.base < merged.base + merged.len
                        {
                            let rel = curr_state.base - merged.base;
                            let end = rel.saturating_add(curr_state.max_access);
                            if end > merged.max_access {
                                merged.max_access = merged.len.min(end);
                            }
                        }
                    }
                    Some(merged)
                }
                (prev, _) => prev.clone(),
            };
            *slot = restored;
        });
    }
}
/// Set decode flags for the current thread.
fn set_decode_flags_raw(flags: u8) {
    DECODE_FLAGS.with(|c| c.set(sanitize_layout_flags(flags)));
}
fn set_decode_flags_active(active: bool) {
    DECODE_FLAGS_ACTIVE.with(|c| c.set(active));
}
pub fn set_decode_flags(flags: u8) {
    set_decode_flags_raw(flags);
    set_decode_flags_active(true);
}
/// Get decode flags for the current thread.
pub fn get_decode_flags() -> u8 {
    DECODE_FLAGS.with(|c| c.get())
}
pub(crate) fn decode_flags_active() -> bool {
    DECODE_FLAGS_ACTIVE.with(|c| c.get())
}
/// RAII guard to restore previous decode flags.
pub struct DecodeFlagsGuard {
    prev_flags: u8,
    prev_active: bool,
}
impl DecodeFlagsGuard {
    pub fn enter(flags: u8) -> Self {
        let prev_flags = get_decode_flags();
        let prev_active = decode_flags_active();
        #[cfg(debug_assertions)]
        if crate::debug_trace_enabled() {
            eprintln!("DecodeFlagsGuard::enter flags=0x{flags:02x}");
        }
        set_decode_flags_raw(flags);
        set_decode_flags_active(true);
        Self {
            prev_flags,
            prev_active,
        }
    }
}
impl Drop for DecodeFlagsGuard {
    fn drop(&mut self) {
        set_decode_flags_raw(self.prev_flags);
        set_decode_flags_active(self.prev_active);
    }
}
/// Convenience: reset both decode flags and payload context.
///
/// Useful in tests or when switching between payloads with different negotiated layouts in the same
/// thread. This deliberately does not clear an active [`DecodeLimits`] scope; payload code must not
/// be able to erase its caller's allocation boundary.
pub fn reset_decode_state() {
    set_decode_flags_raw(0);
    set_decode_flags_active(false);
    clear_payload_ctx();
}
pub(crate) fn prepare_header_decode(flags: u8, require_match: bool) -> Result<(), Error> {
    if decode_flags_active() {
        let active_flags = get_decode_flags();
        if require_match && active_flags != flags {
            return Err(Error::DecodeFlagsMismatch {
                header_flags: flags,
                active_flags,
            });
        }
        clear_payload_ctx();
        return Ok(());
    }
    reset_decode_state();
    Ok(())
}
fn current_decode_flags_effective() -> Option<u8> {
    if decode_flags_active() {
        Some(get_decode_flags())
    } else {
        payload_ctx_flags()
    }
}
/// Return the currently effective decode flags, if any.
///
/// When a Norito header is being decoded this reflects the stored flag set.
/// Otherwise it falls back to any explicitly configured `DecodeFlagsGuard`.
pub fn effective_decode_flags() -> Option<u8> {
    current_decode_flags_effective()
}
#[inline]
fn effective_layout_flags() -> u8 {
    current_decode_flags_effective().unwrap_or_else(default_encode_flags)
}
/// True if compact varint length encoding is enabled for the current decode.
pub fn use_compact_len() -> bool {
    effective_layout_flags() & header_flags::COMPACT_LEN != 0
}
/// True if compact length encoding is enabled in an explicit flag snapshot.
#[doc(hidden)]
pub fn compact_len_enabled_for_flags(flags: u8) -> bool {
    flags & header_flags::COMPACT_LEN != 0
}
/// Byte range for a planned binary sequence element.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceSpan {
    /// Inclusive start offset in the source byte slice.
    pub start: usize,
    /// Exclusive end offset in the source byte slice.
    pub end: usize,
}
impl SequenceSpan {
    /// Return this span as a slice of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthMismatch`] when the planned range is outside `bytes`.
    #[doc(hidden)]
    #[inline]
    pub fn get<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], Error> {
        bytes.get(self.start..self.end).ok_or(Error::LengthMismatch)
    }
    /// Length of the planned element payload.
    #[doc(hidden)]
    #[inline]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
    /// Return whether this span contains no bytes.
    #[doc(hidden)]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
/// Planned element spans and total bytes consumed by a binary sequence.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequencePlan {
    /// Element payload ranges in original sequence order.
    pub spans: Vec<SequenceSpan>,
    /// Total bytes consumed from the source sequence payload.
    pub used: usize,
}
#[cfg(any(feature = "codec-gpu-metal", feature = "codec-gpu-cuda"))]
const SEQUENCE_GPU_MIN_BYTES: usize = 1 << 20;
#[cfg(any(feature = "codec-gpu-metal", feature = "codec-gpu-cuda"))]
const SEQUENCE_GPU_MIN_ELEMENTS: usize = 4096;
/// Plan element byte spans for a Norito binary sequence without materializing values.
///
/// The input starts at the sequence count header. Every element carries its own length prefix,
/// sized per `flags` (`COMPACT_LEN` or fixed-width). Returned spans are byte offsets into the same
/// input slice, and `used` is the total sequence payload length consumed from the front of `bytes`.
#[doc(hidden)]
pub fn plan_binary_sequence(bytes: &[u8], flags: u8) -> Result<SequencePlan, Error> {
    validate_header_flags(flags)?;
    let (count, _) = read_seq_len_slice(bytes)?;
    plan_binary_sequence_with_count(bytes, flags, count)
}
fn plan_binary_sequence_with_count(
    bytes: &[u8],
    flags: u8,
    count: usize,
) -> Result<SequencePlan, Error> {
    validate_header_flags(flags)?;
    #[cfg(any(feature = "codec-gpu-metal", feature = "codec-gpu-cuda"))]
    if !decode_limits_active()
        && bytes.len() >= SEQUENCE_GPU_MIN_BYTES
        && count >= SEQUENCE_GPU_MIN_ELEMENTS
        && let Some(plan) = sequence_gpu::try_plan_binary_sequence(bytes, flags)
    {
        note_payload_access(bytes, plan.used);
        return Ok(plan);
    }
    let plan = plan_binary_sequence_scalar_with_count(bytes, flags, count)?;
    note_payload_access(bytes, plan.used);
    Ok(plan)
}
#[cfg(any(feature = "codec-gpu-metal", feature = "codec-gpu-cuda"))]
fn plan_binary_sequence_scalar(bytes: &[u8], flags: u8) -> Result<SequencePlan, Error> {
    validate_header_flags(flags)?;
    let (count, _) = read_seq_len_slice(bytes)?;
    plan_binary_sequence_scalar_with_count(bytes, flags, count)
}
fn plan_binary_sequence_scalar_with_count(
    bytes: &[u8],
    flags: u8,
    count: usize,
) -> Result<SequencePlan, Error> {
    validate_binary_sequence_reservation(bytes, flags, count)?;
    let mut spans = try_decode_vec_with_capacity(count)?;
    let used = byte_sequence::visit_binary_sequence_with_count(bytes, flags, count, |span| {
        spans.push(span);
        Ok(())
    })?;
    Ok(SequencePlan { spans, used })
}
fn validate_binary_sequence_reservation(
    bytes: &[u8],
    flags: u8,
    count: usize,
) -> Result<(), Error> {
    let (declared_count, offset) = inspect_seq_len_slice(bytes)?;
    if declared_count != count {
        return Err(Error::LengthMismatch);
    }
    let minimum_prefix = if compact_len_enabled_for_flags(flags) {
        1usize
    } else {
        8usize
    };
    let minimum_body = count
        .checked_mul(minimum_prefix)
        .ok_or(Error::LengthMismatch)?;
    let minimum_end = offset
        .checked_add(minimum_body)
        .ok_or(Error::LengthMismatch)?;
    if minimum_end > bytes.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(())
}
fn validate_current_sequence_reservation(bytes: &[u8], count: usize) -> Result<(), Error> {
    validate_binary_sequence_reservation(
        bytes,
        effective_decode_flags().unwrap_or_else(default_encode_flags),
        count,
    )
}
fn validate_current_map_reservation(bytes: &[u8], count: usize) -> Result<(), Error> {
    let (declared_count, offset) = inspect_seq_len_slice(bytes)?;
    if declared_count != count {
        return Err(Error::LengthMismatch);
    }
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    let prefix = if compact_len_enabled_for_flags(flags) {
        1usize
    } else {
        8usize
    };
    let minimum_body = count
        .checked_mul(prefix)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(Error::LengthMismatch)?;
    let minimum_end = offset
        .checked_add(minimum_body)
        .ok_or(Error::LengthMismatch)?;
    if minimum_end > bytes.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(())
}
#[cfg(any(feature = "codec-gpu-metal", feature = "codec-gpu-cuda"))]
mod sequence_gpu {
    use super::{SequencePlan, SequenceSpan, plan_binary_sequence_scalar};
    use std::{
        ffi::{c_char, c_int, c_void},
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AbiSpan {
        start: usize,
        end: usize,
    }
    type SequencePlanHelperFn = unsafe extern "C" fn(
        input_ptr: *const u8,
        input_len: usize,
        flags: u8,
        out_spans: *mut AbiSpan,
        out_capacity: usize,
        out_count: *mut usize,
        out_used: *mut usize,
    ) -> i32;
    const RC_OK: i32 = 0;
    const RC_INVALID: i32 = 1;
    const RC_NO_SPACE: i32 = 2;
    const RC_UNAVAILABLE: i32 = 3;
    struct SequencePlanLib {
        handle: *mut c_void,
        func: SequencePlanHelperFn,
    }
    unsafe impl Send for SequencePlanLib {}
    unsafe impl Sync for SequencePlanLib {}
    impl Drop for SequencePlanLib {
        fn drop(&mut self) {
            unsafe { close_library(self.handle) };
        }
    }
    enum SequencePlanCache {
        Unknown,
        Loaded(SequencePlanLib),
        Disabled,
    }
    static SEQUENCE_PLAN_LIB: OnceLock<Mutex<SequencePlanCache>> = OnceLock::new();
    pub(super) fn try_plan_binary_sequence(bytes: &[u8], flags: u8) -> Option<SequencePlan> {
        let cache = SEQUENCE_PLAN_LIB.get_or_init(|| Mutex::new(SequencePlanCache::Unknown));
        let mut guard = cache.lock().expect("sequence GPU cache poisoned");
        if matches!(*guard, SequencePlanCache::Unknown) {
            *guard = unsafe { load_sequence_plan_library() }
                .map(SequencePlanCache::Loaded)
                .unwrap_or(SequencePlanCache::Disabled);
        }
        let SequencePlanCache::Loaded(lib) = &*guard else {
            return None;
        };
        let plan = match unsafe { call_helper(lib.func, bytes, flags) } {
            HelperOutcome::Planned(plan) => plan,
            HelperOutcome::InvalidInput => {
                if plan_binary_sequence_scalar(bytes, flags).is_ok() {
                    *guard = SequencePlanCache::Disabled;
                }
                return None;
            }
            HelperOutcome::BackendFailure => {
                *guard = SequencePlanCache::Disabled;
                return None;
            }
            HelperOutcome::BackendUnavailable => return None,
        };
        match plan_binary_sequence_scalar(bytes, flags) {
            Ok(scalar) if scalar == plan => Some(plan),
            Ok(_) | Err(_) => {
                *guard = SequencePlanCache::Disabled;
                None
            }
        }
    }
    enum HelperOutcome {
        Planned(SequencePlan),
        InvalidInput,
        BackendUnavailable,
        BackendFailure,
    }
    unsafe fn call_helper(func: SequencePlanHelperFn, bytes: &[u8], flags: u8) -> HelperOutcome {
        let mut spans: Vec<AbiSpan> = Vec::new();
        let mut out_count = 0usize;
        let mut out_used = 0usize;
        let rc = unsafe {
            func(
                bytes.as_ptr(),
                bytes.len(),
                flags,
                spans.as_mut_ptr(),
                spans.capacity(),
                &mut out_count,
                &mut out_used,
            )
        };
        if rc != RC_NO_SPACE {
            return if rc == RC_OK && out_count == 0 && out_used <= bytes.len() {
                HelperOutcome::Planned(SequencePlan {
                    spans: Vec::new(),
                    used: out_used,
                })
            } else if rc == RC_OK || rc == RC_INVALID {
                HelperOutcome::InvalidInput
            } else if rc == RC_UNAVAILABLE {
                HelperOutcome::BackendUnavailable
            } else {
                HelperOutcome::BackendFailure
            };
        }
        let declared_count = match super::inspect_seq_len_slice(bytes) {
            Ok((count, _)) => count,
            Err(_) => return HelperOutcome::InvalidInput,
        };
        if out_count != declared_count
            || super::check_decode_sequence_length(u64::try_from(out_count).unwrap_or(u64::MAX))
                .is_err()
        {
            return HelperOutcome::BackendFailure;
        }
        let allocation_bytes = match out_count.checked_mul(core::mem::size_of::<AbiSpan>()) {
            Some(bytes) => bytes,
            None => return HelperOutcome::BackendFailure,
        };
        if super::reserve_decode_allocation(allocation_bytes).is_err()
            || spans.try_reserve(out_count).is_err()
        {
            return HelperOutcome::BackendFailure;
        }
        let rc = unsafe {
            func(
                bytes.as_ptr(),
                bytes.len(),
                flags,
                spans.as_mut_ptr(),
                spans.capacity(),
                &mut out_count,
                &mut out_used,
            )
        };
        if rc != RC_OK || out_count > spans.capacity() || out_used > bytes.len() {
            return match rc {
                RC_INVALID => HelperOutcome::InvalidInput,
                RC_UNAVAILABLE => HelperOutcome::BackendUnavailable,
                _ => HelperOutcome::BackendFailure,
            };
        }
        unsafe {
            spans.set_len(out_count);
        }
        let spans = spans
            .into_iter()
            .map(|span| {
                if span.start <= span.end && span.end <= bytes.len() {
                    Some(SequenceSpan {
                        start: span.start,
                        end: span.end,
                    })
                } else {
                    None
                }
            })
            .collect::<Option<Vec<_>>>();
        match spans {
            Some(spans) => HelperOutcome::Planned(SequencePlan {
                spans,
                used: out_used,
            }),
            None => HelperOutcome::BackendFailure,
        }
    }
    unsafe fn load_sequence_plan_library() -> Option<SequencePlanLib> {
        #[cfg(unix)]
        {
            for path in candidate_paths() {
                let Some(lib) = (unsafe { load_library_unix(&path) }) else {
                    continue;
                };
                let Some(func) = (unsafe { resolve_symbol(lib) }) else {
                    unsafe { close_library(lib) };
                    continue;
                };
                if sequence_plan_helper_self_test(func) {
                    return Some(SequencePlanLib { handle: lib, func });
                }
                unsafe { close_library(lib) };
            }
        }
        None
    }
    fn sequence_plan_helper_self_test(func: SequencePlanHelperFn) -> bool {
        let flags = super::header_flags::COMPACT_LEN;
        let bytes = make_case(flags);
        let accel = match unsafe { call_helper(func, &bytes, flags) } {
            HelperOutcome::Planned(plan) => plan,
            HelperOutcome::InvalidInput
            | HelperOutcome::BackendUnavailable
            | HelperOutcome::BackendFailure => return false,
        };
        plan_binary_sequence_scalar(&bytes, flags).is_ok_and(|scalar| accel == scalar)
    }
    fn make_case(flags: u8) -> Vec<u8> {
        let _guard = super::DecodeFlagsGuard::enter(flags);
        let mut out = Vec::new();
        super::write_seq_len(&mut out, 3).expect("write sequence length");
        for payload in [&b"a"[..], &[0x55; 130][..], b"tail"] {
            super::write_len(&mut out, payload.len() as u64).expect("write element length");
            out.extend_from_slice(payload);
        }
        out
    }
    fn candidate_paths() -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            #[cfg(all(feature = "codec-gpu-metal", target_os = "macos"))]
            {
                candidates.push(dir.join("libjsonstage1_metal.dylib"));
                candidates.push(dir.join("../lib/libjsonstage1_metal.dylib"));
            }
            #[cfg(feature = "codec-gpu-cuda")]
            {
                candidates.push(dir.join("libjsonstage1_cuda.dylib"));
                candidates.push(dir.join("../lib/libjsonstage1_cuda.dylib"));
                candidates.push(dir.join("libjsonstage1_cuda.so"));
                candidates.push(dir.join("../lib/libjsonstage1_cuda.so"));
            }
        }
        candidates
    }
    #[cfg(unix)]
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
    }
    #[cfg(unix)]
    unsafe fn load_library_unix(path: &std::path::Path) -> Option<*mut c_void> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        const RTLD_LAZY: c_int = 1;
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) {
            return None;
        }
        let cpath = CString::new(bytes).ok()?;
        let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_LAZY) };
        if handle.is_null() { None } else { Some(handle) }
    }
    #[cfg(not(unix))]
    unsafe fn load_library_unix(_path: &std::path::Path) -> Option<*mut c_void> {
        None
    }
    unsafe fn resolve_symbol(handle: *mut c_void) -> Option<SequencePlanHelperFn> {
        #[cfg(unix)]
        {
            let sym = unsafe { dlsym(handle, c"norito_length_prefixed_sequence_plan".as_ptr()) };
            if sym.is_null() {
                return None;
            }
            Some(unsafe { std::mem::transmute::<*mut c_void, SequencePlanHelperFn>(sym) })
        }
        #[cfg(not(unix))]
        {
            let _ = handle;
            None
        }
    }
    unsafe fn close_library(handle: *mut c_void) {
        #[cfg(unix)]
        if !handle.is_null() {
            let _ = unsafe { dlclose(handle) };
        }
        #[cfg(not(unix))]
        let _ = handle;
    }
    #[cfg(test)]
    include!("core/sequence_plan_helper_tests.rs");
}
/// Write a length prefix honoring `COMPACT_LEN`.
pub fn write_len<W: Write>(writer: &mut W, value: u64) -> std::io::Result<()> {
    write_len_with_flags(writer, value, effective_layout_flags())
}
/// Write a length prefix honoring `COMPACT_LEN` from an explicit flag snapshot.
#[doc(hidden)]
pub fn write_len_with_flags<W: Write>(
    writer: &mut W,
    value: u64,
    flags: u8,
) -> std::io::Result<()> {
    if compact_len_enabled_for_flags(flags) {
        let mut buf = [0u8; MAX_VARINT_BYTES];
        let used = encode_varint(value, &mut buf);
        writer.write_all(&buf[..used])?;
        note_compact_len_emitted();
        Ok(())
    } else {
        writer.write_all(&value.to_le_bytes())
    }
}
/// Write a sequence length prefix (fixed u64).
pub fn write_seq_len<W: Write>(writer: &mut W, value: u64) -> std::io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}
/// Append a length prefix honoring `COMPACT_LEN` to `out`.
#[inline]
pub fn write_len_to_vec(out: &mut Vec<u8>, value: u64) {
    write_len_to_vec_with_flags(out, value, effective_layout_flags());
}
/// Append a length prefix honoring `COMPACT_LEN` from an explicit flag snapshot.
#[inline]
#[doc(hidden)]
pub fn write_len_to_vec_with_flags(out: &mut Vec<u8>, value: u64, flags: u8) {
    if compact_len_enabled_for_flags(flags) {
        let mut buf = [0u8; MAX_VARINT_BYTES];
        let used = encode_varint(value, &mut buf);
        out.extend_from_slice(&buf[..used]);
        note_compact_len_emitted();
    } else {
        out.extend_from_slice(&value.to_le_bytes());
    }
}
/// Count a value, then write its length prefix and serialize it directly.
///
/// The helper measures the actual payload before emitting its length. An output destination
/// receives the checked payload directly, while a counting destination consumes the measured
/// size without traversing the payload again. No field-sized staging buffer is retained.
///
/// A stateful second-pass mismatch returns [`Error::LengthMismatch`]. The prefix and an admitted
/// payload prefix may already have been emitted, but a payload overrun cannot grow the destination
/// beyond the declared length. Callers must discard the incomplete destination after any error.
pub fn write_len_prefixed(
    writer: &mut Encoder<'_>,
    value: &dyn SerializePayload,
) -> Result<(), Error> {
    let flags = effective_layout_flags();
    let exact_len = encoded_payload_len(value)?;
    let len = u64::try_from(exact_len).map_err(|_| Error::LengthMismatch)?;
    write_len_with_flags(writer, len, flags)?;
    write_counted_payload(value, writer, exact_len)
}
/// Measure and write a payload with a fixed-width u64 length prefix.
///
/// The payload retains the active layout; only its containing length uses fixed width.
/// This is used by containers whose canonical wire format requires that prefix.
///
/// # Errors
///
/// Returns measurement or write errors, including a changed second-pass length.
#[doc(hidden)]
pub fn write_fixed_len_prefixed(
    writer: &mut Encoder<'_>,
    value: &dyn SerializePayload,
) -> Result<(), Error> {
    let length = encoded_payload_len(value)?;
    writer.write_u64::<LittleEndian>(u64::try_from(length).map_err(|_| Error::LengthMismatch)?)?;
    write_counted_payload(value, writer, length)
}
/// Write a compact varint length prefix regardless of layout flags.
pub fn write_varint_len<W: Write>(writer: &mut W, value: u64) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_VARINT_BYTES];
    let used = encode_varint(value, &mut buf);
    writer.write_all(&buf[..used])
}
/// Append a compact varint length prefix regardless of layout flags.
pub fn write_varint_len_to_vec(out: &mut Vec<u8>, value: u64) {
    let mut buf = [0u8; MAX_VARINT_BYTES];
    let used = encode_varint(value, &mut buf);
    out.extend_from_slice(&buf[..used]);
}
fn write_sequence_payload(
    writer: &mut Encoder<'_>,
    value: &dyn SerializePayload,
    flags: u8,
) -> Result<(), Error> {
    let encoded_len = encoded_payload_len(value)?;
    write_len_with_flags(
        writer,
        u64::try_from(encoded_len).map_err(|_| Error::LengthMismatch)?,
        flags,
    )?;
    write_counted_payload(value, writer, encoded_len)
}

fn encode_seq_payloads<T, I>(writer: &mut Encoder<'_>, items: I) -> Result<(), Error>
where
    T: SerializePayload,
    I: IntoIterator,
    I::IntoIter: ExactSizeIterator,
    I::Item: std::borrow::Borrow<T>,
{
    encode_seq_payloads_with(writer, items, |item, writer, flags| {
        let value: &T = std::borrow::Borrow::borrow(&item);
        write_sequence_payload(writer, value, flags)
    })
}

// All sequence producers share the same count, active-prefix flags and actual
// iterator-cardinality checks, including codec-owned measured heap tie payloads.
fn encode_seq_payloads_with<'writer, I, F>(
    writer: &mut Encoder<'writer>,
    items: I,
    mut write_payload: F,
) -> Result<(), Error>
where
    I: IntoIterator,
    I::IntoIter: ExactSizeIterator,
    F: FnMut(I::Item, &mut Encoder<'writer>, u8) -> Result<(), Error>,
{
    let iter = items.into_iter();
    let len = iter.len();
    write_seq_len(
        writer,
        u64::try_from(len).map_err(|_| Error::LengthMismatch)?,
    )?;
    let flags = effective_layout_flags();
    let mut count = 0usize;
    for item in iter {
        if count == len {
            return Err(Error::LengthMismatch);
        }
        write_payload(item, writer, flags)?;
        count += 1;
    }
    (count == len).then_some(()).ok_or(Error::LengthMismatch)
}
fn encode_slice_payloads<T>(writer: &mut Encoder<'_>, slice: &[T]) -> Result<(), Error>
where
    T: SerializePayload,
{
    encode_seq_payloads::<T, _>(writer, slice.iter())
}
/// Write an element sequence with one length prefix per element.
///
/// Each element uses its own serialization, including u8 elements; this does not use
/// the raw-byte `Vec<u8>` specialization. The sequence count is fixed-width, and the
/// active flags select compact or fixed-width element length prefixes. Measurement and
/// emission have one codec owner. Items may borrow existing elements or contain projected
/// views without collecting another sequence. The iterator's reported count is checked
/// against its actual yields.
///
/// # Errors
///
/// Returns serialization errors, inconsistent iterator cardinality, or a changed
/// second-pass length. Discard the incomplete destination after any error.
#[doc(hidden)]
pub fn write_element_sequence<T, I>(writer: &mut Encoder<'_>, items: I) -> Result<(), Error>
where
    T: SerializePayload,
    I: IntoIterator,
    I::IntoIter: ExactSizeIterator,
    I::Item: std::borrow::Borrow<T>,
{
    encode_seq_payloads::<T, I>(writer, items)
}
/// Canonical element-sequence sizing shared by immutable collection owners.
/// Returns `None` when any original leaf has no representable length hint.
#[doc(hidden)]
pub fn sequence_encoded_len_hint<'a, T, I>(items: I) -> Option<usize>
where
    T: SerializePayload + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut total = 8usize;
    let flags = effective_layout_flags();
    for item in items {
        let elem_len = item
            .encoded_len_exact()
            .or_else(|| item.encoded_len_hint())?;
        total = total.checked_add(len_prefix_len_with_flags(elem_len, flags))?;
        total = total.checked_add(elem_len)?;
    }
    Some(total)
}
/// Exact canonical element-sequence sizing without staging a temporary byte Vec.
/// Returns `None` when any original leaf has no representable exact length.
#[doc(hidden)]
pub fn sequence_encoded_len_exact<'a, T, I>(items: I) -> Option<usize>
where
    T: SerializePayload + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut total = 8usize;
    let flags = effective_layout_flags();
    for item in items {
        let elem_len = item.encoded_len_exact()?;
        total = total.checked_add(len_prefix_len_with_flags(elem_len, flags))?;
        total = total.checked_add(elem_len)?;
    }
    Some(total)
}
fn map_encoded_len_hint<'a, K, V, I>(entries: I) -> Option<usize>
where
    K: SerializePayload + 'a,
    V: SerializePayload + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)>,
{
    let mut total = 8usize;
    let flags = effective_layout_flags();
    for (key, value) in entries {
        let key_len = key.encoded_len_exact().or_else(|| key.encoded_len_hint())?;
        let value_len = value
            .encoded_len_exact()
            .or_else(|| value.encoded_len_hint())?;
        total = total.checked_add(len_prefix_len_with_flags(key_len, flags))?;
        total = total.checked_add(key_len)?;
        total = total.checked_add(len_prefix_len_with_flags(value_len, flags))?;
        total = total.checked_add(value_len)?;
    }
    Some(total)
}
fn map_encoded_len_exact<'a, K, V, I>(entries: I) -> Option<usize>
where
    K: SerializePayload + 'a,
    V: SerializePayload + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)>,
{
    let mut total = 8usize;
    let flags = effective_layout_flags();
    for (key, value) in entries {
        let key_len = key.encoded_len_exact()?;
        let value_len = value.encoded_len_exact()?;
        total = total.checked_add(len_prefix_len_with_flags(key_len, flags))?;
        total = total.checked_add(key_len)?;
        total = total.checked_add(len_prefix_len_with_flags(value_len, flags))?;
        total = total.checked_add(value_len)?;
    }
    Some(total)
}
/// Write the canonical map layout directly from borrowed entries in strict key order.
///
/// This is the same kernel used by `BTreeMap` and sorted `HashMap` serialization. It owns no
/// staging map or entry buffer. Every key/value keeps its source custody while it is measured
/// and emitted, and a counting destination preserves the normal one-pass leaf measurement.
///
/// # Errors
///
/// Rejects missing/extra entries, duplicate or descending keys, and propagates the original
/// field measurement or destination error. The caller must discard partial output on error.
pub fn write_ordered_map_entries<'a, K, V, I>(
    writer: &mut Encoder<'_>,
    len: usize,
    entries: I,
) -> Result<(), Error>
where
    K: SerializePayload + Ord + 'a,
    V: SerializePayload + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)>,
{
    write_seq_len(
        writer,
        u64::try_from(len).map_err(|_| Error::LengthMismatch)?,
    )?;
    let flags = effective_layout_flags();
    let mut count = 0usize;
    let mut previous: Option<&K> = None;
    for (key, value) in entries {
        if count == len || previous.is_some_and(|previous| previous >= key) {
            return Err(Error::LengthMismatch);
        }
        for item in [key as &dyn SerializePayload, value as &dyn SerializePayload] {
            let encoded_len = encoded_payload_len(item)?;
            write_len_with_flags(
                writer,
                u64::try_from(encoded_len).map_err(|_| Error::LengthMismatch)?,
                flags,
            )?;
            write_counted_payload(item, writer, encoded_len)?;
        }
        previous = Some(key);
        count += 1;
    }
    (count == len).then_some(()).ok_or(Error::LengthMismatch)
}
/// Emit a length prefix honoring the `COMPACT_LEN` layout flag.
///
/// When `COMPACT_LEN` is set this writes a compact varint. Otherwise it falls
/// back to a fixed 8-byte little-endian `u64` header.
pub fn write_len_header<W: Write>(writer: &mut W, value: u64) -> std::io::Result<()> {
    write_len(writer, value)
}
/// Append a length prefix honoring the `COMPACT_LEN` layout flag.
///
/// Writes a compact varint when `COMPACT_LEN` is set, or an 8-byte little-endian `u64` otherwise.
pub fn write_len_header_to_vec(out: &mut Vec<u8>, value: u64) {
    write_len_to_vec(out, value);
}
/// Read a length prefix from a slice honoring `COMPACT_LEN`. Returns (value, bytes_consumed).
pub fn read_len_from_slice(bytes: &[u8]) -> Result<(usize, usize), Error> {
    read_len_from_slice_with_flags(bytes, effective_layout_flags())
}
/// Inspect a length prefix without charging an allocation for the referenced bytes.
///
/// This is for bounded zero-copy decoders that retain a borrowed subslice instead of materializing
/// the declared field. The per-field byte limit is still enforced.
#[doc(hidden)]
pub fn inspect_len_from_slice(bytes: &[u8]) -> Result<(usize, usize), Error> {
    let (value, used) = read_raw_len_from_slice_with_flags(bytes, effective_layout_flags())?;
    check_decode_field_length(value)?;
    let len = usize::try_from(value).map_err(|_| Error::LengthMismatch)?;
    Ok((len, used))
}
/// Read a length prefix from a slice using an explicit Norito flag snapshot.
/// Returns (value, bytes consumed).
#[doc(hidden)]
pub fn read_len_from_slice_with_flags(bytes: &[u8], flags: u8) -> Result<(usize, usize), Error> {
    let (value, used) = read_raw_len_from_slice_with_flags(bytes, flags)?;
    enforce_decode_field_length(value)?;
    let len = usize::try_from(value).map_err(|_| Error::LengthMismatch)?;
    Ok((len, used))
}
fn read_raw_len_from_slice_with_flags(bytes: &[u8], flags: u8) -> Result<(u64, usize), Error> {
    if compact_len_enabled_for_flags(flags) {
        let (value, used) = decode_varint_from_slice(bytes)?;
        record_slice_access(bytes, used);
        Ok((value, used))
    } else {
        if bytes.len() < 8 {
            return Err(Error::LengthMismatch);
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bytes[..8]);
        record_slice_access(bytes, 8);
        let value = u64::from_le_bytes(len_bytes);
        Ok((value, 8))
    }
}
/// Read an AoS-style sequence count that follows the active flexible length
/// encoding, accounting it as elements rather than as a field body.
pub(crate) fn read_sequence_len_from_slice(bytes: &[u8]) -> Result<(usize, usize), Error> {
    let (value, used) = read_raw_len_from_slice_with_flags(bytes, effective_layout_flags())?;
    enforce_decode_sequence_length(value)?;
    let len = usize::try_from(value).map_err(|_| Error::LengthMismatch)?;
    Ok((len, used))
}
/// Dynamically read a length prefix from a slice, honoring `COMPACT_LEN`.
/// Returns (value, bytes consumed).
pub fn read_len_dyn_slice(bytes: &[u8]) -> Result<(usize, usize), Error> {
    read_len_from_slice(bytes)
}
/// Read a top-level sequence length header from a slice (fixed u64).
/// Returns (value, bytes consumed).
pub fn read_seq_len_slice(bytes: &[u8]) -> Result<(usize, usize), Error> {
    read_seq_len_slice_impl(bytes, true)
}
/// Inspect a sequence count without charging cumulative elements or an allocation.
///
/// This is for bounded zero-copy decoders that borrow an already-accounted
/// byte sequence. The per-sequence element limit is still enforced.
#[doc(hidden)]
pub fn inspect_seq_len_slice(bytes: &[u8]) -> Result<(usize, usize), Error> {
    read_seq_len_slice_impl(bytes, false)
}
fn read_seq_len_slice_impl(bytes: &[u8], account: bool) -> Result<(usize, usize), Error> {
    if bytes.len() < 8 {
        return Err(Error::LengthMismatch);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[..8]);
    record_slice_access(bytes, 8);
    let raw_len = u64::from_le_bytes(len_bytes);
    if account {
        enforce_decode_sequence_length(raw_len)?;
    } else {
        check_decode_sequence_length(raw_len)?;
    }
    let len = len_u64_to_usize(raw_len)?;
    Ok((len, 8))
}
/// Pointer-based length read without relying on a global payload context.
///
/// # Safety
/// `ptr` must be valid for reading up to the maximum header size
/// (8 bytes for fixed `u64` length or up to 10 bytes for compact varint).
/// Callers must ensure the pointer is within the validated payload.
#[inline]
pub unsafe fn read_len_ptr_unchecked(ptr: *const u8) -> (usize, usize) {
    match unsafe { try_read_len_ptr_unchecked(ptr) } {
        Ok(res) => res,
        Err(err) => {
            panic!("read_len_ptr_unchecked: invalid length header ({err:?})");
        }
    }
}
/// Fallible variant of [`read_len_ptr_unchecked`] that returns an error if a
/// compact-varint length exceeds 10 bytes (malformed input).
///
/// # Safety
/// Same as [`read_len_ptr_unchecked`].
#[inline]
pub unsafe fn try_read_len_ptr_unchecked(ptr: *const u8) -> Result<(usize, usize), Error> {
    if use_compact_len() {
        let (value, used) = unsafe { decode_varint_from_ptr(ptr)? };
        record_payload_access(ptr, used);
        enforce_decode_field_length(value)?;
        let len = usize::try_from(value).map_err(|_| Error::LengthMismatch)?;
        Ok((len, used))
    } else {
        let mut lb = [0u8; 8];
        let header = unsafe { core::slice::from_raw_parts(ptr, 8) };
        lb.copy_from_slice(header);
        record_payload_access(ptr, 8);
        let value = u64::from_le_bytes(lb);
        enforce_decode_field_length(value)?;
        let len = len_u64_to_usize(value)?;
        Ok((len, 8))
    }
}
#[inline]
fn encode_varint(mut value: u64, out: &mut [u8; MAX_VARINT_BYTES]) -> usize {
    let mut i = 0;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out[i] = byte;
            i += 1;
            break;
        } else {
            out[i] = byte | 0x80;
            i += 1;
        }
    }
    i
}
#[inline]
fn varint_encoded_len(value: u64) -> usize {
    let mut buf = [0u8; MAX_VARINT_BYTES];
    encode_varint(value, &mut buf)
}
pub(crate) fn varint_encoded_len_u64(value: u64) -> usize {
    varint_encoded_len(value)
}
fn decode_varint_from_slice(bytes: &[u8]) -> Result<(u64, usize), Error> {
    if bytes.is_empty() {
        return Err(Error::LengthMismatch);
    }
    let mut result = 0u64;
    let mut shift = 0u32;
    for (idx, byte) in bytes.iter().copied().enumerate().take(MAX_VARINT_BYTES) {
        let payload = (byte & 0x7f) as u64;
        if shift == 63 && payload > 1 {
            return Err(Error::LengthMismatch);
        }
        result |= payload << shift;
        if byte & 0x80 == 0 {
            let used = idx + 1;
            if used != varint_encoded_len(result) {
                return Err(Error::LengthMismatch);
            }
            return Ok((result, used));
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    Err(Error::LengthMismatch)
}
#[inline]
unsafe fn decode_varint_from_ptr(ptr: *const u8) -> Result<(u64, usize), Error> {
    let (payload, offset) = payload_bytes_with_offset(ptr)?;
    let slice = &payload[offset..];
    decode_varint_from_slice(slice)
}
/// Read a top-level sequence length header at a raw pointer (fixed u64).
/// Returns (value, bytes consumed).
///
/// # Safety
/// `ptr` must be valid for reading up to 10 bytes (varint) or 8 bytes (u64).
#[inline]
pub unsafe fn read_seq_len_ptr(ptr: *const u8) -> Result<(usize, usize), Error> {
    let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
    let ptr_us = ptr as usize;
    if ptr_us < base || ptr_us >= base + total {
        return Err(Error::LengthMismatch);
    }
    let offset = ptr_us - base;
    let payload = unsafe { core::slice::from_raw_parts(base as *const u8, total) };
    let head = &payload[offset..];
    let (len, used) = read_seq_len_slice(head)?;
    record_payload_access(ptr, used);
    Ok((len, used))
}
/// Pointer-based helper for reading a length header within the current payload context.
///
/// # Safety
/// `ptr` must point into the currently active payload (see [`set_payload_ctx`]).
#[inline]
pub unsafe fn read_len_dyn(ptr: *const u8) -> Result<(usize, usize), Error> {
    read_len_dyn_at_ptr(ptr)
}
/// Safe decode-from-slice trait used by bounded decoders.
pub trait DecodeFromSlice<'a>: Sized {
    /// Decode from the front of `bytes`, returning the value and bytes consumed.
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error>;
}
impl<'a> DecodeFromSlice<'a> for () {
    fn decode_from_slice(_bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        Ok(((), 0))
    }
}
// DecodeFromSlice for primitives and common types
impl<'a> DecodeFromSlice<'a> for u8 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        byte_sequence::read_byte_value(bytes).map(|byte| (byte, 1))
    }
}
impl<'a> DecodeFromSlice<'a> for i8 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let b = *bytes.first().ok_or(Error::LengthMismatch)? as i8;
        Ok((b, 1))
    }
}
impl<'a> DecodeFromSlice<'a> for bool {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let b = *bytes.first().ok_or(Error::LengthMismatch)?;
        match b {
            0 => Ok((false, 1)),
            1 => Ok((true, 1)),
            tag => Err(Error::invalid_tag("bool", tag)),
        }
    }
}
macro_rules! impl_decode_from_slice_le_int {
    ($t:ty, $n:expr) => {
        impl<'a> DecodeFromSlice<'a> for $t {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
                if bytes.len() < $n {
                    return Err(Error::LengthMismatch);
                }
                let mut b = [0u8; $n];
                b.copy_from_slice(&bytes[..$n]);
                Ok((<$t>::from_le_bytes(b), $n))
            }
        }
    };
}
impl_decode_from_slice_le_int!(u16, 2);
impl_decode_from_slice_le_int!(i16, 2);
impl_decode_from_slice_le_int!(u32, 4);
impl_decode_from_slice_le_int!(i32, 4);
impl_decode_from_slice_le_int!(u64, 8);
impl_decode_from_slice_le_int!(i64, 8);
impl_decode_from_slice_le_int!(u128, 16);
impl_decode_from_slice_le_int!(i128, 16);
impl<'a> DecodeFromSlice<'a> for usize {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 8 {
            return Err(Error::LengthMismatch);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[..8]);
        let value = len_u64_to_usize(u64::from_le_bytes(b))?;
        Ok((value, 8))
    }
}
impl<'a> DecodeFromSlice<'a> for isize {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 8 {
            return Err(Error::LengthMismatch);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[..8]);
        let value = i64::from_le_bytes(b);
        let value = isize::try_from(value).map_err(|_| Error::LengthMismatch)?;
        Ok((value, 8))
    }
}
impl<'a> DecodeFromSlice<'a> for f32 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 4 {
            return Err(Error::LengthMismatch);
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&bytes[..4]);
        Ok((f32::from_bits(u32::from_le_bytes(b)), 4))
    }
}
impl<'a> DecodeFromSlice<'a> for f64 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 8 {
            return Err(Error::LengthMismatch);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[..8]);
        Ok((f64::from_bits(u64::from_le_bytes(b)), 8))
    }
}
// DecodeFromSlice for NonZero integer wrappers via their primitive
impl<'a> DecodeFromSlice<'a> for NonZeroU16 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (v, used) = <u16 as DecodeFromSlice>::decode_from_slice(bytes)?;
        let nz = NonZeroU16::new(v).ok_or(Error::InvalidNonZero)?;
        Ok((nz, used))
    }
}
impl<'a> DecodeFromSlice<'a> for NonZeroU32 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (v, used) = <u32 as DecodeFromSlice>::decode_from_slice(bytes)?;
        let nz = NonZeroU32::new(v).ok_or(Error::InvalidNonZero)?;
        Ok((nz, used))
    }
}
impl<'a> DecodeFromSlice<'a> for NonZeroU64 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (v, used) = <u64 as DecodeFromSlice>::decode_from_slice(bytes)?;
        let nz = NonZeroU64::new(v).ok_or(Error::InvalidNonZero)?;
        Ok((nz, used))
    }
}
impl<'a> DecodeFromSlice<'a> for char {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 4 {
            return Err(Error::LengthMismatch);
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&bytes[..4]);
        let v = u32::from_le_bytes(b);
        let c = char::from_u32(v).ok_or_else(|| Error::Message("invalid char".into()))?;
        Ok((c, 4))
    }
}
fn decode_sequence_plan_serial<'a, T>(bytes: &'a [u8], plan: &SequencePlan) -> Result<Vec<T>, Error>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    let mut out = try_decode_vec_with_capacity(plan.spans.len())?;
    for span in &plan.spans {
        let element_slice = span.get(bytes)?;
        record_slice_access(element_slice, span.len());
        let (value, used) = decode_field_canonical::<T>(element_slice)?;
        if used != span.len() {
            return Err(Error::LengthMismatch);
        }
        out.push(value);
    }
    Ok(out)
}
/// `NORITO_TRACE` diagnostic for generic element-sequence decoders.
#[cold]
#[inline(never)]
fn trace_sequence_decode(type_name: &'static str, len: usize) {
    eprintln!("Vec::<{type_name}>::decode len={len}");
}
fn decode_element_sequence_from_slice_with<'a, T, F>(
    bytes: &'a [u8],
    decode_planned: F,
) -> Result<(Vec<T>, usize), Error>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
    F: FnOnce(&'a [u8], u8, &SequencePlan) -> Result<Option<Vec<T>>, Error>,
{
    let (len, _) = read_seq_len_slice(bytes)?;
    if crate::debug_trace_enabled() {
        trace_sequence_decode(core::any::type_name::<T>(), len);
    }
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    let plan = plan_binary_sequence_with_count(bytes, flags, len)?;
    if let Some(out) = decode_planned(bytes, flags, &plan)? {
        return Ok((out, plan.used));
    }
    let out = decode_sequence_plan_serial::<T>(bytes, &plan)?;
    Ok((out, plan.used))
}

/// Decode a generic element sequence from the front of `bytes`.
///
/// Unlike [`decode_vec_from_slice_serial`], this always uses the advertised
/// length-prefixed element layout, including when `T` is `u8`.
/// Callers whose wire type does not use `Vec<u8>`'s raw-byte optimization use
/// this helper and decide separately whether trailing bytes are permitted.
#[doc(hidden)]
pub fn decode_element_sequence_from_slice_serial<'a, T>(
    bytes: &'a [u8],
) -> Result<(Vec<T>, usize), Error>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    decode_element_sequence_from_slice_with::<T, _>(bytes, |_, _, _| Ok(None))
}

fn decode_vec_from_slice_with<'a, T, F>(
    bytes: &'a [u8],
    decode_planned: F,
) -> Result<(Vec<T>, usize), Error>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
    F: FnOnce(&'a [u8], u8, &SequencePlan) -> Result<Option<Vec<T>>, Error>,
{
    // `Vec<u8>` is encoded as `len(u64)` + raw bytes for efficiency. Generic
    // sequence containers use `decode_element_sequence_from_slice_with`
    // instead so this storage optimization never changes their wire layout.
    if core::any::type_name::<T>() == "u8" {
        let (len, offset) = read_seq_len_slice(bytes)?;
        let end = offset.checked_add(len).ok_or(Error::LengthMismatch)?;
        // SAFETY: we verified `T == u8` via `type_name`.
        let slice = bytes.get(offset..end).ok_or(Error::LengthMismatch)?;
        let mut raw = try_decode_vec_with_capacity::<u8>(len)?;
        raw.extend_from_slice(slice);
        let out = unsafe { std::mem::transmute::<Vec<u8>, Vec<T>>(raw) };
        record_slice_access(bytes, end);
        return Ok((out, end));
    }
    decode_element_sequence_from_slice_with::<T, _>(bytes, decode_planned)
}
/// Decode a binary sequence from a slice using the scalar sequence planner.
#[doc(hidden)]
pub fn decode_vec_from_slice_serial<'a, T>(bytes: &'a [u8]) -> Result<(Vec<T>, usize), Error>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    decode_vec_from_slice_with::<T, _>(bytes, |_, _, _| Ok(None))
}
impl<'a, T> DecodeFromSlice<'a> for Vec<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        decode_vec_from_slice_serial::<T>(bytes)
    }
}
fn decode_sequence_elements<'a, T, F>(bytes: &'a [u8], mut on_value: F) -> Result<usize, Error>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
    F: FnMut(T) -> Result<(), Error>,
{
    let (len, _) = read_seq_len_slice(bytes)?;
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    let plan = plan_binary_sequence_with_count(bytes, flags, len)?;
    for span in &plan.spans {
        let element_slice = span.get(bytes)?;
        record_slice_access(element_slice, span.len());
        let (value, used) = decode_field_canonical::<T>(element_slice)?;
        if used != span.len() {
            return Err(Error::LengthMismatch);
        }
        on_value(value)?;
    }
    Ok(plan.used)
}
impl<'a> DecodeFromSlice<'a> for &'a [u8] {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, hdr) = read_seq_len_slice(bytes)?;
        let end = hdr.checked_add(len).ok_or(Error::LengthMismatch)?;
        let data = bytes.get(hdr..end).ok_or(Error::LengthMismatch)?;
        record_slice_access(data, len);
        Ok((data, end))
    }
}
impl<'a, T: DecodeFromSlice<'a> + 'static, const N: usize> DecodeFromSlice<'a> for [T; N] {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // Generic byte arrays use the same element-framed layout as their encoder.
            // Raw fixed-width fields use the explicit byte-array field helpers.
            let mut tmp = [0u8; N];
            let mut offset = 0usize;
            for slot in &mut tmp {
                let remaining = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
                // Each byte is copied directly into the final stack array.
                // Its borrowed element prefix checks length without a heap charge.
                let (elem_len, elem_hdr) = inspect_len_from_slice(remaining)?;
                offset = offset.checked_add(elem_hdr).ok_or(Error::LengthMismatch)?;
                if elem_len != 1 {
                    return Err(Error::LengthMismatch);
                }
                let byte_pos = offset;
                offset = offset.checked_add(elem_len).ok_or(Error::LengthMismatch)?;
                let byte = *bytes.get(byte_pos).ok_or(Error::LengthMismatch)?;
                *slot = byte;
            }
            record_slice_access(bytes, offset);
            let mut arr = core::mem::MaybeUninit::<[T; N]>::uninit();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tmp.as_ptr() as *const T,
                    arr.as_mut_ptr() as *mut T,
                    N,
                );
                return Ok((arr.assume_init(), offset));
            }
        }
        let mut offset = 0usize;
        let out = try_decode_array(|| {
            let remaining = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
            // The fixed array is initialized directly in its final stack
            // storage; the element decoder accounts for any owned children.
            let (len, hdr) = inspect_len_from_slice(remaining)?;
            offset = offset.checked_add(hdr).ok_or(Error::LengthMismatch)?;
            let end = offset.checked_add(len).ok_or(Error::LengthMismatch)?;
            let field = bytes.get(offset..end).ok_or(Error::LengthMismatch)?;
            let start = offset.checked_sub(hdr).ok_or(Error::LengthMismatch)?;
            let consumed = hdr.checked_add(len).ok_or(Error::LengthMismatch)?;
            record_slice_access(&bytes[start..], consumed);
            let _depth = DecodeDepthGuard::enter()?;
            let (val, used) = T::decode_from_slice(field)?;
            if used != len {
                return Err(Error::LengthMismatch);
            }
            offset = end;
            Ok(val)
        })?;
        Ok((out, offset))
    }
}
impl<'a, T> DecodeFromSlice<'a> for VecDeque<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_sequence_reservation(bytes, len)?;
        let allocation_bytes = len
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(Error::LengthMismatch)?;
        reserve_decode_allocation(allocation_bytes)?;
        let mut deque = VecDeque::new();
        deque
            .try_reserve(len)
            .map_err(|_| Error::AllocationFailed {
                bytes: limit_to_u64(allocation_bytes),
            })?;
        let used = decode_sequence_elements::<T, _>(bytes, |value| {
            deque.push_back(value);
            Ok(())
        })?;
        Ok((deque, used))
    }
}
include!("core/owned_collection_allocation.rs");
impl<'a, T> DecodeFromSlice<'a> for LinkedList<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_sequence_reservation(bytes, len)?;
        reserve_decode_allocation(linked_list_node_allocation_bytes::<T>(len)?)?;
        let mut list = LinkedList::new();
        let used = decode_sequence_elements::<T, _>(bytes, |value| {
            list.push_back(value);
            Ok(())
        })?;
        Ok((list, used))
    }
}
impl<'a, T> DecodeFromSlice<'a> for BinaryHeap<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload + Ord,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_sequence_reservation(bytes, len)?;
        let allocation_bytes = len
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(Error::LengthMismatch)?;
        reserve_decode_allocation(allocation_bytes)?;
        let mut heap = BinaryHeap::new();
        heap.try_reserve(len).map_err(|_| Error::AllocationFailed {
            bytes: limit_to_u64(allocation_bytes),
        })?;
        let used = decode_sequence_elements::<T, _>(bytes, |value| {
            heap.push(value);
            Ok(())
        })?;
        Ok((heap, used))
    }
}
impl<'a, T> DecodeFromSlice<'a> for BTreeSet<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload + Ord,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_sequence_reservation(bytes, len)?;
        reserve_decode_btree_allocation::<T, ()>(len)?;
        let mut out = BTreeSet::new();
        let used = decode_sequence_elements::<T, _>(bytes, |value| {
            if !out.insert(value) {
                return Err(Error::LengthMismatch);
            }
            Ok(())
        })?;
        Ok((out, used))
    }
}
impl<'a, T> DecodeFromSlice<'a> for HashSet<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload + Eq + Hash + Ord,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_sequence_reservation(bytes, len)?;
        let allocation_bytes = owned_hash_table_allocation_bytes::<T>(len)?;
        reserve_decode_hash_table_allocation::<T>(len)?;
        let mut out = HashSet::new();
        out.try_reserve(len).map_err(|_| Error::AllocationFailed {
            bytes: limit_to_u64(allocation_bytes),
        })?;
        let used = decode_sequence_elements::<T, _>(bytes, |value| {
            if !out.insert(value) {
                return Err(Error::LengthMismatch);
            }
            Ok(())
        })?;
        Ok((out, used))
    }
}
fn decode_map_entries<'a, K, V, F>(
    bytes: &'a [u8],
    mut on_entry: F,
) -> Result<(usize, usize), Error>
where
    K: for<'de> DeserializePayload<'de> + SerializePayload,
    V: for<'de> DeserializePayload<'de> + SerializePayload,
    F: FnMut(K, V) -> Result<(), Error>,
{
    let (len, mut offset) = read_seq_len_slice(bytes)?;
    for _ in 0..len {
        let (key_len, key_hdr) = read_len_dyn_slice(&bytes[offset..])?;
        offset = offset.checked_add(key_hdr).ok_or(Error::LengthMismatch)?;
        let key_end = offset.checked_add(key_len).ok_or(Error::LengthMismatch)?;
        if key_end > bytes.len() {
            return Err(Error::LengthMismatch);
        }
        let key_slice = &bytes[offset..key_end];
        record_slice_access(key_slice, key_len);
        let (key, key_used) = decode_field_canonical::<K>(key_slice)?;
        if key_used != key_len {
            return Err(Error::LengthMismatch);
        }
        offset = key_end;
        let (value_len, value_hdr) = read_len_dyn_slice(&bytes[offset..])?;
        offset = offset.checked_add(value_hdr).ok_or(Error::LengthMismatch)?;
        let value_end = offset.checked_add(value_len).ok_or(Error::LengthMismatch)?;
        if value_end > bytes.len() {
            return Err(Error::LengthMismatch);
        }
        let value_slice = &bytes[offset..value_end];
        record_slice_access(value_slice, value_len);
        let (value, value_used) = decode_field_canonical::<V>(value_slice)?;
        if value_used != value_len {
            return Err(Error::LengthMismatch);
        }
        offset = value_end;
        on_entry(key, value)?;
    }
    Ok((len, offset))
}
impl<'a, K, V> DecodeFromSlice<'a> for BTreeMap<K, V>
where
    K: for<'de> DeserializePayload<'de> + SerializePayload + Ord,
    V: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_map_reservation(bytes, len)?;
        reserve_decode_btree_allocation::<K, V>(len)?;
        let mut out = BTreeMap::new();
        let (_, used) = decode_map_entries::<K, V, _>(bytes, |key, value| {
            if out.insert(key, value).is_some() {
                return Err(Error::LengthMismatch);
            }
            Ok(())
        })?;
        Ok((out, used))
    }
}
impl<'a, K, V> DecodeFromSlice<'a> for HashMap<K, V>
where
    K: for<'de> DeserializePayload<'de> + SerializePayload + Eq + Hash + Ord,
    V: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, _) = inspect_seq_len_slice(bytes)?;
        validate_current_map_reservation(bytes, len)?;
        let allocation_bytes = owned_hash_table_allocation_bytes::<(K, V)>(len)?;
        reserve_decode_hash_table_allocation::<(K, V)>(len)?;
        let mut out = HashMap::new();
        out.try_reserve(len).map_err(|_| Error::AllocationFailed {
            bytes: limit_to_u64(allocation_bytes),
        })?;
        let (_, used) = decode_map_entries::<K, V, _>(bytes, |key, value| {
            if out.insert(key, value).is_some() {
                return Err(Error::LengthMismatch);
            }
            Ok(())
        })?;
        Ok((out, used))
    }
}

impl<K, V> SerializePayload for BTreeMap<K, V>
where
    K: SerializePayload + Ord,
    V: SerializePayload,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        write_ordered_map_entries(writer, self.len(), self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        map_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        map_encoded_len_exact(self.iter())
    }
}

impl<'a, K, V> DeserializePayload<'a> for BTreeMap<K, V>
where
    K: for<'de> DeserializePayload<'de> + SerializePayload + Ord,
    V: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn deserialize(archived: &'a Archived<BTreeMap<K, V>>) -> Self {
        Self::try_deserialize(archived).expect("BTreeMap decode")
    }
    fn try_deserialize(archived: &'a Archived<BTreeMap<K, V>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (map, _used) = <BTreeMap<K, V> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(map)
    }
}

impl<K, V> SerializePayload for HashMap<K, V>
where
    K: SerializePayload + Eq + Hash + Ord,
    V: SerializePayload,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let mut entries = Vec::new();
        let allocation_bytes = self
            .len()
            .checked_mul(core::mem::size_of::<(&K, &V)>())
            .ok_or(Error::LengthMismatch)?;
        reserve_decode_allocation(allocation_bytes)?;
        entries
            .try_reserve_exact(self.len())
            .map_err(|_| Error::AllocationFailed {
                bytes: limit_to_u64(allocation_bytes),
            })?;
        entries.extend(self.iter());
        entries.sort_unstable_by(|(ka, _), (kb, _)| ka.cmp(kb));
        write_ordered_map_entries(writer, entries.len(), entries.iter().copied())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        map_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        map_encoded_len_exact(self.iter())
    }
}

impl<'a, K, V> DeserializePayload<'a> for HashMap<K, V>
where
    K: for<'de> DeserializePayload<'de> + SerializePayload + Eq + Hash + Ord,
    V: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn deserialize(archived: &'a Archived<HashMap<K, V>>) -> Self {
        Self::try_deserialize(archived).expect("HashMap decode")
    }
    fn try_deserialize(archived: &'a Archived<HashMap<K, V>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (map, _used) = <HashMap<K, V> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(map)
    }
}

impl<T> SerializePayload for BTreeSet<T>
where
    T: SerializePayload + Ord,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        encode_seq_payloads::<T, _>(writer, self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        sequence_encoded_len_exact(self.iter())
    }
}

impl<'a, T> DeserializePayload<'a> for BTreeSet<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload + Ord,
{
    fn deserialize(archived: &'a Archived<BTreeSet<T>>) -> Self {
        Self::try_deserialize(archived).expect("BTreeSet decode")
    }
    fn try_deserialize(archived: &'a Archived<BTreeSet<T>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (set, _used) = <BTreeSet<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(set)
    }
}

impl<T> SerializePayload for HashSet<T>
where
    T: SerializePayload + Eq + Hash + Ord,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let mut items = Vec::new();
        let allocation_bytes = self
            .len()
            .checked_mul(core::mem::size_of::<&T>())
            .ok_or(Error::LengthMismatch)?;
        reserve_decode_allocation(allocation_bytes)?;
        items
            .try_reserve_exact(self.len())
            .map_err(|_| Error::AllocationFailed {
                bytes: limit_to_u64(allocation_bytes),
            })?;
        items.extend(self.iter());
        items.sort_unstable();
        encode_seq_payloads::<T, _>(writer, items.iter().copied())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        sequence_encoded_len_exact(self.iter())
    }
}

impl<'a, T> DeserializePayload<'a> for HashSet<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload + Eq + Hash + Ord,
{
    fn deserialize(archived: &'a Archived<HashSet<T>>) -> Self {
        Self::try_deserialize(archived).expect("HashSet decode")
    }
    fn try_deserialize(archived: &'a Archived<HashSet<T>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (set, _used) = <HashSet<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(set)
    }
}
impl<'a, T> DecodeFromSlice<'a> for Box<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let _depth_guard = OwnedValueDecodeDepthGuard::enter()?;
        let (payload, used) = parse_owned_payload(bytes)?;
        let (value, consumed) = decode_field_canonical::<T>(payload)?;
        if consumed != payload.len() {
            return Err(Error::LengthMismatch);
        }
        reserve_decode_box_allocation::<T>()?;
        Ok((Box::new(value), used))
    }
}
impl<'a, T> DecodeFromSlice<'a> for Rc<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let _depth_guard = OwnedValueDecodeDepthGuard::enter()?;
        let (payload, used) = parse_owned_payload(bytes)?;
        let (value, consumed) = decode_field_canonical::<T>(payload)?;
        if consumed != payload.len() {
            return Err(Error::LengthMismatch);
        }
        reserve_decode_rc_allocation::<T>()?;
        Ok((Rc::new(value), used))
    }
}
impl<'a, T> DecodeFromSlice<'a> for Arc<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let _depth_guard = OwnedValueDecodeDepthGuard::enter()?;
        let (payload, used) = parse_owned_payload(bytes)?;
        let (value, consumed) = decode_field_canonical::<T>(payload)?;
        if consumed != payload.len() {
            return Err(Error::LengthMismatch);
        }
        reserve_decode_arc_allocation::<T>()?;
        Ok((Arc::new(value), used))
    }
}
impl<'a, T: DecodeFromSlice<'a> + Copy> DecodeFromSlice<'a> for Cell<T> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (v, used) = T::decode_from_slice(bytes)?;
        Ok((Cell::new(v), used))
    }
}
impl<'a, T: DecodeFromSlice<'a>> DecodeFromSlice<'a> for RefCell<T> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (v, used) = T::decode_from_slice(bytes)?;
        Ok((RefCell::new(v), used))
    }
}
macro_rules! impl_decode_tuple_from_slice {
    ($( $name:ident $var:ident ),+ ) => {
        impl<'a, $( $name: DecodeFromSlice<'a> ),+> DecodeFromSlice<'a> for ( $( $name, )+ ) {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
                let mut offset = 0usize;
                $(
                    let remaining = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
                    let (len, hdr) = read_len_dyn_slice(remaining)?;
                    offset = offset.checked_add(hdr).ok_or(Error::LengthMismatch)?;
                    let end = offset.checked_add(len).ok_or(Error::LengthMismatch)?;
                    let field = bytes.get(offset..end).ok_or(Error::LengthMismatch)?;
                    let _depth = DecodeDepthGuard::enter()?;
                    let ($var, used) = $name::decode_from_slice(field)?;
                    if used != len {
                        return Err(Error::LengthMismatch);
                    }
                    drop(_depth);
                    offset = end;
                )+
                Ok((( $( $var, )+ ), offset))
            }
        }
    };
}
impl_decode_tuple_from_slice!(A a, B b);
impl_decode_tuple_from_slice!(A a, B b, C c);
impl_decode_tuple_from_slice!(A a, B b, C c, D d);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f, G g);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f, G g, H h);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f, G g, H h, I i);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k);
impl_decode_tuple_from_slice!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l);
impl<'a, T> DecodeFromSlice<'a> for Option<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (payload, used) = prepared_option::option_payload_prefix(bytes, |_| {
            Error::Message("invalid option tag".into())
        })?;
        let value = match payload {
            None => None,
            Some(payload) => {
                let (value, consumed) = decode_field_canonical::<T>(payload)?;
                if consumed != payload.len() {
                    return Err(Error::LengthMismatch);
                }
                Some(value)
            }
        };
        record_slice_access(bytes, used);
        Ok((value, used))
    }
}
impl<'a, T: DecodeFromSlice<'a>, E: DecodeFromSlice<'a>> DecodeFromSlice<'a> for Result<T, E> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let tag = *bytes.first().ok_or(Error::LengthMismatch)?;
        record_slice_access(bytes, 1);
        match tag {
            0 => {
                let (len, hdr) = read_len_dyn_slice(&bytes[1..])?;
                let start = 1 + hdr;
                let end = start.checked_add(len).ok_or(Error::LengthMismatch)?;
                if end > bytes.len() {
                    return Err(Error::LengthMismatch);
                }
                let _depth = DecodeDepthGuard::enter()?;
                let (val, used) = T::decode_from_slice(&bytes[start..end])?;
                record_slice_access(bytes, end);
                if used != len {
                    return Err(Error::LengthMismatch);
                }
                Ok((Ok(val), end))
            }
            1 => {
                let (len, hdr) = read_len_dyn_slice(&bytes[1..])?;
                let start = 1 + hdr;
                let end = start.checked_add(len).ok_or(Error::LengthMismatch)?;
                if end > bytes.len() {
                    return Err(Error::LengthMismatch);
                }
                let _depth = DecodeDepthGuard::enter()?;
                let (err, used) = E::decode_from_slice(&bytes[start..end])?;
                record_slice_access(bytes, end);
                if used != len {
                    return Err(Error::LengthMismatch);
                }
                Ok((Err(err), end))
            }
            _ => Err(Error::Message("invalid result tag".into())),
        }
    }
}
impl<'a> DecodeFromSlice<'a> for Box<str> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        String::decode_from_slice(bytes).map(|(s, used)| (s.into_boxed_str(), used))
    }
}
impl<'a> DecodeFromSlice<'a> for Cow<'a, str> {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        <&'a str as DecodeFromSlice>::decode_from_slice(bytes)
            .map(|(s, used)| (Cow::Borrowed(s), used))
    }
}
/// Magic bytes that identify a Norito archive.
pub const MAGIC: [u8; 4] = *b"NRT0";
/// Current major version of the format.
pub const VERSION_MAJOR: u8 = 0;
/// Empty V1 layout-flag set, used by fixtures that intentionally disable all
/// optional layouts.
pub const V1_LAYOUT_FLAGS: u8 = 0;
/// Current minor version of the format.
///
/// This stays `0` for v1. Header flags carry all active layout selections for a
/// payload, including the compact-length default.
pub const VERSION_MINOR: u8 = 0;
/// Compression algorithm used for the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression.
    None = 0,
    /// Zstd compression.
    Zstd = 1,
}
impl Compression {
    fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Zstd),
            v => Err(Error::unsupported_compression(v)),
        }
    }
}
/// Errors returned during serialization and deserialization.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O failure when reading or writing.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Invalid magic bytes.
    #[error("invalid magic header")]
    InvalidMagic,
    /// Unsupported major version in the header.
    #[error("unsupported version {found} (expected {expected})")]
    UnsupportedVersion { found: u8, expected: u8 },
    /// Unsupported minor version.
    #[error("unsupported minor version {found:#04x} (supported mask {supported:#04x})")]
    UnsupportedMinorVersion { found: u8, supported: u8 },
    /// Unknown compression algorithm or unsupported in this build.
    #[error("unsupported compression {found} (supported {supported:?})")]
    UnsupportedCompression {
        found: u8,
        supported: &'static [Compression],
    },
    /// Stored length does not match data size.
    #[error("length mismatch")]
    LengthMismatch,
    /// Archive length exceeds the supported limit for this build.
    #[error("archive length {length} exceeds limit {limit}")]
    ArchiveLengthExceeded { length: u64, limit: u64 },
    /// A decoded sequence declares more elements than the active decode scope permits.
    #[error("sequence length {length} exceeds decode limit {limit}")]
    SequenceLengthExceeded {
        /// Element count declared by the sequence header.
        length: u64,
        /// Maximum element count allowed by the active decode scope.
        limit: u64,
    },
    /// A length-delimited field exceeds its per-field decode limit.
    #[error("field length {length} exceeds decode limit {limit}")]
    FieldLengthExceeded {
        /// Byte length declared by the field header.
        length: u64,
        /// Maximum byte length allowed for one field.
        limit: u64,
    },
    /// Cumulative decoded elements exceed the active decode budget.
    #[error("cumulative element count {attempted} exceeds decode limit {limit}")]
    TotalElementsExceeded {
        /// Cumulative count after the attempted sequence.
        attempted: u64,
        /// Maximum cumulative element count.
        limit: u64,
    },
    /// Cumulative allocation accounting exceeds the active decode budget.
    #[error("cumulative allocation {attempted} bytes exceeds decode limit {limit}")]
    TotalAllocationExceeded {
        /// Cumulative byte count after the attempted allocation.
        attempted: u64,
        /// Maximum cumulative byte count.
        limit: u64,
    },
    /// Original decode-budget refusal with private, non-wire admission provenance.
    #[error(transparent)]
    ScopedDecodeResource(ScopedDecodeResourceError),
    /// A fallible raw allocation failed.
    #[error("failed to allocate {bytes} bytes while decoding")]
    AllocationFailed {
        /// Requested allocation size.
        bytes: u64,
    },
    /// A data-dependent recursive value exceeded the deterministic decode bound.
    #[error("{context} nesting depth {depth} exceeds limit {limit}")]
    NestingDepthExceeded {
        /// Attempted absolute recursive depth.
        depth: usize,
        /// Maximum recursive depth accepted for this value family.
        limit: usize,
        /// Value family whose recursive decoder reached the bound.
        context: &'static str,
    },
    /// Checksum verification failed.
    #[error("checksum mismatch")]
    ChecksumMismatch,
    /// Schema hash does not match expected type.
    #[error("schema mismatch")]
    SchemaMismatch,
    /// Encountered a payload that uses a feature not supported by this build.
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(&'static str),
    /// Missing payload context for pointer-based decode path.
    #[error("missing payload context")]
    MissingPayloadContext,
    /// Layout flags were not provided, so the payload cannot be framed deterministically.
    #[error("missing layout flags")]
    MissingLayoutFlags,
    /// Header layout flags conflict with an active decode-flag guard.
    #[error("decode flags mismatch (header={header_flags:#04x}, active={active_flags:#04x})")]
    DecodeFlagsMismatch { header_flags: u8, active_flags: u8 },
    /// The frame is not the one canonical V1 representation accepted by an exact-encoding boundary.
    #[error("non-canonical encoding")]
    NonCanonicalEncoding,
    /// Invalid UTF-8 in string-like value.
    #[error("invalid utf8")]
    InvalidUtf8,
    /// JSON helper error (only available when the `json` feature is enabled).
    #[cfg(feature = "json")]
    #[error("json error: {0}")]
    Json(#[from] crate::json::Error),
    /// Invalid tag/discriminant during decode (Option/Result/enum).
    #[error("invalid tag {tag} while decoding {context}")]
    InvalidTag { context: &'static str, tag: u8 },
    /// A decoded value failed its fixed semantic validation. This category owns
    /// no dynamic diagnostic and does not alter any serialized wire layout.
    #[error("invalid {context}")]
    InvalidValue {
        /// Statically named value family whose validator rejected the input.
        context: &'static str,
    },
    /// NonZero value decoded as zero.
    #[error("non-zero value expected")]
    InvalidNonZero,
    /// A panic occurred during decode; returned when a decode guard intercepted a panic.
    #[error("panic during decode of {context}")]
    DecodePanic { context: &'static str },
    /// Payload base pointer does not satisfy the required alignment.
    #[error("payload misaligned (requires {align}-byte alignment, addr={addr:#x})")]
    Misaligned { align: usize, addr: usize },
    /// Custom error message.
    #[error("{0}")]
    Message(String),
}
/// Exact decode resource refusal, retained without allocating an error message.
///
/// This copyable value lets an enclosing error preserve the original refusal and
/// reconstruct [`Error`] at a nested codec boundary. It is not a wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeResourceError {
    /// Archive byte length exceeds the admitted limit.
    ArchiveLengthExceeded {
        /// Declared archive byte length.
        length: u64,
        /// Admitted archive byte limit.
        limit: u64,
    },
    /// Sequence element count exceeds the admitted limit.
    SequenceLengthExceeded {
        /// Declared element count.
        length: u64,
        /// Admitted element limit.
        limit: u64,
    },
    /// Field byte length exceeds the admitted limit.
    FieldLengthExceeded {
        /// Declared field byte length.
        length: u64,
        /// Admitted field byte limit.
        limit: u64,
    },
    /// Cumulative decoded elements exceed the admitted budget.
    TotalElementsExceeded {
        /// Attempted cumulative element count.
        attempted: u64,
        /// Admitted cumulative element limit.
        limit: u64,
    },
    /// Cumulative decode allocations exceed the admitted budget.
    TotalAllocationExceeded {
        /// Attempted cumulative allocation bytes.
        attempted: u64,
        /// Admitted cumulative allocation byte limit.
        limit: u64,
    },
    /// An admitted fallible allocation was refused.
    AllocationFailed {
        /// Requested allocation byte length.
        bytes: u64,
    },
    /// Recursive decoding exceeds the admitted depth.
    NestingDepthExceeded {
        /// Attempted absolute recursive depth.
        depth: usize,
        /// Admitted recursive depth limit.
        limit: usize,
        /// Statically named value family.
        context: &'static str,
    },
}

impl From<DecodeResourceError> for Error {
    fn from(error: DecodeResourceError) -> Self {
        match error {
            DecodeResourceError::ArchiveLengthExceeded { length, limit } => {
                Self::ArchiveLengthExceeded { length, limit }
            }
            DecodeResourceError::SequenceLengthExceeded { length, limit } => {
                Self::SequenceLengthExceeded { length, limit }
            }
            DecodeResourceError::FieldLengthExceeded { length, limit } => {
                Self::FieldLengthExceeded { length, limit }
            }
            DecodeResourceError::TotalElementsExceeded { attempted, limit } => {
                Self::TotalElementsExceeded { attempted, limit }
            }
            DecodeResourceError::TotalAllocationExceeded { attempted, limit } => {
                Self::TotalAllocationExceeded { attempted, limit }
            }
            DecodeResourceError::AllocationFailed { bytes } => Self::AllocationFailed { bytes },
            DecodeResourceError::NestingDepthExceeded {
                depth,
                limit,
                context,
            } => Self::NestingDepthExceeded {
                depth,
                limit,
                context,
            },
        }
    }
}

impl std::fmt::Display for DecodeResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&Error::from(*self), f)
    }
}

impl std::error::Error for DecodeResourceError {}

/// Errors returned by [`to_bytes_bounded`].
#[derive(Debug, thiserror::Error)]
pub enum BoundedEncodeError {
    /// The real counting pass exceeded the caller's complete frame budget.
    #[error("encoded frame requires {encoded_bytes} bytes but the limit is {max_bytes} bytes")]
    FrameTooLarge {
        /// Exact canonical frame length produced by the counting pass.
        encoded_bytes: usize,
        /// Maximum complete frame length accepted by the caller.
        max_bytes: usize,
    },
    /// Reserving the admitted complete frame failed.
    #[error("failed to reserve {bytes} bytes for bounded Norito encoding")]
    AllocationFailed {
        /// Complete frame allocation that was attempted.
        bytes: usize,
    },
    /// Canonical serialization failed or disagreed with its counting pass.
    #[error(transparent)]
    Serialization(#[from] Error),
}
impl Error {
    /// Return whether this error represents a terminal decode resource boundary.
    ///
    /// A caller must treat these failures as terminal rather than attempting
    /// more allocation or structural work after a budget rejected the input.
    #[doc(hidden)]
    #[must_use]
    pub const fn is_decode_resource_limit(&self) -> bool {
        self.decode_resource_error().is_some()
    }

    /// Copy the exact resource refusal without formatting or allocating.
    #[must_use]
    pub const fn decode_resource_error(&self) -> Option<DecodeResourceError> {
        Some(match *self {
            Self::ArchiveLengthExceeded { length, limit } => {
                DecodeResourceError::ArchiveLengthExceeded { length, limit }
            }
            Self::SequenceLengthExceeded { length, limit } => {
                DecodeResourceError::SequenceLengthExceeded { length, limit }
            }
            Self::FieldLengthExceeded { length, limit } => {
                DecodeResourceError::FieldLengthExceeded { length, limit }
            }
            Self::TotalElementsExceeded { attempted, limit } => {
                DecodeResourceError::TotalElementsExceeded { attempted, limit }
            }
            Self::TotalAllocationExceeded { attempted, limit } => {
                DecodeResourceError::TotalAllocationExceeded { attempted, limit }
            }
            Self::ScopedDecodeResource(ref origin) => origin.resource(),
            Self::AllocationFailed { bytes } => DecodeResourceError::AllocationFailed { bytes },
            Self::NestingDepthExceeded {
                depth,
                limit,
                context,
            } => DecodeResourceError::NestingDepthExceeded {
                depth,
                limit,
                context,
            },
            _ => return None,
        })
    }
}
impl From<String> for Error {
    fn from(msg: String) -> Self {
        Self::Message(msg)
    }
}
impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        msg.to_owned().into()
    }
}
impl Error {
    /// Construct a detailed length mismatch error while preserving the canonical variant.
    pub fn length_mismatch_detail(
        context: &'static str,
        offset: usize,
        required: usize,
        available: usize,
    ) -> Self {
        Self::Message(format!(
            "{context}: need {required} bytes at offset {offset}, but only {available} remain"
        ))
    }
    /// Construct an invalid tag error with contextual information.
    pub fn invalid_tag(context: &'static str, tag: u8) -> Self {
        Self::InvalidTag { context, tag }
    }
    /// Construct a decode panic error annotated with the type being decoded.
    pub fn decode_panic(context: &'static str) -> Self {
        Self::DecodePanic { context }
    }
    /// Construct a misalignment error including the offending address.
    pub fn misaligned(align: usize, addr: *const u8) -> Self {
        Self::Misaligned {
            align,
            addr: addr as usize,
        }
    }
    fn supported_compressions() -> &'static [Compression] {
        #[cfg(feature = "compression")]
        {
            const SUPPORTED: &[Compression] = &[Compression::None, Compression::Zstd];
            SUPPORTED
        }
        #[cfg(not(feature = "compression"))]
        {
            const SUPPORTED: &[Compression] = &[Compression::None];
            SUPPORTED
        }
    }
    /// Construct an unsupported compression error using the default supported set.
    pub fn unsupported_compression(found: u8) -> Self {
        Self::UnsupportedCompression {
            found,
            supported: Self::supported_compressions(),
        }
    }
    /// Construct an unsupported compression error with an explicit supported list.
    pub fn unsupported_compression_with(found: u8, supported: &'static [Compression]) -> Self {
        Self::UnsupportedCompression { found, supported }
    }
}
/// Metadata header that prefixes every archive.
///
/// All serialized objects start with this structure.  It allows the
/// deserializer to validate the data before interpreting the payload.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// Magic bytes for detection.
    pub magic: [u8; 4],
    /// Major format version.
    pub major: u8,
    /// Minor format version.
    pub minor: u8,
    /// Schema hash of serialized type.
    pub schema: [u8; 16],
    /// Compression algorithm used for the payload.
    pub compression: Compression,
    /// Uncompressed payload length.
    pub length: u64,
    /// CRC64 checksum of the payload.
    pub checksum: u64,
    /// Feature flags (stored in the final padding byte).
    pub flags: u8,
}
impl Header {
    /// Size of the serialized header in bytes.
    ///
    /// All fields add up to 40 bytes. We include a single padding byte at the end so that future
    /// extensions can reuse it without shifting the payload layout.
    pub const SIZE: usize = 4 + 1 + 1 + 16 + 1 + 8 + 8 + 1;
}
#[inline]
const fn payload_alignment_padding_for_align(align: usize) -> usize {
    if align <= 1 {
        return 0;
    }
    let remainder = Header::SIZE % align;
    if remainder == 0 { 0 } else { align - remainder }
}
#[inline]
pub(crate) fn payload_alignment_padding_for<T>() -> usize {
    payload_alignment_padding_for_align(archived_payload_align::<T>())
}
impl Default for Header {
    fn default() -> Self {
        Self::new([0; 16], 0, 0)
    }
}
impl Header {
    /// Create a new header with provided fields.
    ///
    /// This helper sets the magic bytes and current version while allowing the
    /// caller to specify the schema hash, payload length and checksum.
    pub fn new(schema: [u8; 16], length: u64, checksum: u64) -> Self {
        Self {
            magic: MAGIC,
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            schema,
            compression: Compression::None,
            length,
            checksum,
            flags: 0,
        }
    }
    /// Write the header to the given writer.
    fn write(&self, mut w: impl Write) -> Result<(), Error> {
        validate_header_flags(self.flags)?;
        w.write_all(&self.magic)?;
        w.write_all(&[self.major])?;
        w.write_all(&[self.minor])?;
        w.write_all(&self.schema)?;
        w.write_all(&[self.compression as u8])?;
        w.write_all(&self.length.to_le_bytes())?;
        w.write_all(&self.checksum.to_le_bytes())?;
        w.write_all(&[self.flags])?; // flags in padding byte
        Ok(())
    }
    /// Read and validate one fixed-size Norito archive header.
    ///
    /// # Errors
    ///
    /// Returns an archive-header error when the magic, version, compression,
    /// feature flags, or fixed-width fields are invalid or incomplete.
    pub fn read(mut r: impl Read) -> Result<Self, Error> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        let major = r.read_u8()?;
        if major != VERSION_MAJOR {
            return Err(Error::UnsupportedVersion {
                found: major,
                expected: VERSION_MAJOR,
            });
        }
        let minor = r.read_u8()?;
        if minor != VERSION_MINOR {
            return Err(Error::UnsupportedMinorVersion {
                found: minor,
                supported: VERSION_MINOR,
            });
        }
        let mut schema = [0u8; 16];
        r.read_exact(&mut schema)?;
        let compression = Compression::from_u8(r.read_u8()?)?;
        let length = r.read_u64::<LittleEndian>()?;
        let checksum = r.read_u64::<LittleEndian>()?;
        let mut pad = [0u8; 1];
        r.read_exact(&mut pad)?;
        let flags = pad[0];
        validate_header_flags(flags)?;
        Ok(Self {
            magic,
            major,
            minor,
            schema,
            compression,
            length,
            checksum,
            flags,
        })
    }
}
/// Typed frame serialization with one declared protocol identity.
///
/// Implement [`SerializePayload`] for bytes and [`crate::NoritoSchema`] for
/// identity. The blanket implementation makes that pair the sole framing
/// contract; [`crate::schema::identity::frame_hash`] selects the header digest.
/// Erased field writers use [`SerializePayload`] directly.
pub trait NoritoSerialize: SerializePayload + crate::NoritoSchema {}

impl<T: SerializePayload + crate::NoritoSchema + ?Sized> NoritoSerialize for T {}
/// Object-safe serialization of bare Norito payloads.
///
/// This contract owns bytes and encoded-size hints. It carries no root-frame
/// identity; borrowed field views and erased writers use it directly.
/// Use [`NoritoSerialize`] for a type that can be written as a typed frame.
/// A payload-only derived struct supports bare encoding:
///
/// ```
/// #[derive(norito::SerializePayload)]
/// struct Field<T>(T);
/// struct Leaf(u32);
/// impl norito::SerializePayload for Leaf {
///     fn serialize(
///         &self,
///         writer: &mut norito::core::Encoder<'_>,
///     ) -> Result<(), norito::Error> {
///         norito::SerializePayload::serialize(&self.0, writer)
///     }
/// }
/// let payload = norito::codec::Encode::encode(&Field(Leaf(7)));
/// assert!(!payload.is_empty());
/// ```
///
/// Frame identities belong to `NoritoSchema`; the old codec attribute is rejected:
///
/// ```compile_fail
/// #[derive(norito::SerializePayload)]
/// #[norito(schema_name = "example.Field")]
/// struct Field(u32);
/// ```
///
/// Payload derives support structs and enums, and reject unions:
///
/// ```compile_fail
/// #[derive(norito::SerializePayload)]
/// union Field {
///     value: u32,
/// }
/// ```
///
/// A payload-only derive cannot enter a typed frame:
///
/// ```compile_fail
/// #[derive(norito::SerializePayload)]
/// struct Field(u32);
/// let _ = norito::to_bytes(&Field(7));
/// ```
pub trait SerializePayload {
    /// Serialize `self` into the encoder.
    fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), Error>;
    /// Optional hint: estimated encoded byte length for `self`.
    ///
    /// Implementations should return `Some(len)` when the exact or a tight upper-bound length is
    /// cheap to compute, otherwise return `None`. Canonical encoders do not trust this value for
    /// framing, admission, or allocation; callers may use it only as a diagnostic estimate.
    fn encoded_len_hint(&self) -> Option<usize> {
        None
    }
    /// Exact encoded length for this value, if cheaply computable.
    ///
    /// Returns the exact number of bytes that `serialize()` will write for the archived payload
    /// (excluding the outer Norito header). Implementations should avoid expensive work; return
    /// `None` when exact sizing is not readily available.
    fn encoded_len_exact(&self) -> Option<usize> {
        None
    }
}
/// Serialize a value into an arbitrary writer after erasing its concrete type.
///
/// This is intended for codec internals and generated implementations. Normal
/// callers should use the framed encoding helpers such as [`to_bytes`].
#[doc(hidden)]
pub fn serialize_to_writer(
    value: &dyn SerializePayload,
    writer: &mut dyn Write,
) -> Result<(), Error> {
    let mut encoder = Encoder::new(writer);
    value.serialize(&mut encoder)
}
/// Serialize a value directly and reject a mismatch with its counted length.
///
/// This is a codec-internal seam used by counted length-prefixed writers (`write_counted_payload`).
/// Callers count the payload first and emit its length, then use this helper to ensure a stateful
/// serializer cannot invalidate the emitted length without retaining a second payload-sized buffer.
/// A write beyond `expected_len` is rejected before it reaches `writer`; a shorter successful pass
/// is rejected by the final equality check.
#[doc(hidden)]
pub fn serialize_to_writer_exact<W: Write>(
    value: &dyn SerializePayload,
    writer: &mut W,
    expected_len: usize,
) -> Result<(), Error> {
    let mut exact = ExactLengthWriter::new(writer, expected_len);
    let result = serialize_to_writer(value, &mut exact);
    if exact.rejected_write() {
        return Err(Error::LengthMismatch);
    }
    result?;
    (exact.written_len() == expected_len)
        .then_some(())
        .ok_or(Error::LengthMismatch)
}
// Call only after this codec path has measured this same value. The public
// serialize_to_writer_exact seam deliberately always validates actual bytes:
// its caller-supplied expected_len is not evidence for a counting destination.
fn write_counted_payload(
    value: &dyn SerializePayload,
    writer: &mut Encoder<'_>,
    measured_len: usize,
) -> Result<(), Error> {
    if writer.count_measured_bytes(measured_len)? {
        Ok(())
    } else {
        writer.with_exact_length(measured_len, |writer| value.serialize(writer))
    }
}
/// Serialize a value by appending directly to a byte vector.
///
/// This is the buffer-specialized counterpart to [`serialize_to_writer`] used
/// by generated length-delimited field encoders.
#[doc(hidden)]
pub fn serialize_to_buffer(
    value: &dyn SerializePayload,
    buffer: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut encoder = Encoder::for_buffer(buffer);
    value.serialize(&mut encoder)
}
/// Typed frame decoding contract.
///
/// Framed readers validate this identity before invoking payload reconstruction.
/// Bare fields implement [`DeserializePayload`] without a frame identity.
pub trait NoritoDeserialize<'a>: DeserializePayload<'a> + crate::NoritoSchema {}

impl<'a, T: DeserializePayload<'a> + crate::NoritoSchema> NoritoDeserialize<'a> for T {}

/// Reconstruct a value from its bounded archived payload, without a frame identity.
///
/// The archived reference is an address marker into the active payload context;
/// it is never a reference to a reconstructed Rust value. Fallible implementations
/// must reject invalid fields and preserve the active resource limits.
///
/// A payload implementation alone cannot be used as a typed frame decoder:
///
/// ```compile_fail
/// #[derive(norito::SerializePayload, norito::DeserializePayload)]
/// struct Field(u32);
/// let _ = norito::core::from_bytes::<Field>(&[]);
/// ```
///
/// This restriction also applies through collections:
///
/// ```compile_fail
/// #[derive(norito::SerializePayload, norito::DeserializePayload)]
/// struct Field(u32);
/// let _ = norito::core::from_bytes::<Vec<Field>>(&[]);
/// ```
pub trait DeserializePayload<'a>: Sized {
    /// Reconstruct a valid value, panicking if a fallible decoder rejects it.
    /// Prefer [`Self::try_deserialize`] for untrusted input.
    fn deserialize(archived: &'a Archived<Self>) -> Self;

    /// Reconstruct a value while preserving typed validation failures.
    ///
    /// Infallible implementations may inherit this default. Implementations
    /// that can reject input must override it instead of relying on a panic.
    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, Error> {
        Ok(Self::deserialize(archived))
    }
}
/// Opaque address marker for the archived bytes of `T`.
///
/// This type deliberately does not contain a `T`. Archived payload bytes are wire data and may not
/// be a valid in-memory Rust value (for example, before a fallible decoder validates a niche or
/// enum tag). Decoders use this marker's address together with the active payload context; they
/// must not treat the marker itself as a reconstructed `T`.
#[repr(C)]
pub struct Archived<T: ?Sized> {
    _marker: PhantomData<T>,
}
#[inline]
fn empty_archived_ptr<T: ?Sized>() -> *const Archived<T> {
    core::ptr::NonNull::<Archived<T>>::dangling().as_ptr()
}
#[inline]
pub(crate) fn empty_archived_marker<'a, T: ?Sized>() -> &'a Archived<T> {
    // SAFETY: every `Archived<_>` is the same zero-sized, byte-aligned marker,
    // so the non-null aligned dangling pointer is a valid ZST reference. The
    // unconstrained lifetime is sound because no borrowed `T` is stored.
    unsafe { &*empty_archived_ptr::<T>() }
}
/// Return the logical archived-storage footprint associated with `T`.
///
/// This is intentionally separate from `size_of::<Archived<T>>()`: an
/// [`Archived`] value is only an address marker, while payload allocation and
/// framing still use the wire type's established storage footprint.
#[inline]
pub const fn archived_payload_size<T>() -> usize {
    core::mem::size_of::<T>()
}
/// Return the archived payload alignment associated with `T`.
///
/// The marker itself has byte alignment. Framing and temporary-storage code
/// must use this function when preserving the canonical payload layout.
#[inline]
pub const fn archived_payload_align<T>() -> usize {
    core::mem::align_of::<T>()
}
#[inline]
fn try_read_archived_bytes<T: ?Sized, const N: usize>(
    archived: &Archived<T>,
) -> Result<[u8; N], Error> {
    let ptr = core::ptr::from_ref(archived).cast::<u8>();
    let payload = payload_range_from_ptr(ptr, N)?;
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(payload);
    Ok(bytes)
}
#[inline]
fn read_archived_bytes<T: ?Sized, const N: usize>(archived: &Archived<T>) -> [u8; N] {
    try_read_archived_bytes(archived).expect("archived scalar footprint")
}
impl<T: ?Sized> Archived<T> {
    /// Retag this archived-byte address for another decoder.
    ///
    /// Every `Archived<_>` is the same opaque zero-sized address marker, so this
    /// operation does not reinterpret a Rust `T` as a Rust `U`. The target
    /// decoder remains responsible for validating the wire bytes at the
    /// marker's address against its own schema and payload bounds.
    #[allow(unsafe_code)]
    pub fn cast<U>(&self) -> &Archived<U> {
        // SAFETY: `Archived<T>` and `Archived<U>` are both zero-sized,
        // byte-aligned markers; changing the phantom type preserves the
        // reference's layout and address.
        unsafe { &*core::ptr::from_ref(self).cast::<Archived<U>>() }
    }
}
enum ArchivedBacking<'a> {
    Borrowed(&'a [u8]),
    Owned(ArchiveSlice),
}
/// Owned or borrowed handle to an archived value reconstructed from a byte slice. When the input
/// slice is misaligned for `T` the bytes are copied into an internal buffer with suitable alignment
/// for decoders that perform aligned payload reads.
pub struct ArchivedRef<'a, T: ?Sized> {
    ptr: *const Archived<T>,
    backing: ArchivedBacking<'a>,
    _marker: PhantomData<&'a Archived<T>>,
}
impl<'a, T: ?Sized> ArchivedRef<'a, T> {
    #[inline]
    #[allow(unsafe_code)]
    fn as_ref_impl(&self) -> &Archived<T> {
        // SAFETY: `ptr` is non-null and byte-aligned. The marker is zero-sized,
        // and the corresponding payload backing outlives this reference.
        unsafe { &*self.ptr }
    }
    /// Return the typed marker at the start of the archived payload.
    ///
    /// The marker does not contain a `T`. Callers of [`archived_from_slice`] must install a payload
    /// context for [`Self::bytes`] before invoking a decoder.
    #[inline]
    pub fn archived(&self) -> &Archived<T> {
        self.as_ref_impl()
    }
    /// Underlying byte slice backing the archived value.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match &self.backing {
            ArchivedBacking::Borrowed(bytes) => bytes,
            ArchivedBacking::Owned(slice) => slice.as_slice(),
        }
    }
    /// Retag the payload-start marker for a different decoder.
    ///
    /// This preserves only the marker address; it neither validates the bytes
    /// nor grants the target decoder access beyond [`Self::bytes`].
    #[inline]
    pub fn cast<U>(&self) -> &Archived<U> {
        self.archived().cast::<U>()
    }
}
impl<'a, T: ?Sized> std::convert::AsRef<Archived<T>> for ArchivedRef<'a, T> {
    #[inline]
    fn as_ref(&self) -> &Archived<T> {
        self.as_ref_impl()
    }
}
impl<'a, T: ?Sized> std::ops::Deref for ArchivedRef<'a, T> {
    type Target = Archived<T>;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref_impl()
    }
}
/// Owned archived payload backed by an aligned byte buffer.
///
/// This owns the payload bytes (plus any alignment padding) and guarantees the
/// archived pointer stays valid for the lifetime of the wrapper.
pub struct ArchivedBox<T> {
    buffer: Vec<u8>,
    offset: usize,
    len: usize,
    _marker: PhantomData<Archived<T>>,
}
impl<T> ArchivedBox<T> {
    #[inline]
    pub(crate) fn from_payload(payload: Vec<u8>) -> Self {
        let len = payload.len();
        let align = archived_payload_align::<T>();
        if len == 0 || align <= 1 {
            return Self {
                buffer: payload,
                offset: 0,
                len,
                _marker: PhantomData,
            };
        }
        let base = payload.as_ptr() as usize;
        if base.is_multiple_of(align) {
            return Self {
                buffer: payload,
                offset: 0,
                len,
                _marker: PhantomData,
            };
        }
        let mut buffer = vec![0u8; len + align];
        let buf_base = buffer.as_ptr() as usize;
        let offset = (align - (buf_base % align)) % align;
        buffer[offset..offset + len].copy_from_slice(&payload);
        Self {
            buffer,
            offset,
            len,
            _marker: PhantomData,
        }
    }
    /// Return the typed marker at the start of the owned archived payload.
    ///
    /// The marker does not contain a `T`. Decoding is valid only while a
    /// payload context covering [`Self::bytes`] is active.
    #[inline]
    pub fn archived(&self) -> &Archived<T> {
        if self.len == 0 {
            // SAFETY: the dangling pointer is valid for the zero-sized marker;
            // the payload context prevents a decoder from reading any bytes.
            return unsafe { &*empty_archived_ptr::<T>() };
        }
        let ptr = unsafe { self.buffer.as_ptr().add(self.offset) as *const Archived<T> };
        // SAFETY: `ptr` points into live payload storage. The zero-sized marker
        // itself has no storage-alignment requirement.
        unsafe { &*ptr }
    }
    /// Underlying archived bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        &self.buffer[self.offset..self.offset + self.len]
    }
}
impl<T> std::convert::AsRef<Archived<T>> for ArchivedBox<T> {
    #[inline]
    fn as_ref(&self) -> &Archived<T> {
        self.archived()
    }
}
impl<T> std::ops::Deref for ArchivedBox<T> {
    type Target = Archived<T>;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.archived()
    }
}
/// Decode an already length-bounded archived field from owned aligned storage.
///
/// This is an implementation detail shared by generated deserializers. It intentionally performs
/// neither canonical-length validation nor legacy framing fallback: callers retain responsibility
/// for those policies. The owned copy also keeps nested payload-context accounting isolated in the
/// same way as the historical derive-generated allocation path.
#[doc(hidden)]
#[inline(never)]
pub fn decode_archived_field<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: for<'de> DeserializePayload<'de>,
{
    let logical_len = bytes.len();
    let min_size = archived_payload_size::<T>();
    let mut padded = Vec::new();
    let decode_bytes = if logical_len < min_size {
        reserve_decode_allocation(min_size)?;
        padded
            .try_reserve_exact(min_size)
            .map_err(|_| Error::AllocationFailed {
                bytes: u64::try_from(min_size).unwrap_or(u64::MAX),
            })?;
        padded.extend_from_slice(bytes);
        padded.resize(min_size, 0);
        padded.as_slice()
    } else {
        bytes
    };
    let archived = ArchiveSlice::new_owned(decode_bytes, archived_payload_align::<T>())?;
    let archived_bytes = archived.as_slice();
    let _payload_guard = PayloadCtxGuard::enter_with_len(archived_bytes, logical_len);
    let archived_ptr = if archived_bytes.is_empty() {
        empty_archived_ptr::<T>()
    } else {
        archived_bytes.as_ptr().cast::<Archived<T>>()
    };
    // SAFETY: `ArchiveSlice::new_owned` keeps the payload allocation alive for
    // this entire deserialization call.
    crate::guarded_try_deserialize(|| T::try_deserialize(unsafe { &*archived_ptr }))
}
/// Interpret `bytes` as an archived value and ensure the slice is large enough.
///
/// This validates the archived footprint and produces suitably aligned backing
/// storage. Payload structure and offsets are validated by the subsequent
/// fallible [`DeserializePayload::try_deserialize`] call.
///
/// # Errors
///
/// Returns an error if `bytes` is shorter than the minimum archived header for
/// `T` or if a misaligned payload cannot be copied into aligned storage.
#[inline]
pub fn archived_from_slice<'a, T>(bytes: &'a [u8]) -> Result<ArchivedRef<'a, T>, Error> {
    let min = archived_payload_size::<T>();
    if min > 0 && bytes.len() < min {
        return Err(Error::LengthMismatch);
    }
    let align_target = archived_payload_align::<T>();
    let ptr_usize = bytes.as_ptr() as usize;
    let needs_copy =
        align_target > 1 && !bytes.is_empty() && !ptr_usize.is_multiple_of(align_target);
    if needs_copy {
        let slice = ArchiveSlice::new(bytes, align_target)?;
        let ptr = slice.as_slice().as_ptr() as *const Archived<T>;
        Ok(ArchivedRef {
            ptr,
            backing: ArchivedBacking::Owned(slice),
            _marker: PhantomData,
        })
    } else {
        let ptr = if bytes.is_empty() {
            empty_archived_ptr::<T>()
        } else {
            bytes.as_ptr() as *const Archived<T>
        };
        Ok(ArchivedRef {
            ptr,
            backing: ArchivedBacking::Borrowed(bytes),
            _marker: PhantomData,
        })
    }
}

/// Prepared backing storage for derive-generated slice decoders.
///
/// This centralizes short-payload padding and alignment handling so derive
/// expansions only contain their type-specific field reconstruction.
#[doc(hidden)]
pub struct PreparedDecodeSlice<'a> {
    archive: ArchiveSlice,
    _padded: Option<Vec<u8>>,
    logical_len: usize,
    _borrow: PhantomData<&'a [u8]>,
}

impl PreparedDecodeSlice<'_> {
    /// Return the logical length of the caller-provided payload.
    #[doc(hidden)]
    #[inline]
    pub fn logical_len(&self) -> usize {
        self.logical_len
    }

    /// Return the aligned, possibly zero-padded payload bytes.
    #[doc(hidden)]
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        self.archive.as_slice()
    }

    /// Return an archived marker at the start of the prepared payload.
    #[doc(hidden)]
    #[inline]
    #[allow(unsafe_code)]
    pub fn archived<T>(&self) -> &Archived<T> {
        if self.archive.as_slice().is_empty() {
            return empty_archived_marker();
        }
        // SAFETY: `archive` owns or borrows live aligned storage for the
        // lifetime of `self`; `Archived<T>` is an opaque zero-sized marker.
        unsafe { &*self.archive.as_slice().as_ptr().cast::<Archived<T>>() }
    }
}

/// Prepare one derive-generated archived payload without specializing the
/// padding and alignment machinery for every decoded type.
#[doc(hidden)]
#[inline(never)]
pub fn prepare_decode_from_slice(
    bytes: &[u8],
    minimum_size: usize,
    alignment: usize,
) -> Result<PreparedDecodeSlice<'_>, Error> {
    let logical_len = bytes.len();
    if minimum_size > 0 && logical_len == 0 {
        return Err(Error::LengthMismatch);
    }

    let padded = if minimum_size > 0 && logical_len < minimum_size {
        let mut padded = Vec::with_capacity(minimum_size);
        padded.extend_from_slice(bytes);
        padded.resize(minimum_size, 0);
        Some(padded)
    } else {
        None
    };
    let decode_bytes = padded.as_deref().unwrap_or(bytes);
    let archive = ArchiveSlice::new(decode_bytes, alignment)?;
    Ok(PreparedDecodeSlice {
        archive,
        _padded: padded,
        logical_len,
        _borrow: PhantomData,
    })
}

/// Decode a prepared prefix through its layout-aware payload implementation.
///
/// Generated named-record decoders report their consumed offset through
/// [`finish_context_fields`]. A fresh prefix context permits trailing caller
/// bytes while retaining that exact offset, including a valid zero-byte value.
/// Nested fields retain their canonical boundaries and the caller's resource
/// budgets. This boundary does not require a serializer or frame identity.
#[doc(hidden)]
#[inline]
pub fn decode_prepared_slice_prefix<'de, T>(
    prepared: &'de PreparedDecodeSlice<'_>,
) -> Result<(T, usize), Error>
where
    T: DeserializePayload<'de> + 'de,
{
    let _flags = enter_field_codec_flags();
    let _payload = PayloadCtxGuard::enter_with_len(prepared.bytes(), prepared.logical_len());
    let _boundary = FieldDecodeBoundaryGuard::enter(FieldDecodeBoundary::Prefix);
    let value = T::try_deserialize(prepared.archived::<T>())?;
    let used = payload_ctx_max_access().ok_or(Error::MissingPayloadContext)?;
    if used > prepared.logical_len() {
        return Err(Error::LengthMismatch);
    }
    Ok((value, used))
}

impl SerializePayload for u8 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[*self])?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(1)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(1)
    }
}

impl<'a> DeserializePayload<'a> for u8 {
    fn deserialize(archived: &'a Archived<u8>) -> Self {
        read_archived_bytes::<_, 1>(archived)[0]
    }
    fn try_deserialize(archived: &'a Archived<u8>) -> Result<Self, Error> {
        byte_sequence::read_byte_value(&try_read_archived_bytes::<_, 1>(archived)?)
    }
}

impl SerializePayload for i8 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[*self as u8])?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(1)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(1)
    }
}

impl<'a> DeserializePayload<'a> for i8 {
    fn deserialize(archived: &'a Archived<i8>) -> Self {
        i8::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<i8>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(i8::from_le_bytes)
    }
}

impl SerializePayload for u16 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(2)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(2)
    }
}

impl<'a> DeserializePayload<'a> for u16 {
    fn deserialize(archived: &'a Archived<u16>) -> Self {
        u16::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<u16>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(u16::from_le_bytes)
    }
}

impl SerializePayload for NonZeroU16 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.get().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.get().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.get().encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for NonZeroU16 {
    fn deserialize(archived: &'a Archived<NonZeroU16>) -> Self {
        let val_arch: &Archived<u16> = archived.cast();
        let value = <u16 as DeserializePayload>::deserialize(val_arch);
        NonZeroU16::new(value).expect("non-zero")
    }
    fn try_deserialize(archived: &'a Archived<NonZeroU16>) -> Result<Self, Error> {
        let val_arch: &Archived<u16> = archived.cast();
        let value = <u16 as DeserializePayload>::try_deserialize(val_arch)?;
        NonZeroU16::new(value).ok_or(Error::InvalidNonZero)
    }
}

impl SerializePayload for i16 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(2)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(2)
    }
}

impl<'a> DeserializePayload<'a> for i16 {
    fn deserialize(archived: &'a Archived<i16>) -> Self {
        i16::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<i16>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(i16::from_le_bytes)
    }
}

impl SerializePayload for u32 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(4)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(4)
    }
}

impl<'a> DeserializePayload<'a> for u32 {
    fn deserialize(archived: &'a Archived<u32>) -> Self {
        u32::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<u32>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(u32::from_le_bytes)
    }
}

impl SerializePayload for NonZeroU32 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.get().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.get().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.get().encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for NonZeroU32 {
    fn deserialize(archived: &'a Archived<NonZeroU32>) -> Self {
        let val_arch: &Archived<u32> = archived.cast();
        let value = <u32 as DeserializePayload>::deserialize(val_arch);
        NonZeroU32::new(value).expect("non-zero")
    }
    fn try_deserialize(archived: &'a Archived<NonZeroU32>) -> Result<Self, Error> {
        let val_arch: &Archived<u32> = archived.cast();
        let value = <u32 as DeserializePayload>::try_deserialize(val_arch)?;
        NonZeroU32::new(value).ok_or(Error::InvalidNonZero)
    }
}

impl SerializePayload for bool {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[*self as u8])?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(1)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(1)
    }
}

impl<'a> DeserializePayload<'a> for bool {
    fn deserialize(archived: &'a Archived<bool>) -> Self {
        Self::try_deserialize(archived).expect("invalid bool")
    }
    fn try_deserialize(archived: &'a Archived<bool>) -> Result<Self, Error> {
        match <u8 as DeserializePayload>::try_deserialize(archived.cast())? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(Error::invalid_tag("bool", tag)),
        }
    }
}

impl SerializePayload for char {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&(*self as u32).to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(4)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(4)
    }
}

impl<'a> DeserializePayload<'a> for char {
    fn deserialize(archived: &'a Archived<char>) -> Self {
        let v = <u32 as DeserializePayload>::deserialize(archived.cast());
        char::from_u32(v).expect("invalid char")
    }
    fn try_deserialize(archived: &'a Archived<char>) -> Result<Self, Error> {
        let value = <u32 as DeserializePayload>::try_deserialize(archived.cast())?;
        char::from_u32(value)
            .ok_or_else(|| Error::Message(format!("invalid Unicode scalar value {value:#x}")))
    }
}

impl SerializePayload for () {
    fn serialize(&self, _encoder: &mut Encoder<'_>) -> Result<(), Error> {
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(0)
    }
}

impl<'a> DeserializePayload<'a> for () {
    fn deserialize(_archived: &'a Archived<()>) -> Self {
        // unit type has no data
    }
}

impl<T> SerializePayload for PhantomData<T> {
    fn serialize(&self, _encoder: &mut Encoder<'_>) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, T> DeserializePayload<'a> for PhantomData<T> {
    fn deserialize(_archived: &'a Archived<PhantomData<T>>) -> Self {
        PhantomData
    }
}
impl<'a, T> DecodeFromSlice<'a> for PhantomData<T> {
    fn decode_from_slice(_bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        Ok((PhantomData, 0))
    }
}

impl SerializePayload for i32 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(4)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(4)
    }
}

impl<'a> DeserializePayload<'a> for i32 {
    fn deserialize(archived: &'a Archived<i32>) -> Self {
        i32::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<i32>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(i32::from_le_bytes)
    }
}

impl SerializePayload for u64 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(8)
    }
}

impl<'a> DeserializePayload<'a> for u64 {
    fn deserialize(archived: &'a Archived<u64>) -> Self {
        u64::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<u64>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(u64::from_le_bytes)
    }
}

impl SerializePayload for NonZeroU64 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.get().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.get().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.get().encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for NonZeroU64 {
    fn deserialize(archived: &'a Archived<NonZeroU64>) -> Self {
        let val_arch: &Archived<u64> = archived.cast();
        let value = <u64 as DeserializePayload>::deserialize(val_arch);
        NonZeroU64::new(value).expect("non-zero")
    }
    fn try_deserialize(archived: &'a Archived<NonZeroU64>) -> Result<Self, Error> {
        let val_arch: &Archived<u64> = archived.cast();
        let value = <u64 as DeserializePayload>::try_deserialize(val_arch)?;
        NonZeroU64::new(value).ok_or(Error::InvalidNonZero)
    }
}

impl SerializePayload for i64 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(8)
    }
}

impl<'a> DeserializePayload<'a> for i64 {
    fn deserialize(archived: &'a Archived<i64>) -> Self {
        i64::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<i64>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(i64::from_le_bytes)
    }
}

impl SerializePayload for usize {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&(*self as u64).to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(8)
    }
}

impl<'a> DeserializePayload<'a> for usize {
    fn deserialize(archived: &'a Archived<usize>) -> Self {
        Self::try_deserialize(archived).expect("archived usize does not fit this target")
    }
    fn try_deserialize(archived: &'a Archived<usize>) -> Result<Self, Error> {
        let value = u64::from_le_bytes(try_read_archived_bytes(archived)?);
        usize::try_from(value).map_err(|_| Error::LengthMismatch)
    }
}

impl SerializePayload for isize {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&(*self as i64).to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(8)
    }
}

impl<'a> DeserializePayload<'a> for isize {
    fn deserialize(archived: &'a Archived<isize>) -> Self {
        Self::try_deserialize(archived).expect("archived isize does not fit this target")
    }
    fn try_deserialize(archived: &'a Archived<isize>) -> Result<Self, Error> {
        let value = i64::from_le_bytes(try_read_archived_bytes(archived)?);
        isize::try_from(value).map_err(|_| Error::LengthMismatch)
    }
}

impl SerializePayload for u128 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(16)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(16)
    }
}

impl<'a> DeserializePayload<'a> for u128 {
    fn deserialize(archived: &'a Archived<u128>) -> Self {
        u128::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<u128>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(u128::from_le_bytes)
    }
}

impl SerializePayload for i128 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(16)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(16)
    }
}

impl<'a> DeserializePayload<'a> for i128 {
    fn deserialize(archived: &'a Archived<i128>) -> Self {
        i128::from_le_bytes(read_archived_bytes(archived))
    }
    fn try_deserialize(archived: &'a Archived<i128>) -> Result<Self, Error> {
        try_read_archived_bytes(archived).map(i128::from_le_bytes)
    }
}

impl SerializePayload for f32 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_bits().to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(4)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(4)
    }
}

impl<'a> DeserializePayload<'a> for f32 {
    fn deserialize(archived: &'a Archived<f32>) -> Self {
        Self::from_bits(<u32 as DeserializePayload>::deserialize(archived.cast()))
    }
    fn try_deserialize(archived: &'a Archived<f32>) -> Result<Self, Error> {
        <u32 as DeserializePayload>::try_deserialize(archived.cast()).map(Self::from_bits)
    }
}

impl SerializePayload for f64 {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.to_bits().to_le_bytes())?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(8)
    }
}

impl<'a> DeserializePayload<'a> for f64 {
    fn deserialize(archived: &'a Archived<f64>) -> Self {
        Self::from_bits(<u64 as DeserializePayload>::deserialize(archived.cast()))
    }
    fn try_deserialize(archived: &'a Archived<f64>) -> Result<Self, Error> {
        <u64 as DeserializePayload>::try_deserialize(archived.cast()).map(Self::from_bits)
    }
}

impl SerializePayload for String {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let bytes = self.as_bytes();
        let len = u64::try_from(bytes.len()).map_err(|_| Error::LengthMismatch)?;
        write_len_with_flags(writer, len, effective_layout_flags())?;
        writer.write_all(bytes)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
}

include!("core/owned_string_allocation.rs");

impl<'a> DeserializePayload<'a> for String {
    fn deserialize(archived: &'a Archived<String>) -> Self {
        Self::try_deserialize(archived)
            .unwrap_or_else(|err| panic!("norito: invalid archived String: {err:?}"))
    }
    fn try_deserialize(archived: &'a Archived<String>) -> Result<Self, Error> {
        let ptr = std::ptr::from_ref(archived).cast::<u8>();
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let ptr_us = ptr as usize;
        let base_end = base.checked_add(total).ok_or(Error::LengthMismatch)?;
        if ptr_us < base || ptr_us >= base_end {
            return Err(Error::LengthMismatch);
        }
        // SAFETY: this is the original validated active payload. Its tail is
        // borrowed only while constructing this owned String.
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let (value, _) = prepared_string::string_payload(&payload[ptr_us - base..], |body| {
            record_payload_access(body.as_ptr(), body.len());
        })?;
        try_copy_string_for_decode(value)
    }
}

impl SerializePayload for &str {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let bytes = self.as_bytes();
        let len = u64::try_from(bytes.len()).map_err(|_| Error::LengthMismatch)?;
        write_len_with_flags(writer, len, effective_layout_flags())?;
        writer.write_all(bytes)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
}

impl<'a> DeserializePayload<'a> for &'a str {
    fn deserialize(archived: &'a Archived<&'a str>) -> Self {
        Self::try_deserialize(archived)
            .unwrap_or_else(|err| panic!("norito: invalid archived &str: {err:?}"))
    }
    fn try_deserialize(archived: &'a Archived<&'a str>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let ptr_us = ptr as usize;
        if ptr_us < base || ptr_us >= base + total {
            return Err(Error::LengthMismatch);
        }
        let (len, hdr) = read_len_dyn_at_ptr(ptr)?;
        let off = (ptr_us - base) + hdr;
        let end = off.checked_add(len).ok_or(Error::LengthMismatch)?;
        if end > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        unsafe {
            record_payload_access(payload.as_ptr().add(off), len);
        }
        let bytes = &payload[off..end];
        std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
    }
}
// Bounded implementations for decoding from slices (no raw pointers)
impl<'a> DecodeFromSlice<'a> for String {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (value, used) = prepared_string::string_payload(bytes, |_| {})?;
        let owned = try_copy_string_for_decode(value)?;
        record_slice_access(bytes, used);
        Ok((owned, used))
    }
}
impl<'a> DecodeFromSlice<'a> for &'a str {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let (len, hdr) = read_len_dyn_slice(bytes)?;
        let end = hdr.checked_add(len).ok_or(Error::LengthMismatch)?;
        let data = bytes.get(hdr..end).ok_or(Error::LengthMismatch)?;
        let s = std::str::from_utf8(data).map_err(|_| Error::Message("invalid utf8".into()))?;
        record_slice_access(bytes, end);
        Ok((s, end))
    }
}

impl SerializePayload for Cow<'_, str> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let bytes = self.as_ref().as_bytes();
        let len = u64::try_from(bytes.len()).map_err(|_| Error::LengthMismatch)?;
        write_len_with_flags(writer, len, effective_layout_flags())?;
        writer.write_all(bytes)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
}

impl<'a> DeserializePayload<'a> for Cow<'a, str> {
    fn deserialize(archived: &'a Archived<Cow<'a, str>>) -> Self {
        let s = <&'a str as DeserializePayload>::deserialize(archived.cast());
        Cow::Borrowed(s)
    }
}

impl SerializePayload for Box<str> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.as_ref().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        len_prefixed_payload_len(self.len())
    }
}

impl<'a> DeserializePayload<'a> for Box<str> {
    fn deserialize(archived: &'a Archived<Box<str>>) -> Self {
        let s = String::deserialize(archived.cast());
        s.into_boxed_str()
    }
    fn try_deserialize(archived: &'a Archived<Box<str>>) -> Result<Self, Error> {
        guarded_try_deserialize(|| String::try_deserialize(archived.cast()))
            .map(|s| s.into_boxed_str())
    }
}

impl<T: SerializePayload> SerializePayload for Box<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        serialize_owned(writer, &**self)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        (**self)
            .encoded_len_exact()
            .or_else(|| (**self).encoded_len_hint())
            .and_then(len_prefixed_payload_len)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        (**self)
            .encoded_len_exact()
            .and_then(len_prefixed_payload_len)
    }
}

impl<'a, T> DeserializePayload<'a> for Box<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn deserialize(archived: &'a Archived<Box<T>>) -> Self {
        Self::try_deserialize(archived).expect("Box decode")
    }
    fn try_deserialize(archived: &'a Archived<Box<T>>) -> Result<Self, Error> {
        let bytes = owned_bytes_from_ctx(archived)?;
        let (value, _) = <Box<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}

impl<T: SerializePayload> SerializePayload for Rc<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        serialize_owned(writer, &**self)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        (**self)
            .encoded_len_exact()
            .or_else(|| (**self).encoded_len_hint())
            .and_then(len_prefixed_payload_len)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        (**self)
            .encoded_len_exact()
            .and_then(len_prefixed_payload_len)
    }
}

impl<'a, T> DeserializePayload<'a> for Rc<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn deserialize(archived: &'a Archived<Rc<T>>) -> Self {
        Self::try_deserialize(archived).expect("Rc decode")
    }
    fn try_deserialize(archived: &'a Archived<Rc<T>>) -> Result<Self, Error> {
        let bytes = owned_bytes_from_ctx(archived)?;
        let (value, _) = <Rc<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}

impl<T: SerializePayload> SerializePayload for Arc<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        serialize_owned(writer, &**self)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        (**self)
            .encoded_len_exact()
            .or_else(|| (**self).encoded_len_hint())
            .and_then(len_prefixed_payload_len)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        (**self)
            .encoded_len_exact()
            .and_then(len_prefixed_payload_len)
    }
}

impl<'a, T> DeserializePayload<'a> for Arc<T>
where
    T: SerializePayload + for<'de> DeserializePayload<'de>,
{
    fn deserialize(archived: &'a Archived<Arc<T>>) -> Self {
        Self::try_deserialize(archived).expect("Arc decode")
    }
    fn try_deserialize(archived: &'a Archived<Arc<T>>) -> Result<Self, Error> {
        let bytes = owned_bytes_from_ctx(archived)?;
        let (value, _) = <Arc<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(value)
    }
}

impl<T: SerializePayload + Copy> SerializePayload for Cell<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.get().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(core::mem::size_of::<T>())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(core::mem::size_of::<T>())
    }
}

impl<'a, T: DeserializePayload<'a> + Copy> DeserializePayload<'a> for Cell<T> {
    fn deserialize(archived: &'a Archived<Cell<T>>) -> Self {
        Cell::new(T::deserialize(archived.cast()))
    }
    fn try_deserialize(archived: &'a Archived<Cell<T>>) -> Result<Self, Error> {
        guarded_try_deserialize(|| T::try_deserialize(archived.cast())).map(Cell::new)
    }
}

impl<T: SerializePayload> SerializePayload for RefCell<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.borrow().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.borrow().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.borrow().encoded_len_exact()
    }
}

impl<'a, T: DeserializePayload<'a>> DeserializePayload<'a> for RefCell<T> {
    fn deserialize(archived: &'a Archived<RefCell<T>>) -> Self {
        RefCell::new(T::deserialize(archived.cast()))
    }
    fn try_deserialize(archived: &'a Archived<RefCell<T>>) -> Result<Self, Error> {
        guarded_try_deserialize(|| T::try_deserialize(archived.cast())).map(RefCell::new)
    }
}

impl<T: SerializePayload> SerializePayload for Option<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        match self {
            Some(value) => {
                writer.write_all(&[1])?;
                write_len_prefixed(writer, value)?;
            }
            None => {
                writer.write_all(&[0])?;
            }
        }
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        match self {
            Some(v) => v
                .encoded_len_exact()
                .or_else(|| v.encoded_len_hint())
                .and_then(tagged_len_prefixed_payload_len),
            None => Some(1),
        }
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        match self {
            Some(v) => v
                .encoded_len_exact()
                .and_then(tagged_len_prefixed_payload_len),
            None => Some(1),
        }
    }
}

impl<'a, T> DeserializePayload<'a> for Option<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn deserialize(archived: &'a Archived<Option<T>>) -> Self {
        match Self::try_deserialize(archived) {
            Ok(value) => value,
            Err(err) => panic!("norito: Option decode failed: {err:?}"),
        }
    }
    fn try_deserialize(archived: &'a Archived<Option<T>>) -> Result<Self, Error> {
        let bytes = payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (payload, used) = prepared_option::option_payload_prefix(bytes, |tag| {
            Error::invalid_tag("Option::try_deserialize", tag)
        })?;
        let value = match payload {
            None => None,
            Some(payload) => {
                let (value, consumed) = decode_field_canonical::<T>(payload)?;
                if consumed != payload.len() {
                    return Err(Error::LengthMismatch);
                }
                Some(value)
            }
        };
        record_slice_access(bytes, used);
        Ok(value)
    }
}

impl<T: SerializePayload, E: SerializePayload> SerializePayload for Result<T, E> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        match self {
            Ok(value) => {
                writer.write_all(&[0])?;
                write_len_prefixed(writer, value)?;
            }
            Err(err) => {
                writer.write_all(&[1])?;
                write_len_prefixed(writer, err)?;
            }
        }
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        match self {
            Ok(v) => v
                .encoded_len_exact()
                .or_else(|| v.encoded_len_hint())
                .and_then(tagged_len_prefixed_payload_len),
            Err(e) => e
                .encoded_len_exact()
                .or_else(|| e.encoded_len_hint())
                .and_then(tagged_len_prefixed_payload_len),
        }
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        match self {
            Ok(v) => v
                .encoded_len_exact()
                .and_then(tagged_len_prefixed_payload_len),
            Err(e) => e
                .encoded_len_exact()
                .and_then(tagged_len_prefixed_payload_len),
        }
    }
}

impl<'a, T, E> DeserializePayload<'a> for Result<T, E>
where
    T: DeserializePayload<'a> + DecodeFromSlice<'a>,
    E: DeserializePayload<'a> + DecodeFromSlice<'a>,
{
    fn deserialize(archived: &'a Archived<Result<T, E>>) -> Self {
        match Self::try_deserialize(archived) {
            Ok(value) => value,
            Err(err) => panic!("norito: Result decode failed: {err:?}"),
        }
    }
    fn try_deserialize(archived: &'a Archived<Result<T, E>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let payload = payload_slice_from_ptr(ptr)?;
        let tag = *payload.first().ok_or(Error::LengthMismatch)?;
        let (len, hdr) = read_len_dyn_slice(payload.get(1..).ok_or(Error::LengthMismatch)?)?;
        let data_start = 1usize.checked_add(hdr).ok_or(Error::LengthMismatch)?;
        let data_end = data_start.checked_add(len).ok_or(Error::LengthMismatch)?;
        let field = payload
            .get(data_start..data_end)
            .ok_or(Error::LengthMismatch)?;
        match tag {
            0 => {
                let _depth = DecodeDepthGuard::enter()?;
                let layout = Layout::from_size_align(len, archived_payload_align::<T>())
                    .map_err(|_| Error::LengthMismatch)?;
                let (tmp_ptr, needs_dealloc) = unsafe { alloc_checked(layout) }?;
                if let Err(err) = unsafe { copy_from_payload(field.as_ptr(), tmp_ptr, len) } {
                    unsafe { dealloc_checked(tmp_ptr, layout, needs_dealloc) };
                    return Err(err);
                }
                let tmp_slice = unsafe { std::slice::from_raw_parts(tmp_ptr as *const u8, len) };
                let _g = PayloadCtxGuard::enter(tmp_slice);
                let archived_ptr = if len == 0 {
                    empty_archived_ptr::<T>()
                } else {
                    tmp_ptr.cast::<Archived<T>>()
                };
                let value =
                    guarded_try_deserialize(|| unsafe { T::try_deserialize(&*archived_ptr) });
                unsafe { dealloc_checked(tmp_ptr, layout, needs_dealloc) };
                value.map(Ok)
            }
            1 => {
                let _depth = DecodeDepthGuard::enter()?;
                let layout = Layout::from_size_align(len, archived_payload_align::<E>())
                    .map_err(|_| Error::LengthMismatch)?;
                let (tmp_ptr, needs_dealloc) = unsafe { alloc_checked(layout) }?;
                if let Err(err) = unsafe { copy_from_payload(field.as_ptr(), tmp_ptr, len) } {
                    unsafe { dealloc_checked(tmp_ptr, layout, needs_dealloc) };
                    return Err(err);
                }
                let tmp_slice = unsafe { std::slice::from_raw_parts(tmp_ptr as *const u8, len) };
                let _g = PayloadCtxGuard::enter(tmp_slice);
                let archived_ptr = if len == 0 {
                    empty_archived_ptr::<E>()
                } else {
                    tmp_ptr.cast::<Archived<E>>()
                };
                let err = guarded_try_deserialize(|| unsafe { E::try_deserialize(&*archived_ptr) });
                unsafe { dealloc_checked(tmp_ptr, layout, needs_dealloc) };
                err.map(Err)
            }
            _ => Err(Error::invalid_tag("Result::try_deserialize", tag)),
        }
    }
}

impl<T: SerializePayload, const N: usize> SerializePayload for [T; N] {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let flags = effective_layout_flags();
        for item in self {
            let encoded_len = encoded_payload_len(item)?;
            write_len_with_flags(
                writer,
                u64::try_from(encoded_len).map_err(|_| Error::LengthMismatch)?,
                flags,
            )?;
            write_counted_payload(item, writer, encoded_len)?;
        }
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        let flags = effective_layout_flags();
        let mut total = 0usize;
        for item in self {
            let elem_len = item
                .encoded_len_exact()
                .or_else(|| item.encoded_len_hint())?;
            total = total
                .checked_add(len_prefix_len_with_flags(elem_len, flags))?
                .checked_add(elem_len)?;
        }
        Some(total)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let flags = effective_layout_flags();
        let mut total = 0usize;
        for item in self {
            let elem_len = item.encoded_len_exact()?;
            total = total
                .checked_add(len_prefix_len_with_flags(elem_len, flags))?
                .checked_add(elem_len)?;
        }
        Some(total)
    }
}

impl<'a, T: DeserializePayload<'a> + SerializePayload + 'static, const N: usize>
    DeserializePayload<'a> for [T; N]
{
    fn deserialize(archived: &'a Archived<[T; N]>) -> Self {
        match Self::try_deserialize(archived) {
            Ok(value) => value,
            Err(err) => panic!("norito: array decode failed: {err:?}"),
        }
    }
    fn try_deserialize(archived: &'a Archived<[T; N]>) -> Result<Self, Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            let ptr = archived as *const _ as *const u8;
            let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
            if ptr as usize > base + total {
                return Err(Error::LengthMismatch);
            }
            let start = (ptr as usize)
                .checked_sub(base)
                .ok_or(Error::LengthMismatch)?;
            let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
            let slice = &payload[start..];
            let (value_u8, used) = <[u8; N] as DecodeFromSlice>::decode_from_slice(slice)?;
            record_payload_access(ptr, used);
            let mut arr = core::mem::MaybeUninit::<[T; N]>::uninit();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    value_u8.as_ptr() as *const T,
                    arr.as_mut_ptr() as *mut T,
                    N,
                );
                return Ok(arr.assume_init());
            }
        }
        let ptr = archived as *const _ as *const u8;
        let mut offset = 0usize;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let start = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if start > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[start..];
        let out = try_decode_array(|| {
            let remaining = bytes.get(offset..).ok_or(Error::LengthMismatch)?;
            // The prefix borrows this field; alloc_checked charges its actual copy once.
            let (elem_len, hdr) = inspect_len_from_slice(remaining)?;
            offset = offset.checked_add(hdr).ok_or(Error::LengthMismatch)?;
            let end = offset.checked_add(elem_len).ok_or(Error::LengthMismatch)?;
            let field = bytes.get(offset..end).ok_or(Error::LengthMismatch)?;
            let _depth = DecodeDepthGuard::enter()?;
            unsafe {
                let layout = Layout::from_size_align(elem_len, archived_payload_align::<T>())
                    .map_err(|_| Error::LengthMismatch)?;
                let (tmp_ptr, needs_dealloc) = alloc_checked(layout)?;
                if let Err(err) = copy_from_payload(field.as_ptr(), tmp_ptr, elem_len) {
                    dealloc_checked(tmp_ptr, layout, needs_dealloc);
                    return Err(err);
                }
                let tmp_slice = std::slice::from_raw_parts(tmp_ptr as *const u8, elem_len);
                let _g = PayloadCtxGuard::enter(tmp_slice);
                let archived_ptr = if elem_len == 0 {
                    empty_archived_ptr::<T>()
                } else {
                    tmp_ptr.cast::<Archived<T>>()
                };
                let archived = &*archived_ptr;
                let result = guarded_try_deserialize(|| {
                    let decoded = T::try_deserialize(archived);
                    let used_ctx = payload_ctx_max_access();
                    let value = decoded?;
                    if used_ctx.is_some_and(|used| used > elem_len) {
                        return Err(Error::LengthMismatch);
                    }
                    if used_ctx != Some(elem_len) {
                        // Preserve custom decoders that report partial or no access,
                        // while proving the original field is exactly canonical.
                        match_canonical_payload(&value, field, true)?;
                    }
                    Ok(value)
                });
                // Both decoder and canonical-validation errors pass this cleanup.
                dealloc_checked(tmp_ptr, layout, needs_dealloc);
                let value = result?;
                offset = end;
                Ok(value)
            }
        })?;
        Ok(out)
    }
}
pub mod stream {
    use super::{
        Archived, Compression, DecodeFlagsGuard, DeserializePayload, Error, Header,
        PayloadCtxGuard, archived_payload_align, archived_payload_size, empty_archived_ptr,
        header_flags,
    };
    use crate::guarded_try_deserialize;
    use crc64fast::Digest;
    #[cfg(feature = "compression")]
    use std::io::BufReader;
    use std::{
        alloc::{Layout, alloc, dealloc},
        io::{self, Read},
    };
    pub(crate) fn inspect_sequence_len_from_reader<R>(
        mut reader: R,
        expected_schema: [u8; 16],
        padding: usize,
        max_elements: usize,
    ) -> Result<usize, Error>
    where
        R: Read,
    {
        let header = Header::read(&mut reader)?;
        super::prepare_header_decode(header.flags, false)?;
        if header.schema != expected_schema {
            return Err(Error::SchemaMismatch);
        }
        let payload_len = super::payload_len_to_usize(header.length)?;
        let padding = match header.compression {
            Compression::None => padding,
            Compression::Zstd => 0,
        };
        if padding != 0 {
            skip_padding(&mut reader, padding)?;
        }
        let _flags = DecodeFlagsGuard::enter(header.flags);
        let limits = super::DecodeLimits::new(
            max_elements,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            super::MAX_VALUE_NESTING_DEPTH,
        );
        super::with_decode_limits(limits, || {
            let mut payload = DigestingReader::new(PayloadStream::new(reader, header.compression)?);
            let decoder = SeqLenDecoder::new(&mut payload, header.flags, payload_len)?;
            Ok(decoder.total_len())
        })
    }
    pub(crate) fn fold_sequence_from_reader<R, T, Acc, Init, F>(
        mut reader: R,
        init: Init,
        mut f: F,
        expected_schema: [u8; 16],
        padding: usize,
    ) -> Result<Acc, Error>
    where
        R: Read,
        T: for<'de> DeserializePayload<'de>,
        Init: FnOnce(usize) -> Result<Acc, Error>,
        F: FnMut(Acc, T) -> Acc,
    {
        let header = Header::read(&mut reader)?;
        super::prepare_header_decode(header.flags, false)?;
        if header.schema != expected_schema {
            return Err(Error::SchemaMismatch);
        }
        let payload_len = super::payload_len_to_usize(header.length)?;
        let padding = match header.compression {
            Compression::None => padding,
            Compression::Zstd => 0,
        };
        if padding != 0 {
            skip_padding(&mut reader, padding)?;
        }
        let _fg = DecodeFlagsGuard::enter(header.flags);
        let mut payload = DigestingReader::new(PayloadStream::new(reader, header.compression)?);
        let mut len_decoder = SeqLenDecoder::new(&mut payload, header.flags, payload_len)?;
        let mut acc = init(len_decoder.total_len())?;
        let mut scratch = AlignedScratch::new();
        let archived_align = archived_payload_align::<T>();
        while let Some(elem_len) = len_decoder.next_len(&mut payload)? {
            let available = payload_len
                .checked_sub(payload.consumed)
                .ok_or(Error::LengthMismatch)?;
            if elem_len > available {
                return Err(Error::LengthMismatch);
            }
            let _depth = super::DecodeDepthGuard::enter()?;
            if elem_len == 0 {
                if archived_payload_size::<T>() != 0 {
                    return Err(Error::LengthMismatch);
                }
                let _pg = PayloadCtxGuard::enter(&[]);
                let archived = unsafe { &*empty_archived_ptr::<T>() };
                let val = guarded_try_deserialize(|| {
                    <T as DeserializePayload>::try_deserialize(archived)
                })?;
                acc = f(acc, val);
            } else {
                unsafe {
                    let ptr = scratch.ensure(elem_len, archived_align)?;
                    let tmp_slice_mut = std::slice::from_raw_parts_mut(ptr, elem_len);
                    payload.read_exact_into(tmp_slice_mut)?;
                    let tmp_slice = std::slice::from_raw_parts(ptr as *const u8, elem_len);
                    let _pg = PayloadCtxGuard::enter(tmp_slice);
                    let archived = &*(ptr as *const Archived<T>);
                    let val = guarded_try_deserialize(|| {
                        <T as DeserializePayload>::try_deserialize(archived)
                    })?;
                    acc = f(acc, val);
                }
            }
        }
        if len_decoder.remaining() != 0 {
            return Err(Error::LengthMismatch);
        }
        let remaining_tail = payload_len
            .checked_sub(payload.consumed)
            .ok_or(Error::LengthMismatch)?;
        len_decoder.finish(&mut payload, remaining_tail)?;
        let _ = payload.finalize(payload_len, header.checksum)?;
        Ok(acc)
    }
    #[inline]
    pub(crate) fn u64_to_usize(value: u64) -> Result<usize, Error> {
        super::payload_len_to_usize(value)
    }
    #[inline]
    pub(crate) fn skip_padding<R: Read>(reader: &mut R, mut padding: usize) -> Result<(), Error> {
        if padding == 0 {
            return Ok(());
        }
        let mut buf = [0u8; 1024];
        while padding > 0 {
            let chunk = padding.min(buf.len());
            let read = reader.read(&mut buf[..chunk])?;
            if read == 0 {
                return Err(Error::LengthMismatch);
            }
            if buf[..read].iter().any(|&b| b != 0) {
                return Err(Error::LengthMismatch);
            }
            padding -= read;
        }
        Ok(())
    }
    pub(crate) struct AlignedScratch {
        ptr: *mut u8,
        layout: Option<Layout>,
        capacity: usize,
        align: usize,
    }
    impl AlignedScratch {
        pub(crate) fn new() -> Self {
            Self {
                ptr: std::ptr::null_mut(),
                layout: None,
                capacity: 0,
                align: 1,
            }
        }
        pub(crate) unsafe fn ensure(&mut self, len: usize, align: usize) -> Result<*mut u8, Error> {
            if len == 0 {
                return Ok(std::ptr::NonNull::<u8>::dangling().as_ptr());
            }
            if len <= self.capacity && align <= self.align {
                return Ok(self.ptr);
            }
            let layout = Layout::from_size_align(len, align).map_err(|_| Error::LengthMismatch)?;
            super::reserve_decode_allocation(len)?;
            let ptr = unsafe { alloc(layout) };
            if ptr.is_null() {
                return Err(Error::AllocationFailed {
                    bytes: super::limit_to_u64(len),
                });
            }
            if !self.ptr.is_null()
                && let Some(previous_layout) = self.layout.take()
            {
                unsafe { dealloc(self.ptr, previous_layout) };
            }
            self.ptr = ptr;
            self.capacity = len;
            self.align = align;
            self.layout = Some(layout);
            Ok(ptr)
        }
    }
    impl Drop for AlignedScratch {
        fn drop(&mut self) {
            if let Some(layout) = self.layout.take()
                && !self.ptr.is_null()
            {
                unsafe { dealloc(self.ptr, layout) };
            }
        }
    }
    pub(super) enum PayloadStream<R: Read> {
        Plain(R),
        #[cfg(feature = "compression")]
        Zstd(zstd::Decoder<'static, BufReader<R>>),
    }
    impl<R: Read> PayloadStream<R> {
        pub(super) fn new(reader: R, compression: Compression) -> Result<Self, Error> {
            match compression {
                Compression::None => Ok(Self::Plain(reader)),
                Compression::Zstd => {
                    #[cfg(feature = "compression")]
                    {
                        Ok(Self::Zstd(zstd::Decoder::new(reader)?))
                    }
                    #[cfg(not(feature = "compression"))]
                    {
                        let _ = reader;
                        Err(io::Error::other("compression support disabled").into())
                    }
                }
            }
        }
    }
    impl<R: Read> Read for PayloadStream<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                PayloadStream::Plain(inner) => inner.read(buf),
                #[cfg(feature = "compression")]
                PayloadStream::Zstd(decoder) => decoder.read(buf),
            }
        }
    }
    pub(crate) struct DigestingReader<R> {
        inner: R,
        digest: Digest,
        consumed: usize,
    }
    impl<R: Read> DigestingReader<R> {
        pub(crate) fn new(inner: R) -> Self {
            Self {
                inner,
                digest: Digest::new(),
                consumed: 0,
            }
        }
        pub(crate) fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_exact(buf)?;
            self.digest.write(buf);
            self.consumed += buf.len();
            Ok(())
        }
        pub(crate) fn read_exact_into(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_exact(buf)?;
            Ok(buf.len())
        }
        pub(crate) fn read_u64(&mut self) -> io::Result<u64> {
            let mut b = [0u8; 8];
            self.read_exact(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        pub(crate) fn read_varint_u64(&mut self) -> Result<u64, Error> {
            let mut result = 0u64;
            let mut shift = 0u32;
            let mut used = 0usize;
            for _ in 0..super::MAX_VARINT_BYTES {
                let mut byte = [0u8; 1];
                self.read_exact(&mut byte)?;
                used += 1;
                let b = byte[0];
                let payload = (b & 0x7f) as u64;
                if shift == 63 && payload > 1 {
                    return Err(Error::LengthMismatch);
                }
                result |= payload << shift;
                if b & 0x80 == 0 {
                    if used != super::varint_encoded_len(result) {
                        return Err(Error::LengthMismatch);
                    }
                    return Ok(result);
                }
                shift += 7;
                if shift >= 64 {
                    break;
                }
            }
            Err(Error::LengthMismatch)
        }
        pub(crate) fn read_varint_len(&mut self) -> Result<usize, Error> {
            let raw = self.read_varint_u64()?;
            super::len_u64_to_usize(raw)
        }
        pub(crate) fn finalize(self, expected_len: usize, checksum: u64) -> Result<R, Error> {
            if self.consumed != expected_len {
                dbg!(self.consumed, expected_len);
                return Err(Error::LengthMismatch);
            }
            if self.digest.sum64() != checksum {
                return Err(Error::ChecksumMismatch);
            }
            Ok(self.inner)
        }
        pub(crate) fn consumed(&self) -> usize {
            self.consumed
        }
    }
    /// Streaming reader for the per-element length prefixes of one sequence.
    pub(crate) struct SeqLenDecoder {
        flags: u8,
        total: usize,
        remaining: usize,
    }
    impl SeqLenDecoder {
        #[inline]
        fn read_u64_len<R: Read>(reader: &mut DigestingReader<R>) -> Result<u64, Error> {
            reader.read_u64().map_err(|err| {
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    Error::LengthMismatch
                } else {
                    Error::Io(err)
                }
            })
        }
        #[inline]
        fn map_unexpected_eof(err: Error) -> Error {
            match err {
                Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Error::LengthMismatch,
                other => other,
            }
        }
        pub(crate) fn new<R: Read>(
            reader: &mut DigestingReader<R>,
            flags: u8,
            payload_len: usize,
        ) -> Result<Self, Error> {
            super::validate_header_flags(flags)?;
            let len = Self::read_u64_len(reader)?;
            super::enforce_decode_sequence_length(len)?;
            let total = u64_to_usize(len)?;
            let remaining_payload = payload_len
                .checked_sub(reader.consumed())
                .ok_or(Error::LengthMismatch)?;
            let prefix_bytes = if (flags & header_flags::COMPACT_LEN) != 0 {
                1usize
            } else {
                8usize
            };
            let minimum_headers = total
                .checked_mul(prefix_bytes)
                .ok_or(Error::LengthMismatch)?;
            if minimum_headers > remaining_payload {
                return Err(Error::LengthMismatch);
            }
            Ok(Self {
                flags,
                total,
                remaining: total,
            })
        }
        pub(crate) fn next_len<R: Read>(
            &mut self,
            reader: &mut DigestingReader<R>,
        ) -> Result<Option<usize>, Error> {
            if self.remaining == 0 {
                return Ok(None);
            }
            let len = if (self.flags & header_flags::COMPACT_LEN) != 0 {
                let len = reader.read_varint_len().map_err(Self::map_unexpected_eof)?;
                super::enforce_decode_field_length(
                    u64::try_from(len).map_err(|_| Error::LengthMismatch)?,
                )?;
                len
            } else {
                let raw = Self::read_u64_len(reader)?;
                super::enforce_decode_field_length(raw)?;
                super::len_u64_to_usize(raw)?
            };
            self.remaining -= 1;
            Ok(Some(len))
        }
        pub(crate) fn remaining(&self) -> usize {
            self.remaining
        }
        pub(crate) fn total_len(&self) -> usize {
            self.total
        }
        pub(crate) fn finish<R: Read>(
            &self,
            _reader: &mut DigestingReader<R>,
            remaining_bytes: usize,
        ) -> Result<(), Error> {
            if self.remaining() != 0 || remaining_bytes != 0 {
                return Err(Error::LengthMismatch);
            }
            Ok(())
        }
    }
}

impl<T: SerializePayload> SerializePayload for VecDeque<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        encode_seq_payloads::<T, _>(writer, self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        sequence_encoded_len_exact(self.iter())
    }
}

impl<'a, T> DeserializePayload<'a> for VecDeque<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn deserialize(archived: &'a Archived<VecDeque<T>>) -> Self {
        Self::try_deserialize(archived).expect("norito: VecDeque decode failed")
    }
    fn try_deserialize(archived: &'a Archived<VecDeque<T>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (deque, _used) = <VecDeque<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(deque)
    }
}

impl<T: SerializePayload> SerializePayload for LinkedList<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        encode_seq_payloads::<T, _>(writer, self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        sequence_encoded_len_exact(self.iter())
    }
}

impl<'a, T> DeserializePayload<'a> for LinkedList<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn deserialize(archived: &'a Archived<LinkedList<T>>) -> Self {
        Self::try_deserialize(archived).expect("norito: LinkedList decode failed")
    }
    fn try_deserialize(archived: &'a Archived<LinkedList<T>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize)
            .checked_sub(base)
            .ok_or(Error::LengthMismatch)?;
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (list, _used) = <LinkedList<T> as DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok(list)
    }
}

impl<T> SerializePayload for BinaryHeap<T>
where
    T: SerializePayload + Ord,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        heap_payload::serialize(self, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        sequence_encoded_len_exact(self.iter())
    }
}

impl<'a, T> DeserializePayload<'a> for BinaryHeap<T>
where
    T: DeserializePayload<'a> + Ord,
{
    fn deserialize(archived: &'a Archived<BinaryHeap<T>>) -> Self {
        Self::try_deserialize(archived).expect("BinaryHeap decode")
    }
    fn try_deserialize(archived: &'a Archived<BinaryHeap<T>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let payload = payload_slice_from_ptr(ptr)?;
        let (len, hdr) = unsafe { read_seq_len_ptr(ptr) }?;
        ensure_len_within_remaining(len, payload.len().saturating_sub(hdr))?;
        validate_current_sequence_reservation(payload, len)?;
        let mut offset = hdr;
        let output_bytes = len
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(Error::LengthMismatch)?;
        reserve_decode_allocation(output_bytes)?;
        let mut out = BinaryHeap::new();
        out.try_reserve(len).map_err(|_| Error::AllocationFailed {
            bytes: limit_to_u64(output_bytes),
        })?;
        let align = archived_payload_align::<T>();
        let mut cap = 1usize;
        let mut layout = Layout::from_size_align(cap, align).map_err(|_| Error::LengthMismatch)?;
        let (mut buf, mut buf_needs_dealloc) = unsafe { alloc_checked(layout) }?;
        for _ in 0..len {
            let remaining = match payload.get(offset..) {
                Some(remaining) => remaining,
                None => {
                    unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                    return Err(Error::LengthMismatch);
                }
            };
            let (elem_len, hdr) = match read_len_dyn_slice(remaining) {
                Ok(res) => res,
                Err(err) => {
                    unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                    return Err(err);
                }
            };
            offset = match offset.checked_add(hdr) {
                Some(offset) => offset,
                None => {
                    unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                    return Err(Error::LengthMismatch);
                }
            };
            let end = match offset.checked_add(elem_len) {
                Some(end) => end,
                None => {
                    unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                    return Err(Error::LengthMismatch);
                }
            };
            let field = match payload.get(offset..end) {
                Some(field) => field,
                None => {
                    unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                    return Err(Error::LengthMismatch);
                }
            };
            let _depth = match DecodeDepthGuard::enter() {
                Ok(guard) => guard,
                Err(error) => {
                    unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                    return Err(error);
                }
            };
            if elem_len > cap {
                let new_cap = core::cmp::max(elem_len, cap.saturating_mul(2));
                let new_layout = match Layout::from_size_align(new_cap, align) {
                    Ok(layout) => layout,
                    Err(_) => {
                        unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                        return Err(Error::LengthMismatch);
                    }
                };
                let (new_buf, new_buf_needs_dealloc) = match unsafe { alloc_checked(new_layout) } {
                    Ok(allocation) => allocation,
                    Err(error) => {
                        unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                        return Err(error);
                    }
                };
                unsafe { dealloc_checked(buf, layout, buf_needs_dealloc) };
                buf = new_buf;
                buf_needs_dealloc = new_buf_needs_dealloc;
                layout = new_layout;
                cap = new_cap;
            }
            unsafe {
                if let Err(error) = copy_from_payload(field.as_ptr(), buf, elem_len) {
                    dealloc_checked(buf, layout, buf_needs_dealloc);
                    return Err(error);
                }
                let tmp_slice = std::slice::from_raw_parts(buf as *const u8, elem_len);
                let _g = PayloadCtxGuard::enter(tmp_slice);
                let archived = &*(buf as *const Archived<T>);
                let result = guarded_try_deserialize(|| T::try_deserialize(archived));
                match result {
                    Ok(value) => out.push(value),
                    Err(error) => {
                        dealloc_checked(buf, layout, buf_needs_dealloc);
                        return Err(error);
                    }
                }
            }
            offset = end;
        }
        unsafe {
            dealloc_checked(buf, layout, buf_needs_dealloc);
        }
        Ok(out)
    }
}

// Borrowed bytes use the same fixed-count payload as Vec<u8>, without copying
// private preimages into an additional owned allocation.
impl SerializePayload for &[u8] {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let len = u64::try_from(self.len()).map_err(|_| Error::LengthMismatch)?;
        write_seq_len(writer, len)?;
        writer.write_all(self)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        self.len().checked_add(8)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        self.len().checked_add(8)
    }
}

impl<T: SerializePayload> SerializePayload for Vec<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        if core::any::type_name::<T>() == "u8" {
            // SAFETY: we verified `T == u8` via `type_name`.
            let bytes =
                unsafe { core::slice::from_raw_parts(self.as_ptr().cast::<u8>(), self.len()) };
            return bytes.serialize(writer);
        }
        encode_slice_payloads(writer, self)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        if core::any::type_name::<T>() == "u8" {
            return self.len().checked_add(8);
        }
        sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        if core::any::type_name::<T>() == "u8" {
            return self.len().checked_add(8);
        }
        sequence_encoded_len_exact(self.iter())
    }
}

impl<'a, T> DeserializePayload<'a> for Vec<T>
where
    T: for<'de> DeserializePayload<'de> + SerializePayload,
{
    fn deserialize(archived: &'a Archived<Vec<T>>) -> Self {
        Self::try_deserialize(archived).expect("Vec decode")
    }
    fn try_deserialize(archived: &'a Archived<Vec<T>>) -> Result<Self, Error> {
        let ptr = archived as *const _ as *const u8;
        let (base, total) = payload_ctx().ok_or(Error::MissingPayloadContext)?;
        let offset = (ptr as usize).saturating_sub(base);
        if offset > total {
            return Err(Error::LengthMismatch);
        }
        let payload = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
        let bytes = &payload[offset..];
        let (vec, _used) = decode_vec_from_slice_with::<T, _>(bytes, |_, _, _| Ok(None))?;
        Ok(vec)
    }
}
#[inline]
fn tuple_serialization_flags() -> u8 {
    effective_layout_flags()
}
macro_rules! impl_tuple {
    ($( $name:ident $var:ident $idx:tt ),+ $(,)?) => {
impl<$( $name: SerializePayload ),+> SerializePayload for ( $( $name, )+ ) {
            fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
                // Ensure inner element serializers observe the same layout
                // defaults as the bare codec path (compact lengths when
                // enabled). This keeps nested encodings
                // like `Vec<u8>` consistent with the decoder's expectations.
                let __merged = tuple_serialization_flags();
                let __guard = DecodeFlagsGuard::enter(__merged);
                // Measure each field before streaming it directly to the destination.
                #[cfg(debug_assertions)]
                if crate::debug_trace_enabled() {
                    eprintln!(
                        "norito.tuple.serialize: flags=0x{:02x}",
                        get_decode_flags()
                    );
                }
                $(
                    write_len_prefixed(writer, &self.$idx)?;
                )+
                Ok(())
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                let mut total = 0usize;
                let flags = tuple_serialization_flags();
                let _guard = DecodeFlagsGuard::enter(flags);
                $(
                    let elem_len = self.$idx
                        .encoded_len_exact()
                        .or_else(|| self.$idx.encoded_len_hint())?;
                    total = total
                        .checked_add(len_prefix_len_with_flags(elem_len, flags))?
                        .checked_add(elem_len)?;
                )+
                Some(total)
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                let mut total = 0usize;
                let flags = tuple_serialization_flags();
                let _guard = DecodeFlagsGuard::enter(flags);
                $(
                    let elem_len = self.$idx.encoded_len_exact()?;
                    total = total
                        .checked_add(len_prefix_len_with_flags(elem_len, flags))?
                        .checked_add(elem_len)?;
                )+
                Some(total)
            }
        }
impl<'a, $( $name: DeserializePayload<'a> ),+> DeserializePayload<'a> for ( $( $name, )+ ) {
            fn deserialize(archived: &'a Archived<( $( $name, )+ )>) -> Self {
                Self::try_deserialize(archived)
                    .unwrap_or_else(|err| panic!("norito: tuple decode failed: {err:?}"))
            }
            fn try_deserialize(archived: &'a Archived<( $( $name, )+ )>) -> Result<Self, Error> {
                let ptr = archived as *const _ as *const u8;
                let payload = payload_slice_from_ptr(ptr)?;
                let mut offset = 0usize;
                $(
                    let remaining = payload.get(offset..).ok_or(Error::LengthMismatch)?;
                    let (elem_len, hdr) = read_len_dyn_slice(remaining)?;
                    offset = offset.checked_add(hdr).ok_or(Error::LengthMismatch)?;
                    let end = offset.checked_add(elem_len).ok_or(Error::LengthMismatch)?;
                    let field = payload.get(offset..end).ok_or(Error::LengthMismatch)?;
                    let _depth = DecodeDepthGuard::enter()?;
                    let $var = unsafe {
                        let layout = Layout::from_size_align(
                            elem_len,
                            archived_payload_align::<$name>(),
                        ).map_err(|_| Error::LengthMismatch)?;
                        let (tmp_ptr, needs_dealloc) = alloc_checked(layout)?;
                        if let Err(err) = copy_from_payload(field.as_ptr(), tmp_ptr, elem_len) {
                            dealloc_checked(tmp_ptr, layout, needs_dealloc);
                            return Err(err);
                        }
                        let tmp_slice = std::slice::from_raw_parts(tmp_ptr as *const u8, elem_len);
                        let _g = PayloadCtxGuard::enter(tmp_slice);
                        let archived_ptr = if elem_len == 0 {
                            empty_archived_ptr::<$name>()
                        } else {
                            tmp_ptr.cast::<Archived<$name>>()
                        };
                        let archived = &*archived_ptr;
                        let result = guarded_try_deserialize(|| $name::try_deserialize(archived));
                        dealloc_checked(tmp_ptr, layout, needs_dealloc);
                        result?
                    };
                    drop(_depth);
                    offset = end;
                )+
                let _ = offset;
                Ok(( $( $var ),+ ))
            }
        }
    };
}
impl_tuple!(A a 0, B b 1);
impl_tuple!(A a 0, B b 1, C c 2);
impl_tuple!(A a 0, B b 1, C c 2, D d 3);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6, H h 7);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6, H h 7, I i 8);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6, H h 7, I i 8, J j 9);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6, H h 7, I i 8, J j 9, K k 10);
impl_tuple!(A a 0, B b 1, C c 2, D d 3, E e 4, F f 5, G g 6, H h 7, I i 8, J j 9, K k 10, L l 11);
/// Internal byte sink with aligned growth and incremental CRC64.
///
/// ByteSink implements `Write` and is optimized for small, frequent writes by using a growth policy
/// and typed little-endian writers. It reserves an initial headroom to make space for the Norito
/// header and computes CRC64 incrementally over the appended payload bytes.
pub(crate) struct ByteSink {
    buf: Vec<u8>,
    headroom: usize,
    digest: crc64fast::Digest,
}
impl ByteSink {
    /// Create a new sink with capacity hint for payload and reserved headroom.
    pub(crate) fn with_headroom(payload_capacity: usize, headroom: usize) -> Self {
        // Ensure a minimal capacity to avoid early reallocations on tiny values.
        let mut buf = Vec::with_capacity(headroom + payload_capacity.max(1024));
        buf.resize(headroom, 0); // reserve header space
        Self {
            buf,
            headroom,
            digest: crc64fast::Digest::new(),
        }
    }
    /// Reuse an existing buffer while reserving headroom and payload capacity.
    fn with_headroom_from(mut buf: Vec<u8>, payload_capacity: usize, headroom: usize) -> Self {
        buf.clear();
        let min_capacity = headroom + payload_capacity.max(1024);
        if buf.capacity() < min_capacity {
            buf.reserve(min_capacity - buf.capacity());
        }
        buf.resize(headroom, 0);
        Self {
            buf,
            headroom,
            digest: crc64fast::Digest::new(),
        }
    }
    #[inline]
    fn ensure_capacity(&mut self, extra: usize) {
        let needed = self.buf.len() + extra;
        if self.buf.capacity() < needed {
            // Growth: round up to the next power-of-two-like step to amortize.
            let mut cap = self.buf.capacity().max(self.headroom + 1024);
            while cap < needed {
                cap = cap.saturating_mul(2);
            }
            self.buf.reserve(cap - self.buf.capacity());
        }
    }
    #[inline]
    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) {
        self.ensure_capacity(bytes.len());
        self.buf.extend_from_slice(bytes);
        self.digest.write(bytes);
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn write_u8(&mut self, v: u8) {
        self.ensure_capacity(1);
        self.buf.push(v);
        self.digest.write(&[v]);
    }
    #[inline]
    #[allow(dead_code)]
    fn write_u16_le(&mut self, v: u16) {
        let b = v.to_le_bytes();
        self.write_bytes(&b);
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn write_u32_le(&mut self, v: u32) {
        let b = v.to_le_bytes();
        self.write_bytes(&b);
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn write_u64_le(&mut self, v: u64) {
        let b = v.to_le_bytes();
        self.write_bytes(&b);
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn write_var_u64(&mut self, mut v: u64) {
        let mut buf = [0u8; 10];
        let mut idx = 0usize;
        while v >= 0x80 {
            buf[idx] = (v as u8) | 0x80;
            v >>= 7;
            idx += 1;
        }
        buf[idx] = v as u8;
        self.write_bytes(&buf[..=idx]);
    }
    /// Write a compact varint (7-bit) length when `COMPACT_LEN` is selected.
    /// Align the payload to `align` bytes by writing zero padding.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn align_to(&mut self, align: usize) {
        debug_assert!(align.is_power_of_two());
        let len = self.buf.len();
        let mis = len & (align - 1);
        if mis != 0 {
            let pad = align - mis;
            self.ensure_capacity(pad);
            let start = self.buf.len();
            self.buf.resize(start + pad, 0);
            self.digest.write(&self.buf[start..start + pad]);
        }
    }
    #[inline]
    #[allow(dead_code)]
    fn checksum(&self) -> u64 {
        self.digest.sum64()
    }
    #[inline]
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}
impl Write for ByteSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write_bytes(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode_bare_with_flags<T: SerializePayload>(
    value: &T,
) -> Result<(Vec<u8>, u8), Error> {
    let encode_guard = EncodeContextGuard::enter();
    let base_flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    validate_header_flags(base_flags)?;
    let flags = base_flags;
    let mut sink = ByteSink::with_headroom(0, 0);
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut encoder = Encoder::for_byte_sink(&mut sink);
        value.serialize(&mut encoder)?;
    }
    let payload = sink.into_inner();
    let compact_len_used = compact_len_used();
    drop(encode_guard);
    let final_flags = finalized_encode_flags(flags, compact_len_used);
    Ok((payload, final_flags))
}
/// Return the exact payload length under the active layout without allocating an output buffer.
///
/// This deliberately counts a real serialization pass instead of trusting
/// [`SerializePayload::encoded_len_exact`], because that method is only an optimization hint and an
/// incorrect implementation must not understate a resource-admission bound.
/// Length-only destinations count each nested child once, then account for those measured bytes
/// without traversing the same child again. Actual byte destinations still perform a checked write.
///
/// # Errors
///
/// Returns the underlying serialization error.
pub fn encoded_payload_len(value: &dyn SerializePayload) -> Result<usize, Error> {
    let encode_guard = EncodeContextGuard::enter();
    let flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    validate_header_flags(flags)?;
    let mut counted = LengthCountingWriter::default();
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut encoder = Encoder::for_counting(&mut counted);
        value.serialize(&mut encoder)?;
    }
    let payload_len = counted.finish()?;
    drop(encode_guard);
    Ok(payload_len)
}
/// Count a payload while limiting the bytes visited by nested measurement writers.
///
/// Every leaf and framing byte consumes the shared allowance once. A measured
/// child's length is incorporated without a second charge or traversal. The
/// refusal remains sticky even if a serializer ignores a failed write.
///
/// # Errors
/// Returns a serialization error or [`Error::LengthMismatch`] when the finite
/// count allowance is exceeded. Arbitrary work performed before a serializer
/// writes bytes still belongs to the source owner's separate work boundary.
pub fn encoded_payload_len_bounded(
    value: &dyn SerializePayload,
    maximum: usize,
) -> Result<usize, Error> {
    let guard = encode_writers::CountBudgetGuard::enter(maximum);
    let length = encoded_payload_len(value)?;
    guard.check()?;
    if length > maximum {
        return Err(Error::LengthMismatch);
    }
    Ok(length)
}
/// Count a complete frame under a finite header, padding and payload allowance.
///
/// # Errors
/// Returns [`Error::LengthMismatch`] if framing alone or the measured payload
/// exceeds `maximum`, or the underlying serialization error.
pub fn encoded_frame_len_bounded<T: NoritoSerialize>(
    value: &T,
    maximum: usize,
) -> Result<usize, Error> {
    let framing = Header::SIZE
        .checked_add(payload_alignment_padding_for::<T>())
        .ok_or(Error::LengthMismatch)?;
    let payload_maximum = maximum.checked_sub(framing).ok_or(Error::LengthMismatch)?;
    framing
        .checked_add(encoded_payload_len_bounded(value, payload_maximum)?)
        .ok_or(Error::LengthMismatch)
}
/// Return the exact framed length under the active layout without allocating an output buffer.
///
/// Like [`encoded_payload_len`], this counts a real serialization pass instead
/// of trusting length hints.
///
/// # Errors
///
/// Returns a serialization error or [`Error::LengthMismatch`] if the framed
/// length cannot be represented by `usize`.
pub fn encoded_frame_len<T: NoritoSerialize>(value: &T) -> Result<usize, Error> {
    let framing = Header::SIZE
        .checked_add(payload_alignment_padding_for::<T>())
        .ok_or(Error::LengthMismatch)?;
    // A framed child contributes header bytes even when its payload is empty.
    encode_writers::charge_counted_bytes(framing)?;
    framing
        .checked_add(encoded_payload_len(value)?)
        .ok_or(Error::LengthMismatch)
}
include!("core/exact_byte_vec.rs");
/// Serialize one canonical frame without allowing the output buffer to grow
/// beyond a caller-provided byte limit.
///
/// A real serialization pass determines the complete framed length before any output allocation.
/// The admitted frame is then reserved once and a second pass writes through a hard-cap
/// destination. This deliberately does not trust [`SerializePayload::encoded_len_exact`] or capacity
/// hints: a serializer that emits a different length on the second pass is rejected and its
/// incomplete output is discarded.
///
/// # Errors
///
/// Returns [`BoundedEncodeError::FrameTooLarge`] before allocation when the counted frame exceeds
/// `max_frame_bytes`, [`BoundedEncodeError::AllocationFailed`] when its one output reservation
/// fails, or [`BoundedEncodeError::Serialization`] for codec errors and count mismatches.
pub fn to_bytes_bounded<T: NoritoSerialize>(
    value: &T,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, BoundedEncodeError> {
    let encoded_bytes = encoded_frame_len(value)?;
    if encoded_bytes > max_frame_bytes {
        return Err(BoundedEncodeError::FrameTooLarge {
            encoded_bytes,
            max_bytes: max_frame_bytes,
        });
    }
    let padding = payload_alignment_padding_for::<T>();
    let headroom = Header::SIZE
        .checked_add(padding)
        .ok_or(Error::LengthMismatch)?;
    let expected_payload_len = encoded_bytes
        .checked_sub(headroom)
        .ok_or(Error::LengthMismatch)?;
    let header_payload_len =
        u64::try_from(expected_payload_len).map_err(|_| Error::LengthMismatch)?;
    let mut out = exact_byte_vec_with_capacity(encoded_bytes)?;
    out.resize(headroom, 0);
    let encode_guard = EncodeContextGuard::enter();
    let base_flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    validate_header_flags(base_flags)?;
    let mut bounded = FixedCapacityVecWriter::new(&mut out, encoded_bytes);
    let (serialize_result, payload_len, checksum, destination_rejected_write) = {
        let mut payload_writer = FramedPayloadWriter {
            inner: &mut bounded,
            len: 0,
            digest: crc64fast::Digest::new(),
        };
        let serialize_result = {
            let _guard = DecodeFlagsGuard::enter(base_flags);
            let mut encoder = Encoder::new(&mut payload_writer);
            value.serialize(&mut encoder)
        };
        (
            serialize_result,
            payload_writer.len,
            payload_writer.digest.sum64(),
            payload_writer.inner.rejected_write,
        )
    };
    if destination_rejected_write {
        return Err(Error::LengthMismatch.into());
    }
    serialize_result?;
    if payload_len != expected_payload_len || bounded.len() != encoded_bytes {
        return Err(Error::LengthMismatch.into());
    }
    let compact_len_used = compact_len_used();
    drop(encode_guard);
    let final_flags = finalized_encode_flags(base_flags, compact_len_used);
    let mut header = Header::new(
        crate::schema::identity::frame_hash::<T>(),
        header_payload_len,
        checksum,
    );
    header.flags |= final_flags;
    {
        let mut header_slice = &mut out[..Header::SIZE];
        header.write(&mut header_slice)?;
    }
    Ok(out)
}
/// Serialize an object to a new byte vector.
///
/// The returned buffer begins with [`Header::SIZE`] bytes reserved for the metadata header followed
/// by the archived payload. The header is populated after serialization so that the checksum and
/// length fields reflect the final payload.
pub fn to_bytes<T: NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    to_bytes_in(value, &mut out)?;
    Ok(out)
}
/// Serialize an object into the provided byte buffer.
///
/// The output buffer will be overwritten with a Norito-framed payload containing
/// the header, alignment padding, and archived bytes.
pub fn to_bytes_in<T: NoritoSerialize>(value: &T, out: &mut Vec<u8>) -> Result<(), Error> {
    let encode_guard = EncodeContextGuard::enter();
    let base_flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    validate_header_flags(base_flags)?;
    let flags = base_flags;
    let padding = payload_alignment_padding_for::<T>();
    let headroom = Header::SIZE + padding;
    let mut sink = ByteSink::with_headroom_from(std::mem::take(out), 0, headroom);
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut encoder = Encoder::for_byte_sink(&mut sink);
        value.serialize(&mut encoder)?;
    }
    let payload_len = sink.buf.len().saturating_sub(headroom) as u64;
    let checksum = sink.checksum();
    let compact_len_used = compact_len_used();
    drop(encode_guard);
    let final_flags = finalized_encode_flags(flags, compact_len_used);
    let mut header = Header::new(
        crate::schema::identity::frame_hash::<T>(),
        payload_len,
        checksum,
    );
    header.flags |= final_flags;
    {
        let mut header_slice = &mut sink.buf[..Header::SIZE];
        header.write(&mut header_slice)?;
    }
    *out = sink.into_inner();
    Ok(())
}
/// Serialize an object with a Norito header directly into a seekable writer.
///
/// This is the file-backed equivalent of [`to_bytes`]. It writes a placeholder
/// header first, streams the payload while computing its checksum and final
/// layout flags, then seeks back to fill in the header.
pub fn to_writer_seek<T, W>(writer: &mut W, value: &T) -> Result<(), Error>
where
    T: NoritoSerialize,
    W: Write + Seek,
{
    let start = writer.stream_position()?;
    let encode_guard = EncodeContextGuard::enter();
    let base_flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    validate_header_flags(base_flags)?;
    let flags = base_flags;
    let zero_header = [0u8; Header::SIZE];
    writer.write_all(&zero_header)?;
    let mut padding = payload_alignment_padding_for::<T>();
    if padding != 0 {
        const ZEROS: [u8; 64] = [0; 64];
        while padding != 0 {
            let chunk = padding.min(ZEROS.len());
            writer.write_all(&ZEROS[..chunk])?;
            padding -= chunk;
        }
    }
    let mut payload_writer = FramedPayloadWriter {
        inner: writer,
        len: 0,
        digest: crc64fast::Digest::new(),
    };
    {
        let _guard = DecodeFlagsGuard::enter(flags);
        let mut encoder = Encoder::new(&mut payload_writer);
        value.serialize(&mut encoder)?;
    }
    let payload_len = u64::try_from(payload_writer.len).map_err(|_| Error::LengthMismatch)?;
    let checksum = payload_writer.digest.sum64();
    let compact_len_used = compact_len_used();
    drop(encode_guard);
    let final_flags = finalized_encode_flags(flags, compact_len_used);
    let end = payload_writer.inner.stream_position()?;
    let mut header = Header::new(
        crate::schema::identity::frame_hash::<T>(),
        payload_len,
        checksum,
    );
    header.flags |= final_flags;
    payload_writer.inner.seek(SeekFrom::Start(start))?;
    header.write(&mut payload_writer.inner)?;
    payload_writer.inner.seek(SeekFrom::Start(end))?;
    Ok(())
}
/// Serialize one canonical Norito frame directly into a non-seekable writer.
///
/// A first, allocation-free pass counts the payload, computes its checksum, and records the layout
/// flags needed by the header. After writing that header and its alignment padding, a second pass
/// writes the payload directly. The second pass is rejected if its length, checksum, or finalized
/// flags differ from the first pass, so a stateful serializer cannot silently invalidate the
/// emitted frame.
///
/// This helper does not allocate output-sized scratch, but callers still need to audit any scratch
/// allocation performed inside `T::serialize` itself. An error after the header has been written
/// leaves a partial frame in `writer`; callers must discard that output.
///
/// # Errors
///
/// Returns the underlying writer or serializer error. It returns [`Error::LengthMismatch`],
/// [`Error::ChecksumMismatch`], or [`Error::NonCanonicalEncoding`] when the second serialization
/// pass changes its payload length, payload bytes, or layout flags, respectively.
#[doc(hidden)]
pub fn write_canonical_to_writer<T, W>(value: &T, writer: &mut W) -> Result<(), Error>
where
    T: NoritoSerialize,
    W: Write + ?Sized,
{
    write_frame_to_writer_with_flags(value, writer, default_encode_flags())
}
/// Serialize one Norito frame directly using the active layout flags.
///
/// This is the non-seekable, allocation-free-output counterpart to [`to_writer_seek`]. It preserves
/// ambient layout selection for serializers such as nested instruction frames. Callers that require
/// the canonical V1 layout independent of ambient state must use [`write_canonical_to_writer`].
/// Serializer-internal scratch still requires source auditing.
///
/// # Errors
///
/// Returns writer and serializer errors and rejects second-pass length,
/// checksum, or finalized-layout drift.
#[doc(hidden)]
pub fn write_frame_to_writer<T, W>(value: &T, writer: &mut W) -> Result<(), Error>
where
    T: NoritoSerialize,
    W: Write + ?Sized,
{
    let base_flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    write_frame_to_writer_with_flags(value, writer, base_flags)
}

#[cfg(test)]
mod write_canonical_tests {
    include!("core/write_canonical_tests.rs");
}
struct FramedPayloadWriter<'a, W: ?Sized> {
    inner: &'a mut W,
    len: usize,
    digest: crc64fast::Digest,
}
impl<W: Write + ?Sized> Write for FramedPayloadWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write_all(bytes)?;
        self.len = self.len.saturating_add(bytes.len());
        self.digest.write(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
/// Vec destination whose capacity was reserved before construction.
///
/// Every write checks both the semantic frame limit and the already-reserved capacity before
/// calling `extend_from_slice`, so that call cannot trigger a further allocation.
struct FixedCapacityVecWriter<'a> {
    out: &'a mut Vec<u8>,
    max_len: usize,
    rejected_write: bool,
}
impl<'a> FixedCapacityVecWriter<'a> {
    fn new(out: &'a mut Vec<u8>, max_len: usize) -> Self {
        Self {
            out,
            max_len,
            rejected_write: false,
        }
    }
    fn len(&self) -> usize {
        self.out.len()
    }
}
impl Write for FixedCapacityVecWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let Some(end) = self.out.len().checked_add(bytes.len()) else {
            self.rejected_write = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "bounded Norito frame length overflow",
            ));
        };
        if end > self.max_len || end > self.out.capacity() {
            self.rejected_write = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "bounded Norito frame capacity exceeded",
            ));
        }
        self.out.extend_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Frame a bare payload with a Norito header and explicitly supplied layout flags.
///
/// The caller supplies the flags of the payload's one declared encoding. This
/// helper does not infer them from ambient state or validate the payload's fields.
pub fn frame_bare_with_header_flags<T: NoritoSerialize>(
    payload: &[u8],
    flags: u8,
) -> Result<Vec<u8>, Error> {
    let padding = payload_alignment_padding_for::<T>();
    let frame_len = Header::SIZE
        .checked_add(padding)
        .and_then(|len| len.checked_add(payload.len()))
        .ok_or(Error::LengthMismatch)?;
    let mut out = Vec::with_capacity(frame_len);
    write_bare_frame_with_header_flags::<T, _>(&mut out, payload, flags)?;
    Ok(out)
}
/// Write a bare payload with a Norito header directly to `writer`.
///
/// This is the streaming equivalent of [`frame_bare_with_header_flags`]. It is
/// useful when the framed payload is embedded immediately into a larger archive
/// and materializing a temporary `Vec<u8>` would add avoidable copy traffic.
pub fn write_bare_frame_with_header_flags<T, W>(
    writer: &mut W,
    payload: &[u8],
    flags: u8,
) -> Result<(), Error>
where
    T: NoritoSerialize,
    W: Write + ?Sized,
{
    fixed_frame::write_bare_frame(
        writer,
        payload,
        crate::schema::identity::frame_hash::<T>(),
        payload_alignment_padding_for::<T>(),
        flags,
    )
}
/// Convenience: frame the currently-decoding bare payload (from payload context) with a Norito
/// header using the active decode flags so it can be decoded via `from_bytes`. Returns
/// `Error::MissingPayloadContext` when no payload context is active and `Error::MissingLayoutFlags`
/// if the decoder did not negotiate layout flags.
pub fn frame_current_payload_with_default_header<T: NoritoSerialize>() -> Result<Vec<u8>, Error> {
    if let Some(state) = payload_ctx_state() {
        if let Some(schema) = state.schema
            && schema != crate::schema::identity::frame_hash::<T>()
        {
            return Err(Error::SchemaMismatch);
        }
        // SAFETY: payload_ctx provides a valid slice for the active decode buffer
        let bytes = unsafe { core::slice::from_raw_parts(state.base as *const u8, state.len) };
        let header_flags = if state.flags_active {
            state.flags
        } else if let Some(flags) = current_decode_flags_effective() {
            flags
        } else {
            return Err(Error::MissingLayoutFlags);
        };
        frame_bare_with_header_flags::<T>(bytes, header_flags)
    } else {
        Err(Error::MissingPayloadContext)
    }
}
#[cfg(test)]
mod bytesink_tests {
    use super::*;
    #[test]
    fn bytesink_crc_matches_direct() {
        let mut s = ByteSink::with_headroom(4, Header::SIZE);
        s.write_all(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(s.checksum(), crc64(&[1, 2, 3, 4, 5]));
    }
    #[test]
    fn bytesink_typed_writes_le() {
        let mut s = ByteSink::with_headroom(0, 0);
        s.write_u16_le(0x1234);
        s.write_u32_le(0x89ABCDEF);
        s.write_u64_le(0x0123456789ABCDEF);
        let b = s.into_inner();
        assert_eq!(b.len(), 2 + 4 + 8);
        assert_eq!(&b[0..2], &0x1234u16.to_le_bytes());
        assert_eq!(&b[2..6], &0x89ABCDEFu32.to_le_bytes());
        assert_eq!(&b[6..14], &0x0123456789ABCDEFu64.to_le_bytes());
    }
    #[test]
    fn bytesink_align_to() {
        let mut s = ByteSink::with_headroom(0, 0);
        s.write_u8(0xAA);
        s.align_to(8);
        let before = s.buf.len();
        // Next write starts at 8-byte boundary
        s.write_u8(0xBB);
        let b = s.into_inner();
        assert_eq!(before, 8);
        assert_eq!(b[0], 0xAA);
        assert!(b[1..8].iter().all(|&x| x == 0));
        assert_eq!(b[8], 0xBB);
    }
}
/// Configuration for compression.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionConfig {
    /// Compression level for zstd.
    pub level: i32,
}
// Lightweight telemetry for compression decisions and cost.
// Always counts calls and bytes; timing is gated behind `adaptive-telemetry`.
mod telemetry_compress {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static NONE_SELECTED: AtomicU64 = AtomicU64::new(0);
    static ZSTD_SELECTED: AtomicU64 = AtomicU64::new(0);
    static BYTES_IN_TOTAL: AtomicU64 = AtomicU64::new(0);
    static BYTES_OUT_TOTAL: AtomicU64 = AtomicU64::new(0);
    #[cfg(feature = "adaptive-telemetry")]
    static COMPRESS_TIME_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
    #[derive(Clone, Copy, Debug)]
    pub struct Snapshot {
        pub calls: u64,
        pub none_selected: u64,
        pub zstd_selected: u64,
        pub bytes_in_total: u64,
        pub bytes_out_total: u64,
        #[cfg(feature = "adaptive-telemetry")]
        pub compress_time_ns_total: u64,
    }
    #[inline]
    pub fn record(is_zstd: bool, bytes_in: usize, bytes_out: usize, _time_ns: u64) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        if is_zstd {
            ZSTD_SELECTED.fetch_add(1, Ordering::Relaxed);
        } else {
            NONE_SELECTED.fetch_add(1, Ordering::Relaxed);
        }
        BYTES_IN_TOTAL.fetch_add(bytes_in as u64, Ordering::Relaxed);
        BYTES_OUT_TOTAL.fetch_add(bytes_out as u64, Ordering::Relaxed);
        #[cfg(feature = "adaptive-telemetry")]
        {
            COMPRESS_TIME_NS_TOTAL.fetch_add(_time_ns, Ordering::Relaxed);
        }
    }
    pub fn snapshot() -> Snapshot {
        Snapshot {
            calls: CALLS.load(Ordering::Relaxed),
            none_selected: NONE_SELECTED.load(Ordering::Relaxed),
            zstd_selected: ZSTD_SELECTED.load(Ordering::Relaxed),
            bytes_in_total: BYTES_IN_TOTAL.load(Ordering::Relaxed),
            bytes_out_total: BYTES_OUT_TOTAL.load(Ordering::Relaxed),
            #[cfg(feature = "adaptive-telemetry")]
            compress_time_ns_total: COMPRESS_TIME_NS_TOTAL.load(Ordering::Relaxed),
        }
    }
    pub fn reset() {
        CALLS.store(0, Ordering::Relaxed);
        NONE_SELECTED.store(0, Ordering::Relaxed);
        ZSTD_SELECTED.store(0, Ordering::Relaxed);
        BYTES_IN_TOTAL.store(0, Ordering::Relaxed);
        BYTES_OUT_TOTAL.store(0, Ordering::Relaxed);
        #[cfg(feature = "adaptive-telemetry")]
        {
            COMPRESS_TIME_NS_TOTAL.store(0, Ordering::Relaxed);
        }
    }
    pub(crate) use Snapshot as CompressSnapshot;
}
/// Return a snapshot of compression telemetry metrics.
pub fn compression_metrics_snapshot() -> telemetry_compress::CompressSnapshot {
    telemetry_compress::snapshot()
}
/// Reset compression telemetry metrics.
#[allow(dead_code)]
pub fn compression_metrics_reset() {
    telemetry_compress::reset()
}
/// JSON: export compression telemetry metrics as a compact JSON value.
#[cfg(feature = "json")]
pub fn compression_metrics_json_value() -> crate::json::Value {
    let s = compression_metrics_snapshot();
    let mut map = crate::json::Map::new();
    map.insert("calls".into(), crate::json::Value::from(s.calls));
    map.insert(
        "none_selected".into(),
        crate::json::Value::from(s.none_selected),
    );
    map.insert(
        "zstd_selected".into(),
        crate::json::Value::from(s.zstd_selected),
    );
    map.insert(
        "bytes_in_total".into(),
        crate::json::Value::from(s.bytes_in_total),
    );
    map.insert(
        "bytes_out_total".into(),
        crate::json::Value::from(s.bytes_out_total),
    );
    #[cfg(feature = "adaptive-telemetry")]
    {
        map.insert(
            "compress_time_ns_total".into(),
            crate::json::Value::from(s.compress_time_ns_total),
        );
    }
    crate::json::Value::Object(map)
}
/// JSON: export compression telemetry metrics as a compact JSON string.
#[cfg(feature = "json")]
pub fn compression_metrics_json_string() -> String {
    let v = compression_metrics_json_value();
    crate::json::to_string(&v).unwrap_or_else(|_| String::from("{}"))
}
/// JSON: compute fieldwise delta between two compression telemetry JSON maps.
#[cfg(feature = "json")]
pub fn compression_metrics_delta_json(
    prev: &crate::json::Value,
    curr: &crate::json::Value,
) -> crate::json::Value {
    use crate::json::Value;
    let mut out = crate::json::Map::new();
    let empty = crate::json::Map::new();
    let p = prev.as_object().unwrap_or(&empty);
    let c = curr.as_object().unwrap_or(&empty);
    for k in [
        "calls",
        "none_selected",
        "zstd_selected",
        "bytes_in_total",
        "bytes_out_total",
        #[cfg(feature = "adaptive-telemetry")]
        "compress_time_ns_total",
    ] {
        if let (Some(Value::Number(a)), Some(Value::Number(b))) = (p.get(k), c.get(k)) {
            let av = a.as_u64().unwrap_or(0);
            let bv = b.as_u64().unwrap_or(0);
            out.insert(k.to_string(), Value::from(bv.saturating_sub(av)));
        }
    }
    Value::Object(out)
}
/// Serialize an object and adaptively choose compression based on payload size
/// and hardware availability.
///
/// This API preserves determinism and on‑wire format stability: it only picks whether to apply zstd
/// compression (and GPU offload when compiled and available) based on heuristics. The header
/// encodes the chosen compression and layout flags exactly as in [`to_compressed_bytes`].
pub fn to_bytes_auto<T: NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    let (payload, flags) = encode_bare_with_flags(value)?;
    let checksum = crc64(&payload);
    let len = payload.len() as u64;
    // Choose compression engine using heuristics module
    #[cfg(feature = "adaptive-telemetry")]
    let __t0 = std::time::Instant::now();
    let (algorithm, body) = match heuristics::compress_auto(payload) {
        Ok((Compression::None, p)) => (Compression::None, p),
        Ok((Compression::Zstd, p)) => (Compression::Zstd, p),
        Err(e) => return Err(e.into()),
    };
    #[cfg(feature = "adaptive-telemetry")]
    let __ns = __t0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    #[cfg(not(feature = "adaptive-telemetry"))]
    let __ns: u64 = 0;
    telemetry_compress::record(
        matches!(algorithm, Compression::Zstd),
        len as usize,
        body.len(),
        __ns,
    );
    let padding = if matches!(algorithm, Compression::None) {
        payload_alignment_padding_for::<T>()
    } else {
        0
    };
    let mut out = Vec::with_capacity(Header::SIZE + padding + body.len());
    let mut header = Header::new(crate::schema::identity::frame_hash::<T>(), len, checksum);
    header.compression = algorithm;
    header.flags |= flags;
    header.write(&mut out)?;
    if padding != 0 {
        let len = out.len();
        out.resize(len + padding, 0);
    }
    out.extend_from_slice(&body);
    Ok(out)
}
/// Serialize an object using optional compression.
///
/// When the `gpu-compression` feature is enabled, the zstd encoder is executed on the GPU (CUDA on
/// most platforms, Metal on Apple silicon). Otherwise, the CPU implementation is used.
pub fn to_compressed_bytes<T: NoritoSerialize>(
    value: &T,
    compression: Option<CompressionConfig>,
) -> Result<Vec<u8>, Error> {
    let (payload, flags) = encode_bare_with_flags(value)?;
    let checksum = crc64(&payload);
    let len = payload.len() as u64;
    #[cfg(feature = "adaptive-telemetry")]
    let __t0 = std::time::Instant::now();
    let (algorithm, body) = match compression {
        None => (Compression::None, payload),
        Some(cfg) => {
            #[cfg(not(feature = "compression"))]
            {
                let _ = cfg;
                return Err(std::io::Error::other("compression support disabled").into());
            }
            #[cfg(all(feature = "compression", feature = "gpu-compression"))]
            {
                (Compression::Zstd, gpu_zstd::encode_all(payload, cfg.level)?)
            }
            #[cfg(all(feature = "compression", not(feature = "gpu-compression")))]
            {
                (
                    Compression::Zstd,
                    zstd::encode_all(std::io::Cursor::new(payload), cfg.level)?,
                )
            }
        }
    };
    #[cfg(feature = "adaptive-telemetry")]
    let __ns = __t0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    #[cfg(not(feature = "adaptive-telemetry"))]
    let __ns: u64 = 0;
    telemetry_compress::record(
        matches!(algorithm, Compression::Zstd),
        len as usize,
        body.len(),
        __ns,
    );
    let padding = if matches!(algorithm, Compression::None) {
        payload_alignment_padding_for::<T>()
    } else {
        0
    };
    let mut out = Vec::with_capacity(Header::SIZE + padding + body.len());
    let mut header = Header::new(crate::schema::identity::frame_hash::<T>(), len, checksum);
    header.compression = algorithm;
    header.flags |= flags;
    header.write(&mut out)?;
    if padding != 0 {
        let len = out.len();
        out.resize(len + padding, 0);
    }
    out.extend_from_slice(&body);
    Ok(out)
}
#[cfg(feature = "compression")]
fn validate_zstd_stream(compressed: &[u8]) -> Result<(), Error> {
    if compressed.is_empty() {
        return Err(Error::LengthMismatch);
    }
    let frame_len = zstd::zstd_safe::find_frame_compressed_size(compressed)
        .map_err(|_| Error::LengthMismatch)?;
    if frame_len != compressed.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(())
}
/// Decompress bytes produced by [`to_compressed_bytes`].
///
/// If the `gpu-compression` feature is enabled, decompression runs on the GPU
/// (CUDA or Metal depending on the target). Otherwise the CPU path is used.
///
/// Returns an owning archive wrapper so the payload bytes remain valid for the
/// lifetime of the returned value.
pub fn from_compressed_bytes<T: for<'de> NoritoDeserialize<'de>>(
    bytes: &[u8],
) -> Result<ArchivedBox<T>, Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    let header = Header::read(&mut cursor)?;
    prepare_header_decode(header.flags, true)?;
    if header.schema != crate::schema::identity::frame_hash::<T>() {
        return Err(Error::SchemaMismatch);
    }
    let payload_len = payload_len_to_usize(header.length)?;
    let compressed = &bytes[Header::SIZE..];
    let payload = match header.compression {
        Compression::None => {
            let padding = payload_alignment_padding_for::<T>();
            let trimmed = payload_without_leading_padding_exact(compressed, payload_len, padding)?;
            trimmed.to_vec()
        }
        Compression::Zstd => {
            #[cfg(feature = "compression")]
            validate_zstd_stream(compressed)?;
            #[cfg(all(feature = "compression", feature = "gpu-compression"))]
            {
                gpu_zstd::decode_all(compressed, header.length)?
            }
            #[cfg(all(feature = "compression", not(feature = "gpu-compression")))]
            {
                let decoder = zstd::Decoder::new(compressed)?;
                // Bound output to the declared payload length (+1 to detect overflow).
                let mut out = Vec::with_capacity(payload_len);
                let max_len = payload_len.saturating_add(1);
                decoder.take(max_len as u64).read_to_end(&mut out)?;
                out
            }
            #[cfg(not(feature = "compression"))]
            {
                return Err(std::io::Error::other("compression support disabled").into());
            }
        }
    };
    if payload.len() != payload_len {
        return Err(Error::LengthMismatch);
    }
    if crc64(&payload) != header.checksum {
        return Err(Error::ChecksumMismatch);
    }
    let archived = ArchivedBox::from_payload(payload);
    // Provide payload ctx so pointer-based decoders can read lengths/offsets.
    set_payload_ctx_state(archived.bytes(), Some(header.schema), Some(header.flags));
    Ok(archived)
}
/// Obtain a reference to an archived value from bytes.
///
/// The function validates the frame header, checksum, schema hash, payload
/// length, and alignment, then returns an opaque marker at the payload start
/// without allocating. Type-specific payload bounds and structure are checked
/// by the subsequent fallible [`DeserializePayload::try_deserialize`] call.
pub fn from_bytes<'a, T: NoritoDeserialize<'a>>(bytes: &'a [u8]) -> Result<&'a Archived<T>, Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    let header = Header::read(&mut cursor)?;
    prepare_header_decode(header.flags, true)?;
    if header.compression != Compression::None {
        return Err(Error::unsupported_compression_with(
            header.compression as u8,
            &[Compression::None],
        ));
    }
    if header.schema != crate::schema::identity::frame_hash::<T>() {
        return Err(Error::SchemaMismatch);
    }
    let pos = cursor.position() as usize;
    let slice = &bytes[pos..];
    let payload_len = payload_len_to_usize(header.length)?;
    let padding = payload_alignment_padding_for::<T>();
    let payload = payload_without_leading_padding_exact(slice, payload_len, padding)?;
    if crc64(payload) != header.checksum {
        return Err(Error::ChecksumMismatch);
    }
    let align = archived_payload_align::<T>();
    if align > 1 && (payload.as_ptr() as usize & (align - 1)) != 0 {
        return Err(Error::misaligned(align, payload.as_ptr()));
    }
    // Provide payload ctx for any subsequent decoders that rely on it.
    set_payload_ctx_state(payload, Some(header.schema), Some(header.flags));
    let ptr = if payload.is_empty() {
        empty_archived_ptr::<T>()
    } else {
        payload.as_ptr().cast::<Archived<T>>()
    };
    // SAFETY: `ptr` addresses either the validated payload or the non-null
    // dangling marker used only for a zero-sized archived payload.
    Ok(unsafe { &*ptr })
}
/// A validated view over an archived payload.
///
/// This contains a reference to the payload bytes (after the header) and carries the decode flags
/// set from the header. Constructing a view is observational: it does not install payload or layout
/// state in thread-local decode context. Decode methods scope that state to the operation and
/// restore the caller's state on success, error, or unwind.
#[derive(Clone, Copy)]
pub struct ArchiveView<'a> {
    bytes: &'a [u8],
    padding_len: usize,
    flags: u8,
    schema: [u8; 16],
}
impl<'a> ArchiveView<'a> {
    /// Payload bytes (already validated by checksum and header length).
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Expose header layout flags.
    pub fn flags(&self) -> u8 {
        self.flags
    }
    /// Expose the schema hash stored in the header.
    pub fn schema(&self) -> [u8; 16] {
        self.schema
    }
    fn decode_with<T, F>(&self, decode: F) -> Result<T, Error>
    where
        F: FnOnce(&'a [u8]) -> Result<(T, usize), Error>,
    {
        let _ctx =
            PayloadCtxGuard::enter_with_schema_and_flags(self.bytes, self.schema, self.flags);
        let (value, used) = decode(self.bytes)?;
        validate_decode_consumption(self.bytes, used)?;
        Ok(value)
    }
    fn decode_inner<T: DecodeFromSlice<'a>>(&self) -> Result<T, Error> {
        self.decode_with(T::decode_from_slice)
    }
    /// Decode a value from the payload using the bounded slice-based path,
    /// enforcing the header schema hash and payload-derived resource limits.
    pub fn decode<T>(&self) -> Result<T, Error>
    where
        T: DecodeFromSlice<'a> + NoritoDeserialize<'a>,
    {
        if self.schema != crate::schema::identity::frame_hash::<T>() {
            return Err(Error::SchemaMismatch);
        }
        if self.padding_len != payload_alignment_padding_for::<T>() {
            return Err(Error::LengthMismatch);
        }
        with_decode_limits(crate::canonical_decode_limits(self.bytes.len()), || {
            self.decode_inner()
        })
    }
    /// Decode a value under payload-derived resource limits while requiring the
    /// slice decoder to consume the complete payload.
    ///
    /// This explicit name is retained for call sites that emphasize canonical
    /// framing. All V1 archive-view decoders require complete payload consumption.
    pub fn decode_exact<T>(&self) -> Result<T, Error>
    where
        T: DecodeFromSlice<'a> + NoritoDeserialize<'a>,
    {
        if self.schema != crate::schema::identity::frame_hash::<T>() {
            return Err(Error::SchemaMismatch);
        }
        if self.padding_len != payload_alignment_padding_for::<T>() {
            return Err(Error::LengthMismatch);
        }
        with_decode_limits(crate::canonical_decode_limits(self.bytes.len()), || {
            self.decode_inner()
        })
    }
    /// Decode a value with a custom payload decoder while enforcing the header schema,
    /// type-specific padding, payload-derived resource limits, and complete payload consumption.
    ///
    /// `T` is the original wire type and determines schema and padding. `R` may retain borrowed
    /// payload views or independently prepaid allocations instead of reconstructing `T`. The
    /// callback remains responsible for field structure and canonical validation; a frame view
    /// never authenticates the decoded value. It must report complete payload consumption.
    ///
    /// The view's payload context and layout flags are installed only while `decode` runs and are
    /// restored even if the decoder returns an error or unwinds. Payload-derived limits compose
    /// with any stricter outer decoder budget regardless of the callback's result type.
    pub fn decode_exact_with<T, R, F>(&self, decode: F) -> Result<R, Error>
    where
        T: NoritoDeserialize<'a>,
        F: FnOnce(&'a [u8]) -> Result<(R, usize), Error>,
    {
        if self.schema != crate::schema::identity::frame_hash::<T>() {
            return Err(Error::SchemaMismatch);
        }
        if self.padding_len != payload_alignment_padding_for::<T>() {
            return Err(Error::LengthMismatch);
        }
        with_decode_limits(crate::canonical_decode_limits(self.bytes.len()), || {
            self.decode_with(decode)
        })
    }
    /// Decode a value under payload-derived resource limits without enforcing the schema hash.
    pub fn decode_unchecked<T: DecodeFromSlice<'a>>(&self) -> Result<T, Error> {
        with_decode_limits(crate::canonical_decode_limits(self.bytes.len()), || {
            self.decode_inner()
        })
    }
}
fn validate_decode_consumption(bytes: &[u8], used: usize) -> Result<(), Error> {
    if used == bytes.len() {
        return Ok(());
    }
    Err(Error::LengthMismatch)
}
/// Validate bytes and return an archive view over the payload slice.
pub fn from_bytes_view<'a>(bytes: &'a [u8]) -> Result<ArchiveView<'a>, Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    let header = Header::read(&mut cursor)?;
    if header.compression != Compression::None {
        return Err(Error::unsupported_compression_with(
            header.compression as u8,
            &[Compression::None],
        ));
    }
    let pos = cursor.position() as usize;
    let slice = &bytes[pos..];
    let payload_len = payload_len_to_usize(header.length)?;
    let payload = payload_without_leading_padding(slice, payload_len, MAX_HEADER_PADDING)?;
    let padding_len = slice.len() - payload.len();
    if crc64(payload) != header.checksum {
        return Err(Error::ChecksumMismatch);
    }
    Ok(ArchiveView {
        bytes: payload,
        padding_len,
        flags: header.flags,
        schema: header.schema,
    })
}
/// Decode a value of `T` directly from bytes via an archive view under a
/// payload-derived resource budget.
pub fn decode_from_bytes<'a, T>(bytes: &'a [u8]) -> Result<T, Error>
where
    T: crate::NoritoDeserialize<'a> + DecodeFromSlice<'a> + 'a,
{
    with_decode_limits(crate::canonical_decode_limits(bytes.len()), || {
        decode_from_bytes_inner(bytes)
    })
}
fn decode_from_bytes_inner<'a, T>(bytes: &'a [u8]) -> Result<T, Error>
where
    T: crate::NoritoDeserialize<'a> + DecodeFromSlice<'a> + 'a,
{
    let _state_guard = IsolatedDecodeGuard::enter();
    let view = from_bytes_view(bytes)?;
    if view.schema() != crate::schema::identity::frame_hash::<T>() {
        return Err(Error::SchemaMismatch);
    }
    if view.padding_len != payload_alignment_padding_for::<T>() {
        return Err(Error::LengthMismatch);
    }
    let payload_src = view.as_bytes();
    let flags = view.flags;
    crate::guarded_try_deserialize(|| {
        let _guard = PayloadCtxGuard::enter_with_flags(payload_src, flags);
        let (value, used) = <T as DecodeFromSlice>::decode_from_slice(payload_src)?;
        validate_decode_consumption(payload_src, used)?;
        Ok(value)
    })
}
/// Bounded slice decode with an explicit resource budget.
///
/// This enters the private decoder directly, allowing a caller to select a larger, still-finite
/// budget without inheriting the payload-derived default. Nested calls cannot relax a limit already
/// active in the calling decode scope.
///
/// # Errors
///
/// Returns an archive-validation, deserialization, or resource-budget error.
pub fn decode_from_bytes_with_limits<'a, T>(
    bytes: &'a [u8],
    limits: DecodeLimits,
) -> Result<T, Error>
where
    T: crate::NoritoDeserialize<'a> + DecodeFromSlice<'a> + 'a,
{
    with_decode_limits(limits, || decode_from_bytes_inner(bytes))
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldDecodeBoundary {
    Canonical,
    Prefix,
}
thread_local! {
    static FIELD_DECODE_BOUNDARY: Cell<FieldDecodeBoundary> =
        const { Cell::new(FieldDecodeBoundary::Canonical) };
}
struct FieldDecodeBoundaryGuard {
    previous: FieldDecodeBoundary,
}
impl FieldDecodeBoundaryGuard {
    fn enter(boundary: FieldDecodeBoundary) -> Self {
        let previous = FIELD_DECODE_BOUNDARY.with(|slot| slot.replace(boundary));
        Self { previous }
    }
}
impl Drop for FieldDecodeBoundaryGuard {
    fn drop(&mut self) {
        FIELD_DECODE_BOUNDARY.with(|slot| slot.set(self.previous));
    }
}
trait ErasedFieldSlot {
    fn archived_align(&self) -> usize;
    fn archived_size(&self) -> usize;
    fn dangling_archived(&self) -> *const u8;
    fn type_name(&self) -> &'static str;
    unsafe fn try_decode(&mut self, archived: *const u8) -> Result<(), Error>;
    fn canonical_match(&self, expected: &[u8], require_complete: bool) -> Result<usize, Error>;
}
fn match_canonical_payload(
    value: &dyn SerializePayload,
    expected: &[u8],
    require_complete: bool,
) -> Result<usize, Error> {
    let mut exact = ExactSliceWriter::new(expected);
    let encode_result = serialize_to_writer(value, &mut exact);
    if exact.mismatched() {
        return Err(Error::LengthMismatch);
    }
    encode_result?;
    if require_complete && !exact.is_complete() {
        return Err(Error::LengthMismatch);
    }
    Ok(exact.matched_len())
}
pub(crate) struct TypedFieldSlot<T> {
    value: Option<T>,
}
impl<T> TypedFieldSlot<T> {
    pub(crate) fn new() -> Self {
        Self { value: None }
    }
    pub(crate) fn into_value(mut self) -> Result<T, Error> {
        self.take_value()
    }
    pub(crate) fn take_value(&mut self) -> Result<T, Error> {
        self.value.take().ok_or(Error::LengthMismatch)
    }
    pub(crate) fn value(&self) -> Result<&T, Error> {
        self.value.as_ref().ok_or(Error::LengthMismatch)
    }
}
impl<T> ErasedFieldSlot for TypedFieldSlot<T>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    fn archived_align(&self) -> usize {
        archived_payload_align::<T>()
    }
    fn archived_size(&self) -> usize {
        archived_payload_size::<T>()
    }
    fn dangling_archived(&self) -> *const u8 {
        empty_archived_ptr::<T>().cast::<u8>()
    }
    fn type_name(&self) -> &'static str {
        core::any::type_name::<T>()
    }
    unsafe fn try_decode(&mut self, archived: *const u8) -> Result<(), Error> {
        let archived = unsafe { &*archived.cast::<Archived<T>>() };
        let value = T::try_deserialize(archived)?;
        self.value = Some(value);
        Ok(())
    }
    fn canonical_match(&self, expected: &[u8], require_complete: bool) -> Result<usize, Error> {
        let value = self.value.as_ref().ok_or(Error::LengthMismatch)?;
        match_canonical_payload(value, expected, require_complete)
    }
}
fn invoke_erased_field_decoder(
    slot: &mut dyn ErasedFieldSlot,
    archived: *const u8,
) -> Result<(), Error> {
    let type_name = slot.type_name();
    let mut decode = || unsafe { slot.try_decode(archived) };
    crate::guarded_try_deserialize_erased(type_name, &mut decode)
}
fn resolve_erased_field_used(
    boundary: FieldDecodeBoundary,
    slot: &dyn ErasedFieldSlot,
    payload: &[u8],
    used_ctx: Option<usize>,
) -> Result<usize, Error> {
    let payload_len = payload.len();
    match boundary {
        FieldDecodeBoundary::Canonical => match used_ctx {
            Some(used) if used != 0 => {
                if used == payload_len {
                    Ok(used)
                } else if used > payload_len {
                    Err(Error::LengthMismatch)
                } else {
                    slot.canonical_match(payload, true)
                }
            }
            _ => slot.canonical_match(payload, true),
        },
        FieldDecodeBoundary::Prefix => {
            if let Some(used) = used_ctx.filter(|used| *used != 0) {
                if used > payload_len {
                    return Err(Error::LengthMismatch);
                }
                let canonical = slot.canonical_match(payload, false)?;
                if used > canonical {
                    return Err(Error::LengthMismatch);
                }
                Ok(canonical)
            } else {
                slot.canonical_match(payload, false)
            }
        }
    }
}
#[inline(never)]
fn decode_field_erased(
    bytes: &[u8],
    boundary: FieldDecodeBoundary,
    slot: &mut dyn ErasedFieldSlot,
) -> Result<usize, Error> {
    if matches!(boundary, FieldDecodeBoundary::Canonical) {
        // The canonical field slice is borrowed. Check its wire-size ceiling
        // here; concrete decoders charge only buffers and owned values they
        // actually allocate (including any required realignment copy).
        check_decode_field_length(u64::try_from(bytes.len()).map_err(|_| Error::LengthMismatch)?)?;
    }
    let _depth = DecodeDepthGuard::enter()?;
    if bytes.is_empty() {
        if slot.archived_size() != 0 {
            return Err(Error::LengthMismatch);
        }
        let _guard = PayloadCtxGuard::enter(&[]);
        let dangling = slot.dangling_archived();
        invoke_erased_field_decoder(slot, dangling)?;
        return Ok(0);
    }
    struct RootGuard(bool);
    impl Drop for RootGuard {
        fn drop(&mut self) {
            if self.0 {
                clear_decode_root();
            }
        }
    }
    let _root_guard = if payload_root_span().is_none() {
        set_decode_root(bytes);
        Some(RootGuard(true))
    } else {
        None
    };
    let _flags_guard = enter_field_codec_flags();
    let align = slot.archived_align();
    let needs_realign = align > 1 && !(bytes.as_ptr() as usize).is_multiple_of(align);
    let aligned = if needs_realign {
        Some(ArchiveSlice::new(bytes, align)?)
    } else {
        None
    };
    let payload = match aligned.as_ref() {
        Some(aligned) => aligned.as_slice(),
        None => bytes,
    };
    if crate::debug_trace_enabled() && matches!(boundary, FieldDecodeBoundary::Canonical) {
        let path = if needs_realign {
            "misaligned"
        } else {
            "aligned"
        };
        eprintln!(
            "decode_field_canonical::<{}> {path} path len={} align={}",
            slot.type_name(),
            bytes.len(),
            align
        );
    }
    let payload_guard = PayloadCtxGuard::enter(payload);
    let _boundary_guard = FieldDecodeBoundaryGuard::enter(boundary);
    invoke_erased_field_decoder(slot, payload.as_ptr())?;
    let used_ctx = payload_ctx_max_access();
    drop(payload_guard);
    let used = resolve_erased_field_used(boundary, slot, bytes, used_ctx)?;
    // A realigned copy cannot merge its child context into the caller, and
    // scalar decoders may not record an access at all. Record the resolved
    // canonical consumption against the original field in both cases.
    note_payload_access(bytes, used);
    Ok(used)
}
/// Decode into one caller-retained value slot, returning no large owned temporary through
/// the framing and resource-scope stack. The slot owns cleanup on every failure or unwind.
pub(crate) fn decode_field_canonical_into_slot<T>(
    bytes: &[u8],
    slot: &mut TypedFieldSlot<T>,
) -> Result<(), Error>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    let used = decode_field_erased(bytes, FieldDecodeBoundary::Canonical, slot)?;
    if used != bytes.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(())
}
/// Decode a field payload using the canonical codec implementation without
/// requiring a specialized `DecodeFromSlice` implementation.
///
/// Returns both the decoded value and the number of bytes that were consumed from `bytes`.
pub fn decode_field_canonical<T>(bytes: &[u8]) -> Result<(T, usize), Error>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    let mut slot = TypedFieldSlot::<T>::new();
    let used = decode_field_erased(bytes, FieldDecodeBoundary::Canonical, &mut slot)?;
    Ok((slot.into_value()?, used))
}
/// Decode a single field from the front of `bytes`, permitting trailing bytes after the field.
///
/// This is intended for callers that decode a self-delimiting value followed by bytes they own
/// (for example an outer frame's trailer). The returned `usize` is the canonical byte length
/// consumed by the decoded field; the caller decides whether the remainder is permitted.
pub fn decode_field_prefix<T>(bytes: &[u8]) -> Result<(T, usize), Error>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    let mut slot = TypedFieldSlot::<T>::new();
    let used = decode_field_erased(bytes, FieldDecodeBoundary::Prefix, &mut slot)?;
    Ok((slot.into_value()?, used))
}
/// Borrow `len` bytes at `offset` from the active payload context and return the next offset.
#[inline(never)]
fn take_context_field(
    ptr: *const u8,
    offset: usize,
    len: usize,
) -> Result<(&'static [u8], usize), Error> {
    let payload = payload_slice_from_ptr(ptr)?;
    let end = offset.checked_add(len).ok_or(Error::LengthMismatch)?;
    let field = payload.get(offset..end).ok_or(Error::LengthMismatch)?;
    Ok((field, end))
}
#[inline(never)]
fn take_length_prefixed_context_field(
    ptr: *const u8,
    offset: usize,
) -> Result<(&'static [u8], usize), Error> {
    take_length_prefixed_field(payload_slice_from_ptr(ptr)?, offset)
}
fn take_length_prefixed_field(payload: &[u8], offset: usize) -> Result<(&[u8], usize), Error> {
    let remaining = payload.get(offset..).ok_or(Error::LengthMismatch)?;
    // Framing borrows the original payload; it owns no body or alignment buffer.
    // Concrete child decoders charge the storage they actually construct.
    let (field_len, header_len) = inspect_len_from_slice(remaining)?;
    let data_start = offset
        .checked_add(header_len)
        .ok_or(Error::LengthMismatch)?;
    let data_end = data_start
        .checked_add(field_len)
        .ok_or(Error::LengthMismatch)?;
    let field = payload
        .get(data_start..data_end)
        .ok_or(Error::LengthMismatch)?;
    Ok((field, data_end))
}
/// Decode one length-prefixed field relative to an active payload context.
///
/// This is a shared implementation detail for derive-generated decoders. It
/// advances `offset` past the framing header and the canonically consumed
/// field, while keeping all pointer/range validation in one non-generic path.
#[doc(hidden)]
#[inline(never)]
pub fn decode_context_field_canonical<T>(ptr: *const u8, offset: &mut usize) -> Result<T, Error>
where
    T: for<'de> crate::DeserializePayload<'de> + crate::SerializePayload,
{
    let (field, next_offset) = take_length_prefixed_context_field(ptr, *offset)?;
    let (value, used) = decode_field_canonical::<T>(field)?;
    if used != field.len() {
        return Err(Error::LengthMismatch);
    }
    *offset = next_offset;
    Ok(value)
}
/// Copy one fixed-width byte-array field relative to an active payload context.
///
/// The field has no length prefix; hand-written decoders use this for raw `[u8; N]` members.
#[doc(hidden)]
#[inline(never)]
pub fn decode_context_byte_array<const N: usize>(
    ptr: *const u8,
    offset: &mut usize,
) -> Result<[u8; N], Error> {
    let (field, next_offset) = take_context_field(ptr, *offset, N)?;
    let mut value = [0; N];
    value.copy_from_slice(field);
    *offset = next_offset;
    Ok(value)
}
/// Copy one length-prefixed byte-array field relative to an active payload context.
///
/// The prefix follows the active `COMPACT_LEN` layout and must declare exactly `N` bytes.
#[doc(hidden)]
#[inline(never)]
pub fn decode_context_framed_byte_array<const N: usize>(
    ptr: *const u8,
    offset: &mut usize,
) -> Result<[u8; N], Error> {
    let (field, next_offset) = take_length_prefixed_context_field(ptr, *offset)?;
    if field.len() != N {
        return Err(Error::LengthMismatch);
    }
    let mut value = [0; N];
    value.copy_from_slice(field);
    *offset = next_offset;
    Ok(value)
}
/// Finish a derive-generated field sequence at the active decode boundary.
///
/// Canonical field decodes must consume the complete payload. Prefix decodes may leave trailing
/// bytes for the caller and report their exact offset.
#[doc(hidden)]
#[inline(never)]
pub fn finish_context_fields(ptr: *const u8, offset: usize) -> Result<(), Error> {
    let payload = payload_slice_from_ptr(ptr)?;
    let boundary = FIELD_DECODE_BOUNDARY.with(Cell::get);
    if offset > payload.len()
        || (boundary == FieldDecodeBoundary::Canonical && offset != payload.len())
    {
        return Err(Error::LengthMismatch);
    }
    note_payload_access(payload, offset);
    Ok(())
}
/// Decode a field using its `DecodeFromSlice` implementation, ensuring full
/// consumption without re-encoding for canonical byte checks.
///
/// This is intended for hot paths where re-serializing is too costly and the
/// slice-based decoder already guarantees canonical consumption.
fn decode_field_with_slice_decoder<T>(
    bytes: &[u8],
    require_full_consumption: bool,
) -> Result<(T, usize), Error>
where
    T: for<'de> crate::DeserializePayload<'de> + for<'de> DecodeFromSlice<'de>,
{
    if bytes.is_empty() {
        if archived_payload_size::<T>() == 0 {
            let _guard = PayloadCtxGuard::enter(&[]);
            let value = unsafe {
                crate::guarded_try_deserialize(|| T::try_deserialize(&*empty_archived_ptr::<T>()))?
            };
            return Ok((value, 0));
        }
        return Err(Error::LengthMismatch);
    }
    struct RootGuard(bool);
    impl Drop for RootGuard {
        fn drop(&mut self) {
            if self.0 {
                clear_decode_root();
            }
        }
    }
    let _root_guard = if payload_root_span().is_none() {
        set_decode_root(bytes);
        Some(RootGuard(true))
    } else {
        None
    };
    let _flags_guard = enter_field_codec_flags();
    let payload_guard = PayloadCtxGuard::enter(bytes);
    let (value, used) = <T as DecodeFromSlice>::decode_from_slice(bytes)?;
    if require_full_consumption && used != bytes.len() {
        return Err(Error::LengthMismatch);
    }
    note_payload_access(bytes, used);
    drop(payload_guard);
    Ok((value, used))
}
pub fn decode_field_canonical_slice<T>(bytes: &[u8]) -> Result<(T, usize), Error>
where
    T: for<'de> crate::DeserializePayload<'de> + for<'de> DecodeFromSlice<'de>,
{
    decode_field_with_slice_decoder(bytes, true)
}
/// Decode a field using its `DecodeFromSlice` implementation, ensuring full
/// consumption without re-encoding for canonical byte checks.
///
/// This is intended for hot paths where re-serializing is too costly and the
/// slice-based decoder already guarantees canonical consumption.
pub fn decode_field_canonical_from_slice<T>(bytes: &[u8]) -> Result<(T, usize), Error>
where
    T: for<'de> crate::DeserializePayload<'de> + for<'de> DecodeFromSlice<'de>,
{
    decode_field_canonical_slice(bytes)
}
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "core/budget_context_tests.rs"]
mod budget_context_tests;

#[cfg(test)]
#[path = "core/history_owned_serialization_tests.rs"]
mod history_owned_serialization_tests;
