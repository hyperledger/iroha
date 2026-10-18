//! Count-first, allocation-bounded JSON serialization.
use super::{JsonObjectKey, JsonSerialize, MAX_JSON_VALUE_NESTING_DEPTH, Value, native};
use std::{
    alloc::{Layout, alloc},
    collections::{BTreeMap, BTreeSet},
    fmt,
    mem::MaybeUninit,
};
/// Fixed-shape failures from bounded JSON serialization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoundedJsonError {
    /// The serializer has no checked writer implementation.
    #[error("bounded JSON serialization is unsupported")]
    Unsupported,
    /// The compact JSON body exceeds the caller's byte cap.
    #[error("bounded JSON body exceeds its byte limit")]
    BodyTooLarge,
    /// Reserving the admitted destination buffer failed.
    #[error("bounded JSON destination allocation failed")]
    AllocationFailed,
    /// Original caller-budget or physical destination-allocation refusal.
    #[error(transparent)]
    DecodeResource(crate::core::DecodeResourceError),
    /// Original refusal with its private canonical admission scope identity.
    #[error(transparent)]
    ScopedDecodeResource(crate::core::ScopedDecodeResourceError),
    /// The serializer emitted a different length on its checked second pass.
    #[error("bounded JSON serializer length changed between passes")]
    LengthMismatch,
}
impl BoundedJsonError {
    /// Preserve the actual resource owner when a checked serializer joins binary decoding.
    #[doc(hidden)]
    pub fn from_decode_resource(error: crate::core::Error) -> Self {
        match error {
            crate::core::Error::ScopedDecodeResource(origin) => Self::ScopedDecodeResource(origin),
            error => error
                .decode_resource_error()
                .map_or(Self::Unsupported, Self::DecodeResource),
        }
    }

    /// Return the original binary resource error without reconstructing its scope identity.
    #[doc(hidden)]
    pub fn into_core_error(self) -> crate::core::Error {
        match self {
            Self::ScopedDecodeResource(origin) => crate::core::Error::ScopedDecodeResource(origin),
            Self::DecodeResource(error) => error.into(),
            Self::AllocationFailed => crate::core::Error::AllocationFailed { bytes: 0 },
            error => crate::core::Error::Message(error.to_string()),
        }
    }
}

/// A JSON output sink which checks every append before accepting it.
///
/// Implementations used by [`to_json_bounded`] never expose their destination
/// as an unbounded string. The hidden escape hatch exists only so legacy manual
/// serializers keep their ordinary, unbounded behaviour.
pub trait JsonWriteSink {
    /// Append one Unicode scalar value.
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError>;
    /// Append one UTF-8 string slice.
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError>;
    /// Reserve capacity for an ordinary unbounded sink.
    ///
    /// Counted and exact sinks ignore this hint because their capacity is admitted separately.
    fn reserve(&mut self, _additional: usize) -> Result<(), BoundedJsonError> {
        Ok(())
    }
    /// Enter a JSON array or object.
    ///
    /// Checked built-in sinks reserve one structural level for the terminal
    /// value, matching the parser's root-at-depth-one convention.
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        Ok(())
    }
    /// Enter an array or object which the writer has established is empty.
    ///
    /// The matching [`Self::end_container`] is still required. Between these calls the
    /// writer must emit only that empty container's delimiters. Checked built-in sinks
    /// admit the terminal structural level without reserving a nonexistent child level.
    /// Other sinks retain their ordinary paired container ownership by default.
    fn begin_empty_container(&mut self) -> Result<(), BoundedJsonError> {
        self.begin_container()
    }
    /// Leave one successfully entered JSON array or object, including on a returned write refusal.
    fn end_container(&mut self) {}
    /// Return the legacy output only for an ordinary unbounded write.
    #[doc(hidden)]
    fn unbounded_output(&mut self) -> Option<&mut String> {
        None
    }
}
pub(super) struct UnboundedJsonSink<'a> {
    output: &'a mut String,
}
impl<'a> UnboundedJsonSink<'a> {
    pub(super) fn new(output: &'a mut String) -> Self {
        Self { output }
    }
}
impl JsonWriteSink for UnboundedJsonSink<'_> {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.output.push(value);
        Ok(())
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        self.output.push_str(value);
        Ok(())
    }
    fn reserve(&mut self, additional: usize) -> Result<(), BoundedJsonError> {
        self.output.reserve(additional);
        Ok(())
    }
    fn unbounded_output(&mut self) -> Option<&mut String> {
        Some(self.output)
    }
}
struct CountingJsonSink {
    length: usize,
    limit: usize,
    depth: usize,
}
impl CountingJsonSink {
    fn new(limit: usize) -> Self {
        Self {
            length: 0,
            limit,
            depth: 0,
        }
    }
    fn admit(&mut self, additional: usize) -> Result<(), BoundedJsonError> {
        let next = self
            .length
            .checked_add(additional)
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        if next > self.limit {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.length = next;
        Ok(())
    }
}
impl JsonWriteSink for CountingJsonSink {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.admit(value.len_utf8())
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        self.admit(value.len())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if next >= MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn begin_empty_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if next > MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }
}
#[cfg(test)]
struct ExactJsonSink<'a> {
    output: &'a mut String,
    length: usize,
    expected: usize,
    depth: usize,
}
#[cfg(test)]
impl<'a> ExactJsonSink<'a> {
    fn new(output: &'a mut String, expected: usize) -> Self {
        Self {
            output,
            length: 0,
            expected,
            depth: 0,
        }
    }
    fn admit(&mut self, additional: usize) -> Result<(), BoundedJsonError> {
        let next = self
            .length
            .checked_add(additional)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        if next > self.expected {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.length = next;
        Ok(())
    }
}
#[cfg(test)]
impl JsonWriteSink for ExactJsonSink<'_> {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.admit(value.len_utf8())?;
        self.output.push(value);
        Ok(())
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        self.admit(value.len())?;
        self.output.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        if next >= MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.depth = next;
        Ok(())
    }
    fn begin_empty_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        if next > MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }
}
struct ExactBoxedJsonSink<'a> {
    output: &'a mut [MaybeUninit<u8>],
    length: usize,
    depth: usize,
}
impl<'a> ExactBoxedJsonSink<'a> {
    fn new(output: &'a mut [MaybeUninit<u8>]) -> Self {
        Self {
            output,
            length: 0,
            depth: 0,
        }
    }
    fn admit(&mut self, additional: usize) -> Result<std::ops::Range<usize>, BoundedJsonError> {
        let start = self.length;
        let end = start
            .checked_add(additional)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        if end > self.output.len() {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.length = end;
        Ok(start..end)
    }
}
impl JsonWriteSink for ExactBoxedJsonSink<'_> {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0_u8; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        let range = self.admit(value.len())?;
        for (slot, byte) in self.output[range].iter_mut().zip(value.bytes()) {
            slot.write(byte);
        }
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        if next >= MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.depth = next;
        Ok(())
    }
    fn begin_empty_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        if next > MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::LengthMismatch);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }
}
fn allocate_exact_json_destination(
    length: usize,
) -> Result<Box<[MaybeUninit<u8>]>, BoundedJsonError> {
    if length == 0 {
        return Ok(Vec::new().into_boxed_slice());
    }
    let bytes = u64::try_from(length).map_err(|_| BoundedJsonError::BodyTooLarge)?;
    let layout =
        Layout::array::<MaybeUninit<u8>>(length).map_err(|_| BoundedJsonError::BodyTooLarge)?;
    // SAFETY: `layout` is non-zero and came from `Layout::array`. A null
    // result is handled before the pointer is converted into an owning box.
    let allocation = unsafe { alloc(layout) }.cast::<MaybeUninit<u8>>();
    if allocation.is_null() {
        return Err(BoundedJsonError::DecodeResource(
            crate::core::DecodeResourceError::AllocationFailed { bytes },
        ));
    }
    let slice = std::ptr::slice_from_raw_parts_mut(allocation, length);
    // SAFETY: `allocation` owns exactly `layout`; a boxed slice of `length`
    // `MaybeUninit<u8>` values has that same layout and safely owns raw storage.
    Ok(unsafe { Box::from_raw(slice) })
}
fn to_json_bounded_boxed_with_allocator<T, A>(
    value: &T,
    max_bytes: usize,
    allocate_destination: A,
) -> Result<Box<[u8]>, BoundedJsonError>
where
    T: JsonSerialize + ?Sized,
    A: FnOnce(usize) -> Result<Box<[MaybeUninit<u8>]>, BoundedJsonError>,
{
    let mut counter = CountingJsonSink::new(max_bytes);
    value.json_serialize_to(&mut counter)?;
    let expected = counter.length;
    crate::core::reserve_decode_allocation(expected)
        .map_err(BoundedJsonError::from_decode_resource)?;
    record_destination_allocation_attempt();
    let mut output = allocate_destination(expected)?;
    if output.len() != expected {
        return Err(BoundedJsonError::LengthMismatch);
    }
    let actual = {
        let mut sink = ExactBoxedJsonSink::new(&mut output);
        value
            .json_serialize_to(&mut sink)
            .map_err(|error| match error {
                BoundedJsonError::DecodeResource(_)
                | BoundedJsonError::ScopedDecodeResource(_)
                | BoundedJsonError::AllocationFailed => error,
                _ => BoundedJsonError::LengthMismatch,
            })?;
        sink.length
    };
    if actual != expected {
        return Err(BoundedJsonError::LengthMismatch);
    }
    // SAFETY: a successful exact second pass initialized every element in the
    // slice. `MaybeUninit<u8>` and `u8` have identical layouts, and ownership
    // transfers without reallocating the destination.
    let output = unsafe { Box::from_raw(Box::into_raw(output) as *mut [u8]) };
    if std::str::from_utf8(&output).is_err() {
        return Err(BoundedJsonError::LengthMismatch);
    }
    Ok(output)
}
/// Serialize `value` only when its compact JSON body fits in `max_bytes`.
///
/// The first pass executes the checked serializer against an allocation-free counter. Only an
/// admitted exact-layout destination is allocated, after which the same checked serializer runs
/// again against a sink that rejects every overrun before it appends. The completed box is
/// transferred into a `String` without copying or reallocating. Stateful serializers which produce
/// a shorter second pass are rejected by the final equality check. When serialization runs inside
/// an active decode scope, the admitted destination is charged before allocation.
///
/// This is an output-only bound: it neither parses nor validates JSON input, and it cannot police
/// allocations inside user-provided serializers or field predicates. An explicit custom checked
/// serializer is a certification boundary: it must preserve JSON grammar and structural-depth
/// accounting and control its own allocations. Built-in checked writers avoid destination-sized
/// scratch data.
pub fn to_json_bounded<T: JsonSerialize + ?Sized>(
    value: &T,
    max_bytes: usize,
) -> Result<String, BoundedJsonError> {
    let output = to_json_bounded_boxed(value, max_bytes)?;
    String::from_utf8(output.into_vec()).map_err(|_| BoundedJsonError::LengthMismatch)
}
/// Serialize `value` into one exact-layout boxed UTF-8 destination.
///
/// This performs the same allocation-free count and checked second pass as
/// [`to_json_bounded`], but allocates the admitted byte layout directly. The
/// returned box therefore has no allocator-dependent spare capacity and can be
/// transferred into a response body without copying or reallocating it.
pub fn to_json_bounded_boxed<T: JsonSerialize + ?Sized>(
    value: &T,
    max_bytes: usize,
) -> Result<Box<[u8]>, BoundedJsonError> {
    to_json_bounded_boxed_with_allocator(value, max_bytes, allocate_exact_json_destination)
}
#[cfg(test)]
std::thread_local! {
    static DESTINATION_ALLOCATION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn record_destination_allocation_attempt() {
    DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
}
#[cfg(not(test))]
fn record_destination_allocation_attempt() {}
/// Write a JSON string with the canonical Norito escaping rules.
pub fn write_json_string_to<S: JsonWriteSink + ?Sized>(
    value: &str,
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    output.reserve(value.len().saturating_add(2))?;
    output.push('"')?;
    write_json_string_content_to(value, output)?;
    output.push('"')
}

enum JsonStringContent<'a> {
    Character(char),
    Text(&'a str),
}

fn visit_json_string_content<E>(
    value: &str,
    mut visitor: impl FnMut(JsonStringContent<'_>) -> Result<(), E>,
) -> Result<(), E> {
    for character in value.chars() {
        match character {
            '"' => visitor(JsonStringContent::Text("\\\""))?,
            '\\' => visitor(JsonStringContent::Text("\\\\"))?,
            '\n' => visitor(JsonStringContent::Text("\\n"))?,
            '\r' => visitor(JsonStringContent::Text("\\r"))?,
            '\t' => visitor(JsonStringContent::Text("\\t"))?,
            '\u{08}' => visitor(JsonStringContent::Text("\\b"))?,
            '\u{0C}' => visitor(JsonStringContent::Text("\\f"))?,
            control if (control as u32) < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let byte = control as u8;
                visitor(JsonStringContent::Text("\\u00"))?;
                visitor(JsonStringContent::Character(
                    HEX[(byte >> 4) as usize] as char,
                ))?;
                visitor(JsonStringContent::Character(
                    HEX[(byte & 0x0f) as usize] as char,
                ))?;
            }
            ordinary => visitor(JsonStringContent::Character(ordinary))?,
        }
    }
    Ok(())
}

pub(super) fn write_json_string_content_to<S: JsonWriteSink + ?Sized>(
    value: &str,
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    visit_json_string_content(value, |content| match content {
        JsonStringContent::Character(character) => output.push(character),
        JsonStringContent::Text(text) => output.push_str(text),
    })
}

/// Stream one [`fmt::Display`] value as a JSON string without staging its text.
///
/// The formatter's chunks are escaped with the same rules as [`write_json_string_to`]. A
/// checked-sink failure stops formatting immediately and is returned unchanged, so an output limit
/// cannot be hidden behind a later formatting error.
#[doc(hidden)]
pub fn write_json_display_to<T: fmt::Display + ?Sized, S: JsonWriteSink + ?Sized>(
    value: &T,
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    output.push('"')?;
    visit_json_display_text(value, |chunk| write_json_string_content_to(chunk, output))?;
    output.push('"')
}

/// Visit a display value's raw text without allocating an intermediate string.
///
/// This helper neither quotes nor escapes the text. It preserves the first
/// visitor error and stops subsequent visitor calls even if a formatter ignores
/// its write error. An intrinsic formatting failure returns
/// [`BoundedJsonError::Unsupported`].
///
/// # Errors
///
/// Returns the first visitor error, or `Unsupported` if formatting itself fails.
pub fn visit_json_display_text<T: fmt::Display + ?Sized>(
    value: &T,
    visitor: impl FnMut(&str) -> Result<(), BoundedJsonError>,
) -> Result<(), BoundedJsonError> {
    struct DisplayVisitor<F> {
        visitor: F,
        error: Option<BoundedJsonError>,
    }

    impl<F: FnMut(&str) -> Result<(), BoundedJsonError>> fmt::Write for DisplayVisitor<F> {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            if self.error.is_some() {
                return Err(fmt::Error);
            }
            match (self.visitor)(value) {
                Ok(()) => Ok(()),
                Err(error) => {
                    self.error = Some(error);
                    Err(fmt::Error)
                }
            }
        }
    }

    let mut streamed = DisplayVisitor {
        visitor,
        error: None,
    };
    let formatted = fmt::write(&mut streamed, format_args!("{value}"));
    if let Some(error) = streamed.error {
        return Err(error);
    }
    formatted.map_err(|_| BoundedJsonError::Unsupported)
}
fn write_json_string_content(value: &str, output: &mut String) {
    let result: Result<(), core::convert::Infallible> =
        visit_json_string_content(value, |content| {
            match content {
                JsonStringContent::Character(character) => output.push(character),
                JsonStringContent::Text(text) => output.push_str(text),
            }
            Ok(())
        });
    match result {
        Ok(()) => {}
        Err(error) => match error {},
    }
}
fn write_json_object_key<K: JsonObjectKey + ?Sized>(key: &K, output: &mut String) {
    output.push('"');
    let result: Result<(), core::convert::Infallible> = key.visit_json_key_text(|chunk| {
        write_json_string_content(chunk, output);
        Ok(())
    });
    match result {
        Ok(()) => {}
        Err(error) => match error {},
    }
    output.push('"');
}
fn write_json_object_key_to<K: JsonObjectKey + ?Sized>(
    key: &K,
    output: &mut dyn JsonWriteSink,
) -> Result<(), BoundedJsonError> {
    output.push('"')?;
    key.visit_json_key_text_checked(|chunk| write_json_string_content_to(chunk, output))?;
    output.push('"')
}
fn visit_u128_text<E>(
    mut value: u128,
    mut visitor: impl FnMut(&str) -> Result<(), E>,
) -> Result<(), E> {
    const BUFFER_LEN: usize = 39;
    let mut buffer = [0_u8; BUFFER_LEN];
    let mut start = buffer.len();
    if value == 0 {
        return visitor("0");
    }
    while value > 0 {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    // SAFETY: the populated suffix contains only ASCII decimal digits.
    visitor(unsafe { std::str::from_utf8_unchecked(&buffer[start..]) })
}
fn visit_i64_text<E>(value: i64, mut visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
    if value < 0 {
        visitor("-")?;
    }
    visit_u128_text(u128::from(value.unsigned_abs()), visitor)
}
fn write_u128_to<S: JsonWriteSink + ?Sized>(
    mut value: u128,
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    const BUF_LEN: usize = 39;
    let mut buffer = [0_u8; BUF_LEN];
    let mut start = buffer.len();
    if value == 0 {
        return output.push('0');
    }
    while value > 0 {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    // SAFETY: the buffer suffix contains only ASCII decimal digits.
    output.push_str(unsafe { std::str::from_utf8_unchecked(&buffer[start..]) })
}
fn write_i64_to<S: JsonWriteSink + ?Sized>(
    value: i64,
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    if value < 0 {
        output.push('-')?;
        write_u128_to(u128::from(value.unsigned_abs()), output)
    } else {
        write_u128_to(u128::from(value.unsigned_abs()), output)
    }
}
fn write_f64_to<S: JsonWriteSink + ?Sized>(
    value: f64,
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    if !value.is_finite() {
        return output.push_str("null");
    }
    let mut buffer = ryu::Buffer::new();
    let formatted = buffer.format_finite(value);
    if let Some(exp_index) = formatted.as_bytes().iter().position(|byte| *byte == b'e') {
        output.push_str(&formatted[..=exp_index])?;
        match formatted.as_bytes().get(exp_index + 1) {
            Some(b'+') | Some(b'-') => output.push_str(&formatted[exp_index + 1..]),
            Some(_) => {
                output.push('+')?;
                output.push_str(&formatted[exp_index + 1..])
            }
            None => Ok(()),
        }
    } else {
        output.push_str(formatted)
    }
}
fn encode_hex_to<S: JsonWriteSink + ?Sized>(
    bytes: &[u8],
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.reserve(bytes.len().saturating_mul(2).saturating_add(2))?;
    output.push('"')?;
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char)?;
        output.push(HEX[(byte & 0x0f) as usize] as char)?;
    }
    output.push('"')
}
/// Typed, straight-line JSON writer with an opt-in checked sink path.
pub trait FastJsonWrite {
    /// Fixed JSON object field order, when independent of the serialized value.
    ///
    /// Derived named structs report their emitted fields after renaming and
    /// skipping. Flattened fields and conditional omissions have no fixed order.
    /// Reading this schema never constructs or serializes a value.
    fn json_object_field_order() -> Option<&'static [&'static str]>
    where
        Self: Sized,
    {
        None
    }
    /// Serialize into the legacy unbounded string destination.
    fn write_json(&self, output: &mut String);
    /// Serialize into a checked sink.
    ///
    /// Existing manual implementations inherit a fail-closed bounded path but
    /// continue to work through the legacy unbounded destination.
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let Some(unbounded) = output.unbounded_output() else {
            return Err(BoundedJsonError::Unsupported);
        };
        self.write_json(unbounded);
        Ok(())
    }
}
/// Run a checked typed writer against the legacy unbounded destination.
#[doc(hidden)]
pub fn write_json_unbounded<T: FastJsonWrite + ?Sized>(value: &T, output: &mut String) {
    let mut sink = UnboundedJsonSink::new(output);
    value
        .write_json_to(&mut sink)
        .expect("checked JSON writer must accept the legacy unbounded sink");
}
impl FastJsonWrite for Value {
    fn write_json(&self, output: &mut String) {
        super::write_value_to_string(self, output, false, 0);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_value_to(self, output, 0)
    }
}
impl<T: JsonSerialize + ?Sized> FastJsonWrite for Box<T> {
    fn write_json(&self, output: &mut String) {
        (**self).json_serialize(output);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        (**self).json_serialize_to(output)
    }
}
/// Bridge: any type with a typed writer can serve as a JSON serializer.
impl<T: FastJsonWrite> JsonSerialize for T {
    fn json_serialize(&self, output: &mut String) {
        self.write_json(output)
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        self.write_json_to(output)
    }
}
impl JsonSerialize for bool {
    fn json_serialize(&self, output: &mut String) {
        output.push_str(if *self { "true" } else { "false" });
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.push_str(if *self { "true" } else { "false" })
    }
}
impl JsonObjectKey for bool {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        visitor(if *self { "true" } else { "false" })
    }
}
macro_rules! impl_nonzero_json {
    ($($ty:ty),+ $(,)?) => {$(impl_nonzero_json!(@one $ty);)+};
    (@one $ty:ty) => {
        impl JsonSerialize for $ty {
            fn json_serialize(&self, output: &mut String) {
                super::write_u128_json(output, u128::from(self.get()));
            }
            fn json_serialize_to(
                &self,
                output: &mut dyn JsonWriteSink,
            ) -> Result<(), BoundedJsonError> {
                write_u128_to(u128::from(self.get()), output)
            }
        }
        impl JsonObjectKey for $ty {
            fn visit_json_key_text<E>(
                &self,
                visitor: impl FnMut(&str) -> Result<(), E>,
            ) -> Result<(), E> {
                visit_u128_text(u128::from(self.get()), visitor)
            }
        }
    };
}
impl_nonzero_json!(
    core::num::NonZeroU128,
    core::num::NonZeroU64,
    core::num::NonZeroU32,
    core::num::NonZeroU16,
);
impl JsonSerialize for core::num::NonZeroUsize {
    fn json_serialize(&self, output: &mut String) {
        super::write_u128_json(output, u128::from(self.get() as u64));
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_u128_to(u128::from(self.get() as u64), output)
    }
}
impl JsonObjectKey for core::num::NonZeroUsize {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        visit_u128_text(u128::from(self.get() as u64), visitor)
    }
}
impl JsonSerialize for str {
    fn json_serialize(&self, output: &mut String) {
        super::write_json_string(self, output);
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_json_string_to(self, output)
    }
}
impl JsonSerialize for std::time::Duration {
    fn json_serialize(&self, output: &mut String) {
        output.push_str("{\"secs\":");
        JsonSerialize::json_serialize(&self.as_secs(), output);
        output.push_str(",\"nanos\":");
        JsonSerialize::json_serialize(&self.subsec_nanos(), output);
        output.push('}');
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.begin_container()?;
        let result = (|| {
            output.push_str("{\"secs\":")?;
            JsonSerialize::json_serialize_to(&self.as_secs(), output)?;
            output.push_str(",\"nanos\":")?;
            JsonSerialize::json_serialize_to(&self.subsec_nanos(), output)?;
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result
    }
}
impl<T: JsonSerialize> JsonSerialize for Option<T> {
    fn json_serialize(&self, output: &mut String) {
        match self {
            Some(value) => value.json_serialize(output),
            None => output.push_str("null"),
        }
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        match self {
            Some(value) => value.json_serialize_to(output),
            None => output.push_str("null"),
        }
    }
}
impl JsonSerialize for () {
    fn json_serialize(&self, output: &mut String) {
        output.push_str("null");
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.push_str("null")
    }
}
impl<T: JsonSerialize> JsonSerialize for Vec<T> {
    fn json_serialize(&self, output: &mut String) {
        output.push('[');
        for (index, value) in self.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            value.json_serialize(output);
        }
        output.push(']');
    }
    fn json_serialize_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.begin_container()?;
        let result = (|| {
            output.push('[')?;
            for (index, value) in self.iter().enumerate() {
                if index != 0 {
                    output.push(',')?;
                }
                value.json_serialize_to(output)?;
            }
            output.push(']')?;
            Ok(())
        })();
        output.end_container();
        result
    }
}
macro_rules! impl_unsigned_fast_json {
    ($($ty:ty),+ $(,)?) => {$(impl_unsigned_fast_json!(@one $ty);)+};
    (@one $ty:ty) => {
        impl FastJsonWrite for $ty {
            fn write_json(&self, output: &mut String) {
                super::write_u128_json(output, u128::from(*self));
            }
            fn write_json_to(
                &self,
                output: &mut dyn JsonWriteSink,
            ) -> Result<(), BoundedJsonError> {
                write_u128_to(u128::from(*self), output)
            }
        }
        impl JsonObjectKey for $ty {
            fn visit_json_key_text<E>(
                &self,
                visitor: impl FnMut(&str) -> Result<(), E>,
            ) -> Result<(), E> {
                visit_u128_text(u128::from(*self), visitor)
            }
        }
    };
}
macro_rules! impl_signed_fast_json {
    ($($ty:ty),+ $(,)?) => {$(impl_signed_fast_json!(@one $ty);)+};
    (@one $ty:ty) => {
        impl FastJsonWrite for $ty {
            fn write_json(&self, output: &mut String) {
                super::write_i64_json(output, i64::from(*self));
            }
            fn write_json_to(
                &self,
                output: &mut dyn JsonWriteSink,
            ) -> Result<(), BoundedJsonError> {
                write_i64_to(i64::from(*self), output)
            }
        }
        impl JsonObjectKey for $ty {
            fn visit_json_key_text<E>(
                &self,
                visitor: impl FnMut(&str) -> Result<(), E>,
            ) -> Result<(), E> {
                visit_i64_text(i64::from(*self), visitor)
            }
        }
    };
}
impl_unsigned_fast_json!(u8, u16, u32, u64, u128);
impl_signed_fast_json!(i8, i16, i32, i64);
impl FastJsonWrite for usize {
    fn write_json(&self, output: &mut String) {
        super::write_u128_json(output, u128::from(*self as u64));
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_u128_to(u128::from(*self as u64), output)
    }
}
impl JsonObjectKey for usize {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        visit_u128_text(u128::from(*self as u64), visitor)
    }
}
impl FastJsonWrite for isize {
    fn write_json(&self, output: &mut String) {
        super::write_i64_json(output, *self as i64);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_i64_to(*self as i64, output)
    }
}
impl JsonObjectKey for isize {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        visit_i64_text(*self as i64, visitor)
    }
}
impl<T: JsonSerialize + Ord> FastJsonWrite for BTreeSet<T> {
    fn write_json(&self, output: &mut String) {
        output.push('[');
        for (index, value) in self.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            value.json_serialize(output);
        }
        output.push(']');
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.begin_container()?;
        let result = (|| {
            output.push('[')?;
            for (index, value) in self.iter().enumerate() {
                if index != 0 {
                    output.push(',')?;
                }
                value.json_serialize_to(output)?;
            }
            output.push(']')?;
            Ok(())
        })();
        output.end_container();
        result
    }
}
impl<K, V> FastJsonWrite for BTreeMap<K, V>
where
    K: JsonObjectKey + Ord,
    V: JsonSerialize,
{
    fn write_json(&self, output: &mut String) {
        output.push('{');
        for (index, (key, value)) in self.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            write_json_object_key(key, output);
            output.push(':');
            value.json_serialize(output);
        }
        output.push('}');
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.begin_container()?;
        let result = (|| {
            output.push('{')?;
            for (index, (key, value)) in self.iter().enumerate() {
                if index != 0 {
                    output.push(',')?;
                }
                write_json_object_key_to(key, output)?;
                output.push(':')?;
                value.json_serialize_to(output)?;
            }
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result
    }
}
impl FastJsonWrite for f64 {
    fn write_json(&self, output: &mut String) {
        super::write_f64_json(*self, output);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_f64_to(*self, output)
    }
}
impl<T: FastJsonWrite + ?Sized> FastJsonWrite for &T {
    fn write_json(&self, output: &mut String) {
        (**self).write_json(output);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        (**self).write_json_to(output)
    }
}
impl<T: FastJsonWrite + ?Sized> FastJsonWrite for &mut T {
    fn write_json(&self, output: &mut String) {
        (**self).write_json(output);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        (**self).write_json_to(output)
    }
}
impl FastJsonWrite for str {
    fn write_json(&self, output: &mut String) {
        super::write_json_string(self, output);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_json_string_to(self, output)
    }
}
impl FastJsonWrite for String {
    fn write_json(&self, output: &mut String) {
        super::write_json_string(self, output);
    }
    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        write_json_string_to(self, output)
    }
}
impl JsonObjectKey for str {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        visitor(self)
    }
}
impl JsonObjectKey for String {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        self.as_str().visit_json_key_text(visitor)
    }
}
impl<T: JsonObjectKey + ?Sized> JsonObjectKey for &T {
    fn visit_json_key_text<E>(&self, visitor: impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        (**self).visit_json_key_text(visitor)
    }

    fn visit_json_key_text_checked(
        &self,
        visitor: impl FnMut(&str) -> Result<(), BoundedJsonError>,
    ) -> Result<(), BoundedJsonError> {
        (**self).visit_json_key_text_checked(visitor)
    }
}
pub(super) fn write_hex_to<S: JsonWriteSink + ?Sized>(
    bytes: &[u8],
    output: &mut S,
) -> Result<(), BoundedJsonError> {
    encode_hex_to(bytes, output)
}
pub(super) fn write_value_to<S: JsonWriteSink + ?Sized>(
    value: &Value,
    output: &mut S,
    depth: usize,
) -> Result<(), BoundedJsonError> {
    enum Frame<'a> {
        Value(&'a Value, usize),
        Array {
            values: core::slice::Iter<'a, Value>,
            child_depth: usize,
            wrote_value: bool,
        },
        Object {
            values: std::collections::btree_map::Iter<'a, String, Value>,
            child_depth: usize,
            wrote_value: bool,
        },
    }

    // One frame is needed for each admitted container plus its current child.
    // The extra slot lets an unchecked custom sink reach the first forbidden
    // child and receive the same `Unsupported` error as the recursive walker.
    const FRAME_CAPACITY: usize = MAX_JSON_VALUE_NESTING_DEPTH + 1;
    let mut frames: [Option<Frame<'_>>; FRAME_CAPACITY] = [const { None }; FRAME_CAPACITY];
    frames[0] = Some(Frame::Value(value, depth));
    let mut frame_count = 1_usize;

    let mut entered_containers = 0_usize;
    let result = (|| {
        while frame_count != 0 {
            frame_count -= 1;
            let frame = frames[frame_count]
                .take()
                .expect("JSON value writer frame must be initialized");
            match frame {
                Frame::Value(value, depth) => {
                    if depth >= MAX_JSON_VALUE_NESTING_DEPTH {
                        return Err(BoundedJsonError::Unsupported);
                    }
                    match value {
                        Value::Null => output.push_str("null")?,
                        Value::Bool(value) => {
                            output.push_str(if *value { "true" } else { "false" })?;
                        }
                        Value::Number(native::Number::I64(value)) => write_i64_to(*value, output)?,
                        Value::Number(native::Number::U64(value)) => {
                            write_u128_to(u128::from(*value), output)?;
                        }
                        Value::Number(native::Number::U128(value)) => {
                            write_u128_to(*value, output)?;
                        }
                        Value::Number(native::Number::F64(value)) => write_f64_to(*value, output)?,
                        Value::String(value) => write_json_string_to(value, output)?,
                        Value::Array(values) => {
                            if values.is_empty() {
                                output.begin_empty_container()?;
                            } else {
                                output.begin_container()?;
                            }
                            entered_containers += 1;
                            output.push('[')?;
                            let child_depth =
                                depth.checked_add(1).ok_or(BoundedJsonError::Unsupported)?;
                            frames[frame_count] = Some(Frame::Array {
                                values: values.iter(),
                                child_depth,
                                wrote_value: false,
                            });
                            frame_count += 1;
                        }
                        Value::Object(values) => {
                            if values.is_empty() {
                                output.begin_empty_container()?;
                            } else {
                                output.begin_container()?;
                            }
                            entered_containers += 1;
                            output.push('{')?;
                            let child_depth =
                                depth.checked_add(1).ok_or(BoundedJsonError::Unsupported)?;
                            frames[frame_count] = Some(Frame::Object {
                                values: values.iter(),
                                child_depth,
                                wrote_value: false,
                            });
                            frame_count += 1;
                        }
                    }
                }
                Frame::Array {
                    mut values,
                    child_depth,
                    wrote_value,
                } => {
                    if let Some(value) = values.next() {
                        if wrote_value {
                            output.push(',')?;
                        }
                        frames[frame_count] = Some(Frame::Array {
                            values,
                            child_depth,
                            wrote_value: true,
                        });
                        frame_count += 1;
                        frames[frame_count] = Some(Frame::Value(value, child_depth));
                        frame_count += 1;
                    } else {
                        output.push(']')?;
                        output.end_container();
                        entered_containers -= 1;
                    }
                }
                Frame::Object {
                    mut values,
                    child_depth,
                    wrote_value,
                } => {
                    if let Some((key, value)) = values.next() {
                        if wrote_value {
                            output.push(',')?;
                        }
                        write_json_string_to(key, output)?;
                        output.push(':')?;
                        frames[frame_count] = Some(Frame::Object {
                            values,
                            child_depth,
                            wrote_value: true,
                        });
                        frame_count += 1;
                        frames[frame_count] = Some(Frame::Value(value, child_depth));
                        frame_count += 1;
                    } else {
                        output.push('}')?;
                        output.end_container();
                        entered_containers -= 1;
                    }
                }
            }
        }

        Ok(())
    })();
    while entered_containers != 0 {
        output.end_container();
        entered_containers -= 1;
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };
    #[derive(crate::derive::JsonSerialize)]
    struct Payload {
        label: String,
        values: Vec<Option<u64>>,
        by_name: BTreeMap<String, u64>,
    }
    #[derive(crate::derive::JsonSerialize)]
    #[norito(tag = "kind", content = "payload", rename_all = "snake_case")]
    enum Choice {
        Named { note: String, enabled: bool },
    }
    fn fixture() -> Payload {
        Payload {
            label: "quote=\" slash=\\ newline=\n cent=¢".to_owned(),
            values: vec![Some(7), None, Some(u64::MAX)],
            by_name: BTreeMap::from([("alpha".to_owned(), 1), ("beta".to_owned(), 2)]),
        }
    }
    #[test]
    fn derived_compound_output_matches_the_unbounded_golden() {
        let payload = fixture();
        let ordinary = super::super::to_json(&payload).expect("ordinary JSON");
        let bounded = to_json_bounded(&payload, ordinary.len()).expect("exact cap");
        assert_eq!(bounded, ordinary);
        let boxed = to_json_bounded_boxed(&payload, ordinary.len()).expect("exact boxed cap");
        assert_eq!(&*boxed, ordinary.as_bytes());
        assert_eq!(
            bounded,
            r#"{"label":"quote=\" slash=\\ newline=\n cent=¢","values":[7,null,18446744073709551615],"by_name":{"alpha":1,"beta":2}}"#
        );
        let choice = Choice::Named {
            note: "ok".to_owned(),
            enabled: true,
        };
        let ordinary = super::super::to_json(&choice).expect("ordinary enum JSON");
        assert_eq!(
            to_json_bounded(&choice, ordinary.len()).expect("bounded enum JSON"),
            ordinary
        );
        assert_eq!(
            ordinary,
            r#"{"kind":"named","payload":{"note":"ok","enabled":true}}"#
        );
    }
    #[test]
    fn u128_value_respects_the_exact_output_budget() {
        let value = Value::from(u128::MAX);
        let expected = u128::MAX.to_string();

        assert_eq!(
            to_json_bounded(&value, expected.len()).expect("exact u128 budget"),
            expected
        );
        assert_eq!(
            to_json_bounded(&value, expected.len() - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
    }
    #[test]
    fn checked_string_writer_matches_canonical_escaping() {
        let value = "\"\\\n\r\t\u{08}\u{0c}\u{1f}/¢";
        let ordinary = super::super::to_json(value).expect("ordinary escaped JSON");
        assert_eq!(ordinary, r#""\"\\\n\r\t\b\f\u001f/¢""#);
        assert_eq!(
            to_json_bounded(value, ordinary.len()).expect("bounded escaped JSON"),
            ordinary
        );
    }
    fn assert_bounded_parity<T: JsonSerialize + ?Sized>(value: &T) {
        let ordinary = super::super::to_json(value).expect("ordinary JSON");
        let bounded = to_json_bounded(value, ordinary.len()).expect("bounded JSON");
        assert_eq!(bounded, ordinary);
    }
    #[test]
    fn built_in_checked_writers_preserve_container_and_value_bytes() {
        let value = Value::Object(BTreeMap::from([
            (
                "array".to_owned(),
                Value::Array(vec![
                    Value::Null,
                    Value::Bool(true),
                    Value::String("a\tb".to_owned()),
                ]),
            ),
            (
                "number".to_owned(),
                Value::Number(native::Number::F64(1.25e20)),
            ),
        ]));
        assert_bounded_parity(&value);
        let hash_set = std::collections::HashSet::from([9_u64, 1, 7, 3]);
        assert_bounded_parity(&hash_set);
        assert_bounded_parity(&BTreeSet::from([9_u64, 1, 7, 3]));
        assert_bounded_parity(&[0_u8, 1, 0xfe, 0xff]);
        assert_bounded_parity(&std::time::Duration::new(9, 17));
        assert_bounded_parity(&Box::new(vec![Some(1_u64), None]));
    }
    fn nested_array_value(containers: usize) -> Value {
        (0..containers).fold(Value::Null, |value, _| Value::Array(vec![value]))
    }
    fn nested_object_value(containers: usize) -> Value {
        (0..containers).fold(Value::Null, |value, _| {
            Value::Object(BTreeMap::from([("nested".to_owned(), value)]))
        })
    }
    fn nested_alternating_value(containers: usize) -> Value {
        (0..containers).fold(Value::Null, |value, index| {
            if index % 2 == 0 {
                Value::Array(vec![value])
            } else {
                Value::Object(BTreeMap::from([("nested".to_owned(), value)]))
            }
        })
    }
    fn nested_alternating_json(containers: usize) -> String {
        (0..containers).fold("null".to_owned(), |value, index| {
            if index % 2 == 0 {
                format!("[{value}]")
            } else {
                format!("{{\"nested\":{value}}}")
            }
        })
    }
    fn assert_programmatic_depth_boundary(builder: fn(usize) -> Value) {
        let accepted = builder(MAX_JSON_VALUE_NESTING_DEPTH - 1);
        let ordinary = super::super::to_json(&accepted).expect("ordinary depth-boundary JSON");
        assert_eq!(
            to_json_bounded(&accepted, ordinary.len()).expect("bounded depth-boundary JSON"),
            ordinary
        );
        let rejected = builder(MAX_JSON_VALUE_NESTING_DEPTH);
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            to_json_bounded(&rejected, usize::MAX),
            Err(BoundedJsonError::Unsupported)
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
        let rejected_bytes =
            super::super::to_json(&rejected).expect("ordinary over-depth JSON bytes");
        let mut output = String::new();
        output
            .try_reserve_exact(rejected_bytes.len())
            .expect("test exact destination");
        let mut exact = ExactJsonSink::new(&mut output, rejected_bytes.len());
        assert_eq!(
            rejected.json_serialize_to(&mut exact),
            Err(BoundedJsonError::LengthMismatch)
        );
    }
    #[test]
    fn programmatic_array_depth_matches_the_parser_boundary() {
        assert_programmatic_depth_boundary(nested_array_value);
    }
    #[test]
    fn programmatic_object_depth_matches_the_parser_boundary() {
        assert_programmatic_depth_boundary(nested_object_value);
    }
    #[test]
    fn programmatic_value_writer_fits_a_128k_stack() {
        std::thread::Builder::new()
            .name("bounded-json-value-writer".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let accepted_depth = MAX_JSON_VALUE_NESTING_DEPTH - 1;
                let accepted = nested_alternating_value(accepted_depth);
                let expected = nested_alternating_json(accepted_depth);
                assert_eq!(
                    to_json_bounded(&accepted, expected.len())
                        .expect("serialize the exact depth boundary"),
                    expected
                );
                super::super::drop_json_value_iteratively(accepted);

                let rejected = nested_alternating_value(MAX_JSON_VALUE_NESTING_DEPTH);
                assert_eq!(
                    to_json_bounded(&rejected, usize::MAX),
                    Err(BoundedJsonError::Unsupported)
                );
                super::super::drop_json_value_iteratively(rejected);
            })
            .expect("spawn constrained-stack JSON writer")
            .join()
            .expect("constrained-stack JSON writer");
    }
    #[test]
    fn unchecked_raw_value_fails_closed_before_destination_allocation() {
        let raw = super::super::RawValue::from_string(r#"{"ok":[1,true,null]}"#.to_owned());
        assert_eq!(
            super::super::to_json(&raw).expect("legacy raw JSON serialization"),
            raw.get()
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            to_json_bounded(&raw, usize::MAX),
            Err(BoundedJsonError::Unsupported)
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
        let mut counter = CountingJsonSink::new(usize::MAX);
        assert_eq!(
            raw.json_serialize_to(&mut counter),
            Err(BoundedJsonError::Unsupported)
        );
        assert_eq!(counter.length, 0);
        let mut output = String::new();
        let initial_capacity = output.capacity();
        assert_eq!(initial_capacity, 0);
        {
            let mut exact = ExactJsonSink::new(&mut output, raw.get().len());
            assert_eq!(
                raw.json_serialize_to(&mut exact),
                Err(BoundedJsonError::Unsupported)
            );
            assert_eq!(exact.length, 0);
        }
        assert_eq!(output.len(), 0);
        assert_eq!(output.capacity(), initial_capacity);
    }
    #[test]
    fn cap_rejection_happens_before_destination_allocation() {
        let payload = fixture();
        let exact = super::super::to_json(&payload)
            .expect("ordinary JSON")
            .len();
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            to_json_bounded(&payload, exact - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(
            to_json_bounded_boxed(&payload, exact - 1),
            Err(BoundedJsonError::BodyTooLarge)
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        let string = to_json_bounded(&payload, exact).expect("exact String cap");
        assert_eq!(string.len(), exact);
        assert_eq!(string.capacity(), exact);
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 1));
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        let boxed = to_json_bounded_boxed(&payload, exact).expect("exact boxed cap");
        assert_eq!(boxed.len(), exact);
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 1));
    }
    struct EmptyChecked;
    impl JsonSerialize for EmptyChecked {
        fn json_serialize(&self, _output: &mut String) {}
        fn json_serialize_to(
            &self,
            _output: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            Ok(())
        }
    }
    #[test]
    fn boxed_destination_supports_an_exact_zero_length() {
        let output = to_json_bounded_boxed(&EmptyChecked, 0).expect("zero-byte destination");
        assert!(output.is_empty());
    }
    #[test]
    fn boxed_destination_allocation_failure_is_recoverable() {
        let payload = fixture();
        let exact = super::super::to_json(&payload)
            .expect("ordinary JSON")
            .len();
        let attempted = Cell::new(None);
        assert_eq!(
            to_json_bounded_boxed_with_allocator(&payload, exact, |length| {
                attempted.set(Some(length));
                Err(BoundedJsonError::AllocationFailed)
            }),
            Err(BoundedJsonError::AllocationFailed)
        );
        assert_eq!(attempted.get(), Some(exact));
    }
    #[test]
    fn second_pass_retains_actual_nested_admission_refusal() {
        struct Original(Cell<usize>);
        impl JsonSerialize for Original {
            fn json_serialize(&self, output: &mut String) {
                output.push('0');
            }
            fn json_serialize_to(
                &self,
                output: &mut dyn JsonWriteSink,
            ) -> Result<(), BoundedJsonError> {
                let pass = self.0.get();
                self.0.set(pass + 1);
                if pass == 1 {
                    crate::core::reserve_decode_allocation(1)
                        .map_err(BoundedJsonError::from_decode_resource)?;
                }
                output.push('0')
            }
        }
        let value = Original(Cell::new(0));
        let refused = crate::core::with_decode_limits_scope(
            crate::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, usize::MAX),
            || to_json_bounded(&value, 1),
        );
        assert_eq!(
            refused,
            Err(BoundedJsonError::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: 2,
                    limit: 1
                },
            ))
        );
        assert_eq!(value.0.get(), 2, "actual second-pass allocation refused");
        value.0.set(0);
        assert_eq!(to_json_bounded(&value, 1).unwrap(), "0");
    }
    #[test]
    fn active_decode_budget_rejects_destination_before_reserve() {
        let payload = fixture();
        let exact = super::super::to_json(&payload)
            .expect("ordinary JSON")
            .len();
        let limits = crate::core::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            exact - 1,
            usize::MAX,
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            crate::core::with_decode_limits_scope(limits, || { to_json_bounded(&payload, exact) }),
            Err(BoundedJsonError::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(exact).unwrap(),
                    limit: u64::try_from(exact - 1).unwrap(),
                },
            ))
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
    }
    #[test]
    fn active_decode_budget_accounts_for_exact_boxed_destination() {
        let payload = fixture();
        let exact = super::super::to_json(&payload)
            .expect("ordinary JSON")
            .len();
        let too_small = crate::core::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            exact - 1,
            usize::MAX,
        );
        assert_eq!(
            crate::core::with_decode_limits_scope(too_small, || {
                to_json_bounded_boxed(&payload, exact)
            }),
            Err(BoundedJsonError::DecodeResource(
                crate::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(exact).unwrap(),
                    limit: u64::try_from(exact - 1).unwrap(),
                },
            ))
        );
        let exact_limit =
            crate::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, exact, usize::MAX);
        assert!(
            crate::core::with_decode_limits_scope(exact_limit, || {
                to_json_bounded_boxed(&payload, exact)
            })
            .is_ok()
        );
    }
    struct UnsupportedManual;
    impl JsonSerialize for UnsupportedManual {
        fn json_serialize(&self, output: &mut String) {
            output.push_str("null");
        }
    }
    #[test]
    fn legacy_manual_serializer_fails_closed_before_allocation() {
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            to_json_bounded(&UnsupportedManual, usize::MAX),
            Err(BoundedJsonError::Unsupported)
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
        assert_eq!(
            super::super::to_json(&UnsupportedManual).expect("legacy serializer"),
            "null"
        );
    }
    struct Stateful {
        calls: Cell<usize>,
        first: &'static str,
        second: &'static str,
    }
    impl JsonSerialize for Stateful {
        fn json_serialize(&self, output: &mut String) {
            output.push_str(self.first);
        }
        fn json_serialize_to(
            &self,
            output: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            output.push_str(if call == 0 { self.first } else { self.second })
        }
    }
    #[test]
    fn stateful_second_pass_overrun_is_rejected_before_append() {
        static HOSTILE_SECOND_PASS: [u8; 1024 * 1024] = [b'0'; 1024 * 1024];
        // SAFETY: every byte in the static fixture is ASCII `0`.
        let hostile = unsafe { std::str::from_utf8_unchecked(&HOSTILE_SECOND_PASS) };
        let value = Stateful {
            calls: Cell::new(0),
            first: "0",
            second: hostile,
        };
        assert_eq!(
            to_json_bounded(&value, 1),
            Err(BoundedJsonError::LengthMismatch)
        );
        let boxed_value = Stateful {
            calls: Cell::new(0),
            first: "0",
            second: hostile,
        };
        assert_eq!(
            to_json_bounded_boxed(&boxed_value, 1),
            Err(BoundedJsonError::LengthMismatch)
        );
        let mut output = String::with_capacity(1);
        let initial_capacity = output.capacity();
        let mut sink = ExactJsonSink::new(&mut output, 1);
        assert_eq!(
            sink.push_str(hostile),
            Err(BoundedJsonError::LengthMismatch)
        );
        assert!(output.is_empty(), "overrun must reject before append");
        assert_eq!(output.capacity(), initial_capacity);
    }
    #[test]
    fn stateful_short_second_pass_is_rejected_by_final_check() {
        let value = Stateful {
            calls: Cell::new(0),
            first: "00",
            second: "0",
        };
        assert_eq!(
            to_json_bounded(&value, 2),
            Err(BoundedJsonError::LengthMismatch)
        );
        let boxed_value = Stateful {
            calls: Cell::new(0),
            first: "00",
            second: "0",
        };
        assert_eq!(
            to_json_bounded_boxed(&boxed_value, 2),
            Err(BoundedJsonError::LengthMismatch)
        );
    }
    struct ErrorsOnSecondPass {
        calls: Cell<usize>,
    }
    impl JsonSerialize for ErrorsOnSecondPass {
        fn json_serialize(&self, output: &mut String) {
            output.push_str("00");
        }
        fn json_serialize_to(
            &self,
            output: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            output.push('0')?;
            if call == 0 {
                output.push('0')
            } else {
                Err(BoundedJsonError::Unsupported)
            }
        }
    }
    #[test]
    fn second_pass_error_discards_the_partial_destination() {
        let value = ErrorsOnSecondPass {
            calls: Cell::new(0),
        };
        assert_eq!(
            to_json_bounded(&value, 2),
            Err(BoundedJsonError::LengthMismatch)
        );
        assert_eq!(value.calls.get(), 2);
        let boxed_value = ErrorsOnSecondPass {
            calls: Cell::new(0),
        };
        assert_eq!(
            to_json_bounded_boxed(&boxed_value, 2),
            Err(BoundedJsonError::LengthMismatch)
        );
        assert_eq!(boxed_value.calls.get(), 2);
    }
    static CUSTOM_BOUNDED_CALLS: AtomicUsize = AtomicUsize::new(0);
    mod custom {
        use super::*;
        pub fn serialize(value: &u64, output: &mut String) {
            output.push('"');
            output.push_str(&value.to_string());
            output.push('"');
        }
        pub fn serialize_bounded(
            value: &u64,
            output: &mut dyn JsonWriteSink,
        ) -> Result<(), BoundedJsonError> {
            CUSTOM_BOUNDED_CALLS.fetch_add(1, Ordering::Relaxed);
            output.push('"')?;
            write_u128_to(u128::from(*value), output)?;
            output.push('"')
        }
    }
    #[derive(crate::derive::JsonSerialize)]
    struct ExplicitCustom {
        #[norito(with = "custom", bounded_with = "custom::serialize_bounded")]
        value: u64,
    }
    #[derive(crate::derive::JsonSerialize)]
    struct UnsupportedCustom {
        #[norito(with = "custom")]
        value: u64,
    }
    #[derive(crate::derive::JsonSerialize)]
    struct ExtraFields {
        depth: u64,
        label: String,
    }
    fn write_flattened_extra(
        value: &ExtraFields,
        output: &mut dyn JsonWriteSink,
        first: &mut bool,
    ) -> Result<(), BoundedJsonError> {
        if !*first {
            output.push(',')?;
        } else {
            *first = false;
        }
        output.push_str("\"depth\":")?;
        value.depth.json_serialize_to(output)?;
        output.push_str(",\"label\":")?;
        value.label.json_serialize_to(output)
    }
    #[derive(crate::derive::JsonSerialize)]
    struct ExplicitFlatten {
        id: u64,
        #[norito(flatten, bounded_with = "write_flattened_extra")]
        extra: ExtraFields,
    }
    #[derive(crate::derive::JsonSerialize)]
    struct UnsupportedFlatten {
        id: u64,
        #[norito(flatten)]
        extra: ExtraFields,
    }
    #[test]
    fn custom_field_requires_an_explicit_bounded_seam() {
        CUSTOM_BOUNDED_CALLS.store(0, Ordering::Relaxed);
        let explicit = ExplicitCustom { value: 42 };
        assert_eq!(
            to_json_bounded(&explicit, 14).expect("explicit bounded seam"),
            r#"{"value":"42"}"#
        );
        assert_eq!(CUSTOM_BOUNDED_CALLS.load(Ordering::Relaxed), 2);
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            to_json_bounded(&UnsupportedCustom { value: 42 }, usize::MAX),
            Err(BoundedJsonError::Unsupported)
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
    }
    #[test]
    fn flattened_field_requires_an_explicit_bounded_seam() {
        let explicit = ExplicitFlatten {
            id: 7,
            extra: ExtraFields {
                depth: 3,
                label: "ok".to_owned(),
            },
        };
        let ordinary = super::super::to_json(&explicit).expect("ordinary flattened JSON");
        assert_eq!(ordinary, r#"{"id":7,"depth":3,"label":"ok"}"#);
        assert_eq!(
            to_json_bounded(&explicit, ordinary.len()).expect("bounded flattened JSON"),
            ordinary
        );
        let unsupported = UnsupportedFlatten {
            id: 7,
            extra: ExtraFields {
                depth: 3,
                label: "ok".to_owned(),
            },
        };
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
        assert_eq!(
            to_json_bounded(&unsupported, usize::MAX),
            Err(BoundedJsonError::Unsupported)
        );
        DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
    }
    #[test]
    fn error_messages_are_fixed() {
        assert_eq!(
            BoundedJsonError::Unsupported.to_string(),
            "bounded JSON serialization is unsupported"
        );
        assert_eq!(
            BoundedJsonError::BodyTooLarge.to_string(),
            "bounded JSON body exceeds its byte limit"
        );
        assert_eq!(
            BoundedJsonError::AllocationFailed.to_string(),
            "bounded JSON destination allocation failed"
        );
        assert_eq!(
            BoundedJsonError::LengthMismatch.to_string(),
            "bounded JSON serializer length changed between passes"
        );
    }
}

#[cfg(test)]
mod empty_terminal_tests {
    //! Empty terminal containers share the parser's original structural boundary.

    use super::*;

    fn nested_empty(containers: usize, object: bool, alternate: bool) -> (Value, String) {
        let (mut value, mut text) = if object {
            (Value::Object(BTreeMap::new()), String::from("{}"))
        } else {
            (Value::Array(Vec::new()), String::from("[]"))
        };
        for index in 1..containers {
            if object ^ (alternate && index % 2 == 1) {
                value = Value::Object(BTreeMap::from([(String::from("k"), value)]));
                text = format!("{{\"k\":{text}}}");
            } else {
                value = Value::Array(vec![value]);
                text = format!("[{text}]");
            }
        }
        (value, text)
    }

    #[test]
    fn empty_terminals_preserve_depth_33_in_every_checked_sink() {
        for (object, alternate) in [(false, false), (true, false), (false, true), (true, true)] {
            let (value, expected) = nested_empty(MAX_JSON_VALUE_NESTING_DEPTH, object, alternate);
            assert_eq!(super::super::parse_value(&expected).unwrap(), value);
            assert_eq!(to_json_bounded(&value, expected.len()).unwrap(), expected);
            assert_eq!(
                to_json_bounded_boxed(&value, expected.len())
                    .unwrap()
                    .as_ref(),
                expected.as_bytes()
            );
            let mut output = String::new();
            let mut sink = ExactJsonSink::new(&mut output, expected.len());
            value.json_serialize_to(&mut sink).unwrap();
            assert_eq!(sink.depth, 0);
            assert_eq!(sink.length, expected.len());
            assert_eq!(output, expected);
            DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
            assert_eq!(
                to_json_bounded(&value, expected.len() - 1),
                Err(BoundedJsonError::BodyTooLarge)
            );
            DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
        }
    }

    #[test]
    fn forbidden_empty_terminal_and_populated_container_keep_original_refusals() {
        for object in [false, true] {
            let (value, _) = nested_empty(MAX_JSON_VALUE_NESTING_DEPTH + 1, object, false);
            DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| attempts.set(0));
            assert_eq!(
                to_json_bounded(&value, usize::MAX),
                Err(BoundedJsonError::Unsupported)
            );
            DESTINATION_ALLOCATION_ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 0));
        }
        let mut counter = CountingJsonSink::new(usize::MAX);
        for _ in 1..MAX_JSON_VALUE_NESTING_DEPTH {
            counter.begin_container().unwrap();
        }
        assert_eq!(
            counter.begin_container(),
            Err(BoundedJsonError::Unsupported)
        );
        assert_eq!(counter.depth, MAX_JSON_VALUE_NESTING_DEPTH - 1);
        let mut output = String::new();
        let mut exact = ExactJsonSink::new(&mut output, 0);
        for _ in 1..MAX_JSON_VALUE_NESTING_DEPTH {
            exact.begin_container().unwrap();
        }
        assert_eq!(
            exact.begin_container(),
            Err(BoundedJsonError::LengthMismatch)
        );
        assert_eq!(exact.depth, MAX_JSON_VALUE_NESTING_DEPTH - 1);
        let mut bytes = [];
        let mut boxed = ExactBoxedJsonSink::new(&mut bytes);
        for _ in 1..MAX_JSON_VALUE_NESTING_DEPTH {
            boxed.begin_container().unwrap();
        }
        assert_eq!(
            boxed.begin_container(),
            Err(BoundedJsonError::LengthMismatch)
        );
        assert_eq!(boxed.depth, MAX_JSON_VALUE_NESTING_DEPTH - 1);
    }

    #[test]
    fn terminal_writer_releases_only_its_own_entered_containers_on_refusal() {
        struct RecordingSink {
            depth: usize,
            entries: usize,
            exits: usize,
            remaining: usize,
        }
        impl JsonWriteSink for RecordingSink {
            fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
                let mut bytes = [0_u8; 4];
                self.push_str(value.encode_utf8(&mut bytes))
            }
            fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
                self.remaining = self
                    .remaining
                    .checked_sub(value.len())
                    .ok_or(BoundedJsonError::BodyTooLarge)?;
                Ok(())
            }
            fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
                self.depth += 1;
                self.entries += 1;
                Ok(())
            }
            fn end_container(&mut self) {
                self.depth -= 1;
                self.exits += 1;
            }
        }
        let (value, text) = nested_empty(MAX_JSON_VALUE_NESTING_DEPTH, false, true);
        for remaining in [text.len(), text.len() - 1] {
            let mut sink = RecordingSink {
                depth: 3,
                entries: 0,
                exits: 0,
                remaining,
            };
            let result = value.json_serialize_to(&mut sink);
            if remaining == text.len() {
                result.unwrap();
            } else {
                assert_eq!(result, Err(BoundedJsonError::BodyTooLarge));
            }
            assert_eq!(sink.entries, MAX_JSON_VALUE_NESTING_DEPTH);
            assert_eq!(sink.exits, sink.entries);
            assert_eq!(
                sink.depth, 3,
                "the writer cannot release inherited sink levels"
            );
        }
    }
}
