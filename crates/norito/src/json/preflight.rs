//! Allocation-free lexical admission for untrusted JSON documents.
use super::MAX_JSON_VALUE_NESTING_DEPTH;
/// Resource ceilings enforced before an owned JSON decoder is entered.
///
/// These limits cover representation-independent lexical facts. A caller constructing an owned Rust
/// value must additionally translate the returned [`JsonPreflightProfile`] into a source-audited
/// allocation bound for that concrete type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonPreflightLimits {
    max_raw_bytes: usize,
    max_values: usize,
    max_encoded_string_bytes: usize,
    max_decoded_string_bytes: usize,
    max_total_decoded_string_bytes: usize,
    max_container_entries: usize,
    max_array_entries: usize,
    max_object_entries: usize,
    max_total_elements: usize,
    max_nesting_depth: usize,
}
impl JsonPreflightLimits {
    /// Construct complete lexical limits for one JSON document.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        max_raw_bytes: usize,
        max_values: usize,
        max_encoded_string_bytes: usize,
        max_decoded_string_bytes: usize,
        max_total_decoded_string_bytes: usize,
        max_container_entries: usize,
        max_array_entries: usize,
        max_object_entries: usize,
        max_total_elements: usize,
        max_nesting_depth: usize,
    ) -> Self {
        Self {
            max_raw_bytes,
            max_values,
            max_encoded_string_bytes,
            max_decoded_string_bytes,
            max_total_decoded_string_bytes,
            max_container_entries,
            max_array_entries,
            max_object_entries,
            max_total_elements,
            max_nesting_depth,
        }
    }
    /// Derive JSON lexical ceilings from a raw-body limit and Norito limits.
    ///
    /// JSON arrays and objects both act as sequences. Their combined entry count consumes the
    /// total-element budget, while every individual container consumes the per-sequence budget. One
    /// scalar or container root is allowed in addition to those elements.
    /// The root also requires no additional decode depth; the lexical depth includes it.
    #[must_use]
    pub fn from_decode_limits(max_raw_bytes: usize, limits: crate::core::DecodeLimits) -> Self {
        let elements = limits.max_total_elements();
        Self {
            max_raw_bytes,
            max_values: elements.saturating_add(1),
            max_encoded_string_bytes: max_raw_bytes,
            max_decoded_string_bytes: limits.max_field_bytes(),
            max_total_decoded_string_bytes: max_raw_bytes,
            max_container_entries: limits.max_sequence_elements(),
            max_array_entries: elements,
            max_object_entries: elements,
            max_total_elements: elements,
            max_nesting_depth: limits
                .max_nesting_depth()
                .saturating_add(1)
                .min(MAX_JSON_VALUE_NESTING_DEPTH),
        }
    }
    const fn lexical_unbounded() -> Self {
        Self {
            max_raw_bytes: usize::MAX,
            max_values: usize::MAX,
            max_encoded_string_bytes: usize::MAX,
            max_decoded_string_bytes: usize::MAX,
            max_total_decoded_string_bytes: usize::MAX,
            max_container_entries: usize::MAX,
            max_array_entries: usize::MAX,
            max_object_entries: usize::MAX,
            max_total_elements: usize::MAX,
            max_nesting_depth: MAX_JSON_VALUE_NESTING_DEPTH,
        }
    }
}
/// A resource measured by JSON lexical preflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonPreflightResource {
    /// Raw input bytes.
    RawBytes,
    /// Total JSON values.
    Values,
    /// Source bytes in one quoted string token.
    EncodedStringBytes,
    /// Decoded UTF-8 bytes in one string.
    DecodedStringBytes,
    /// Aggregate decoded UTF-8 string bytes.
    TotalDecodedStringBytes,
    /// Entries in one array or object.
    ContainerEntries,
    /// Aggregate array entries.
    ArrayEntries,
    /// Aggregate object entries.
    ObjectEntries,
    /// Aggregate array and object entries.
    TotalElements,
    /// Nested JSON values.
    NestingDepth,
    /// A checked lexical counter.
    Arithmetic,
}
/// Stable syntax classes returned without copying hostile input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonPreflightSyntax {
    /// The byte slice is not valid UTF-8.
    InvalidUtf8,
    /// A value was expected but no token remained.
    UnexpectedEnd,
    /// The next byte cannot begin a JSON value.
    UnexpectedToken,
    /// Extra non-whitespace bytes follow the root value.
    TrailingCharacters,
    /// A comma is followed immediately by an array end delimiter.
    TrailingArrayComma,
    /// A comma is followed immediately by an object end delimiter.
    TrailingObjectComma,
    /// An object key is not followed by a colon.
    ExpectedColon,
    /// An array delimiter or separator is malformed.
    InvalidArray,
    /// An object key, delimiter, or separator is malformed.
    InvalidObject,
    /// A string is unterminated or contains a forbidden byte.
    InvalidString,
    /// A string escape is malformed.
    InvalidEscape,
    /// A Unicode escape or surrogate pair is malformed.
    InvalidUnicodeEscape,
    /// A low surrogate appeared without a preceding high surrogate.
    UnexpectedLowSurrogate,
    /// A number does not use JSON number grammar.
    InvalidNumber,
    /// A number's integer component contains a forbidden leading zero.
    LeadingZero,
    /// A boolean or null literal is malformed.
    InvalidLiteral,
}
impl JsonPreflightSyntax {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::UnexpectedEnd => "unexpected end of JSON",
            Self::UnexpectedToken => "unexpected JSON token",
            Self::TrailingCharacters => "trailing characters",
            Self::TrailingArrayComma => "trailing comma in array",
            Self::TrailingObjectComma => "trailing comma in object",
            Self::ExpectedColon => "expected ':'",
            Self::InvalidArray => "invalid JSON array",
            Self::InvalidObject => "invalid JSON object",
            Self::InvalidString => "invalid JSON string",
            Self::InvalidEscape => "invalid JSON string escape",
            Self::InvalidUnicodeEscape => "invalid JSON Unicode escape",
            Self::UnexpectedLowSurrogate => "unexpected low surrogate",
            Self::InvalidNumber => "invalid JSON number",
            Self::LeadingZero => "leading zeros are not allowed in JSON numbers",
            Self::InvalidLiteral => "invalid JSON literal",
        }
    }
}
/// Failure from allocation-free JSON lexical preflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonPreflightError {
    resource: Option<JsonPreflightResource>,
    syntax: Option<JsonPreflightSyntax>,
    offset: usize,
    attempted: usize,
    limit: usize,
}
impl JsonPreflightError {
    const fn syntax(offset: usize, syntax: JsonPreflightSyntax) -> Self {
        Self {
            resource: None,
            syntax: Some(syntax),
            offset,
            attempted: 0,
            limit: 0,
        }
    }
    const fn resource(
        resource: JsonPreflightResource,
        attempted: usize,
        limit: usize,
        offset: usize,
    ) -> Self {
        Self {
            resource: Some(resource),
            syntax: None,
            offset,
            attempted,
            limit,
        }
    }
    const fn arithmetic(offset: usize) -> Self {
        Self::resource(
            JsonPreflightResource::Arithmetic,
            usize::MAX,
            usize::MAX,
            offset,
        )
    }
    /// Resource exceeded by this error, if it is a limit failure.
    #[must_use]
    pub const fn resource_kind(self) -> Option<JsonPreflightResource> {
        self.resource
    }
    /// Syntax class, if the document is malformed.
    #[must_use]
    pub const fn syntax_kind(self) -> Option<JsonPreflightSyntax> {
        self.syntax
    }
    /// Byte offset at which the failure was detected.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
    /// Attempted resource value for a limit failure.
    #[must_use]
    pub const fn attempted(self) -> usize {
        self.attempted
    }
    /// Configured resource ceiling for a limit failure.
    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }
}
impl core::fmt::Display for JsonPreflightError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(syntax) = self.syntax {
            return write!(formatter, "{} at byte {}", syntax.message(), self.offset);
        }
        write!(
            formatter,
            "JSON {:?} charge {} exceeds limit {} at byte {}",
            self.resource.expect("preflight error has one class"),
            self.attempted,
            self.limit,
            self.offset
        )
    }
}
impl std::error::Error for JsonPreflightError {}
/// Allocation-relevant lexical facts about one complete JSON document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JsonPreflightProfile {
    raw_bytes: usize,
    values: usize,
    arrays: usize,
    objects: usize,
    array_entries: usize,
    object_entries: usize,
    object_btree_node_upper_bound: usize,
    object_btree_allocation_bytes: usize,
    root_container_entries: usize,
    max_container_entries: usize,
    encoded_string_bytes: usize,
    decoded_string_bytes: usize,
    object_key_decoded_bytes: usize,
    max_encoded_string_bytes: usize,
    max_decoded_string_bytes: usize,
    string_capacity_bytes: usize,
    max_escaped_string_capacity_bytes: usize,
    max_nesting_depth: usize,
    value_span_bytes: usize,
}
impl JsonPreflightProfile {
    /// Raw input bytes.
    #[must_use]
    pub const fn raw_bytes(self) -> usize {
        self.raw_bytes
    }
    /// Number of JSON values, including the root and containers.
    #[must_use]
    pub const fn values(self) -> usize {
        self.values
    }
    /// Number of arrays.
    #[must_use]
    pub const fn arrays(self) -> usize {
        self.arrays
    }
    /// Number of objects.
    #[must_use]
    pub const fn objects(self) -> usize {
        self.objects
    }
    /// Aggregate number of array entries.
    #[must_use]
    pub const fn array_entries(self) -> usize {
        self.array_entries
    }
    /// Aggregate number of object entries.
    #[must_use]
    pub const fn object_entries(self) -> usize {
        self.object_entries
    }
    /// Exact sum of the parser's conservative B-tree node count for every object in this document.
    #[must_use]
    pub const fn object_btree_node_upper_bound(self) -> usize {
        self.object_btree_node_upper_bound
    }
    /// Sum of the native `Value` parser's conservative allocation charge for each object's nodes.
    ///
    /// Empty objects allocate no nodes. Objects through eleven lexical entries charge one leaf;
    /// larger objects retain the collection owner's full split and internal-node bound. Duplicate
    /// keys retain their original lexical-entry charge, just as the parser's admission does.
    #[must_use]
    pub const fn object_btree_allocation_bytes(self) -> usize {
        self.object_btree_allocation_bytes
    }
    /// Number of entries in the root array or object, or zero for a scalar.
    #[must_use]
    pub const fn root_container_entries(self) -> usize {
        self.root_container_entries
    }
    /// Largest entry count observed in one array or object.
    #[must_use]
    pub const fn max_container_entries(self) -> usize {
        self.max_container_entries
    }
    /// Aggregate source bytes in quoted string tokens, including quotes.
    #[must_use]
    pub const fn encoded_string_bytes(self) -> usize {
        self.encoded_string_bytes
    }
    /// Aggregate decoded UTF-8 bytes in strings and object keys.
    #[must_use]
    pub const fn decoded_string_bytes(self) -> usize {
        self.decoded_string_bytes
    }
    /// Aggregate decoded UTF-8 bytes used by object keys.
    #[must_use]
    pub const fn object_key_decoded_bytes(self) -> usize {
        self.object_key_decoded_bytes
    }
    /// Largest source length of one quoted string token.
    #[must_use]
    pub const fn max_encoded_string_bytes(self) -> usize {
        self.max_encoded_string_bytes
    }
    /// Largest decoded UTF-8 length of one string.
    #[must_use]
    pub const fn max_decoded_string_bytes(self) -> usize {
        self.max_decoded_string_bytes
    }
    /// Aggregate exact-reserve capacity requested for owned string results.
    #[must_use]
    pub const fn string_capacity_bytes(self) -> usize {
        self.string_capacity_bytes
    }
    /// Largest exact-reserve capacity requested for one escaped string.
    #[must_use]
    pub const fn max_escaped_string_capacity_bytes(self) -> usize {
        self.max_escaped_string_capacity_bytes
    }
    /// Deepest JSON value, counting the root as one.
    #[must_use]
    pub const fn max_nesting_depth(self) -> usize {
        self.max_nesting_depth
    }
    /// Sum of the source spans of every JSON value.
    ///
    /// This bounds codecs that copy an encoded subtree once at every typed
    /// value boundary. A zero-copy decoder does not need to charge it.
    #[must_use]
    pub const fn value_span_bytes(self) -> usize {
        self.value_span_bytes
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameState {
    ArrayFirstOrEnd,
    ArrayValue,
    ArrayCommaOrEnd,
    ObjectFirstKeyOrEnd,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectCommaOrEnd,
}
#[derive(Clone, Copy, Debug)]
struct Frame {
    state: FrameState,
    value_start: usize,
    entries: usize,
}
impl Frame {
    const EMPTY: Self = Self {
        state: FrameState::ArrayFirstOrEnd,
        value_start: 0,
        entries: 0,
    };
    const fn is_object(self) -> bool {
        matches!(
            self.state,
            FrameState::ObjectFirstKeyOrEnd
                | FrameState::ObjectKey
                | FrameState::ObjectColon
                | FrameState::ObjectValue
                | FrameState::ObjectCommaOrEnd
        )
    }
}
#[derive(Clone, Copy, Debug)]
struct StringProfile {
    encoded_bytes: usize,
    decoded_bytes: usize,
    capacity_bytes: usize,
    escaped: bool,
}
struct Scanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    root_depth: usize,
    limits: JsonPreflightLimits,
    profile: JsonPreflightProfile,
    frames: [Frame; MAX_JSON_VALUE_NESTING_DEPTH],
    frame_len: usize,
    root_complete: bool,
}
impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8], offset: usize, root_depth: usize, limits: JsonPreflightLimits) -> Self {
        Self {
            bytes,
            offset,
            root_depth,
            limits,
            profile: JsonPreflightProfile::default(),
            frames: [Frame::EMPTY; MAX_JSON_VALUE_NESTING_DEPTH],
            frame_len: 0,
            root_complete: false,
        }
    }
    fn error(&self, syntax: JsonPreflightSyntax) -> JsonPreflightError {
        JsonPreflightError::syntax(self.offset.min(self.bytes.len()), syntax)
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }
    fn expect(&mut self, byte: u8, syntax: JsonPreflightSyntax) -> Result<(), JsonPreflightError> {
        if self.bump() != Some(byte) {
            return Err(self.error(syntax));
        }
        Ok(())
    }
    fn checked_add(&self, lhs: usize, rhs: usize) -> Result<usize, JsonPreflightError> {
        lhs.checked_add(rhs)
            .ok_or_else(|| JsonPreflightError::arithmetic(self.offset))
    }
    fn enforce(
        &self,
        resource: JsonPreflightResource,
        attempted: usize,
        limit: usize,
    ) -> Result<(), JsonPreflightError> {
        if attempted > limit {
            return Err(JsonPreflightError::resource(
                resource,
                attempted,
                limit,
                self.offset,
            ));
        }
        Ok(())
    }
    fn start_value(&mut self) -> Result<(), JsonPreflightError> {
        let depth = self
            .root_depth
            .checked_add(self.frame_len)
            .ok_or_else(|| JsonPreflightError::arithmetic(self.offset))?;
        self.enforce(
            JsonPreflightResource::NestingDepth,
            depth,
            self.limits
                .max_nesting_depth
                .min(MAX_JSON_VALUE_NESTING_DEPTH),
        )?;
        self.profile.max_nesting_depth = self.profile.max_nesting_depth.max(depth);
        let values = self.checked_add(self.profile.values, 1)?;
        self.enforce(
            JsonPreflightResource::Values,
            values,
            self.limits.max_values,
        )?;
        self.profile.values = values;
        self.skip_whitespace();
        let value_start = self.offset;
        match self.peek() {
            Some(b'{') => {
                self.bump();
                self.profile.objects = self.checked_add(self.profile.objects, 1)?;
                self.push_frame(Frame {
                    state: FrameState::ObjectFirstKeyOrEnd,
                    value_start,
                    entries: 0,
                })
            }
            Some(b'[') => {
                self.bump();
                self.profile.arrays = self.checked_add(self.profile.arrays, 1)?;
                self.push_frame(Frame {
                    state: FrameState::ArrayFirstOrEnd,
                    value_start,
                    entries: 0,
                })
            }
            Some(b'"') => {
                let string = self.parse_string()?;
                self.record_string(string, false)?;
                self.complete_scalar(value_start)
            }
            Some(b't') => {
                self.parse_literal(b"true")?;
                self.complete_scalar(value_start)
            }
            Some(b'f') => {
                self.parse_literal(b"false")?;
                self.complete_scalar(value_start)
            }
            Some(b'n') => {
                self.parse_literal(b"null")?;
                self.complete_scalar(value_start)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.parse_number()?;
                self.complete_scalar(value_start)
            }
            Some(_) => Err(self.error(JsonPreflightSyntax::UnexpectedToken)),
            None => Err(self.error(JsonPreflightSyntax::UnexpectedEnd)),
        }
    }
    fn push_frame(&mut self, frame: Frame) -> Result<(), JsonPreflightError> {
        if self.frame_len >= self.frames.len() {
            return Err(JsonPreflightError::resource(
                JsonPreflightResource::NestingDepth,
                self.root_depth.saturating_add(self.frame_len),
                self.limits.max_nesting_depth,
                self.offset,
            ));
        }
        self.frames[self.frame_len] = frame;
        self.frame_len += 1;
        Ok(())
    }
    fn complete_scalar(&mut self, value_start: usize) -> Result<(), JsonPreflightError> {
        let span = self
            .offset
            .checked_sub(value_start)
            .ok_or_else(|| JsonPreflightError::arithmetic(self.offset))?;
        self.profile.value_span_bytes = self.checked_add(self.profile.value_span_bytes, span)?;
        if self.frame_len == 0 {
            self.root_complete = true;
        }
        Ok(())
    }
    fn close_container(&mut self) -> Result<(), JsonPreflightError> {
        let frame = self.frames[self.frame_len - 1];
        self.frame_len -= 1;
        self.profile.max_container_entries = self.profile.max_container_entries.max(frame.entries);
        if frame.is_object() {
            let nodes = crate::core::owned_btree_node_count_upper_bound(frame.entries)
                .map_err(|_| JsonPreflightError::arithmetic(self.offset))?;
            self.profile.object_btree_node_upper_bound =
                self.checked_add(self.profile.object_btree_node_upper_bound, nodes)?;
            let bytes =
                crate::core::owned_btree_allocation_bytes::<String, super::Value>(frame.entries)
                    .map_err(|_| JsonPreflightError::arithmetic(self.offset))?;
            self.profile.object_btree_allocation_bytes =
                self.checked_add(self.profile.object_btree_allocation_bytes, bytes)?;
        }
        if self.frame_len == 0 {
            self.profile.root_container_entries = frame.entries;
        }
        let span = self
            .offset
            .checked_sub(frame.value_start)
            .ok_or_else(|| JsonPreflightError::arithmetic(self.offset))?;
        self.profile.value_span_bytes = self.checked_add(self.profile.value_span_bytes, span)?;
        if self.frame_len == 0 {
            self.root_complete = true;
        }
        Ok(())
    }
    fn add_entry(&mut self, array: bool) -> Result<(), JsonPreflightError> {
        let index = self.frame_len - 1;
        let entries = self.checked_add(self.frames[index].entries, 1)?;
        self.enforce(
            JsonPreflightResource::ContainerEntries,
            entries,
            self.limits.max_container_entries,
        )?;
        self.frames[index].entries = entries;
        if array {
            let total = self.checked_add(self.profile.array_entries, 1)?;
            self.enforce(
                JsonPreflightResource::ArrayEntries,
                total,
                self.limits.max_array_entries,
            )?;
            self.profile.array_entries = total;
        } else {
            let total = self.checked_add(self.profile.object_entries, 1)?;
            self.enforce(
                JsonPreflightResource::ObjectEntries,
                total,
                self.limits.max_object_entries,
            )?;
            self.profile.object_entries = total;
        }
        let combined = self.checked_add(self.profile.array_entries, self.profile.object_entries)?;
        self.enforce(
            JsonPreflightResource::TotalElements,
            combined,
            self.limits.max_total_elements,
        )
    }
    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), JsonPreflightError> {
        let end = self.checked_add(self.offset, literal.len())?;
        if self.bytes.get(self.offset..end) != Some(literal) {
            return Err(self.error(JsonPreflightSyntax::InvalidLiteral));
        }
        self.offset = end;
        Ok(())
    }
    fn parse_number(&mut self) -> Result<(), JsonPreflightError> {
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.error(JsonPreflightSyntax::LeadingZero));
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(self.error(JsonPreflightSyntax::InvalidNumber)),
        }
        if self.peek() == Some(b'.') {
            self.offset += 1;
            let digits = self.offset;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == digits {
                return Err(self.error(JsonPreflightSyntax::InvalidNumber));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let digits = self.offset;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == digits {
                return Err(self.error(JsonPreflightSyntax::InvalidNumber));
            }
        }
        Ok(())
    }
    fn parse_string(&mut self) -> Result<StringProfile, JsonPreflightError> {
        let token_start = self.offset;
        self.expect(b'"', JsonPreflightSyntax::InvalidString)?;
        let mut decoded_bytes = 0usize;
        let mut escaped = false;
        loop {
            let byte = self
                .bump()
                .ok_or_else(|| self.error(JsonPreflightSyntax::InvalidString))?;
            let added = match byte {
                b'"' => break,
                b'\\' => {
                    escaped = true;
                    match self
                        .bump()
                        .ok_or_else(|| self.error(JsonPreflightSyntax::InvalidEscape))?
                    {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => 1,
                        b'u' => self.parse_unicode_escape()?,
                        _ => return Err(self.error(JsonPreflightSyntax::InvalidEscape)),
                    }
                }
                0x00..=0x1f => return Err(self.error(JsonPreflightSyntax::InvalidString)),
                _ => 1,
            };
            decoded_bytes = self.checked_add(decoded_bytes, added)?;
            self.enforce(
                JsonPreflightResource::DecodedStringBytes,
                decoded_bytes,
                self.limits.max_decoded_string_bytes,
            )?;
        }
        let encoded_bytes = self
            .offset
            .checked_sub(token_start)
            .ok_or_else(|| JsonPreflightError::arithmetic(self.offset))?;
        self.enforce(
            JsonPreflightResource::EncodedStringBytes,
            encoded_bytes,
            self.limits.max_encoded_string_bytes,
        )?;
        Ok(StringProfile {
            encoded_bytes,
            decoded_bytes,
            capacity_bytes: decoded_bytes,
            escaped,
        })
    }
    fn record_string(
        &mut self,
        string: StringProfile,
        object_key: bool,
    ) -> Result<(), JsonPreflightError> {
        self.profile.encoded_string_bytes =
            self.checked_add(self.profile.encoded_string_bytes, string.encoded_bytes)?;
        let decoded = self.checked_add(self.profile.decoded_string_bytes, string.decoded_bytes)?;
        self.enforce(
            JsonPreflightResource::TotalDecodedStringBytes,
            decoded,
            self.limits.max_total_decoded_string_bytes,
        )?;
        self.profile.decoded_string_bytes = decoded;
        if object_key {
            self.profile.object_key_decoded_bytes =
                self.checked_add(self.profile.object_key_decoded_bytes, string.decoded_bytes)?;
        }
        self.profile.max_encoded_string_bytes = self
            .profile
            .max_encoded_string_bytes
            .max(string.encoded_bytes);
        self.profile.max_decoded_string_bytes = self
            .profile
            .max_decoded_string_bytes
            .max(string.decoded_bytes);
        self.profile.string_capacity_bytes =
            self.checked_add(self.profile.string_capacity_bytes, string.capacity_bytes)?;
        if string.escaped {
            self.profile.max_escaped_string_capacity_bytes = self
                .profile
                .max_escaped_string_capacity_bytes
                .max(string.capacity_bytes);
        }
        Ok(())
    }
    fn parse_unicode_escape(&mut self) -> Result<usize, JsonPreflightError> {
        let high = self.parse_hex_quad()?;
        if (0xd800..=0xdbff).contains(&high) {
            self.expect(b'\\', JsonPreflightSyntax::InvalidUnicodeEscape)?;
            self.expect(b'u', JsonPreflightSyntax::InvalidUnicodeEscape)?;
            let low = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(self.error(JsonPreflightSyntax::InvalidUnicodeEscape));
            }
            return Ok(4);
        }
        if (0xdc00..=0xdfff).contains(&high) {
            return Err(JsonPreflightError::syntax(
                self.offset.saturating_sub(1),
                JsonPreflightSyntax::UnexpectedLowSurrogate,
            ));
        }
        char::from_u32(high)
            .map(char::len_utf8)
            .ok_or_else(|| self.error(JsonPreflightSyntax::InvalidUnicodeEscape))
    }
    fn parse_hex_quad(&mut self) -> Result<u32, JsonPreflightError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = self
                .bump()
                .ok_or_else(|| self.error(JsonPreflightSyntax::InvalidUnicodeEscape))?;
            let nibble = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a' + 10),
                b'A'..=b'F' => u32::from(digit - b'A' + 10),
                _ => return Err(self.error(JsonPreflightSyntax::InvalidUnicodeEscape)),
            };
            value = (value << 4) | nibble;
        }
        Ok(value)
    }
    fn run(
        mut self,
        complete_document: bool,
        allow_trailing_container_commas: bool,
    ) -> Result<(JsonPreflightProfile, usize), JsonPreflightError> {
        self.skip_whitespace();
        self.start_value()?;
        while !self.root_complete {
            self.skip_whitespace();
            let index = self.frame_len - 1;
            match self.frames[index].state {
                FrameState::ArrayFirstOrEnd => {
                    if self.peek() == Some(b']') {
                        self.offset += 1;
                        self.close_container()?;
                    } else {
                        self.add_entry(true)?;
                        self.frames[index].state = FrameState::ArrayCommaOrEnd;
                        self.start_value()?;
                    }
                }
                FrameState::ArrayValue => {
                    if self.peek() == Some(b']') {
                        if allow_trailing_container_commas {
                            self.offset += 1;
                            self.close_container()?;
                            continue;
                        }
                        return Err(self.error(JsonPreflightSyntax::TrailingArrayComma));
                    }
                    self.add_entry(true)?;
                    self.frames[index].state = FrameState::ArrayCommaOrEnd;
                    self.start_value()?;
                }
                FrameState::ArrayCommaOrEnd => match self.bump() {
                    Some(b',') => self.frames[index].state = FrameState::ArrayValue,
                    Some(b']') => self.close_container()?,
                    _ => return Err(self.error(JsonPreflightSyntax::InvalidArray)),
                },
                FrameState::ObjectFirstKeyOrEnd => {
                    if self.peek() == Some(b'}') {
                        self.offset += 1;
                        self.close_container()?;
                    } else {
                        self.add_entry(false)?;
                        let key = self.parse_string()?;
                        self.record_string(key, true)?;
                        self.frames[index].state = FrameState::ObjectColon;
                    }
                }
                FrameState::ObjectKey => {
                    if self.peek() == Some(b'}') {
                        if allow_trailing_container_commas {
                            self.offset += 1;
                            self.close_container()?;
                            continue;
                        }
                        return Err(self.error(JsonPreflightSyntax::TrailingObjectComma));
                    }
                    self.add_entry(false)?;
                    let key = self.parse_string()?;
                    self.record_string(key, true)?;
                    self.frames[index].state = FrameState::ObjectColon;
                }
                FrameState::ObjectColon => {
                    if self.peek() != Some(b':') {
                        return Err(self.error(JsonPreflightSyntax::ExpectedColon));
                    }
                    self.offset += 1;
                    self.frames[index].state = FrameState::ObjectValue;
                }
                FrameState::ObjectValue => {
                    self.frames[index].state = FrameState::ObjectCommaOrEnd;
                    self.start_value()?;
                }
                FrameState::ObjectCommaOrEnd => match self.bump() {
                    Some(b',') => self.frames[index].state = FrameState::ObjectKey,
                    Some(b'}') => self.close_container()?,
                    _ => return Err(self.error(JsonPreflightSyntax::InvalidObject)),
                },
            }
        }
        if complete_document {
            self.skip_whitespace();
            if self.offset != self.bytes.len() {
                return Err(self.error(JsonPreflightSyntax::TrailingCharacters));
            }
        }
        Ok((self.profile, self.offset))
    }
}
/// Validate and profile one complete JSON document without heap allocation.
///
/// Duplicate object names are left to the typed decoder. Retaining them here would require an
/// input-sized key set and is not necessary for lexical or allocation admission.
pub fn preflight_slice(
    bytes: &[u8],
    limits: JsonPreflightLimits,
) -> Result<JsonPreflightProfile, JsonPreflightError> {
    if bytes.len() > limits.max_raw_bytes {
        return Err(JsonPreflightError::resource(
            JsonPreflightResource::RawBytes,
            bytes.len(),
            limits.max_raw_bytes,
            0,
        ));
    }
    if let Err(error) = core::str::from_utf8(bytes) {
        return Err(JsonPreflightError::syntax(
            error.valid_up_to(),
            JsonPreflightSyntax::InvalidUtf8,
        ));
    }
    let (mut profile, _) = Scanner::new(bytes, 0, 1, limits).run(true, false)?;
    profile.raw_bytes = bytes.len();
    Ok(profile)
}
pub(super) fn value_profile_at_depth(
    input: &str,
    start: usize,
    root_depth: usize,
) -> Result<(JsonPreflightProfile, usize), JsonPreflightError> {
    if root_depth == 0 || start > input.len() || !input.is_char_boundary(start) {
        return Err(JsonPreflightError::syntax(
            start.min(input.len()),
            JsonPreflightSyntax::UnexpectedToken,
        ));
    }
    Scanner::new(
        input.as_bytes(),
        start,
        root_depth,
        JsonPreflightLimits::lexical_unbounded(),
    )
    .run(false, false)
}
pub(super) fn container_profile_at_depth(
    input: &str,
    start: usize,
    root_depth: usize,
) -> Result<(JsonPreflightProfile, usize), JsonPreflightError> {
    if root_depth == 0 || start > input.len() || !input.is_char_boundary(start) {
        return Err(JsonPreflightError::syntax(
            start.min(input.len()),
            JsonPreflightSyntax::UnexpectedToken,
        ));
    }
    Scanner::new(
        input.as_bytes(),
        start,
        root_depth,
        JsonPreflightLimits::lexical_unbounded(),
    )
    .run(false, true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, PartialEq, Eq, crate::derive::JsonDeserialize)]
    struct TaggedContent {
        value: String,
    }
    #[derive(Debug, PartialEq, Eq, crate::derive::JsonDeserialize)]
    #[norito(tag = "kind", content = "content")]
    enum TaggedFixture {
        Item(TaggedContent),
    }
    fn generous() -> JsonPreflightLimits {
        JsonPreflightLimits::new(
            1 << 20,
            1 << 16,
            1 << 20,
            1 << 20,
            1 << 20,
            1 << 16,
            1 << 16,
            1 << 16,
            1 << 16,
            MAX_JSON_VALUE_NESTING_DEPTH,
        )
    }
    #[test]
    fn preserves_actionable_container_syntax_classes() {
        for (input, expected) in [
            (&b"[0,]"[..], JsonPreflightSyntax::TrailingArrayComma),
            (&b"{\"a\":0,}"[..], JsonPreflightSyntax::TrailingObjectComma),
            (&b"{\"a\" 0}"[..], JsonPreflightSyntax::ExpectedColon),
        ] {
            assert_eq!(
                preflight_slice(input, generous())
                    .expect_err("malformed container")
                    .syntax_kind(),
                Some(expected)
            );
        }
    }
    #[test]
    fn profiles_strings_containers_and_value_spans() {
        let input = br#"{"a":["\u0041\n",0],"b":{"c":true}}"#;
        let profile = preflight_slice(input, generous()).expect("valid JSON");
        assert_eq!(profile.raw_bytes(), input.len());
        assert_eq!(profile.values(), 6);
        assert_eq!(profile.arrays(), 1);
        assert_eq!(profile.objects(), 2);
        assert_eq!(profile.array_entries(), 2);
        assert_eq!(profile.object_entries(), 3);
        assert_eq!(profile.object_btree_node_upper_bound(), 2);
        assert_eq!(profile.root_container_entries(), 2);
        assert_eq!(profile.max_container_entries(), 2);
        assert_eq!(profile.decoded_string_bytes(), 5);
        assert_eq!(profile.object_key_decoded_bytes(), 3);
        assert_eq!(profile.max_decoded_string_bytes(), 2);
        assert_eq!(profile.max_nesting_depth(), 3);
        assert_eq!(
            profile.string_capacity_bytes(),
            profile.decoded_string_bytes()
        );
        assert_eq!(profile.max_escaped_string_capacity_bytes(), 2);
        assert!(profile.value_span_bytes() > input.len());
    }
    #[test]
    fn sums_btree_nodes_per_object_instead_of_from_aggregate_entries() {
        let input = br#"[{"a":0,"b":0,"c":0,"d":0,"e":0},{}]"#;
        let profile = preflight_slice(input, generous()).expect("valid JSON");
        assert_eq!(profile.objects(), 2);
        assert_eq!(profile.object_entries(), 5);
        assert_eq!(profile.object_btree_node_upper_bound(), 1);
    }
    #[test]
    fn profiles_native_value_object_charge_at_leaf_split_and_nested_boundaries() {
        for entries in [0, 1, 5, 6, 10, 11, 12, 13, 31, 64, 256] {
            let fields = (0..entries)
                .map(|index| format!("\"k{index}\":0"))
                .collect::<Vec<_>>()
                .join(",");
            let object = format!("{{{fields}}}");
            let profile = preflight_slice(object.as_bytes(), generous()).unwrap();
            let owner =
                crate::core::owned_btree_allocation_bytes::<String, super::super::Value>(entries)
                    .unwrap();
            assert_eq!(
                profile.object_btree_allocation_bytes(),
                owner,
                "entries={entries}"
            );
            let nested = format!("{{\"full\":{object},\"empty\":{{}}}}");
            let profile = preflight_slice(nested.as_bytes(), generous()).unwrap();
            assert_eq!(
                profile.object_btree_allocation_bytes(),
                owner
                    + crate::core::owned_btree_allocation_bytes::<String, super::super::Value>(2)
                        .unwrap(),
                "each object retains its own original charge"
            );
        }
    }
    #[test]
    fn duplicate_object_keys_retain_original_lexical_parser_charge() {
        let object = format!("{{{}}}", ["\"same\":0"; 12].join(","));
        let profile = preflight_slice(object.as_bytes(), generous()).unwrap();
        assert_eq!(profile.object_entries(), 12);
        assert_eq!(
            profile.object_btree_allocation_bytes(),
            crate::core::owned_btree_allocation_bytes::<String, super::super::Value>(12).unwrap()
        );
        let error = crate::json::from_slice::<super::super::Value>(object.as_bytes())
            .expect_err("duplicate keys retain the original canonical parser refusal");
        assert!(matches!(error, crate::json::Error::DuplicateField { field } if field == "same"));
    }
    #[test]
    fn enforces_exact_decode_limit_mapping() {
        let input = br#"{"a":[0,1]}"#;
        let limits = crate::core::DecodeLimits::new(2, 1, 3, usize::MAX, 2);
        preflight_slice(
            input,
            JsonPreflightLimits::from_decode_limits(input.len(), limits),
        )
        .expect("exact limits fit");
        let short = crate::core::DecodeLimits::new(1, 1, 3, usize::MAX, 3);
        assert_eq!(
            preflight_slice(
                input,
                JsonPreflightLimits::from_decode_limits(input.len(), short),
            )
            .expect_err("array exceeds per-container limit")
            .resource_kind(),
            Some(JsonPreflightResource::ContainerEntries)
        );
        let shallow = crate::core::DecodeLimits::new(2, 1, 3, usize::MAX, 1);
        assert_eq!(
            preflight_slice(
                input,
                JsonPreflightLimits::from_decode_limits(input.len(), shallow),
            )
            .expect_err("nested scalar exceeds depth")
            .resource_kind(),
            Some(JsonPreflightResource::NestingDepth)
        );
    }
    #[test]
    fn exact_raw_string_and_total_element_boundaries() {
        let input = br#"["ab",{"c":0}]"#;
        let mut limits = generous();
        limits.max_raw_bytes = input.len() - 1;
        assert_eq!(
            preflight_slice(input, limits)
                .expect_err("raw limit")
                .resource_kind(),
            Some(JsonPreflightResource::RawBytes)
        );
        limits = generous();
        limits.max_decoded_string_bytes = 1;
        assert_eq!(
            preflight_slice(input, limits)
                .expect_err("decoded string limit")
                .resource_kind(),
            Some(JsonPreflightResource::DecodedStringBytes)
        );
        limits = generous();
        limits.max_total_elements = 2;
        assert_eq!(
            preflight_slice(input, limits)
                .expect_err("combined element limit")
                .resource_kind(),
            Some(JsonPreflightResource::TotalElements)
        );
    }
    #[test]
    fn rejects_malformed_json_without_reflecting_input() {
        for input in [
            &b"[0,]"[..],
            &b"{\"a\":1,}"[..],
            &b"\"\\x\""[..],
            &b"01"[..],
            &b"1."[..],
            &b"1e+"[..],
            &b"true false"[..],
            &b"{a:0}"[..],
        ] {
            preflight_slice(input, generous()).expect_err("malformed JSON");
        }
        let error = preflight_slice(&[b'"', 0xff, b'"'], generous()).expect_err("invalid UTF-8");
        assert_eq!(error.syntax_kind(), Some(JsonPreflightSyntax::InvalidUtf8));
        assert_eq!(error.to_string(), "invalid UTF-8 at byte 1");
        let leading_zero = preflight_slice(b"-012", generous()).expect_err("leading zero");
        assert_eq!(
            leading_zero.syntax_kind(),
            Some(JsonPreflightSyntax::LeadingZero)
        );
        assert_eq!(leading_zero.offset(), 2);
        let isolated_low =
            preflight_slice(br#""\uDD1E""#, generous()).expect_err("isolated low surrogate");
        assert_eq!(
            isolated_low.syntax_kind(),
            Some(JsonPreflightSyntax::UnexpectedLowSurrogate)
        );
        assert_eq!(isolated_low.offset(), 6);
    }
    #[test]
    fn fixed_stack_accepts_exact_depth_and_rejects_one_more() {
        let at_limit = format!(
            "{}null{}",
            "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1),
            "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1)
        );
        preflight_slice(at_limit.as_bytes(), generous()).expect("exact depth");
        let over = format!("[{at_limit}]");
        assert_eq!(
            preflight_slice(over.as_bytes(), generous())
                .expect_err("over depth")
                .resource_kind(),
            Some(JsonPreflightResource::NestingDepth)
        );
    }
    #[test]
    fn prefix_scan_returns_exact_value_end() {
        let input = "  {\"a\":[1]} trailing";
        let start = input.find('{').expect("object start");
        let (_, end) = value_profile_at_depth(input, start, 1).expect("value boundary");
        assert_eq!(&input[start..end], "{\"a\":[1]}");
    }
    #[test]
    fn tagged_derive_borrows_content_in_either_field_order() {
        for input in [
            r#"{"kind":"Item","content":{"value":"ok"}}"#,
            r#"{"content":{"value":"ok"},"kind":"Item"}"#,
            r#"{"\u006b\u0069\u006e\u0064":"Item","content":{"value":"ok"}}"#,
        ] {
            assert_eq!(
                super::super::from_str::<TaggedFixture>(input).expect("tagged JSON"),
                TaggedFixture::Item(TaggedContent {
                    value: "ok".to_owned(),
                })
            );
        }
    }
    #[test]
    fn parser_raw_value_slice_borrows_original_input() {
        let input = r#"  {"nested":[1,2]} tail"#;
        let mut parser = super::super::Parser::new(input);
        let raw = parser.raw_value_slice().expect("borrow raw value");
        assert_eq!(raw, r#"{"nested":[1,2]}"#);
        assert_eq!(raw.as_ptr(), input[2..].as_ptr());
        parser.skip_ws();
        assert_eq!(parser.input_from_pos(), "tail");
    }
}
