//! Canonical schema-bound Norito frames for Kotodama V1 numeric values.
//!
//! These frames are consensus-visible. They deliberately use fixed-width
//! `u32` mantissa lengths, minimal little-endian two's-complement bytes, no
//! compression, no layout flags, and no alignment padding.
use crate::{
    bigint::{BigInt, BigIntError},
    numeric::{
        MAX_DECIMAL_SCALE, MAX_MANTISSA_BYTES, Numeric, NumericOperationError, NumericWorkStep,
        ObservedNumericError, Quantity,
    },
};
use norito::{
    Archived, DeserializePayload, Error as NoritoError, NoritoSerialize, SerializePayload,
    json::{self, FastJsonWrite, JsonDeserialize},
};
/// Nominal schema name of a V1 integer frame.
pub const INT_SCHEMA_NAME_V1: &str = "iroha.numeric.IntValueV1";
/// Nominal schema name of a V1 decimal frame.
pub const DECIMAL_SCHEMA_NAME_V1: &str = "iroha.numeric.DecimalValueV1";
/// Nominal schema name of a V1 quantity frame.
pub const QUANTITY_SCHEMA_NAME_V1: &str = "iroha.numeric.QuantityValueV1";
/// Type-name schema hash of [`INT_SCHEMA_NAME_V1`].
pub const INT_SCHEMA_HASH_V1: [u8; 16] = [
    0x07, 0xc0, 0x39, 0x45, 0x73, 0x63, 0xb9, 0xe1, 0xd3, 0x6b, 0xbd, 0x31, 0xd9, 0x3d, 0xec, 0x4a,
];
/// Type-name schema hash of [`DECIMAL_SCHEMA_NAME_V1`].
pub const DECIMAL_SCHEMA_HASH_V1: [u8; 16] = [
    0xba, 0x2f, 0xfe, 0xd5, 0x2e, 0x4d, 0x8e, 0xe1, 0x6f, 0x17, 0xef, 0xef, 0xe1, 0x82, 0x85, 0x24,
];
/// Type-name schema hash of [`QUANTITY_SCHEMA_NAME_V1`].
pub const QUANTITY_SCHEMA_HASH_V1: [u8; 16] = [
    0xe4, 0x76, 0x99, 0x84, 0xc8, 0x1c, 0xe0, 0xe8, 0xb6, 0x78, 0xf2, 0xeb, 0x06, 0x27, 0x4e, 0xe3,
];
/// Norito header length used by all V1 numeric frames.
pub const NUMERIC_FRAME_HEADER_BYTES_V1: usize = 40;
/// Maximum canonical integer frame length.
pub const MAX_INT_FRAME_BYTES_V1: usize = NUMERIC_FRAME_HEADER_BYTES_V1 + 4 + MAX_MANTISSA_BYTES;
/// Maximum canonical decimal frame length.
pub const MAX_DECIMAL_FRAME_BYTES_V1: usize = MAX_INT_FRAME_BYTES_V1 + 1;
/// Maximum canonical quantity frame length.
pub const MAX_QUANTITY_FRAME_BYTES_V1: usize = MAX_DECIMAL_FRAME_BYTES_V1;
/// Pointer-ABI TLV overhead outside the schema-bound frame.
pub const NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1: usize = 39;
/// Maximum integer pointer-envelope length.
pub const MAX_INT_ENVELOPE_BYTES_V1: usize =
    MAX_INT_FRAME_BYTES_V1 + NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1;
/// Maximum decimal pointer-envelope length.
pub const MAX_DECIMAL_ENVELOPE_BYTES_V1: usize =
    MAX_DECIMAL_FRAME_BYTES_V1 + NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1;
/// Maximum quantity pointer-envelope length.
pub const MAX_QUANTITY_ENVELOPE_BYTES_V1: usize =
    MAX_QUANTITY_FRAME_BYTES_V1 + NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1;
/// Failure while validating or decoding a canonical V1 numeric frame.
#[derive(Debug, Clone, displaydoc::Display, thiserror::Error)]
pub enum NumericAbiError {
    /// Frame is shorter than the fixed Norito header
    FrameTooShort,
    /// Frame exceeds the maximum size for its declared numeric type
    FrameTooLarge,
    /// Frame does not use the canonical Norito V1 header
    InvalidHeader,
    /// Frame schema hash does not match the nominal numeric type
    SchemaMismatch,
    /// Numeric frames must be uncompressed
    CompressionNotAllowed,
    /// Numeric frames must use layout flags zero
    LayoutFlagsNotAllowed,
    /// Declared payload length is invalid or does not consume the frame exactly
    LengthMismatch,
    /// Mantissa encoding is outside the signed domain
    MantissaOverflow,
    /// Mantissa encoding is not minimal
    NonCanonicalMantissa,
    /// Decimal scale is outside `0..=28`
    InvalidScale,
    /// Decimal representation contains removable trailing zeroes
    NonCanonicalDecimal,
    /// Quantity mantissa is negative
    NegativeQuantity,
    /// Norito frame validation failed: {_0}
    Norito(String),
}
impl PartialEq for NumericAbiError {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
            && match (self, other) {
                (Self::Norito(lhs), Self::Norito(rhs)) => lhs == rhs,
                _ => true,
            }
    }
}
impl Eq for NumericAbiError {}
/// Failure from a staged numeric-frame decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedNumericAbiError<E> {
    /// Structural or canonical frame failure.
    Abi(NumericAbiError),
    /// The caller rejected the canonical-value phase before it began.
    Observer(E),
}
/// A canonical-value decode work unit reported immediately before it begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericAbiWorkStep {
    /// Scan and decode the bounded numeric body.
    CanonicalBody {
        /// Complete body length in bytes.
        body_bytes: u16,
    },
    /// Probe a scaled decimal mantissa for divisibility by ten.
    CanonicalityProbe {
        /// Mantissa width in logical 64-bit limbs.
        mantissa_limbs: u16,
        /// Encoded decimal scale.
        scale: u8,
    },
}
/// Canonical V1 integer frame value.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IntValueV1(BigInt);
impl IntValueV1 {
    /// Validate and wrap a signed-domain integer.
    ///
    /// # Errors
    /// Rejects values outside the signed 512-bit V1 domain.
    pub fn try_new(value: BigInt) -> Result<Self, NumericAbiError> {
        Self::try_new_with_mantissa_len(value).map(|(value, _)| value)
    }
    /// Validate an integer and return its exact minimal mantissa byte length.
    ///
    /// This combines the V1 domain scan with output-length preparation so a
    /// metered serializer does not need to validate the same value twice.
    ///
    /// # Errors
    /// Rejects values outside the signed 512-bit V1 domain.
    pub fn try_new_with_mantissa_len(value: BigInt) -> Result<(Self, usize), NumericAbiError> {
        let mantissa_len = validated_int_mantissa_len(&value)?;
        Ok((Self(value), mantissa_len))
    }
    /// Prepare the exact nominal frame while borrowing its original integer.
    ///
    /// Preparation retains the minimal length without copying native digits or
    /// acquiring allocation credit. The borrow keeps the source immutable until
    /// its prepared frame is no longer used.
    ///
    /// # Errors
    /// Rejects values outside the signed 512-bit V1 domain.
    pub fn prepare_frame(value: &BigInt) -> Result<PreparedNumericFrameV1<'_>, NumericAbiError> {
        let mantissa_len = validated_int_mantissa_len(value)?;
        Ok(PreparedNumericFrameV1 {
            source: NumericFrameSourceV1::Int(value),
            frame_len: NUMERIC_FRAME_HEADER_BYTES_V1 + 4 + mantissa_len,
        })
    }
    /// Borrow the integer.
    #[must_use]
    pub fn as_int(&self) -> &BigInt {
        &self.0
    }
    /// Consume the wrapper and return the integer.
    #[must_use]
    pub fn into_int(self) -> BigInt {
        self.0
    }
    /// Encode a canonical, uncompressed, schema-bound Norito frame.
    ///
    /// # Errors
    /// Returns a Norito framing error.
    pub fn encode_frame(&self) -> Result<Vec<u8>, NumericAbiError> {
        NumericFrameSourceV1::Int(&self.0).encode_frame()
    }
    /// Strictly decode a canonical schema-bound integer frame.
    ///
    /// # Errors
    /// Rejects malformed headers, checksum errors, wrong schemas, nonzero
    /// flags, noncanonical signed bytes, trailing bytes, and oversized values.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, NumericAbiError> {
        match Self::decode_frame_observed(frame, |_| Ok::<_, core::convert::Infallible>(())) {
            Ok(value) => Ok(value),
            Err(ObservedNumericAbiError::Abi(error)) => Err(error),
            Err(ObservedNumericAbiError::Observer(never)) => match never {},
        }
    }
    /// Decode in stages, reporting each canonical-value work unit after
    /// structural Norito validation and before that work begins.
    ///
    /// # Errors
    /// Returns a structural/canonical ABI error or the observer error.
    pub fn decode_frame_observed<E>(
        frame: &[u8],
        mut observer: impl FnMut(NumericAbiWorkStep) -> Result<(), E>,
    ) -> Result<Self, ObservedNumericAbiError<E>> {
        decode_frame_observed(
            frame,
            INT_SCHEMA_HASH_V1,
            MAX_INT_FRAME_BYTES_V1,
            &mut observer,
            |body, _| {
                decode_int_body(body)
                    .map(|(value, used)| (Self(value), used))
                    .map_err(ObservedNumericAbiError::Abi)
            },
        )
    }
}
/// Canonical V1 exact-decimal frame value.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DecimalValueV1(Numeric);
impl DecimalValueV1 {
    /// Wrap a canonical decimal value.
    ///
    /// Every publicly constructible [`Numeric`] satisfies the canonical
    /// decimal invariant. This constructor preserves that proof without a
    /// redundant divisibility probe during output serialization.
    #[must_use]
    pub fn new(value: Numeric) -> Self {
        Self(value)
    }
    /// Prepare the exact nominal frame while borrowing a canonical decimal.
    ///
    /// The existing Numeric invariant supplies its domain and normalization;
    /// preparation only retains the minimal length and never copies its digits.
    #[must_use]
    pub fn prepare_frame(value: &Numeric) -> PreparedNumericFrameV1<'_> {
        PreparedNumericFrameV1 {
            source: NumericFrameSourceV1::Decimal(value),
            frame_len: NUMERIC_FRAME_HEADER_BYTES_V1 + 4 + value.mantissa().twos_byte_len() + 1,
        }
    }
    /// Canonicalize a decimal for the V1 wire domain.
    ///
    /// # Errors
    /// Returns a canonical result-domain failure.
    pub fn try_from_numeric(value: Numeric) -> Result<Self, NumericOperationError> {
        Ok(Self(value.canonicalize_decimal()?))
    }
    /// Wrap an already canonical decimal.
    ///
    /// # Errors
    /// Rejects noncanonical input.
    pub fn from_canonical_numeric(value: Numeric) -> Result<Self, NumericOperationError> {
        value.validate_decimal()?;
        Ok(Self(value))
    }
    /// Borrow the canonical decimal.
    #[must_use]
    pub fn as_numeric(&self) -> &Numeric {
        &self.0
    }
    /// Consume the wrapper and return the canonical decimal.
    #[must_use]
    pub fn into_numeric(self) -> Numeric {
        self.0
    }
    /// Encode a canonical, uncompressed, schema-bound Norito frame.
    ///
    /// # Errors
    /// Returns a Norito framing error.
    pub fn encode_frame(&self) -> Result<Vec<u8>, NumericAbiError> {
        NumericFrameSourceV1::Decimal(&self.0).encode_frame()
    }
    /// Strictly decode a canonical schema-bound decimal frame.
    ///
    /// # Errors
    /// Rejects every noncanonical or malformed representation.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, NumericAbiError> {
        match Self::decode_frame_observed(frame, |_| Ok::<_, core::convert::Infallible>(())) {
            Ok(value) => Ok(value),
            Err(ObservedNumericAbiError::Abi(error)) => Err(error),
            Err(ObservedNumericAbiError::Observer(never)) => match never {},
        }
    }
    /// Decode in stages, reporting each canonical-value work unit after
    /// structural Norito validation and before that work begins.
    ///
    /// # Errors
    /// Returns a structural/canonical ABI error or the observer error.
    pub fn decode_frame_observed<E>(
        frame: &[u8],
        mut observer: impl FnMut(NumericAbiWorkStep) -> Result<(), E>,
    ) -> Result<Self, ObservedNumericAbiError<E>> {
        decode_frame_observed(
            frame,
            DECIMAL_SCHEMA_HASH_V1,
            MAX_DECIMAL_FRAME_BYTES_V1,
            &mut observer,
            |body, observer| {
                decode_scaled_body_observed(body, observer).map(|(value, used)| (Self(value), used))
            },
        )
    }
}
/// Canonical V1 non-negative quantity frame value.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QuantityValueV1(Quantity);
impl QuantityValueV1 {
    /// Wrap a nominal canonical quantity.
    #[must_use]
    pub fn new(value: Quantity) -> Self {
        Self(value)
    }
    /// Prepare the exact nominal frame while borrowing a canonical quantity.
    ///
    /// Its existing nonnegative canonical invariant remains with the original
    /// owner; preparation retains length without copying any native digits.
    #[must_use]
    pub fn prepare_frame(value: &Quantity) -> PreparedNumericFrameV1<'_> {
        PreparedNumericFrameV1 {
            source: NumericFrameSourceV1::Quantity(value),
            frame_len: NUMERIC_FRAME_HEADER_BYTES_V1 + 4 + value.mantissa().twos_byte_len() + 1,
        }
    }
    /// Borrow the quantity.
    #[must_use]
    pub fn as_quantity(&self) -> &Quantity {
        &self.0
    }
    /// Consume the wrapper and return the quantity.
    #[must_use]
    pub fn into_quantity(self) -> Quantity {
        self.0
    }
    /// Encode a canonical, uncompressed, schema-bound Norito frame.
    ///
    /// # Errors
    /// Returns a Norito framing error.
    pub fn encode_frame(&self) -> Result<Vec<u8>, NumericAbiError> {
        NumericFrameSourceV1::Quantity(&self.0).encode_frame()
    }
    /// Strictly decode a canonical schema-bound quantity frame.
    ///
    /// # Errors
    /// Rejects every malformed, noncanonical, or negative representation.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, NumericAbiError> {
        match Self::decode_frame_observed(frame, |_| Ok::<_, core::convert::Infallible>(())) {
            Ok(value) => Ok(value),
            Err(ObservedNumericAbiError::Abi(error)) => Err(error),
            Err(ObservedNumericAbiError::Observer(never)) => match never {},
        }
    }
    /// Decode in stages, reporting each canonical-value work unit after
    /// structural Norito validation and before that work begins.
    ///
    /// # Errors
    /// Returns a structural/canonical ABI error or the observer error.
    pub fn decode_frame_observed<E>(
        frame: &[u8],
        mut observer: impl FnMut(NumericAbiWorkStep) -> Result<(), E>,
    ) -> Result<Self, ObservedNumericAbiError<E>> {
        decode_frame_observed(
            frame,
            QUANTITY_SCHEMA_HASH_V1,
            MAX_QUANTITY_FRAME_BYTES_V1,
            &mut observer,
            |body, observer| {
                let (value, used) = decode_scaled_body_observed(body, observer)?;
                let quantity = Quantity::from_canonical_numeric(value)
                    .map_err(|error| match error {
                        NumericOperationError::NegativeQuantity => {
                            NumericAbiError::NegativeQuantity
                        }
                        NumericOperationError::NonCanonical => NumericAbiError::NonCanonicalDecimal,
                        _ => NumericAbiError::Norito(error.to_string()),
                    })
                    .map_err(ObservedNumericAbiError::Abi)?;
                Ok((Self(quantity), used))
            },
        )
    }
}
/// Prepared canonical numeric frame borrowing one immutable original value.
///
/// This opaque owner carries only its source borrow and exact length. It grants
/// no allocation credit or codec/schema identity, and serialization uses the
/// corresponding actual V1 nominal value type. The existing frame-name and
/// output allocations remain separate original-owner funding work.
/// TODO: fund remaining native result/scratch/frame/envelope/host custody.
pub struct PreparedNumericFrameV1<'value> {
    source: NumericFrameSourceV1<'value>,
    frame_len: usize,
}
impl PreparedNumericFrameV1<'_> {
    /// Read the retained exact frame length without repeating a value scan.
    #[must_use]
    pub fn frame_len(&self) -> usize {
        self.frame_len
    }
    /// Encode through the sole canonical body and actual nominal frame writer.
    ///
    /// # Errors
    /// Preserves the original Norito serialization or framing error.
    pub fn encode_frame(&self) -> Result<Vec<u8>, NumericAbiError> {
        self.source.encode_frame()
    }
}
enum NumericFrameSourceV1<'value> {
    Int(&'value BigInt),
    Decimal(&'value Numeric),
    Quantity(&'value Quantity),
}
impl NumericFrameSourceV1<'_> {
    fn encode_frame(&self) -> Result<Vec<u8>, NumericAbiError> {
        match self {
            Self::Int(value) => {
                encode_numeric_frame::<IntValueV1>(|writer| serialize_int_body(value, writer))
            }
            Self::Decimal(value) => encode_numeric_frame::<DecimalValueV1>(|writer| {
                serialize_scaled_body(value, writer)
            }),
            Self::Quantity(value) => encode_numeric_frame::<QuantityValueV1>(|writer| {
                serialize_scaled_body(value.as_numeric(), writer)
            }),
        }
    }
}
fn validated_int_mantissa_len(value: &BigInt) -> Result<usize, NumericAbiError> {
    let mantissa_len = value.twos_byte_len();
    if mantissa_len > MAX_MANTISSA_BYTES {
        return Err(NumericAbiError::MantissaOverflow);
    }
    Ok(mantissa_len)
}
impl FastJsonWrite for IntValueV1 {
    fn write_json(&self, out: &mut String) {
        json::write_json_string(&self.0.to_string(), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(&self.0.to_string(), out)
    }
}
impl JsonDeserialize for IntValueV1 {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let source = parser.parse_string()?;
        let value = source
            .parse::<BigInt>()
            .map_err(|error| json::Error::InvalidField {
                field: "int".into(),
                message: format!("invalid int `{source}`: {error}"),
            })?;
        if value.to_string() != source {
            return Err(json::Error::InvalidField {
                field: "int".into(),
                message: format!("noncanonical int `{source}`"),
            });
        }
        Self::try_new(value).map_err(|error| json::Error::InvalidField {
            field: "int".into(),
            message: format!("invalid int `{source}`: {error}"),
        })
    }
}
impl FastJsonWrite for DecimalValueV1 {
    fn write_json(&self, out: &mut String) {
        self.0.write_json(out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.write_json_to(out)
    }
}
impl JsonDeserialize for DecimalValueV1 {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = Numeric::json_deserialize(parser)?;
        Self::from_canonical_numeric(value).map_err(|error| json::Error::InvalidField {
            field: "decimal".into(),
            message: format!("invalid decimal: {error}"),
        })
    }
}
impl FastJsonWrite for QuantityValueV1 {
    fn write_json(&self, out: &mut String) {
        self.0.write_json(out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.write_json_to(out)
    }
}
impl JsonDeserialize for QuantityValueV1 {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Ok(Self(Quantity::json_deserialize(parser)?))
    }
}
// Borrow the same canonical mantissa serializer used by BigInt's Norito codec.
// Valid V1 values need no native-digit clone or temporary encoded byte Vec.
fn serialize_int_body(
    value: &BigInt,
    writer: &mut norito::core::Encoder<'_>,
) -> Result<(), NoritoError> {
    value.serialize(writer).map_err(|error| match error {
        // Preserve the numeric payload writer's existing error representation.
        NoritoError::Io(error) => NoritoError::Message(error.to_string()),
        error => error,
    })
}
fn serialize_scaled_body(
    value: &Numeric,
    writer: &mut norito::core::Encoder<'_>,
) -> Result<(), NoritoError> {
    serialize_int_body(value.mantissa(), writer)?;
    writer
        .write_all(&[u8::try_from(value.scale()).expect("validated decimal scale fits u8")])
        .map_err(|error| NoritoError::Message(error.to_string()))
}
fn encode_numeric_frame<T: NoritoSerialize>(
    serialize: impl FnOnce(&mut norito::core::Encoder<'_>) -> Result<(), NoritoError>,
) -> Result<Vec<u8>, NumericAbiError> {
    // All three canonical bodies are at most u32 length + signed512 bytes +
    // one scale byte. The existing frame writer still owns header/CRC/output.
    let mut body = [0_u8; 4 + MAX_MANTISSA_BYTES + 1];
    let unused = {
        let mut remaining = body.as_mut_slice();
        serialize(&mut norito::core::Encoder::new(&mut remaining))
            .map_err(|error| NumericAbiError::Norito(error.to_string()))?;
        remaining.len()
    };
    let used = body.len() - unused;
    encode_frame::<T>(&body[..used])
}
fn encode_frame<T: NoritoSerialize>(body: &[u8]) -> Result<Vec<u8>, NumericAbiError> {
    norito::core::frame_bare_with_header_flags::<T>(body, 0)
        .map_err(|error| NumericAbiError::Norito(error.to_string()))
}
fn validate_frame_header(
    frame: &[u8],
    schema: [u8; 16],
    maximum: usize,
) -> Result<(), NumericAbiError> {
    if frame.len() < NUMERIC_FRAME_HEADER_BYTES_V1 {
        return Err(NumericAbiError::FrameTooShort);
    }
    if frame.len() > maximum {
        return Err(NumericAbiError::FrameTooLarge);
    }
    if frame[..4] != norito::core::MAGIC
        || frame[4] != norito::core::VERSION_MAJOR
        || frame[5] != norito::core::VERSION_MINOR
    {
        return Err(NumericAbiError::InvalidHeader);
    }
    if frame[6..22] != schema {
        return Err(NumericAbiError::SchemaMismatch);
    }
    if frame[22] != 0 {
        return Err(NumericAbiError::CompressionNotAllowed);
    }
    if frame[39] != 0 {
        return Err(NumericAbiError::LayoutFlagsNotAllowed);
    }
    let length = u64::from_le_bytes(
        frame[23..31]
            .try_into()
            .expect("fixed header length was checked"),
    );
    let length = usize::try_from(length).map_err(|_| NumericAbiError::LengthMismatch)?;
    if NUMERIC_FRAME_HEADER_BYTES_V1.checked_add(length) != Some(frame.len()) {
        return Err(NumericAbiError::LengthMismatch);
    }
    Ok(())
}
fn validate_frame(frame: &[u8], schema: [u8; 16], maximum: usize) -> Result<(), NumericAbiError> {
    validate_frame_header(frame, schema, maximum)?;
    let checksum = u64::from_le_bytes(
        frame[31..39]
            .try_into()
            .expect("fixed header length was checked"),
    );
    let body = &frame[NUMERIC_FRAME_HEADER_BYTES_V1..];
    if norito::core::hardware_crc64(body) != checksum {
        return Err(NumericAbiError::Norito(
            NoritoError::ChecksumMismatch.to_string(),
        ));
    }
    Ok(())
}
fn decode_frame_observed<T, E, F>(
    frame: &[u8],
    schema: [u8; 16],
    maximum: usize,
    observer: &mut F,
    decode_body: impl FnOnce(&[u8], &mut F) -> Result<(T, usize), ObservedNumericAbiError<E>>,
) -> Result<T, ObservedNumericAbiError<E>>
where
    F: FnMut(NumericAbiWorkStep) -> Result<(), E>,
{
    validate_frame(frame, schema, maximum).map_err(ObservedNumericAbiError::Abi)?;
    let body = &frame[NUMERIC_FRAME_HEADER_BYTES_V1..];
    observer(NumericAbiWorkStep::CanonicalBody {
        body_bytes: u16::try_from(body.len())
            .expect("the bounded numeric V1 body length always fits u16"),
    })
    .map_err(ObservedNumericAbiError::Observer)?;
    let (value, used) = decode_body(body, observer)?;
    if used != body.len() {
        return Err(ObservedNumericAbiError::Abi(
            NumericAbiError::LengthMismatch,
        ));
    }
    Ok(value)
}
fn decode_int_body(bytes: &[u8]) -> Result<(BigInt, usize), NumericAbiError> {
    if bytes.len() < 4 {
        return Err(NumericAbiError::LengthMismatch);
    }
    let length = usize::try_from(u32::from_le_bytes(
        bytes[..4].try_into().expect("length prefix was checked"),
    ))
    .map_err(|_| NumericAbiError::LengthMismatch)?;
    if length > MAX_MANTISSA_BYTES {
        return Err(NumericAbiError::MantissaOverflow);
    }
    let end = 4_usize
        .checked_add(length)
        .ok_or(NumericAbiError::LengthMismatch)?;
    if end > bytes.len() {
        return Err(NumericAbiError::LengthMismatch);
    }
    let payload = &bytes[4..end];
    let value = BigInt::from_twos_bytes(payload).map_err(|error| match error {
        BigIntError::Overflow => NumericAbiError::MantissaOverflow,
        BigIntError::NonCanonical => NumericAbiError::NonCanonicalMantissa,
        BigIntError::DivisionByZero => unreachable!("decoding does not divide"),
    })?;
    if value.to_twos_bytes() != payload {
        return Err(NumericAbiError::NonCanonicalMantissa);
    }
    Ok((value, end))
}
fn decode_scaled_body(bytes: &[u8]) -> Result<(Numeric, usize), NumericAbiError> {
    match decode_scaled_body_observed(bytes, &mut |_| Ok::<_, core::convert::Infallible>(())) {
        Ok(value) => Ok(value),
        Err(ObservedNumericAbiError::Abi(error)) => Err(error),
        Err(ObservedNumericAbiError::Observer(never)) => match never {},
    }
}
fn decode_scaled_body_observed<E, F>(
    bytes: &[u8],
    observer: &mut F,
) -> Result<(Numeric, usize), ObservedNumericAbiError<E>>
where
    F: FnMut(NumericAbiWorkStep) -> Result<(), E>,
{
    let (mantissa, used) = decode_int_body(bytes).map_err(ObservedNumericAbiError::Abi)?;
    let end = used
        .checked_add(1)
        .ok_or_else(|| ObservedNumericAbiError::Abi(NumericAbiError::LengthMismatch))?;
    if end > bytes.len() {
        return Err(ObservedNumericAbiError::Abi(
            NumericAbiError::LengthMismatch,
        ));
    }
    let scale = u32::from(bytes[used]);
    if scale > MAX_DECIMAL_SCALE {
        return Err(ObservedNumericAbiError::Abi(NumericAbiError::InvalidScale));
    }
    let value = Numeric::try_new_raw(mantissa, scale).map_err(|error| {
        ObservedNumericAbiError::Abi(match error {
            crate::numeric::NumericError::MantissaTooLarge => NumericAbiError::MantissaOverflow,
            crate::numeric::NumericError::ScaleTooLarge => NumericAbiError::InvalidScale,
            crate::numeric::NumericError::Malformed => {
                unreachable!("decoded fields are structured")
            }
        })
    })?;
    let validation = value.validate_decimal_observed(&mut |step| {
        let NumericWorkStep::CanonicalityProbe {
            mantissa_limbs,
            scale,
        } = step
        else {
            unreachable!("decimal validation emits only canonicality probes")
        };
        observer(NumericAbiWorkStep::CanonicalityProbe {
            mantissa_limbs,
            scale,
        })
    });
    match validation {
        Ok(()) => {}
        Err(ObservedNumericError::Numeric(_)) => {
            return Err(ObservedNumericAbiError::Abi(
                NumericAbiError::NonCanonicalDecimal,
            ));
        }
        Err(ObservedNumericError::Observer(error)) => {
            return Err(ObservedNumericAbiError::Observer(error));
        }
    }
    Ok((value, end))
}
// Nominal Rust identities compose inside generic containers. The root frame
// projects to the V1 pointer-ABI identity already used by the fixed codec.
macro_rules! numeric_schema_identity {
    ($($ty:ty => ($nominal:literal, $frame:ident)),+ $(,)?) => {$(
        impl norito::NoritoSchema for $ty {
            fn nominal_name() -> String { $nominal.to_owned() }
            fn frame_name() -> String { $frame.to_owned() }
        }
    )+};
}
numeric_schema_identity! {
    IntValueV1 => ("iroha_primitives::numeric_abi::IntValueV1", INT_SCHEMA_NAME_V1),
    DecimalValueV1 => ("iroha_primitives::numeric_abi::DecimalValueV1", DECIMAL_SCHEMA_NAME_V1),
    QuantityValueV1 => ("iroha_primitives::numeric_abi::QuantityValueV1", QUANTITY_SCHEMA_NAME_V1),
}
macro_rules! impl_payload_codec {
    ($ty:ty, $serialize:expr, $length:expr, $decode:expr) => {
        impl SerializePayload for $ty {
            fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), NoritoError> {
                $serialize(self, writer)
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                $length(self)
            }
        }
        impl<'a> DeserializePayload<'a> for $ty {
            fn deserialize(archived: &'a Archived<Self>) -> Self {
                Self::try_deserialize(archived).expect("invalid canonical numeric frame")
            }
            fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, NoritoError> {
                let bytes =
                    norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast())?;
                let (value, used) = $decode(bytes)
                    .map_err(|error: NumericAbiError| NoritoError::Message(error.to_string()))?;
                if used != bytes.len() {
                    return Err(NoritoError::Message(
                        NumericAbiError::LengthMismatch.to_string(),
                    ));
                }
                Ok(value)
            }
        }
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                $decode(bytes).map_err(|error: NumericAbiError| {
                    norito::core::Error::Message(error.to_string())
                })
            }
        }
    };
}
impl_payload_codec!(
    IntValueV1,
    |value: &IntValueV1, writer: &mut norito::core::Encoder<'_>| serialize_int_body(
        &value.0, writer
    ),
    |value: &IntValueV1| value.0.encoded_len_exact(),
    |bytes: &[u8]| decode_int_body(bytes).map(|(value, used)| (IntValueV1(value), used))
);
impl_payload_codec!(
    DecimalValueV1,
    |value: &DecimalValueV1, writer: &mut norito::core::Encoder<'_>| serialize_scaled_body(
        &value.0, writer
    ),
    |value: &DecimalValueV1| value.0.mantissa().encoded_len_exact()?.checked_add(1),
    |bytes: &[u8]| decode_scaled_body(bytes).map(|(value, used)| (DecimalValueV1(value), used))
);
impl_payload_codec!(
    QuantityValueV1,
    |value: &QuantityValueV1, writer: &mut norito::core::Encoder<'_>| serialize_scaled_body(
        value.0.as_numeric(),
        writer
    ),
    |value: &QuantityValueV1| value.0.mantissa().encoded_len_exact()?.checked_add(1),
    |bytes: &[u8]| {
        let (value, used) = decode_scaled_body(bytes)?;
        let quantity = Quantity::from_canonical_numeric(value).map_err(|error| match error {
            NumericOperationError::NegativeQuantity => NumericAbiError::NegativeQuantity,
            NumericOperationError::NonCanonical => NumericAbiError::NonCanonicalDecimal,
            _ => NumericAbiError::Norito(error.to_string()),
        })?;
        Ok((QuantityValueV1(quantity), used))
    }
);
#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;
    fn fixture_int_body(value: &BigInt) -> Vec<u8> {
        let mut body =
            Vec::with_capacity(value.encoded_len_exact().expect("bounded integer length"));
        serialize_int_body(value, &mut norito::core::Encoder::for_buffer(&mut body))
            .expect("canonical fixture body");
        body
    }
    fn encode_with_alternate_norito_layout<T: norito::NoritoSerialize>(value: &T) -> Vec<u8> {
        let (payload, canonical_flags) = norito::codec::encode_with_header_flags(value);
        assert_eq!(
            canonical_flags, 0,
            "numeric V1 payloads use no layout-dependent body features"
        );
        norito::core::frame_bare_with_header_flags::<T>(
            &payload,
            norito::core::header_flags::COMPACT_LEN,
        )
        .expect("frame alternate-layout numeric value")
    }
    fn schema_hash_hex(hash: &[u8; 16]) -> String {
        let mut encoded = String::with_capacity(hash.len() * 2);
        for byte in hash {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }
    #[test]
    fn canonical_norito_document_matches_numeric_v1_wire_limits() {
        let document = include_str!("../../../norito.md");
        for (source_name, schema_name, schema_hash, maximum_frame_bytes) in [
            (
                "int",
                INT_SCHEMA_NAME_V1,
                INT_SCHEMA_HASH_V1,
                MAX_INT_FRAME_BYTES_V1,
            ),
            (
                "decimal",
                DECIMAL_SCHEMA_NAME_V1,
                DECIMAL_SCHEMA_HASH_V1,
                MAX_DECIMAL_FRAME_BYTES_V1,
            ),
            (
                "quantity",
                QUANTITY_SCHEMA_NAME_V1,
                QUANTITY_SCHEMA_HASH_V1,
                MAX_QUANTITY_FRAME_BYTES_V1,
            ),
        ] {
            let row = format!(
                "| `{source_name}` | `{schema_name}` | `{}` | {maximum_frame_bytes} |",
                schema_hash_hex(&schema_hash)
            );
            assert!(document.contains(&row), "missing canonical row: {row}");
        }
        let max_mantissa_bytes = crate::numeric::MAX_MANTISSA_BYTES;
        assert!(document.contains(&format!(
            "`byte_len_u32_le` is fixed-width (never a compact varint), is at most {max_mantissa_bytes},"
        )));
        assert!(document.contains(&format!(
            "{MAX_INT_ENVELOPE_BYTES_V1}, {MAX_DECIMAL_ENVELOPE_BYTES_V1}, and {MAX_QUANTITY_ENVELOPE_BYTES_V1} bytes"
        )));
        assert!(document.contains("exactly one quotient/remainder attempt at that proven scale"));
        assert!(!document.contains("Exact division tries output scales `0..=28`"));
    }
    #[test]
    fn schema_hashes_match_normative_names() {
        assert_eq!(
            norito::core::schema_hash_for_name(INT_SCHEMA_NAME_V1),
            INT_SCHEMA_HASH_V1
        );
        assert_eq!(
            norito::core::schema_hash_for_name(DECIMAL_SCHEMA_NAME_V1),
            DECIMAL_SCHEMA_HASH_V1
        );
        assert_eq!(
            norito::core::schema_hash_for_name(QUANTITY_SCHEMA_NAME_V1),
            QUANTITY_SCHEMA_HASH_V1
        );
    }
    #[test]
    fn canonical_frames_roundtrip_and_have_exact_small_sizes() {
        let integer = IntValueV1::try_new(BigInt::from_i128(-129)).expect("bounded integer");
        let integer_frame = integer.encode_frame().expect("encode integer");
        assert_eq!(integer_frame.len(), NUMERIC_FRAME_HEADER_BYTES_V1 + 6);
        assert_eq!(IntValueV1::decode_frame(&integer_frame), Ok(integer));
        let decimal = DecimalValueV1::try_from_numeric(Numeric::new(-12_500, 3))
            .expect("canonicalize decimal");
        assert_eq!(decimal.as_numeric(), &Numeric::new(-125, 1));
        let decimal_frame = decimal.encode_frame().expect("encode decimal");
        assert_eq!(DecimalValueV1::decode_frame(&decimal_frame), Ok(decimal));
        let quantity = QuantityValueV1::new("12.50".parse().expect("quantity"));
        let quantity_frame = quantity.encode_frame().expect("encode quantity");
        assert_eq!(QuantityValueV1::decode_frame(&quantity_frame), Ok(quantity));
    }
    #[test]
    fn numeric_v1_values_reject_alternate_outer_norito_layouts() {
        fn assert_canonical_only<T>(value: &T)
        where
            T: core::fmt::Debug + PartialEq + norito::NoritoSerialize,
            for<'de> T: norito::NoritoDeserialize<'de>,
        {
            let canonical = norito::encode_canonical(value).expect("encode canonical numeric");
            assert_eq!(
                &norito::decode_canonical::<T>(&canonical).expect("decode canonical numeric"),
                value
            );
            let alternate = encode_with_alternate_norito_layout(value);
            assert_ne!(alternate, canonical);
            assert_eq!(
                &norito::decode_from_bytes::<T>(&alternate)
                    .expect("alternate numeric remains structurally decodable"),
                value
            );
            assert!(matches!(
                norito::decode_canonical::<T>(&alternate),
                Err(norito::Error::NonCanonicalEncoding)
            ));
        }
        assert_canonical_only(
            &IntValueV1::try_new(BigInt::from_i128(-129)).expect("bounded integer"),
        );
        assert_canonical_only(
            &DecimalValueV1::try_from_numeric(Numeric::new(-125, 2)).expect("canonical decimal"),
        );
        assert_canonical_only(&QuantityValueV1::new(
            "1.25".parse().expect("canonical quantity"),
        ));
    }
    #[test]
    fn numeric_value_json_codecs_enforce_nominal_v1_domains() {
        let integer = IntValueV1::try_new(BigInt::from_i128(-129)).expect("bounded integer");
        let integer_json = norito::json::to_json(&integer).expect("encode int JSON");
        assert_eq!(integer_json, "\"-129\"");
        assert_eq!(
            norito::json::from_str::<IntValueV1>(&integer_json).expect("decode int JSON"),
            integer
        );
        let mut maximum_bytes = vec![0xff_u8; MAX_MANTISSA_BYTES - 1];
        maximum_bytes.push(0x7f);
        let maximum = BigInt::from_twos_bytes(&maximum_bytes).expect("maximum");
        let mut minimum_bytes = vec![0_u8; MAX_MANTISSA_BYTES];
        minimum_bytes[MAX_MANTISSA_BYTES - 1] = 0x80;
        let minimum = BigInt::from_twos_bytes(&minimum_bytes).expect("minimum");
        for endpoint in [maximum.clone(), minimum.clone()] {
            let wrapped = IntValueV1::try_new(endpoint).expect("signed endpoint");
            let encoded = norito::json::to_json(&wrapped).expect("encode endpoint JSON");
            assert_eq!(
                norito::json::from_str::<IntValueV1>(&encoded).expect("decode endpoint JSON"),
                wrapped
            );
        }
        let above_maximum = maximum
            .checked_add(&BigInt::one())
            .expect("generic bigint upper neighbor");
        let below_minimum = minimum
            .checked_sub(&BigInt::one())
            .expect("generic bigint lower neighbor");
        for invalid in [
            "1".to_owned(),
            "\"01\"".to_owned(),
            "\"-0\"".to_owned(),
            "\"+1\"".to_owned(),
            format!("\"{above_maximum}\""),
            format!("\"{below_minimum}\""),
        ] {
            assert!(
                norito::json::from_str::<IntValueV1>(&invalid).is_err(),
                "invalid V1 int JSON accepted: {invalid}"
            );
        }
        let decimal = DecimalValueV1::try_from_numeric("-1.25".parse().expect("decimal"))
            .expect("V1 decimal");
        let decimal_json = norito::json::to_json(&decimal).expect("encode decimal JSON");
        assert_eq!(decimal_json, "\"-1.25\"");
        assert_eq!(
            norito::json::from_str::<DecimalValueV1>(&decimal_json).expect("decode decimal JSON"),
            decimal
        );
        for invalid in [
            "1.25".to_owned(),
            "\"1.20\"".to_owned(),
            "\"1e2\"".to_owned(),
            "\".5\"".to_owned(),
            format!("\"0.{}1\"", "0".repeat(28)),
            format!("\"{above_maximum}\""),
        ] {
            assert!(
                norito::json::from_str::<DecimalValueV1>(&invalid).is_err(),
                "invalid V1 decimal JSON accepted: {invalid}"
            );
        }
        let quantity = QuantityValueV1::new("1.25".parse().expect("quantity"));
        let quantity_json = norito::json::to_json(&quantity).expect("encode quantity JSON");
        assert_eq!(quantity_json, "\"1.25\"");
        assert_eq!(
            norito::json::from_str::<QuantityValueV1>(&quantity_json)
                .expect("decode quantity JSON"),
            quantity
        );
        for invalid in [
            "1.25".to_owned(),
            "\"-1\"".to_owned(),
            "\"-0\"".to_owned(),
            "\"01\"".to_owned(),
            "\"1.0\"".to_owned(),
            format!("\"0.{}1\"", "0".repeat(28)),
            format!("\"{above_maximum}\""),
        ] {
            assert!(
                norito::json::from_str::<QuantityValueV1>(&invalid).is_err(),
                "invalid V1 quantity JSON accepted: {invalid}"
            );
        }
    }
    #[test]
    fn frame_validation_does_not_leak_norito_layout_state() {
        norito::core::reset_decode_state();
        let marker = String::from("missing");
        let expected = norito::to_bytes(&marker).expect("encode marker before numeric decode");
        let frame = IntValueV1::try_new(BigInt::from_i128(7))
            .expect("bounded integer")
            .encode_frame()
            .expect("encode integer frame");
        IntValueV1::decode_frame(&frame).expect("decode integer frame");
        assert_eq!(
            norito::core::effective_decode_flags(),
            None,
            "numeric validation must not retain its zero-layout frame context"
        );
        assert_eq!(
            norito::to_bytes(&marker).expect("encode marker after numeric decode"),
            expected,
            "numeric validation must not alter the next canonical encoding"
        );
    }
    #[allow(clippy::too_many_lines)] // One contiguous loop pins both sides of every signed byte boundary.
    #[test]
    fn every_signed_byte_boundary_has_pinned_canonical_bytes_and_frame_length() {
        fn assert_canonical_frame(value: &BigInt, expected_mantissa: &[u8]) {
            let frame = IntValueV1::try_new(value.clone())
                .expect("bounded boundary integer")
                .encode_frame()
                .expect("boundary frame");
            let body = &frame[NUMERIC_FRAME_HEADER_BYTES_V1..];
            assert_eq!(
                frame.len(),
                NUMERIC_FRAME_HEADER_BYTES_V1 + 4 + expected_mantissa.len(),
                "value={value}",
            );
            assert_eq!(
                &body[..4],
                &u32::try_from(expected_mantissa.len())
                    .expect("bounded mantissa length")
                    .to_le_bytes(),
                "value={value}",
            );
            assert_eq!(&body[4..], expected_mantissa, "value={value}");
            assert_eq!(
                BigInt::from_twos_bytes(expected_mantissa)
                    .expect("canonical fixture is a valid generic bigint"),
                *value,
                "arithmetic and byte-vector fixtures disagree",
            );
            assert_eq!(
                IntValueV1::decode_frame(&frame)
                    .expect("decode boundary")
                    .into_int(),
                *value,
            );
        }
        let zero = BigInt::zero();
        let one = BigInt::one();
        let negative_one = zero.checked_sub(&one).expect("negative one");
        assert_canonical_frame(&zero, &[]);
        assert_canonical_frame(&one, &[0x01]);
        assert_canonical_frame(&negative_one, &[0xff]);
        // At each N-byte signed boundary, pin both values on both sides. The
        // values are produced arithmetically while the byte vectors are built
        // directly from the mathematical two's-complement forms, independently
        // of `BigInt::to_twos_bytes` and `BigInt::twos_byte_len`.
        let mut positive_successor = BigInt::from_i128(128);
        for narrower_bytes in 1..MAX_MANTISSA_BYTES {
            let positive_maximum = positive_successor
                .checked_sub(&one)
                .expect("positive boundary predecessor");
            let negative_minimum = positive_successor
                .checked_neg()
                .expect("negative boundary endpoint");
            let negative_predecessor = negative_minimum
                .checked_sub(&one)
                .expect("negative boundary predecessor");
            let mut positive_maximum_bytes = vec![0xff; narrower_bytes];
            positive_maximum_bytes[narrower_bytes - 1] = 0x7f;
            let mut positive_successor_bytes = vec![0; narrower_bytes + 1];
            positive_successor_bytes[narrower_bytes - 1] = 0x80;
            let mut negative_minimum_bytes = vec![0; narrower_bytes];
            negative_minimum_bytes[narrower_bytes - 1] = 0x80;
            let mut negative_predecessor_bytes = vec![0xff; narrower_bytes + 1];
            negative_predecessor_bytes[narrower_bytes - 1] = 0x7f;
            assert_canonical_frame(&positive_maximum, &positive_maximum_bytes);
            assert_canonical_frame(&positive_successor, &positive_successor_bytes);
            assert_canonical_frame(&negative_minimum, &negative_minimum_bytes);
            assert_canonical_frame(&negative_predecessor, &negative_predecessor_bytes);
            for _ in 0..8 {
                positive_successor = positive_successor
                    .checked_add(&positive_successor)
                    .expect("next byte boundary power of two");
            }
        }
        let mut maximum_bytes = vec![0xff; MAX_MANTISSA_BYTES];
        maximum_bytes[MAX_MANTISSA_BYTES - 1] = 0x7f;
        let maximum = positive_successor
            .checked_sub(&one)
            .expect("signed V1 maximum");
        assert_canonical_frame(&maximum, &maximum_bytes);
        let above_maximum = maximum
            .checked_add(&one)
            .expect("generic bigint represents the positive domain neighbor");
        let mut above_maximum_bytes = vec![0; MAX_MANTISSA_BYTES + 1];
        above_maximum_bytes[MAX_MANTISSA_BYTES - 1] = 0x80;
        assert_eq!(
            above_maximum,
            BigInt::from_twos_bytes(&above_maximum_bytes)
                .expect("canonical 65-byte positive neighbor"),
        );
        let mut minimum_bytes = vec![0; MAX_MANTISSA_BYTES];
        minimum_bytes[MAX_MANTISSA_BYTES - 1] = 0x80;
        let minimum = positive_successor.checked_neg().expect("signed V1 minimum");
        assert_canonical_frame(&minimum, &minimum_bytes);
        let below_minimum = minimum
            .checked_sub(&one)
            .expect("generic bigint represents the negative domain neighbor");
        let mut below_minimum_bytes = vec![0xff; MAX_MANTISSA_BYTES + 1];
        below_minimum_bytes[MAX_MANTISSA_BYTES - 1] = 0x7f;
        assert_eq!(
            below_minimum,
            BigInt::from_twos_bytes(&below_minimum_bytes)
                .expect("canonical 65-byte negative neighbor"),
        );
        assert_eq!(
            IntValueV1::try_new(above_maximum),
            Err(NumericAbiError::MantissaOverflow),
        );
        assert_eq!(
            IntValueV1::try_new(below_minimum),
            Err(NumericAbiError::MantissaOverflow),
        );
    }
    #[test]
    fn signed_endpoint_frames_hit_pinned_maximum() {
        let endpoint_bytes = [
            vec![0xff_u8; MAX_MANTISSA_BYTES - 1]
                .into_iter()
                .chain([0x7f])
                .collect::<Vec<_>>(),
            vec![0_u8; MAX_MANTISSA_BYTES - 1]
                .into_iter()
                .chain([0x80])
                .collect::<Vec<_>>(),
        ];
        for bytes in endpoint_bytes {
            let value = IntValueV1::try_new(BigInt::from_twos_bytes(&bytes).expect("endpoint"))
                .expect("512-bit endpoint");
            let frame = value.encode_frame().expect("frame");
            assert_eq!(frame.len(), MAX_INT_FRAME_BYTES_V1);
            assert_eq!(IntValueV1::decode_frame(&frame), Ok(value));
        }
        assert_eq!(MAX_INT_ENVELOPE_BYTES_V1, 147);
        assert_eq!(MAX_DECIMAL_ENVELOPE_BYTES_V1, 148);
        assert_eq!(MAX_QUANTITY_ENVELOPE_BYTES_V1, 148);
    }
    #[test]
    fn integer_wrapper_rejects_both_signed_domain_neighbors() {
        let mut maximum_bytes = vec![0xff_u8; MAX_MANTISSA_BYTES - 1];
        maximum_bytes.push(0x7f);
        let maximum = BigInt::from_twos_bytes(&maximum_bytes).expect("maximum");
        let above_maximum = maximum
            .checked_add(&BigInt::one())
            .expect("generic bigint can represent the upper neighbor");
        let mut minimum_bytes = vec![0_u8; MAX_MANTISSA_BYTES - 1];
        minimum_bytes.push(0x80);
        let minimum = BigInt::from_twos_bytes(&minimum_bytes).expect("minimum");
        let below_minimum = minimum
            .checked_sub(&BigInt::one())
            .expect("generic bigint can represent the lower neighbor");
        assert_eq!(
            IntValueV1::try_new(above_maximum),
            Err(NumericAbiError::MantissaOverflow)
        );
        assert_eq!(
            IntValueV1::try_new(below_minimum),
            Err(NumericAbiError::MantissaOverflow)
        );
    }
    #[test]
    fn cross_type_and_header_mutations_are_rejected_before_payload_decode() {
        let frame = IntValueV1::try_new(BigInt::one())
            .expect("bounded integer")
            .encode_frame()
            .expect("integer frame");
        assert!(matches!(
            DecimalValueV1::decode_frame(&frame),
            Err(NumericAbiError::SchemaMismatch)
        ));
        for (index, expected) in [
            (0, NumericAbiError::InvalidHeader),
            (4, NumericAbiError::InvalidHeader),
            (5, NumericAbiError::InvalidHeader),
            (6, NumericAbiError::SchemaMismatch),
            (22, NumericAbiError::CompressionNotAllowed),
            (39, NumericAbiError::LayoutFlagsNotAllowed),
        ] {
            let mut mutated = frame.clone();
            mutated[index] ^= 1;
            assert_eq!(
                IntValueV1::decode_frame(&mutated).expect_err("mutation must fail"),
                expected,
                "header byte {index}"
            );
        }
    }
    #[test]
    fn truncation_extension_and_declared_length_attacks_are_rejected() {
        let frame = IntValueV1::try_new(BigInt::from_i128(128))
            .expect("bounded integer")
            .encode_frame()
            .expect("frame");
        for end in 0..frame.len() {
            assert!(
                IntValueV1::decode_frame(&frame[..end]).is_err(),
                "end={end}"
            );
        }
        let mut extended = frame.clone();
        extended.push(0);
        assert_eq!(
            IntValueV1::decode_frame(&extended),
            Err(NumericAbiError::LengthMismatch)
        );
        for declared in [0_u64, 1, u64::MAX] {
            let mut malformed = frame.clone();
            malformed[23..31].copy_from_slice(&declared.to_le_bytes());
            assert_eq!(
                IntValueV1::decode_frame(&malformed),
                Err(NumericAbiError::LengthMismatch)
            );
        }
    }
    #[test]
    fn bare_body_rejects_every_redundant_sign_extension_and_scaled_noncanonical_form() {
        for payload in [&[0_u8][..], &[1, 0], &[0xff, 0xff]] {
            let mut body = Vec::new();
            body.extend_from_slice(&u32::try_from(payload.len()).expect("small").to_le_bytes());
            body.extend_from_slice(payload);
            assert_eq!(
                decode_int_body(&body),
                Err(NumericAbiError::NonCanonicalMantissa)
            );
            let frame = encode_frame::<IntValueV1>(&body)
                .expect("frame helper recomputes checksum for malformed body");
            assert_eq!(
                IntValueV1::decode_frame(&frame),
                Err(NumericAbiError::NonCanonicalMantissa)
            );
        }
        for (mantissa, scale, expected) in [
            (0_i128, 1_u8, NumericAbiError::NonCanonicalDecimal),
            (10, 1, NumericAbiError::NonCanonicalDecimal),
            (1, 29, NumericAbiError::InvalidScale),
        ] {
            let mut body = fixture_int_body(&BigInt::from_i128(mantissa));
            body.push(scale);
            assert_eq!(decode_scaled_body(&body), Err(expected.clone()));
            let frame = encode_frame::<DecimalValueV1>(&body)
                .expect("frame helper recomputes checksum for malformed body");
            assert_eq!(DecimalValueV1::decode_frame(&frame), Err(expected));
        }
    }
    #[test]
    fn quantity_body_rejects_negative_value_even_when_otherwise_canonical() {
        let mut body = fixture_int_body(&BigInt::from_i128(-1));
        body.push(0);
        let frame = encode_frame::<QuantityValueV1>(&body).expect("well-formed frame");
        assert_eq!(
            QuantityValueV1::decode_frame(&frame),
            Err(NumericAbiError::NegativeQuantity)
        );
    }
    #[test]
    fn checksum_tampering_is_rejected() {
        let mut frame = IntValueV1::try_new(BigInt::from_i128(42))
            .expect("bounded integer")
            .encode_frame()
            .expect("frame");
        let final_index = frame.len() - 1;
        frame[final_index] ^= 0x80;
        assert!(matches!(
            IntValueV1::decode_frame(&frame),
            Err(NumericAbiError::Norito(_))
        ));
    }
    #[test]
    fn frame_validation_preserves_ambient_norito_decode_state() {
        let frame = QuantityValueV1::new(Quantity::from(42_u32))
            .encode_frame()
            .expect("canonical quantity frame");
        norito::core::reset_decode_state();
        assert_eq!(norito::core::effective_decode_flags(), None);
        QuantityValueV1::decode_frame(&frame).expect("decode without ambient state");
        assert_eq!(
            norito::core::effective_decode_flags(),
            None,
            "numeric frame validation must not publish archive-view state"
        );
        let default_flags = norito::core::default_encode_flags();
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(default_flags);
            QuantityValueV1::decode_frame(&frame).expect("decode inside an outer Norito context");
            assert_eq!(
                norito::core::effective_decode_flags(),
                Some(default_flags),
                "numeric frame validation must preserve its caller's layout policy"
            );
        }
        assert_eq!(norito::core::effective_decode_flags(), None);
    }
    #[test]
    fn staged_decode_places_observer_between_structure_and_canonical_value_work() {
        let valid = IntValueV1::try_new(BigInt::from_i128(42))
            .expect("bounded integer")
            .encode_frame()
            .expect("valid frame");
        assert_eq!(
            IntValueV1::decode_frame_observed(&valid, |_| Err("out-of-gas")),
            Err(ObservedNumericAbiError::Observer("out-of-gas"))
        );
        let mut bad_checksum = valid;
        let final_index = bad_checksum.len() - 1;
        bad_checksum[final_index] ^= 1;
        let mut structure_callback_ran = false;
        let result = IntValueV1::decode_frame_observed(&bad_checksum, |_| {
            structure_callback_ran = true;
            Ok::<_, ()>(())
        });
        assert!(!structure_callback_ran);
        assert!(matches!(
            result,
            Err(ObservedNumericAbiError::Abi(NumericAbiError::Norito(_)))
        ));
        let mut noncanonical_body = Vec::new();
        noncanonical_body.extend_from_slice(&1_u32.to_le_bytes());
        noncanonical_body.push(0);
        let noncanonical =
            encode_frame::<IntValueV1>(&noncanonical_body).expect("recompute structural checksum");
        let mut canonical_callback_ran = false;
        assert_eq!(
            IntValueV1::decode_frame_observed(&noncanonical, |_| {
                canonical_callback_ran = true;
                Ok::<_, ()>(())
            }),
            Err(ObservedNumericAbiError::Abi(
                NumericAbiError::NonCanonicalMantissa
            ))
        );
        assert!(canonical_callback_ran);
        let decimal = DecimalValueV1::try_from_numeric("1.2".parse().expect("decimal"))
            .expect("canonical decimal");
        let decimal_frame = decimal.encode_frame().expect("decimal frame");
        let mut steps = Vec::new();
        assert_eq!(
            DecimalValueV1::decode_frame_observed(&decimal_frame, |step| {
                steps.push(step);
                Ok::<_, ()>(())
            }),
            Ok(decimal)
        );
        assert_eq!(
            steps,
            [
                NumericAbiWorkStep::CanonicalBody { body_bytes: 6 },
                NumericAbiWorkStep::CanonicalityProbe {
                    mantissa_limbs: 1,
                    scale: 1,
                },
            ]
        );
        assert_eq!(
            DecimalValueV1::decode_frame_observed(&decimal_frame, |step| match step {
                NumericAbiWorkStep::CanonicalBody { .. } => Ok(()),
                NumericAbiWorkStep::CanonicalityProbe { .. } => Err("out-of-gas"),
            }),
            Err(ObservedNumericAbiError::Observer("out-of-gas"))
        );
    }

    #[test]
    fn canonical_numeric_body_writer_matches_literal_payloads_and_frame_prefixes() {
        for (bytes, expected) in [
            (&[][..], &[0, 0, 0, 0][..]),
            (&[0x01][..], &[1, 0, 0, 0, 0x01][..]),
            (&[0xff][..], &[1, 0, 0, 0, 0xff][..]),
            (&[0x80, 0x00][..], &[2, 0, 0, 0, 0x80, 0x00][..]),
            (&[0x80][..], &[1, 0, 0, 0, 0x80][..]),
            (&[0x7f, 0xff][..], &[2, 0, 0, 0, 0x7f, 0xff][..]),
        ] {
            let value = IntValueV1::try_new(BigInt::from_twos_bytes(bytes).unwrap()).unwrap();
            let mut body = [0xa5; 69];
            let unused = {
                let mut output = body.as_mut_slice();
                value
                    .serialize(&mut norito::core::Encoder::new(&mut output))
                    .unwrap();
                output.len()
            };
            let used = body.len() - unused;
            assert_eq!(&body[..used], expected);
            assert!(body[used..].iter().all(|byte| *byte == 0xa5));
            assert_eq!(value.encoded_len_exact(), Some(expected.len()));
            let frame = value.encode_frame().unwrap();
            assert_eq!(frame, encode_frame::<IntValueV1>(expected).unwrap());
            assert_eq!(IntValueV1::decode_frame(&frame), Ok(value));
        }
        for scale in 0..=MAX_DECIMAL_SCALE {
            for (mantissa, expected_byte) in [(1_i128, 0x01), (-1, 0xff)] {
                let numeric = Numeric::try_new(BigInt::from_i128(mantissa), scale).unwrap();
                let value = DecimalValueV1::new(numeric.clone());
                let expected = [1, 0, 0, 0, expected_byte, u8::try_from(scale).unwrap()];
                let mut body = [0xa5; 69];
                let unused = {
                    let mut output = body.as_mut_slice();
                    value
                        .serialize(&mut norito::core::Encoder::new(&mut output))
                        .unwrap();
                    output.len()
                };
                let used = body.len() - unused;
                assert_eq!(&body[..used], expected);
                assert!(body[used..].iter().all(|byte| *byte == 0xa5));
                assert_eq!(value.encoded_len_exact(), Some(expected.len()));
                let frame = value.encode_frame().unwrap();
                assert_eq!(frame, encode_frame::<DecimalValueV1>(&expected).unwrap());
                assert_eq!(DecimalValueV1::decode_frame(&frame), Ok(value));
                if mantissa >= 0 {
                    let quantity =
                        QuantityValueV1::new(Quantity::from_canonical_numeric(numeric).unwrap());
                    assert_eq!(quantity.encoded_len_exact(), Some(expected.len()));
                    let frame = quantity.encode_frame().unwrap();
                    assert_eq!(frame, encode_frame::<QuantityValueV1>(&expected).unwrap());
                    assert_eq!(QuantityValueV1::decode_frame(&frame), Ok(quantity));
                }
            }
        }
    }

    #[test]
    fn numeric_payload_writer_refusals_keep_the_existing_message_cause() {
        struct RefuseAfter {
            available: usize,
        }
        impl std::io::Write for RefuseAfter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > self.available {
                    return Err(std::io::ErrorKind::WriteZero.into());
                }
                self.available -= bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let integer = IntValueV1::try_new(BigInt::from_i128(-129)).unwrap();
        let decimal = DecimalValueV1::new(Numeric::try_new(1, 28).unwrap());
        let quantity = QuantityValueV1::new(
            Quantity::from_canonical_numeric(Numeric::try_new(1, 28).unwrap()).unwrap(),
        );
        let values: [&dyn SerializePayload; 3] = [&integer, &decimal, &quantity];
        for value in values {
            let length = value.encoded_len_exact().unwrap();
            for available in 0..length {
                let mut output = RefuseAfter { available };
                let error = value
                    .serialize(&mut norito::core::Encoder::new(&mut output))
                    .expect_err("a short original writer must refuse");
                match error {
                    NoritoError::Message(message) => assert_eq!(
                        message,
                        std::io::Error::from(std::io::ErrorKind::WriteZero).to_string(),
                    ),
                    error => panic!("numeric payload changed its writer cause: {error}"),
                }
            }
            let mut output = RefuseAfter { available: length };
            value
                .serialize(&mut norito::core::Encoder::new(&mut output))
                .unwrap();
            assert_eq!(output.available, 0);
        }
    }
    fn literal_prepared_body(bytes: &[u8], scale: Option<u8>) -> Vec<u8> {
        let mut body = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
        body.extend_from_slice(bytes);
        if let Some(scale) = scale {
            body.push(scale);
        }
        body
    }
    #[test]
    fn prepared_numeric_frames_borrow_exact_sources_and_keep_nominal_frames() {
        for bytes in [
            &[][..],
            &[0x01],
            &[0xff],
            &[0x80, 0x00],
            &[0x80],
            &[0x7f, 0xff],
        ] {
            let source = BigInt::from_twos_bytes(bytes).unwrap();
            let before = source.clone();
            let prepared = IntValueV1::prepare_frame(&source).unwrap();
            assert!(
                matches!(&prepared.source, NumericFrameSourceV1::Int(retained) if core::ptr::eq(*retained, &raw const source))
            );
            let body = literal_prepared_body(bytes, None);
            let expected = encode_frame::<IntValueV1>(&body).unwrap();
            assert_eq!(prepared.frame_len(), 44 + bytes.len());
            for _ in 0..2 {
                let frame = prepared.encode_frame().unwrap();
                assert_eq!(frame, expected);
                assert_eq!(IntValueV1::decode_frame(&frame).unwrap().as_int(), &source);
                assert_eq!(
                    DecimalValueV1::decode_frame(&frame).err(),
                    Some(NumericAbiError::SchemaMismatch)
                );
            }
            assert_eq!(source, before);
        }
        for (integer, byte) in [(1, 0x01), (-1, 0xff)] {
            let source = Numeric::try_new(integer, 28).unwrap();
            let before = source.clone();
            let prepared = DecimalValueV1::prepare_frame(&source);
            assert!(
                matches!(&prepared.source, NumericFrameSourceV1::Decimal(retained) if core::ptr::eq(*retained, &raw const source))
            );
            let body = literal_prepared_body(&[byte], Some(28));
            let expected = encode_frame::<DecimalValueV1>(&body).unwrap();
            assert_eq!(prepared.frame_len(), 46);
            for _ in 0..2 {
                let frame = prepared.encode_frame().unwrap();
                assert_eq!(frame, expected);
                assert_eq!(
                    DecimalValueV1::decode_frame(&frame).unwrap().as_numeric(),
                    &source
                );
                assert_eq!(
                    QuantityValueV1::decode_frame(&frame).err(),
                    Some(NumericAbiError::SchemaMismatch)
                );
            }
            assert_eq!(source, before);
        }
        let source = Quantity::from_canonical_numeric(Numeric::try_new(1, 28).unwrap()).unwrap();
        let before = source.clone();
        let prepared = QuantityValueV1::prepare_frame(&source);
        assert!(
            matches!(&prepared.source, NumericFrameSourceV1::Quantity(retained) if core::ptr::eq(*retained, &raw const source))
        );
        let expected =
            encode_frame::<QuantityValueV1>(&literal_prepared_body(&[1], Some(28))).unwrap();
        assert_eq!(prepared.frame_len(), 46);
        for _ in 0..2 {
            let frame = prepared.encode_frame().unwrap();
            assert_eq!(frame, expected);
            assert_eq!(
                QuantityValueV1::decode_frame(&frame).unwrap().as_quantity(),
                &source
            );
            assert_eq!(
                IntValueV1::decode_frame(&frame).err(),
                Some(NumericAbiError::SchemaMismatch)
            );
        }
        assert_eq!(source, before);
    }
    #[test]
    fn prepared_numeric_lengths_cover_signed_neighbors_and_scaled_boundaries() {
        for width in 1..=MAX_MANTISSA_BYTES {
            let mut positive = vec![0xff; width];
            positive[width - 1] = 0x7f;
            let mut negative = vec![0; width];
            negative[width - 1] = 0x80;
            for bytes in [&positive, &negative] {
                let source = BigInt::from_twos_bytes(bytes).unwrap();
                let prepared = IntValueV1::prepare_frame(&source).unwrap();
                assert_eq!(prepared.frame_len(), 44 + width);
                assert_eq!(
                    prepared.encode_frame().unwrap(),
                    encode_frame::<IntValueV1>(&literal_prepared_body(bytes, None)).unwrap()
                );
                for scale in 0..=MAX_DECIMAL_SCALE {
                    let numeric = Numeric::try_new(source.clone(), scale).unwrap();
                    let prepared = DecimalValueV1::prepare_frame(&numeric);
                    let body = literal_prepared_body(bytes, Some(u8::try_from(scale).unwrap()));
                    assert_eq!(prepared.frame_len(), 45 + width);
                    assert_eq!(
                        prepared.encode_frame().unwrap(),
                        encode_frame::<DecimalValueV1>(&body).unwrap()
                    );
                    if !source.is_negative() {
                        let quantity = Quantity::from_canonical_numeric(numeric).unwrap();
                        let prepared = QuantityValueV1::prepare_frame(&quantity);
                        assert_eq!(prepared.frame_len(), 45 + width);
                        assert_eq!(
                            prepared.encode_frame().unwrap(),
                            encode_frame::<QuantityValueV1>(&body).unwrap()
                        );
                    }
                }
            }
        }
        let mut above = [0; MAX_MANTISSA_BYTES + 1];
        above[MAX_MANTISSA_BYTES - 1] = 0x80;
        let mut below = [0xff; MAX_MANTISSA_BYTES + 1];
        below[MAX_MANTISSA_BYTES - 1] = 0x7f;
        for bytes in [&above, &below] {
            let source = BigInt::from_twos_bytes(bytes).unwrap();
            assert_eq!(
                IntValueV1::prepare_frame(&source).err(),
                Some(NumericAbiError::MantissaOverflow)
            );
            assert_eq!(
                IntValueV1::try_new_with_mantissa_len(source).err(),
                Some(NumericAbiError::MantissaOverflow)
            );
        }
        let zero = Numeric::try_new(0, 28).unwrap();
        assert_eq!(DecimalValueV1::prepare_frame(&zero).frame_len(), 45);
        let quantity = Quantity::from_canonical_numeric(zero).unwrap();
        assert_eq!(QuantityValueV1::prepare_frame(&quantity).frame_len(), 45);
    }
}
