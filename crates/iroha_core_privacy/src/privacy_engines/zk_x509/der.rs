//! Strict, bounded DER primitives for the native zk-X509 relation.
//!
//! The parser in this module is authoritative for the closed zk-X509 profile.
//! It borrows every value from the input and performs no heap allocation.
//! Before returning the outer value it recursively validates the complete DER
//! tree, including definite minimal lengths, canonical primitive encodings,
//! nesting depth, value count, and `SET OF` order. Primitive `OCTET STRING`
//! payloads remain opaque and must be parsed separately when an X.509
//! extension assigns them an inner ASN.1 type.
pub use super::der_limits::{
    ZK_X509_DER_MAX_DOCUMENT_BYTES_V1, ZK_X509_DER_MAX_NESTING_DEPTH_V1,
    ZK_X509_DER_MAX_VALUE_BYTES_V1, ZK_X509_DER_MAX_VALUES_V1,
};
use thiserror::Error;
/// DER content octets of `ecdsa-with-SHA256` (`1.2.840.10045.4.3.2`).
pub const ZK_X509_ECDSA_WITH_SHA256_OID_CONTENT_V1: &[u8] =
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// DER content octets of `id-ecPublicKey` (`1.2.840.10045.2.1`).
pub const ZK_X509_ID_EC_PUBLIC_KEY_OID_CONTENT_V1: &[u8] =
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// DER content octets of `prime256v1` (`1.2.840.10045.3.1.7`).
pub const ZK_X509_PRIME256V1_OID_CONTENT_V1: &[u8] =
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// Exact DER `AlgorithmIdentifier` for ECDSA with SHA-256 and absent parameters.
pub const ZK_X509_ECDSA_WITH_SHA256_ALGORITHM_IDENTIFIER_DER_V1: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
/// Exact DER `AlgorithmIdentifier` for a P-256 subject public key.
pub const ZK_X509_P256_PUBLIC_KEY_ALGORITHM_IDENTIFIER_DER_V1: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];
/// Resource limits applied while validating one DER document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerLimitsV1 {
    /// Maximum complete input bytes.
    pub(crate) max_document_bytes: usize,
    /// Maximum content bytes in any one value.
    pub(crate) max_value_bytes: usize,
    /// Maximum value nesting depth, including the top-level value.
    pub(crate) max_nesting_depth: usize,
    /// Maximum recursively encountered value count.
    pub(crate) max_values: usize,
}
impl ZkX509DerLimitsV1 {
    /// Construct explicit limits.
    pub(crate) const fn new(
        max_document_bytes: usize,
        max_value_bytes: usize,
        max_nesting_depth: usize,
        max_values: usize,
    ) -> Self {
        Self {
            max_document_bytes,
            max_value_bytes,
            max_nesting_depth,
            max_values,
        }
    }
    /// Return the fixed first-release X.509 DER limits.
    #[doc(hidden)]
    pub const fn profile() -> Self {
        Self::new(
            ZK_X509_DER_MAX_DOCUMENT_BYTES_V1,
            ZK_X509_DER_MAX_VALUE_BYTES_V1,
            ZK_X509_DER_MAX_NESTING_DEPTH_V1,
            ZK_X509_DER_MAX_VALUES_V1,
        )
    }
}
/// ASN.1 tag class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkX509DerClassV1 {
    /// Universal ASN.1 tag.
    Universal,
    /// Application-specific tag.
    Application,
    /// Context-specific tag.
    ContextSpecific,
    /// Private tag.
    Private,
}
/// Canonically decoded DER identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ZkX509DerTagV1 {
    /// ASN.1 class.
    pub(crate) class: ZkX509DerClassV1,
    /// Whether the value uses constructed form.
    pub(crate) constructed: bool,
    /// Decoded tag number.
    pub(crate) number: u32,
}
impl ZkX509DerTagV1 {
    /// Universal BOOLEAN.
    pub(crate) const BOOLEAN: Self = Self::universal(false, 1);
    /// Universal INTEGER.
    pub(crate) const INTEGER: Self = Self::universal(false, 2);
    /// Universal BIT STRING.
    pub(crate) const BIT_STRING: Self = Self::universal(false, 3);
    /// Universal OCTET STRING.
    pub(crate) const OCTET_STRING: Self = Self::universal(false, 4);
    /// Universal OBJECT IDENTIFIER.
    pub(crate) const OBJECT_IDENTIFIER: Self = Self::universal(false, 6);
    /// Universal SEQUENCE.
    pub(crate) const SEQUENCE: Self = Self::universal(true, 16);
    /// Universal SET.
    pub(crate) const SET: Self = Self::universal(true, 17);
    const fn universal(constructed: bool, number: u32) -> Self {
        Self {
            class: ZkX509DerClassV1::Universal,
            constructed,
            number,
        }
    }
}
/// Exact failure returned by the bounded DER parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509DerErrorV1 {
    /// A DER document must contain one value.
    #[error("zk-X509 DER document is empty")]
    EmptyInput,
    /// The complete document exceeds its fixed byte limit.
    #[error("zk-X509 DER document has {actual} bytes; maximum is {max}")]
    InputTooLarge {
        /// Observed input bytes.
        actual: usize,
        /// Maximum input bytes.
        max: usize,
    },
    /// One DER value exceeds its fixed content limit.
    #[error("zk-X509 DER value has {actual} content bytes; maximum is {max}")]
    ValueTooLarge {
        /// Declared content bytes.
        actual: usize,
        /// Maximum content bytes.
        max: usize,
    },
    /// The recursive value count exceeds its fixed limit.
    #[error("zk-X509 DER document exceeds its {max}-value limit")]
    TooManyValues {
        /// Maximum values.
        max: usize,
    },
    /// Constructed values exceed the fixed nesting limit.
    #[error("zk-X509 DER nesting depth {depth} exceeds maximum {max}")]
    NestingTooDeep {
        /// Rejected depth.
        depth: usize,
        /// Maximum depth.
        max: usize,
    },
    /// A high-tag-number identifier ended before its terminating octet.
    #[error("zk-X509 DER identifier is truncated")]
    TruncatedIdentifier,
    /// A high-tag-number identifier uses a leading zero group or encodes a low tag.
    #[error("zk-X509 DER identifier uses a non-minimal tag encoding")]
    NonMinimalTag,
    /// A decoded high tag cannot fit the fixed tag-number representation.
    #[error("zk-X509 DER tag number overflows u32")]
    TagNumberOverflow,
    /// End-of-contents is forbidden in DER.
    #[error("zk-X509 DER forbids the end-of-contents tag")]
    EndOfContentsForbidden,
    /// The closed X.509 primitive layer does not admit this universal tag.
    #[error("zk-X509 DER universal tag {number} is unsupported")]
    UnsupportedUniversalTag {
        /// Rejected universal tag number.
        number: u32,
    },
    /// A universal value uses the wrong primitive/constructed form.
    #[error(
        "zk-X509 DER universal tag {number} constructed={actual_constructed}; expected constructed={expected_constructed}"
    )]
    InvalidUniversalTagForm {
        /// Universal tag number.
        number: u32,
        /// Required form.
        expected_constructed: bool,
        /// Observed form.
        actual_constructed: bool,
    },
    /// A value is missing its first length octet or long-form length body.
    #[error("zk-X509 DER length is truncated")]
    TruncatedLength,
    /// BER indefinite length is forbidden.
    #[error("zk-X509 DER forbids indefinite length")]
    IndefiniteLength,
    /// A length cannot fit the platform-independent parser representation.
    #[error("zk-X509 DER length overflows usize")]
    LengthOverflow,
    /// Long-form length has a leading zero or encodes a short-form value.
    #[error("zk-X509 DER length is not minimally encoded")]
    NonMinimalLength,
    /// The declared value extends past the available bytes.
    #[error("zk-X509 DER value declares {declared} bytes but only {remaining} remain")]
    TruncatedValue {
        /// Declared content bytes.
        declared: usize,
        /// Available content bytes.
        remaining: usize,
    },
    /// Bytes remain after the sole top-level value.
    #[error("zk-X509 DER document has {bytes} trailing bytes")]
    TrailingData {
        /// Unconsumed bytes.
        bytes: usize,
    },
    /// A required child value is absent.
    #[error("zk-X509 DER container ended before a required value")]
    UnexpectedEndOfContainer,
    /// A typed parser encountered a different tag.
    #[error("zk-X509 DER expected tag {expected:?}, found {actual:?}")]
    UnexpectedTag {
        /// Required tag.
        expected: ZkX509DerTagV1,
        /// Observed tag.
        actual: ZkX509DerTagV1,
    },
    /// A caller requested children from a primitive value.
    #[error("zk-X509 DER value is not constructed")]
    ExpectedConstructedValue,
    /// DER `SET OF` children are not lexicographically ordered.
    #[error("zk-X509 DER SET OF elements are not in canonical order")]
    SetElementsOutOfOrder,
    /// A BOOLEAN is not exactly `00` or `ff`.
    #[error("zk-X509 DER BOOLEAN is not canonical")]
    InvalidBoolean,
    /// NULL has non-empty content.
    #[error("zk-X509 DER NULL must have empty content")]
    InvalidNull,
    /// INTEGER has no content octets.
    #[error("zk-X509 DER INTEGER is empty")]
    EmptyInteger,
    /// INTEGER has an unnecessary sign-extension octet.
    #[error("zk-X509 DER INTEGER is not minimally encoded")]
    NonMinimalInteger,
    /// A positive-only INTEGER is negative.
    #[error("zk-X509 DER INTEGER must be non-negative")]
    NegativeInteger,
    /// A positive-only INTEGER is zero.
    #[error("zk-X509 DER INTEGER must be non-zero")]
    ZeroInteger,
    /// A positive INTEGER exceeds its caller-provided unsigned width.
    #[error("zk-X509 DER INTEGER has {actual} unsigned bytes; maximum is {max}")]
    IntegerTooLarge {
        /// Observed unsigned bytes.
        actual: usize,
        /// Maximum unsigned bytes.
        max: usize,
    },
    /// OBJECT IDENTIFIER has no subidentifier.
    #[error("zk-X509 DER OBJECT IDENTIFIER is empty")]
    EmptyObjectIdentifier,
    /// An OBJECT IDENTIFIER subidentifier has a leading zero base-128 group.
    #[error("zk-X509 DER OBJECT IDENTIFIER has a non-minimal subidentifier")]
    NonMinimalObjectIdentifier,
    /// The last OBJECT IDENTIFIER subidentifier has no terminating octet.
    #[error("zk-X509 DER OBJECT IDENTIFIER is truncated")]
    TruncatedObjectIdentifier,
    /// BIT STRING omits its unused-bit count.
    #[error("zk-X509 DER BIT STRING is empty")]
    EmptyBitString,
    /// BIT STRING's unused-bit count is outside 0..=7.
    #[error("zk-X509 DER BIT STRING unused-bit count {unused_bits} exceeds seven")]
    InvalidUnusedBitCount {
        /// Rejected unused-bit count.
        unused_bits: u8,
    },
    /// An empty BIT STRING claims unused bits.
    #[error("zk-X509 DER empty BIT STRING must have zero unused bits")]
    UnusedBitsWithoutPayload,
    /// Bits declared unused are not zero.
    #[error("zk-X509 DER BIT STRING has non-zero unused bits")]
    NonZeroUnusedBits,
    /// `AlgorithmIdentifier` omits its algorithm OID.
    #[error("zk-X509 AlgorithmIdentifier omits its algorithm OID")]
    MissingAlgorithmObjectIdentifier,
    /// The signature `AlgorithmIdentifier` is not exactly ECDSA with SHA-256.
    #[error("zk-X509 signature AlgorithmIdentifier is not ecdsa-with-SHA256")]
    UnsupportedSignatureAlgorithm,
    /// ECDSA-with-SHA256 parameters must be absent, not NULL.
    #[error("zk-X509 ecdsa-with-SHA256 AlgorithmIdentifier parameters must be absent")]
    ForbiddenSignatureAlgorithmParameters,
    /// The subject-public-key algorithm is not `id-ecPublicKey`.
    #[error("zk-X509 subject-public-key AlgorithmIdentifier is not id-ecPublicKey")]
    UnsupportedPublicKeyAlgorithm,
    /// The subject-public-key `AlgorithmIdentifier` omits its named curve.
    #[error("zk-X509 id-ecPublicKey AlgorithmIdentifier omits its named curve")]
    MissingPublicKeyAlgorithmParameters,
    /// The named curve is not exactly `prime256v1`.
    #[error("zk-X509 subject-public-key AlgorithmIdentifier is not prime256v1")]
    UnsupportedNamedCurve,
    /// `AlgorithmIdentifier` contains fields beyond the exact profile shape.
    #[error("zk-X509 AlgorithmIdentifier contains unexpected trailing fields")]
    UnexpectedAlgorithmIdentifierFields,
}
/// One recursively validated borrowed DER value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerValueV1<'a> {
    tag: ZkX509DerTagV1,
    encoded: &'a [u8],
    contents: &'a [u8],
}
impl<'a> ZkX509DerValueV1<'a> {
    /// Return the decoded tag.
    pub(crate) const fn tag(self) -> ZkX509DerTagV1 {
        self.tag
    }
    /// Return the complete canonical TLV bytes.
    pub(crate) const fn encoded(self) -> &'a [u8] {
        self.encoded
    }
    /// Return the content octets.
    pub(crate) const fn contents(self) -> &'a [u8] {
        self.contents
    }
    /// Require an exact tag.
    pub(crate) fn require_tag(self, expected: ZkX509DerTagV1) -> Result<Self, ZkX509DerErrorV1> {
        if self.tag != expected {
            return Err(ZkX509DerErrorV1::UnexpectedTag {
                expected,
                actual: self.tag,
            });
        }
        Ok(self)
    }
    /// Interpret this value as a canonical INTEGER.
    pub(crate) fn as_integer(self) -> Result<ZkX509DerIntegerV1<'a>, ZkX509DerErrorV1> {
        self.require_tag(ZkX509DerTagV1::INTEGER)?;
        validate_integer_contents(self.contents)?;
        Ok(ZkX509DerIntegerV1 {
            contents: self.contents,
        })
    }
    /// Interpret this value as a canonical OBJECT IDENTIFIER.
    pub(crate) fn as_object_identifier(
        self,
    ) -> Result<ZkX509DerObjectIdentifierV1<'a>, ZkX509DerErrorV1> {
        self.require_tag(ZkX509DerTagV1::OBJECT_IDENTIFIER)?;
        validate_object_identifier_contents(self.contents)?;
        Ok(ZkX509DerObjectIdentifierV1 {
            contents: self.contents,
        })
    }
    /// Interpret this value as a canonical BIT STRING.
    pub(crate) fn as_bit_string(self) -> Result<ZkX509DerBitStringV1<'a>, ZkX509DerErrorV1> {
        self.require_tag(ZkX509DerTagV1::BIT_STRING)?;
        let (unused_bits, bytes) = validate_bit_string_contents(self.contents)?;
        Ok(ZkX509DerBitStringV1 { unused_bits, bytes })
    }
    /// Create a bounded reader over this constructed value's children.
    pub(crate) fn children(
        self,
        limits: ZkX509DerLimitsV1,
    ) -> Result<ZkX509DerReaderV1<'a>, ZkX509DerErrorV1> {
        if !self.tag.constructed {
            return Err(ZkX509DerErrorV1::ExpectedConstructedValue);
        }
        Ok(ZkX509DerReaderV1 {
            remaining: self.contents,
            limits,
        })
    }
}
/// Reader over already recursively validated DER children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerReaderV1<'a> {
    remaining: &'a [u8],
    limits: ZkX509DerLimitsV1,
}
impl<'a> ZkX509DerReaderV1<'a> {
    /// Return whether every child was consumed.
    pub(crate) const fn is_empty(self) -> bool {
        self.remaining.is_empty()
    }
    /// Read one required child.
    pub(crate) fn read_value(&mut self) -> Result<ZkX509DerValueV1<'a>, ZkX509DerErrorV1> {
        if self.remaining.is_empty() {
            return Err(ZkX509DerErrorV1::UnexpectedEndOfContainer);
        }
        let (value, remaining) = parse_value_prefix(self.remaining, self.limits)?;
        self.remaining = remaining;
        Ok(value)
    }
}
/// Canonical borrowed INTEGER content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerIntegerV1<'a> {
    contents: &'a [u8],
}
impl<'a> ZkX509DerIntegerV1<'a> {
    /// Return the exact signed two's-complement content bytes.
    pub(crate) const fn contents(self) -> &'a [u8] {
        self.contents
    }
    /// Require a positive non-zero integer and return its unsigned magnitude.
    pub(crate) fn positive_unsigned(
        self,
        max_bytes: usize,
    ) -> Result<ZkX509DerPositiveIntegerV1<'a>, ZkX509DerErrorV1> {
        let first = *self
            .contents
            .first()
            .ok_or(ZkX509DerErrorV1::EmptyInteger)?;
        if first & 0x80 != 0 {
            return Err(ZkX509DerErrorV1::NegativeInteger);
        }
        let unsigned = if self.contents.len() > 1 && self.contents[0] == 0 {
            &self.contents[1..]
        } else {
            self.contents
        };
        if unsigned.iter().all(|byte| *byte == 0) {
            return Err(ZkX509DerErrorV1::ZeroInteger);
        }
        if unsigned.len() > max_bytes {
            return Err(ZkX509DerErrorV1::IntegerTooLarge {
                actual: unsigned.len(),
                max: max_bytes,
            });
        }
        Ok(ZkX509DerPositiveIntegerV1 { bytes: unsigned })
    }
}
/// Positive non-zero unsigned magnitude derived from a canonical INTEGER.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerPositiveIntegerV1<'a> {
    bytes: &'a [u8],
}
impl<'a> ZkX509DerPositiveIntegerV1<'a> {
    /// Return the unsigned magnitude with any required DER sign octet removed.
    pub(crate) const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}
/// Canonical borrowed OBJECT IDENTIFIER content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerObjectIdentifierV1<'a> {
    contents: &'a [u8],
}
impl<'a> ZkX509DerObjectIdentifierV1<'a> {
    /// Return the exact base-128 content octets.
    pub(crate) const fn contents(self) -> &'a [u8] {
        self.contents
    }
    /// Compare against exact canonical OID content octets.
    pub(crate) fn equals(self, expected_contents: &[u8]) -> bool {
        self.contents == expected_contents
    }
}
/// Canonical borrowed BIT STRING payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509DerBitStringV1<'a> {
    unused_bits: u8,
    bytes: &'a [u8],
}
impl<'a> ZkX509DerBitStringV1<'a> {
    /// Return the number of zero padding bits in the final payload octet.
    pub(crate) const fn unused_bits(self) -> u8 {
        self.unused_bits
    }
    /// Return the BIT STRING payload without the unused-bit count octet.
    pub(crate) const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}
/// Parse and recursively validate exactly one bounded DER value.
pub fn parse_single_der_value_v1(
    input: &[u8],
    limits: ZkX509DerLimitsV1,
) -> Result<ZkX509DerValueV1<'_>, ZkX509DerErrorV1> {
    if input.is_empty() {
        return Err(ZkX509DerErrorV1::EmptyInput);
    }
    if input.len() > limits.max_document_bytes {
        return Err(ZkX509DerErrorV1::InputTooLarge {
            actual: input.len(),
            max: limits.max_document_bytes,
        });
    }
    let mut value_count = 0_usize;
    let (value, remaining) = scan_value(input, 1, limits, &mut value_count)?;
    if !remaining.is_empty() {
        return Err(ZkX509DerErrorV1::TrailingData {
            bytes: remaining.len(),
        });
    }
    Ok(value)
}
/// Validate the exact ECDSA-with-SHA256 `AlgorithmIdentifier` used by certificates and CRLs.
pub fn validate_ecdsa_with_sha256_algorithm_identifier_v1(
    encoded: &[u8],
    limits: ZkX509DerLimitsV1,
) -> Result<(), ZkX509DerErrorV1> {
    let sequence =
        parse_single_der_value_v1(encoded, limits)?.require_tag(ZkX509DerTagV1::SEQUENCE)?;
    let mut fields = sequence.children(limits)?;
    let algorithm = fields
        .read_value()
        .map_err(map_missing_algorithm_oid)?
        .as_object_identifier()?;
    if !algorithm.equals(ZK_X509_ECDSA_WITH_SHA256_OID_CONTENT_V1) {
        return Err(ZkX509DerErrorV1::UnsupportedSignatureAlgorithm);
    }
    if !fields.is_empty() {
        return Err(ZkX509DerErrorV1::ForbiddenSignatureAlgorithmParameters);
    }
    Ok(())
}
/// Validate the exact id-ecPublicKey/prime256v1 `AlgorithmIdentifier` used by SPKIs.
pub fn validate_p256_public_key_algorithm_identifier_v1(
    encoded: &[u8],
    limits: ZkX509DerLimitsV1,
) -> Result<(), ZkX509DerErrorV1> {
    let sequence =
        parse_single_der_value_v1(encoded, limits)?.require_tag(ZkX509DerTagV1::SEQUENCE)?;
    let mut fields = sequence.children(limits)?;
    let algorithm = fields
        .read_value()
        .map_err(map_missing_algorithm_oid)?
        .as_object_identifier()?;
    if !algorithm.equals(ZK_X509_ID_EC_PUBLIC_KEY_OID_CONTENT_V1) {
        return Err(ZkX509DerErrorV1::UnsupportedPublicKeyAlgorithm);
    }
    let curve = fields
        .read_value()
        .map_err(map_missing_public_key_parameters)?
        .as_object_identifier()?;
    if !curve.equals(ZK_X509_PRIME256V1_OID_CONTENT_V1) {
        return Err(ZkX509DerErrorV1::UnsupportedNamedCurve);
    }
    if !fields.is_empty() {
        return Err(ZkX509DerErrorV1::UnexpectedAlgorithmIdentifierFields);
    }
    Ok(())
}
fn map_missing_algorithm_oid(error: ZkX509DerErrorV1) -> ZkX509DerErrorV1 {
    if error == ZkX509DerErrorV1::UnexpectedEndOfContainer {
        ZkX509DerErrorV1::MissingAlgorithmObjectIdentifier
    } else {
        error
    }
}
fn map_missing_public_key_parameters(error: ZkX509DerErrorV1) -> ZkX509DerErrorV1 {
    if error == ZkX509DerErrorV1::UnexpectedEndOfContainer {
        ZkX509DerErrorV1::MissingPublicKeyAlgorithmParameters
    } else {
        error
    }
}
fn scan_value<'a>(
    input: &'a [u8],
    depth: usize,
    limits: ZkX509DerLimitsV1,
    value_count: &mut usize,
) -> Result<(ZkX509DerValueV1<'a>, &'a [u8]), ZkX509DerErrorV1> {
    if depth > limits.max_nesting_depth {
        return Err(ZkX509DerErrorV1::NestingTooDeep {
            depth,
            max: limits.max_nesting_depth,
        });
    }
    if *value_count >= limits.max_values {
        return Err(ZkX509DerErrorV1::TooManyValues {
            max: limits.max_values,
        });
    }
    *value_count = (*value_count)
        .checked_add(1)
        .ok_or(ZkX509DerErrorV1::TooManyValues {
            max: limits.max_values,
        })?;
    let (value, remaining) = parse_value_prefix(input, limits)?;
    if value.tag.constructed {
        let child_depth = depth
            .checked_add(1)
            .ok_or(ZkX509DerErrorV1::NestingTooDeep {
                depth: usize::MAX,
                max: limits.max_nesting_depth,
            })?;
        scan_constructed_contents(
            value.contents,
            child_depth,
            value.tag == ZkX509DerTagV1::SET,
            limits,
            value_count,
        )?;
    }
    Ok((value, remaining))
}
fn scan_constructed_contents(
    mut input: &[u8],
    depth: usize,
    require_set_order: bool,
    limits: ZkX509DerLimitsV1,
    value_count: &mut usize,
) -> Result<(), ZkX509DerErrorV1> {
    let mut previous: Option<&[u8]> = None;
    while !input.is_empty() {
        let (value, remaining) = scan_value(input, depth, limits, value_count)?;
        if require_set_order
            && previous.is_some_and(|previous_encoded| previous_encoded > value.encoded)
        {
            return Err(ZkX509DerErrorV1::SetElementsOutOfOrder);
        }
        previous = Some(value.encoded);
        input = remaining;
    }
    Ok(())
}
fn parse_value_prefix(
    input: &[u8],
    limits: ZkX509DerLimitsV1,
) -> Result<(ZkX509DerValueV1<'_>, &[u8]), ZkX509DerErrorV1> {
    let (tag, identifier_bytes) = parse_identifier(input)?;
    validate_universal_tag_form(tag)?;
    let length_input = input
        .get(identifier_bytes..)
        .ok_or(ZkX509DerErrorV1::TruncatedLength)?;
    let (content_bytes, length_bytes) = parse_length(length_input)?;
    if content_bytes > limits.max_value_bytes {
        return Err(ZkX509DerErrorV1::ValueTooLarge {
            actual: content_bytes,
            max: limits.max_value_bytes,
        });
    }
    let header_bytes = identifier_bytes
        .checked_add(length_bytes)
        .ok_or(ZkX509DerErrorV1::LengthOverflow)?;
    let available_content = input
        .len()
        .checked_sub(header_bytes)
        .ok_or(ZkX509DerErrorV1::TruncatedLength)?;
    if content_bytes > available_content {
        return Err(ZkX509DerErrorV1::TruncatedValue {
            declared: content_bytes,
            remaining: available_content,
        });
    }
    let encoded_bytes = header_bytes
        .checked_add(content_bytes)
        .ok_or(ZkX509DerErrorV1::LengthOverflow)?;
    let encoded = &input[..encoded_bytes];
    let contents = &input[header_bytes..encoded_bytes];
    validate_primitive_contents(tag, contents)?;
    Ok((
        ZkX509DerValueV1 {
            tag,
            encoded,
            contents,
        },
        &input[encoded_bytes..],
    ))
}
fn parse_identifier(input: &[u8]) -> Result<(ZkX509DerTagV1, usize), ZkX509DerErrorV1> {
    let first = *input.first().ok_or(ZkX509DerErrorV1::TruncatedIdentifier)?;
    let class = match first >> 6 {
        0 => ZkX509DerClassV1::Universal,
        1 => ZkX509DerClassV1::Application,
        2 => ZkX509DerClassV1::ContextSpecific,
        _ => ZkX509DerClassV1::Private,
    };
    let constructed = first & 0x20 != 0;
    let low_number = u32::from(first & 0x1f);
    if low_number != 0x1f {
        return Ok((
            ZkX509DerTagV1 {
                class,
                constructed,
                number: low_number,
            },
            1,
        ));
    }
    let mut number = 0_u32;
    let mut index = 1_usize;
    let first_high = *input
        .get(index)
        .ok_or(ZkX509DerErrorV1::TruncatedIdentifier)?;
    if first_high == 0x80 {
        return Err(ZkX509DerErrorV1::NonMinimalTag);
    }
    loop {
        let byte = *input
            .get(index)
            .ok_or(ZkX509DerErrorV1::TruncatedIdentifier)?;
        number = number
            .checked_mul(128)
            .and_then(|value| value.checked_add(u32::from(byte & 0x7f)))
            .ok_or(ZkX509DerErrorV1::TagNumberOverflow)?;
        index = index
            .checked_add(1)
            .ok_or(ZkX509DerErrorV1::TagNumberOverflow)?;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if number < 31 {
        return Err(ZkX509DerErrorV1::NonMinimalTag);
    }
    Ok((
        ZkX509DerTagV1 {
            class,
            constructed,
            number,
        },
        index,
    ))
}
fn parse_length(input: &[u8]) -> Result<(usize, usize), ZkX509DerErrorV1> {
    let first = *input.first().ok_or(ZkX509DerErrorV1::TruncatedLength)?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let length_octets = usize::from(first & 0x7f);
    if length_octets == 0 {
        return Err(ZkX509DerErrorV1::IndefiniteLength);
    }
    let body = input
        .get(1..)
        .and_then(|remaining| remaining.get(..length_octets))
        .ok_or(ZkX509DerErrorV1::TruncatedLength)?;
    if body[0] == 0 {
        return Err(ZkX509DerErrorV1::NonMinimalLength);
    }
    if length_octets > core::mem::size_of::<usize>() {
        return Err(ZkX509DerErrorV1::LengthOverflow);
    }
    let mut length = 0_usize;
    for byte in body {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(ZkX509DerErrorV1::LengthOverflow)?;
    }
    if length < 128 {
        return Err(ZkX509DerErrorV1::NonMinimalLength);
    }
    let encoded_octets = 1_usize
        .checked_add(length_octets)
        .ok_or(ZkX509DerErrorV1::LengthOverflow)?;
    Ok((length, encoded_octets))
}
fn validate_universal_tag_form(tag: ZkX509DerTagV1) -> Result<(), ZkX509DerErrorV1> {
    if tag.class != ZkX509DerClassV1::Universal {
        return Ok(());
    }
    if tag.number == 0 {
        return Err(ZkX509DerErrorV1::EndOfContentsForbidden);
    }
    let expected_constructed = match tag.number {
        1..=6 | 10 | 12 | 18..=20 | 22..=24 | 26 | 28 | 30 => false,
        16 | 17 => true,
        number => return Err(ZkX509DerErrorV1::UnsupportedUniversalTag { number }),
    };
    if tag.constructed != expected_constructed {
        return Err(ZkX509DerErrorV1::InvalidUniversalTagForm {
            number: tag.number,
            expected_constructed,
            actual_constructed: tag.constructed,
        });
    }
    Ok(())
}
fn validate_primitive_contents(
    tag: ZkX509DerTagV1,
    contents: &[u8],
) -> Result<(), ZkX509DerErrorV1> {
    if tag.class != ZkX509DerClassV1::Universal || tag.constructed {
        return Ok(());
    }
    match tag.number {
        1 => validate_boolean_contents(contents),
        2 | 10 => validate_integer_contents(contents),
        3 => validate_bit_string_contents(contents).map(|_| ()),
        5 => validate_null_contents(contents),
        6 => validate_object_identifier_contents(contents),
        _ => Ok(()),
    }
}
fn validate_boolean_contents(contents: &[u8]) -> Result<(), ZkX509DerErrorV1> {
    if contents.len() != 1 || !matches!(contents[0], 0x00 | 0xff) {
        return Err(ZkX509DerErrorV1::InvalidBoolean);
    }
    Ok(())
}
fn validate_null_contents(contents: &[u8]) -> Result<(), ZkX509DerErrorV1> {
    if !contents.is_empty() {
        return Err(ZkX509DerErrorV1::InvalidNull);
    }
    Ok(())
}
fn validate_integer_contents(contents: &[u8]) -> Result<(), ZkX509DerErrorV1> {
    let first = *contents.first().ok_or(ZkX509DerErrorV1::EmptyInteger)?;
    if let Some(second) = contents.get(1).copied() {
        let redundant_positive_sign = first == 0 && second & 0x80 == 0;
        let redundant_negative_sign = first == 0xff && second & 0x80 != 0;
        if redundant_positive_sign || redundant_negative_sign {
            return Err(ZkX509DerErrorV1::NonMinimalInteger);
        }
    }
    Ok(())
}
fn validate_object_identifier_contents(contents: &[u8]) -> Result<(), ZkX509DerErrorV1> {
    if contents.is_empty() {
        return Err(ZkX509DerErrorV1::EmptyObjectIdentifier);
    }
    let mut starts_subidentifier = true;
    for byte in contents {
        if starts_subidentifier && *byte == 0x80 {
            return Err(ZkX509DerErrorV1::NonMinimalObjectIdentifier);
        }
        starts_subidentifier = byte & 0x80 == 0;
    }
    if !starts_subidentifier {
        return Err(ZkX509DerErrorV1::TruncatedObjectIdentifier);
    }
    Ok(())
}
fn validate_bit_string_contents(contents: &[u8]) -> Result<(u8, &[u8]), ZkX509DerErrorV1> {
    let unused_bits = *contents.first().ok_or(ZkX509DerErrorV1::EmptyBitString)?;
    if unused_bits > 7 {
        return Err(ZkX509DerErrorV1::InvalidUnusedBitCount { unused_bits });
    }
    let bytes = &contents[1..];
    if bytes.is_empty() && unused_bits != 0 {
        return Err(ZkX509DerErrorV1::UnusedBitsWithoutPayload);
    }
    if unused_bits != 0 {
        let mask = (1_u8 << unused_bits) - 1;
        if bytes.last().is_some_and(|last| last & mask != 0) {
            return Err(ZkX509DerErrorV1::NonZeroUnusedBits);
        }
    }
    Ok((unused_bits, bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> ZkX509DerLimitsV1 {
        ZkX509DerLimitsV1::profile()
    }
    fn single(input: &[u8]) -> Result<ZkX509DerValueV1<'_>, ZkX509DerErrorV1> {
        parse_single_der_value_v1(input, limits())
    }
    #[test]
    fn one_top_level_value_is_borrowed_and_trailing_bytes_are_rejected() {
        let encoded = [0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let value = single(&encoded).expect("canonical sequence");
        assert_eq!(value.tag(), ZkX509DerTagV1::SEQUENCE);
        assert_eq!(value.encoded(), &encoded);
        assert_eq!(value.contents(), &encoded[2..]);
        assert_eq!(single(&[]), Err(ZkX509DerErrorV1::EmptyInput));
        let mut trailing = encoded.to_vec();
        trailing.extend_from_slice(&[0x05, 0x00]);
        assert_eq!(
            single(&trailing),
            Err(ZkX509DerErrorV1::TrailingData { bytes: 2 })
        );
    }
    #[test]
    fn document_value_depth_and_count_limits_fail_before_allocation() {
        let tiny_document = ZkX509DerLimitsV1::new(2, 16, 4, 4);
        assert_eq!(
            parse_single_der_value_v1(&[0x04, 0x01, 0x00], tiny_document),
            Err(ZkX509DerErrorV1::InputTooLarge { actual: 3, max: 2 })
        );
        let tiny_value = ZkX509DerLimitsV1::new(16, 2, 4, 4);
        assert_eq!(
            parse_single_der_value_v1(&[0x04, 0x03, 0, 0, 0], tiny_value),
            Err(ZkX509DerErrorV1::ValueTooLarge { actual: 3, max: 2 })
        );
        let nested = [0x30, 0x02, 0x30, 0x00];
        let one_level = ZkX509DerLimitsV1::new(16, 16, 1, 4);
        assert_eq!(
            parse_single_der_value_v1(&nested, one_level),
            Err(ZkX509DerErrorV1::NestingTooDeep { depth: 2, max: 1 })
        );
        let three_values = [0x30, 0x04, 0x05, 0x00, 0x05, 0x00];
        let two_values = ZkX509DerLimitsV1::new(16, 16, 4, 2);
        assert_eq!(
            parse_single_der_value_v1(&three_values, two_values),
            Err(ZkX509DerErrorV1::TooManyValues { max: 2 })
        );
    }
    #[test]
    fn definite_minimal_lengths_are_the_only_lengths_admitted() {
        let mut long_form = vec![0x30, 0x81, 0x80, 0x04, 0x7e];
        long_form.extend(core::iter::repeat(0_u8).take(126));
        single(&long_form).expect("minimal 128-byte long form");
        assert_eq!(single(&[0x04]), Err(ZkX509DerErrorV1::TruncatedLength));
        assert_eq!(
            single(&[0x04, 0x80]),
            Err(ZkX509DerErrorV1::IndefiniteLength)
        );
        assert_eq!(
            single(&[0x04, 0x81]),
            Err(ZkX509DerErrorV1::TruncatedLength)
        );
        assert_eq!(
            single(&[0x04, 0x81, 0x7f]),
            Err(ZkX509DerErrorV1::NonMinimalLength)
        );
        assert_eq!(
            single(&[0x04, 0x82, 0x00, 0x80]),
            Err(ZkX509DerErrorV1::NonMinimalLength)
        );
        assert_eq!(
            single(&[0x04, 0x04, 0xaa, 0xbb]),
            Err(ZkX509DerErrorV1::TruncatedValue {
                declared: 4,
                remaining: 2
            })
        );
        let length_octets = core::mem::size_of::<usize>() + 1;
        let mut overflowing = vec![
            0x04,
            0x80 | u8::try_from(length_octets).expect("small width"),
        ];
        overflowing.extend(core::iter::repeat(0xff).take(length_octets));
        assert_eq!(single(&overflowing), Err(ZkX509DerErrorV1::LengthOverflow));
        assert_eq!(
            single(&[0x04, 0x83, 0x01, 0x00, 0x00]),
            Err(ZkX509DerErrorV1::ValueTooLarge {
                actual: 65_536,
                max: ZK_X509_DER_MAX_VALUE_BYTES_V1,
            })
        );
    }
    #[test]
    fn identifiers_are_minimal_bounded_and_use_canonical_universal_forms() {
        let high_context_tag = [0x9f, 0x1f, 0x00];
        let value = single(&high_context_tag).expect("minimal context tag 31");
        assert_eq!(
            value.tag(),
            ZkX509DerTagV1 {
                class: ZkX509DerClassV1::ContextSpecific,
                constructed: false,
                number: 31,
            }
        );
        assert_eq!(single(&[0x9f]), Err(ZkX509DerErrorV1::TruncatedIdentifier));
        assert_eq!(
            single(&[0x9f, 0x80, 0x00]),
            Err(ZkX509DerErrorV1::NonMinimalTag)
        );
        assert_eq!(
            single(&[0x9f, 0x1e, 0x00]),
            Err(ZkX509DerErrorV1::NonMinimalTag)
        );
        assert_eq!(
            single(&[0x9f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00]),
            Err(ZkX509DerErrorV1::TagNumberOverflow)
        );
        assert_eq!(
            single(&[0x00, 0x00]),
            Err(ZkX509DerErrorV1::EndOfContentsForbidden)
        );
        assert_eq!(
            single(&[0x07, 0x00]),
            Err(ZkX509DerErrorV1::UnsupportedUniversalTag { number: 7 })
        );
        assert_eq!(
            single(&[0x22, 0x00]),
            Err(ZkX509DerErrorV1::InvalidUniversalTagForm {
                number: 2,
                expected_constructed: false,
                actual_constructed: true,
            })
        );
        assert_eq!(
            single(&[0x10, 0x00]),
            Err(ZkX509DerErrorV1::InvalidUniversalTagForm {
                number: 16,
                expected_constructed: true,
                actual_constructed: false,
            })
        );
    }
    #[test]
    fn set_of_order_is_checked_recursively() {
        let sorted = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        single(&sorted).expect("sorted SET OF");
        let reversed = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        assert_eq!(
            single(&reversed),
            Err(ZkX509DerErrorV1::SetElementsOutOfOrder)
        );
    }
    #[test]
    fn integers_are_minimal_and_positive_projection_is_bounded() {
        for encoded in [
            &[0x02, 0x01, 0x00][..],
            &[0x02, 0x01, 0x7f],
            &[0x02, 0x02, 0x00, 0x80],
            &[0x02, 0x01, 0x80],
            &[0x02, 0x02, 0xff, 0x7f],
        ] {
            single(encoded).expect("canonical signed INTEGER");
        }
        assert_eq!(single(&[0x02, 0x00]), Err(ZkX509DerErrorV1::EmptyInteger));
        assert_eq!(
            single(&[0x02, 0x02, 0x00, 0x7f]),
            Err(ZkX509DerErrorV1::NonMinimalInteger)
        );
        assert_eq!(
            single(&[0x02, 0x02, 0xff, 0x80]),
            Err(ZkX509DerErrorV1::NonMinimalInteger)
        );
        let sign_padded = single(&[0x02, 0x02, 0x00, 0x80])
            .expect("positive INTEGER")
            .as_integer()
            .expect("INTEGER tag");
        assert_eq!(sign_padded.contents(), &[0x00, 0x80]);
        assert_eq!(
            sign_padded
                .positive_unsigned(1)
                .expect("one-byte magnitude")
                .bytes(),
            &[0x80]
        );
        assert_eq!(
            single(&[0x02, 0x01, 0x80])
                .expect("negative INTEGER")
                .as_integer()
                .expect("INTEGER tag")
                .positive_unsigned(32),
            Err(ZkX509DerErrorV1::NegativeInteger)
        );
        assert_eq!(
            single(&[0x02, 0x01, 0x00])
                .expect("zero INTEGER")
                .as_integer()
                .expect("INTEGER tag")
                .positive_unsigned(32),
            Err(ZkX509DerErrorV1::ZeroInteger)
        );
        assert_eq!(
            single(&[0x02, 0x02, 0x01, 0x00])
                .expect("two-byte INTEGER")
                .as_integer()
                .expect("INTEGER tag")
                .positive_unsigned(1),
            Err(ZkX509DerErrorV1::IntegerTooLarge { actual: 2, max: 1 })
        );
    }
    #[test]
    fn object_identifiers_require_minimal_terminated_base128_arcs() {
        let oid = single(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
            .expect("canonical OID")
            .as_object_identifier()
            .expect("OID tag");
        assert!(oid.equals(ZK_X509_ECDSA_WITH_SHA256_OID_CONTENT_V1));
        assert_eq!(oid.contents(), ZK_X509_ECDSA_WITH_SHA256_OID_CONTENT_V1);
        // First combined arc value 1079 encodes 2.999, followed by arc 3.
        single(&[0x06, 0x03, 0x88, 0x37, 0x03]).expect("multi-byte first subidentifier");
        assert_eq!(
            single(&[0x06, 0x00]),
            Err(ZkX509DerErrorV1::EmptyObjectIdentifier)
        );
        assert_eq!(
            single(&[0x06, 0x02, 0x80, 0x00]),
            Err(ZkX509DerErrorV1::NonMinimalObjectIdentifier)
        );
        assert_eq!(
            single(&[0x06, 0x01, 0x81]),
            Err(ZkX509DerErrorV1::TruncatedObjectIdentifier)
        );
        let wide_but_canonical_arc = [
            0x06, 0x0b, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00,
        ];
        single(&wide_but_canonical_arc)
            .expect("canonical OID arcs are byte-validated without an integer-width limit");
    }
    #[test]
    fn bit_strings_bind_unused_count_and_zero_padding() {
        let empty = single(&[0x03, 0x01, 0x00])
            .expect("empty BIT STRING")
            .as_bit_string()
            .expect("BIT STRING tag");
        assert_eq!(empty.unused_bits(), 0);
        assert!(empty.bytes().is_empty());
        let partial = single(&[0x03, 0x02, 0x03, 0xa0])
            .expect("partially used final octet")
            .as_bit_string()
            .expect("BIT STRING tag");
        assert_eq!(partial.unused_bits(), 3);
        assert_eq!(partial.bytes(), &[0xa0]);
        assert_eq!(single(&[0x03, 0x00]), Err(ZkX509DerErrorV1::EmptyBitString));
        assert_eq!(
            single(&[0x03, 0x01, 0x08]),
            Err(ZkX509DerErrorV1::InvalidUnusedBitCount { unused_bits: 8 })
        );
        assert_eq!(
            single(&[0x03, 0x01, 0x01]),
            Err(ZkX509DerErrorV1::UnusedBitsWithoutPayload)
        );
        assert_eq!(
            single(&[0x03, 0x02, 0x03, 0xa1]),
            Err(ZkX509DerErrorV1::NonZeroUnusedBits)
        );
    }
    #[test]
    fn boolean_and_null_are_canonical() {
        single(&[0x01, 0x01, 0x00]).expect("canonical FALSE");
        single(&[0x01, 0x01, 0xff]).expect("canonical TRUE");
        single(&[0x05, 0x00]).expect("canonical NULL");
        assert_eq!(
            single(&[0x01, 0x01, 0x01]),
            Err(ZkX509DerErrorV1::InvalidBoolean)
        );
        assert_eq!(single(&[0x01, 0x00]), Err(ZkX509DerErrorV1::InvalidBoolean));
        assert_eq!(
            single(&[0x05, 0x01, 0x00]),
            Err(ZkX509DerErrorV1::InvalidNull)
        );
    }
    #[test]
    fn signature_algorithm_identifier_is_exact_and_parameters_are_absent() {
        validate_ecdsa_with_sha256_algorithm_identifier_v1(
            ZK_X509_ECDSA_WITH_SHA256_ALGORITHM_IDENTIFIER_DER_V1,
            limits(),
        )
        .expect("exact signature algorithm");
        assert_eq!(
            validate_ecdsa_with_sha256_algorithm_identifier_v1(&[0x30, 0x00], limits()),
            Err(ZkX509DerErrorV1::MissingAlgorithmObjectIdentifier)
        );
        let with_null = [
            0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00,
        ];
        assert_eq!(
            validate_ecdsa_with_sha256_algorithm_identifier_v1(&with_null, limits()),
            Err(ZkX509DerErrorV1::ForbiddenSignatureAlgorithmParameters)
        );
        let sha384 = [
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
        ];
        assert_eq!(
            validate_ecdsa_with_sha256_algorithm_identifier_v1(&sha384, limits()),
            Err(ZkX509DerErrorV1::UnsupportedSignatureAlgorithm)
        );
        assert!(matches!(
            validate_ecdsa_with_sha256_algorithm_identifier_v1(
                &ZK_X509_ECDSA_WITH_SHA256_ALGORITHM_IDENTIFIER_DER_V1[2..],
                limits()
            ),
            Err(ZkX509DerErrorV1::UnexpectedTag { .. })
        ));
    }
    #[test]
    fn public_key_algorithm_identifier_is_exact_p256_with_named_curve() {
        validate_p256_public_key_algorithm_identifier_v1(
            ZK_X509_P256_PUBLIC_KEY_ALGORITHM_IDENTIFIER_DER_V1,
            limits(),
        )
        .expect("exact P-256 public-key algorithm");
        let missing_curve = [
            0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        ];
        assert_eq!(
            validate_p256_public_key_algorithm_identifier_v1(&missing_curve, limits()),
            Err(ZkX509DerErrorV1::MissingPublicKeyAlgorithmParameters)
        );
        let wrong_algorithm = [
            0x30, 0x14, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        assert_eq!(
            validate_p256_public_key_algorithm_identifier_v1(&wrong_algorithm, limits()),
            Err(ZkX509DerErrorV1::UnsupportedPublicKeyAlgorithm)
        );
        let secp384r1 = [
            0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
            0x81, 0x04, 0x00, 0x22,
        ];
        assert_eq!(
            validate_p256_public_key_algorithm_identifier_v1(&secp384r1, limits()),
            Err(ZkX509DerErrorV1::UnsupportedNamedCurve)
        );
        let with_extra_null = [
            0x30, 0x15, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x05, 0x00,
        ];
        assert_eq!(
            validate_p256_public_key_algorithm_identifier_v1(&with_extra_null, limits()),
            Err(ZkX509DerErrorV1::UnexpectedAlgorithmIdentifierFields)
        );
    }
    #[test]
    fn every_algorithm_identifier_truncation_fails_closed() {
        for canonical in [
            ZK_X509_ECDSA_WITH_SHA256_ALGORITHM_IDENTIFIER_DER_V1,
            ZK_X509_P256_PUBLIC_KEY_ALGORITHM_IDENTIFIER_DER_V1,
        ] {
            for end in 0..canonical.len() {
                let result = if canonical == ZK_X509_ECDSA_WITH_SHA256_ALGORITHM_IDENTIFIER_DER_V1 {
                    validate_ecdsa_with_sha256_algorithm_identifier_v1(&canonical[..end], limits())
                } else {
                    validate_p256_public_key_algorithm_identifier_v1(&canonical[..end], limits())
                };
                assert!(result.is_err(), "prefix length {end} unexpectedly parsed");
            }
        }
    }
    #[test]
    fn x509_parser_is_only_a_differential_oracle_for_algorithm_shape() {
        use x509_parser::{prelude::FromDer, x509::AlgorithmIdentifier};
        let (remaining, signature) =
            AlgorithmIdentifier::from_der(ZK_X509_ECDSA_WITH_SHA256_ALGORITHM_IDENTIFIER_DER_V1)
                .expect("oracle parses canonical signature AlgorithmIdentifier");
        assert!(remaining.is_empty());
        assert_eq!(signature.algorithm.to_id_string(), "1.2.840.10045.4.3.2");
        assert!(signature.parameters.is_none());
        let (remaining, public_key) =
            AlgorithmIdentifier::from_der(ZK_X509_P256_PUBLIC_KEY_ALGORITHM_IDENTIFIER_DER_V1)
                .expect("oracle parses canonical public-key AlgorithmIdentifier");
        assert!(remaining.is_empty());
        assert_eq!(public_key.algorithm.to_id_string(), "1.2.840.10045.2.1");
        assert!(public_key.parameters.is_some());
        // The generic oracle accepts an explicit NULL here. The native profile
        // is deliberately stricter and remains the authoritative decision.
        let with_null = [
            0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00,
        ];
        let (remaining, oracle) =
            AlgorithmIdentifier::from_der(&with_null).expect("oracle accepts optional parameters");
        assert!(remaining.is_empty());
        assert!(oracle.parameters.is_some());
        assert_eq!(
            validate_ecdsa_with_sha256_algorithm_identifier_v1(&with_null, limits()),
            Err(ZkX509DerErrorV1::ForbiddenSignatureAlgorithmParameters)
        );
    }
}
