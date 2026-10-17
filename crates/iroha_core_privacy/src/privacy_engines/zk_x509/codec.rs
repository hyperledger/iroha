//! Canonical private-witness codec for the native zk-X509 relation.
//!
//! The local prover accepts one uncompressed Norito V1 schema with flags zero.
//! Serialization uses the derived field grammar; bounded decoding fills the
//! final clearing owner directly without aligned or padded private scratch.
//! The fixed, nonrecursive field graph has no attacker-selected nesting.
//! This container does not change the separately specified proof codec.
use super::{
    der_air::ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
    merkle::{
        ZK_X509_CA_COMPACT_TREE_CAPACITY_V1, ZK_X509_CA_COMPACT_TREE_DEPTH_V1,
        ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1, ZkX509CaMembershipPathV1,
    },
    private_table::{PrivateTableV1, zeroize_words_v1},
    profile::{
        ZK_X509_ATTRIBUTE_SALT_BYTES_V1, ZK_X509_MAX_CHAIN_DEPTH_V1, ZK_X509_MAX_CRL_BYTES_V1,
        ZK_X509_MIN_CHAIN_DEPTH_V1,
    },
};
use core::fmt;
use iroha_data_model::privacy::{ZK_X509_MAX_CERTIFICATE_BYTES_V1, ZK_X509_MAX_CHAIN_BYTES_V1};
use norito::core::{DecodeFromSlice, Header};
use thiserror::Error;
use zeroize::Zeroize;
const WITNESS_FLAGS_V1: u8 = 0;
const NORITO_LENGTH_BYTES_V1: usize = 8;
// Header padding is the same type-alignment rule used by the Norito writer.
const WITNESS_FRAME_PREFIX_BYTES_V1: usize =
    Header::SIZE.next_multiple_of(norito::core::archived_payload_align::<ZkX509WitnessV1>());
const OPENING_PAYLOAD_BYTES_V1: usize =
    2 * NORITO_LENGTH_BYTES_V1 + 1 + ZK_X509_ATTRIBUTE_SALT_BYTES_V1;
// The nested array follows Norito's generic array grammar: each byte and
// each 32-byte digest has its own length-delimited element, without counts.
const DIGEST_PAYLOAD_BYTES_V1: usize = 32 * (NORITO_LENGTH_BYTES_V1 + 1);
const SIBLINGS_PAYLOAD_BYTES_V1: usize =
    ZK_X509_CA_COMPACT_TREE_DEPTH_V1 * (NORITO_LENGTH_BYTES_V1 + DIGEST_PAYLOAD_BYTES_V1);
const PATH_PAYLOAD_BYTES_V1: usize = 2 * NORITO_LENGTH_BYTES_V1 + 2 + SIBLINGS_PAYLOAD_BYTES_V1;
const MAX_CHAIN_PAYLOAD_BYTES_V1: usize = NORITO_LENGTH_BYTES_V1
    + ZK_X509_MAX_CHAIN_DEPTH_V1
        * (2 * NORITO_LENGTH_BYTES_V1 + ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1);
const MAX_WITNESS_PAYLOAD_BYTES_V1: usize = 5 * NORITO_LENGTH_BYTES_V1
    + MAX_CHAIN_PAYLOAD_BYTES_V1
    + NORITO_LENGTH_BYTES_V1
    + ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1
    + PATH_PAYLOAD_BYTES_V1
    + ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1
    + NORITO_LENGTH_BYTES_V1
    + MAX_DISCLOSED_ATTRIBUTES_V1 * (NORITO_LENGTH_BYTES_V1 + OPENING_PAYLOAD_BYTES_V1);
const MAX_WITNESS_FRAME_BYTES_V1: usize =
    WITNESS_FRAME_PREFIX_BYTES_V1 + MAX_WITNESS_PAYLOAD_BYTES_V1;
pub const ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1: usize = 64;
const MAX_DISCLOSED_ATTRIBUTES_V1: usize = 4;
const _: () = {
    assert!(
        ZK_X509_MAX_CERTIFICATE_BYTES_V1 as usize
            == ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
    );
    assert!(
        ZK_X509_MAX_CHAIN_BYTES_V1 as usize
            == ZK_X509_MAX_CHAIN_DEPTH_V1 * ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
    );
    assert!(ZK_X509_MAX_CRL_BYTES_V1 == ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1);
    assert!(ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1 == ZK_X509_MAX_CRL_BYTES_V1);
};
/// One private opening of a publicly committed subject attribute.
#[derive(Clone, Copy, PartialEq, Eq, norito::SerializePayload)]
pub struct ZkX509AttributeOpeningV1 {
    /// Closed attribute index (`0=C`, `1=O`, `2=OU`, `3=CN`).
    pub(crate) index: u8,
    /// Fixed-width private commitment salt.
    pub(crate) salt: [u8; ZK_X509_ATTRIBUTE_SALT_BYTES_V1],
}
impl fmt::Debug for ZkX509AttributeOpeningV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkX509AttributeOpeningV1")
            .field("index", &self.index)
            .field("salt", &"[REDACTED]")
            .finish()
    }
}
impl Zeroize for ZkX509AttributeOpeningV1 {
    fn zeroize(&mut self) {
        self.index.zeroize();
        self.salt.zeroize();
    }
}
/// Complete bounded private input to the native reference relation and prover.
#[derive(Clone, PartialEq, Eq, norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_engines::zk_x509::ZkX509WitnessV1")]
#[doc(hidden)]
pub struct ZkX509WitnessV1 {
    /// Exact DER certificates ordered leaf first and root last.
    pub(crate) certificate_chain_der: Vec<Vec<u8>>,
    /// Exact complete signed base-CRL DER for the leaf issuer.
    pub(crate) crl_der: Vec<u8>,
    /// Governed root-CA compact-tree membership witness.
    pub(crate) ca_membership_path: ZkX509CaMembershipPathV1,
    /// Fresh low-`s` P-256 signature by the leaf subject key as fixed
    /// canonical `r || s`.
    pub(crate) wallet_ownership_signature_rs: [u8; ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1],
    /// Private attribute salts in strict disclosed-index order.
    pub(crate) attribute_openings: Vec<ZkX509AttributeOpeningV1>,
}
impl fmt::Debug for ZkX509WitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZkX509WitnessV1 { [REDACTED] }")
    }
}
impl Zeroize for ZkX509WitnessV1 {
    fn zeroize(&mut self) {
        for certificate in &mut self.certificate_chain_der {
            zeroize_words_v1(certificate);
            certificate.zeroize();
        }
        self.certificate_chain_der.clear();
        zeroize_words_v1(&mut self.crl_der);
        self.crl_der.zeroize();
        zeroize_words_v1(core::slice::from_mut(&mut self.ca_membership_path.index));
        for sibling in &mut self.ca_membership_path.siblings {
            zeroize_words_v1(sibling);
        }
        zeroize_words_v1(&mut self.wallet_ownership_signature_rs);
        for opening in &mut self.attribute_openings {
            zeroize_words_v1(core::slice::from_mut(&mut opening.index));
            zeroize_words_v1(&mut opening.salt);
        }
        // Vec::zeroize also clears spare capacity that callers may have used
        // before truncating a private buffer; live-cell erasure is observable
        // in tests without inspecting freed or uninitialized storage.
        self.attribute_openings.zeroize();
    }
}
impl Drop for ZkX509WitnessV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Canonical witness decoding or encoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509WitnessCodecErrorV1 {
    /// The Norito header, V1 schema, checksum, or fixed layout does not match.
    #[error("zk-X509 witness header is not canonical")]
    InvalidHeader,
    /// The certificate count is outside the fixed two-to-three range.
    #[error("zk-X509 witness certificate-chain depth is invalid")]
    InvalidChainDepth,
    /// A certificate length is zero, oversized, or not representable.
    #[error("zk-X509 witness certificate length is invalid")]
    InvalidCertificateLength,
    /// The complete CRL length is zero, oversized, or not representable.
    #[error("zk-X509 witness CRL length is invalid")]
    InvalidCrlLength,
    /// The private sorted-leaf index is outside the twelve-bit tree.
    #[error("zk-X509 witness CA membership index is invalid")]
    InvalidCaPathIndex,
    /// Attribute openings are out of range, duplicated, or out of order.
    #[error("zk-X509 witness attribute openings are not canonical")]
    InvalidAttributeOpenings,
    /// A declared field extends beyond the available input.
    #[error("zk-X509 witness is truncated")]
    Truncated,
    /// Bytes remain after the sole canonical witness.
    #[error("zk-X509 witness has trailing bytes")]
    TrailingBytes,
    /// The encoded witness size overflows the platform representation.
    #[error("zk-X509 witness length overflows")]
    LengthOverflow,
    /// A bounded private-witness allocation could not be reserved.
    #[error("zk-X509 witness allocation failed")]
    AllocationFailed,
    /// A Norito field or cumulative decode allocation exceeds its active limit.
    #[error("zk-X509 witness exceeds its decode resource limit")]
    ResourceLimit,
    /// The complete frame exceeds the fixed maximum witness shape.
    #[error("zk-X509 witness exceeds its maximum frame size")]
    FrameTooLarge,
    /// A field is not in the sole accepted Norito flags-zero representation.
    #[error("zk-X509 witness field is not canonical Norito")]
    NonCanonicalField,
    /// Streaming serialization failed or changed its counted length.
    #[error("zk-X509 witness Norito serialization failed")]
    EncodingFailed,
}
impl ZkX509WitnessV1 {
    /// Number of exact DER certificates in the private chain.
    #[inline]
    pub fn certificate_chain_len_v1(&self) -> usize {
        self.certificate_chain_der.len()
    }
    /// Encode the sole Norito witness frame into one clearing allocation.
    pub fn encode_v1(&self) -> Result<Vec<u8>, ZkX509WitnessCodecErrorV1> {
        validate_witness_shape_v1(self)?;
        encode_witness_frame_v1(self)
    }
    /// Decode exactly one bounded Norito witness, retaining no borrowed input.
    pub(crate) fn decode_exact_v1(encoded: &[u8]) -> Result<Self, ZkX509WitnessCodecErrorV1> {
        if encoded.len() < Header::SIZE {
            return Err(ZkX509WitnessCodecErrorV1::Truncated);
        }
        let header = Header::read(encoded).map_err(|_| ZkX509WitnessCodecErrorV1::InvalidHeader)?;
        if header.flags != WITNESS_FLAGS_V1
            || header.compression != norito::core::Compression::None
            || header.schema != norito::schema::identity::frame_hash::<Self>()
        {
            return Err(ZkX509WitnessCodecErrorV1::InvalidHeader);
        }
        let payload_len = usize::try_from(header.length)
            .map_err(|_| ZkX509WitnessCodecErrorV1::LengthOverflow)?;
        let framed_len = WITNESS_FRAME_PREFIX_BYTES_V1
            .checked_add(payload_len)
            .ok_or(ZkX509WitnessCodecErrorV1::LengthOverflow)?;
        // Diagnose suffixes before the maximum so a maximum-size frame with
        // one extra byte still reports the same exact-consumption failure.
        if encoded.len() > framed_len {
            return Err(ZkX509WitnessCodecErrorV1::TrailingBytes);
        }
        if framed_len > MAX_WITNESS_FRAME_BYTES_V1 {
            return Err(ZkX509WitnessCodecErrorV1::FrameTooLarge);
        }
        if encoded.len() < framed_len {
            return Err(ZkX509WitnessCodecErrorV1::Truncated);
        }
        let view = norito::core::from_bytes_view(encoded)
            .map_err(|_| ZkX509WitnessCodecErrorV1::InvalidHeader)?;
        norito::core::with_decode_limits_scope(witness_decode_limits_v1(), || {
            // Preserve the relation's precise shape error without encoding it
            // in an allocated Norito message. Framing remains Norito-owned.
            let mut shape_error = None;
            view.decode_exact_with::<Self, Self, _>(|payload| {
                decode_witness_payload_v1(payload)
                    .map(|witness| (witness, payload.len()))
                    .map_err(|error| {
                        shape_error = Some(error);
                        norito::Error::NonCanonicalEncoding
                    })
            })
            .map_err(|error| shape_error.unwrap_or_else(|| map_norito_error_v1(error)))
        })
    }
    /// Construct malformed-shape frames using the actual serializer in tests.
    #[cfg(test)]
    pub(crate) fn encode_unchecked_for_test_v1(
        &self,
    ) -> Result<Vec<u8>, ZkX509WitnessCodecErrorV1> {
        encode_witness_frame_v1(self)
    }
}

impl<'a> DecodeFromSlice<'a> for ZkX509WitnessV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        norito::core::with_decode_limits(witness_decode_limits_v1(), || {
            if bytes.len() > MAX_WITNESS_PAYLOAD_BYTES_V1 {
                return Err(norito::Error::ArchiveLengthExceeded {
                    length: bytes.len() as u64,
                    limit: MAX_WITNESS_PAYLOAD_BYTES_V1 as u64,
                });
            }
            if norito::core::effective_decode_flags() != Some(WITNESS_FLAGS_V1) {
                return Err(norito::Error::NonCanonicalEncoding);
            }
            let witness = decode_witness_payload_v1(bytes)
                .map_err(|_| norito::Error::NonCanonicalEncoding)?;
            norito::core::note_payload_access(bytes, bytes.len());
            Ok((witness, bytes.len()))
        })
    }
}
impl<'a> norito::DeserializePayload<'a> for ZkX509WitnessV1 {
    fn deserialize(archived: &'a norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid archived zk-X509 witness")
    }
    fn try_deserialize(archived: &'a norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let payload = norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast())?;
        Self::decode_from_slice(payload).map(|(witness, _)| witness)
    }
}

fn witness_decode_limits_v1() -> norito::DecodeLimits {
    let bytes = ZK_X509_MAX_CHAIN_DEPTH_V1 * ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
        + ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1;
    // Sequence decoding charges one unit per element. The additional Vec
    // header/opening allocation charges below bring this total to real owned
    // element payloads, without charging borrowed field spans a second time.
    norito::DecodeLimits::new(
        ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1,
        MAX_WITNESS_PAYLOAD_BYTES_V1,
        bytes + ZK_X509_MAX_CHAIN_DEPTH_V1 + MAX_DISCLOSED_ATTRIBUTES_V1,
        bytes
            + ZK_X509_MAX_CHAIN_DEPTH_V1 * core::mem::size_of::<Vec<u8>>()
            + MAX_DISCLOSED_ATTRIBUTES_V1 * core::mem::size_of::<ZkX509AttributeOpeningV1>(),
        // The hand-owned parser has a fixed nonrecursive graph. This setting
        // does not claim dynamic nesting accounting for its borrowed spans.
        norito::core::MAX_VALUE_NESTING_DEPTH,
    )
}

fn encoded_witness_len_v1(witness: &ZkX509WitnessV1) -> Result<usize, ZkX509WitnessCodecErrorV1> {
    let _flags = norito::core::DecodeFlagsGuard::enter(WITNESS_FLAGS_V1);
    let length = norito::core::encoded_frame_len(witness)
        .map_err(|_| ZkX509WitnessCodecErrorV1::EncodingFailed)?;
    if length > MAX_WITNESS_FRAME_BYTES_V1 {
        return Err(ZkX509WitnessCodecErrorV1::FrameTooLarge);
    }
    Ok(length)
}

fn encode_witness_frame_v1(
    witness: &ZkX509WitnessV1,
) -> Result<Vec<u8>, ZkX509WitnessCodecErrorV1> {
    let length = encoded_witness_len_v1(witness)?;
    let mut writer = PrivateWitnessWriterV1::new(length)?;
    let _flags = norito::core::DecodeFlagsGuard::enter(WITNESS_FLAGS_V1);
    norito::core::write_frame_to_writer(witness, &mut writer)
        .map_err(|_| ZkX509WitnessCodecErrorV1::EncodingFailed)?;
    if writer.bytes.len() != length {
        return Err(ZkX509WitnessCodecErrorV1::EncodingFailed);
    }
    Ok(writer.bytes.into_vec())
}

struct PrivateWitnessWriterV1 {
    bytes: PrivateTableV1<u8>,
    maximum: usize,
}
impl PrivateWitnessWriterV1 {
    fn new(maximum: usize) -> Result<Self, ZkX509WitnessCodecErrorV1> {
        if maximum > MAX_WITNESS_FRAME_BYTES_V1 {
            return Err(ZkX509WitnessCodecErrorV1::FrameTooLarge);
        }
        let mut bytes = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
        bytes
            .try_reserve_exact(maximum)
            .map_err(|_| ZkX509WitnessCodecErrorV1::AllocationFailed)?;
        Ok(Self { bytes, maximum })
    }
}
impl std::io::Write for PrivateWitnessWriterV1 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::WriteZero)?;
        if end > self.maximum || end > self.bytes.capacity() {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn map_norito_error_v1(error: norito::Error) -> ZkX509WitnessCodecErrorV1 {
    match error {
        norito::Error::AllocationFailed { .. } => ZkX509WitnessCodecErrorV1::AllocationFailed,
        norito::Error::SequenceLengthExceeded { .. }
        | norito::Error::FieldLengthExceeded { .. }
        | norito::Error::TotalElementsExceeded { .. }
        | norito::Error::TotalAllocationExceeded { .. }
        | norito::Error::NestingDepthExceeded { .. }
        | norito::Error::ArchiveLengthExceeded { .. } => ZkX509WitnessCodecErrorV1::ResourceLimit,
        norito::Error::LengthMismatch => ZkX509WitnessCodecErrorV1::Truncated,
        _ => ZkX509WitnessCodecErrorV1::NonCanonicalField,
    }
}

fn decode_witness_payload_v1(payload: &[u8]) -> Result<ZkX509WitnessV1, ZkX509WitnessCodecErrorV1> {
    let mut reader = WitnessReaderV1::new(payload);
    // Ownership precedes every private copy, including partial nested records.
    let mut witness = ZkX509WitnessV1 {
        certificate_chain_der: Vec::new(),
        crl_der: Vec::new(),
        ca_membership_path: ZkX509CaMembershipPathV1 {
            index: 0,
            siblings: [[0; 32]; ZK_X509_CA_COMPACT_TREE_DEPTH_V1],
        },
        wallet_ownership_signature_rs: [0; ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1],
        attribute_openings: Vec::new(),
    };
    let mut chain = reader.field()?;
    let chain_depth = chain.sequence_count(
        ZK_X509_MIN_CHAIN_DEPTH_V1,
        ZK_X509_MAX_CHAIN_DEPTH_V1,
        ZkX509WitnessCodecErrorV1::InvalidChainDepth,
    )?;
    reserve_sequence_v1(&mut witness.certificate_chain_der, chain_depth)?;
    for _ in 0..chain_depth {
        let mut certificate = chain.field()?;
        let bytes =
            certificate.byte_sequence(ZkX509WitnessCodecErrorV1::InvalidCertificateLength)?;
        witness.certificate_chain_der.push(Vec::new());
        let owned = witness
            .certificate_chain_der
            .last_mut()
            .ok_or(ZkX509WitnessCodecErrorV1::InvalidChainDepth)?;
        // read_seq_len_slice already charged each byte before this reservation.
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkX509WitnessCodecErrorV1::AllocationFailed)?;
        owned.extend_from_slice(bytes);
    }
    chain.finish()?;
    let mut crl = reader.field()?;
    let bytes = crl.byte_sequence(ZkX509WitnessCodecErrorV1::InvalidCrlLength)?;
    witness
        .crl_der
        .try_reserve_exact(bytes.len())
        .map_err(|_| ZkX509WitnessCodecErrorV1::AllocationFailed)?;
    witness.crl_der.extend_from_slice(bytes);
    let mut path = reader.field()?;
    witness.ca_membership_path.index = path.scalar::<u16>()?;
    if usize::from(witness.ca_membership_path.index) >= ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 {
        return Err(ZkX509WitnessCodecErrorV1::InvalidCaPathIndex);
    }
    let mut siblings = path.field()?;
    for sibling in &mut witness.ca_membership_path.siblings {
        let mut digest = siblings.field()?;
        for byte in sibling {
            *byte = digest.scalar::<u8>()?;
        }
        digest.finish()?;
    }
    siblings.finish()?;
    path.finish()?;
    witness
        .wallet_ownership_signature_rs
        .copy_from_slice(reader.exact_field(ZK_X509_WALLET_SIGNATURE_RS_BYTES_V1)?);
    let mut openings = reader.field()?;
    let count = openings.sequence_count(
        0,
        MAX_DISCLOSED_ATTRIBUTES_V1,
        ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings,
    )?;
    reserve_sequence_v1(&mut witness.attribute_openings, count)?;
    for _ in 0..count {
        let mut opening = openings.field()?;
        witness.attribute_openings.push(ZkX509AttributeOpeningV1 {
            index: 0,
            salt: [0; ZK_X509_ATTRIBUTE_SALT_BYTES_V1],
        });
        let owned = witness
            .attribute_openings
            .last_mut()
            .ok_or(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings)?;
        owned.index = opening.scalar::<u8>()?;
        owned
            .salt
            .copy_from_slice(opening.exact_field(ZK_X509_ATTRIBUTE_SALT_BYTES_V1)?);
        opening.finish()?;
    }
    openings.finish()?;
    reader.finish()?;
    validate_witness_shape_v1(&witness)?;
    Ok(witness)
}

fn reserve_sequence_v1<T>(
    values: &mut Vec<T>,
    count: usize,
) -> Result<(), ZkX509WitnessCodecErrorV1> {
    let additional = count
        .checked_mul(core::mem::size_of::<T>().saturating_sub(1))
        .ok_or(ZkX509WitnessCodecErrorV1::LengthOverflow)?;
    norito::core::reserve_decode_allocation(additional).map_err(map_norito_error_v1)?;
    values
        .try_reserve_exact(count)
        .map_err(|_| ZkX509WitnessCodecErrorV1::AllocationFailed)
}

fn validate_witness_shape_v1(witness: &ZkX509WitnessV1) -> Result<(), ZkX509WitnessCodecErrorV1> {
    if !(ZK_X509_MIN_CHAIN_DEPTH_V1..=ZK_X509_MAX_CHAIN_DEPTH_V1)
        .contains(&witness.certificate_chain_der.len())
    {
        return Err(ZkX509WitnessCodecErrorV1::InvalidChainDepth);
    }
    if witness.certificate_chain_der.iter().any(|certificate| {
        certificate.is_empty()
            || certificate.len() > ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
    }) {
        return Err(ZkX509WitnessCodecErrorV1::InvalidCertificateLength);
    }
    if witness.crl_der.is_empty() || witness.crl_der.len() > ZK_X509_CRL_COMMITMENT_MAX_DER_BYTES_V1
    {
        return Err(ZkX509WitnessCodecErrorV1::InvalidCrlLength);
    }
    if usize::from(witness.ca_membership_path.index) >= ZK_X509_CA_COMPACT_TREE_CAPACITY_V1 {
        return Err(ZkX509WitnessCodecErrorV1::InvalidCaPathIndex);
    }
    if witness.attribute_openings.len() > MAX_DISCLOSED_ATTRIBUTES_V1
        || witness
            .attribute_openings
            .iter()
            .any(|opening| opening.index >= MAX_DISCLOSED_ATTRIBUTES_V1 as u8)
        || witness
            .attribute_openings
            .windows(2)
            .any(|pair| pair[0].index >= pair[1].index)
    {
        return Err(ZkX509WitnessCodecErrorV1::InvalidAttributeOpenings);
    }
    Ok(())
}
struct WitnessReaderV1<'a> {
    remaining: &'a [u8],
}
impl<'a> WitnessReaderV1<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ZkX509WitnessCodecErrorV1> {
        let (value, tail) = self
            .remaining
            .split_at_checked(length)
            .ok_or(ZkX509WitnessCodecErrorV1::Truncated)?;
        self.remaining = tail;
        Ok(value)
    }
    fn field(&mut self) -> Result<Self, ZkX509WitnessCodecErrorV1> {
        // These are borrowed spans. Only actual owned allocations are charged.
        let (length, prefix) =
            norito::core::inspect_len_from_slice(self.remaining).map_err(map_norito_error_v1)?;
        self.take(prefix)?;
        Ok(Self::new(self.take(length)?))
    }
    fn exact_field(&mut self, expected: usize) -> Result<&'a [u8], ZkX509WitnessCodecErrorV1> {
        let field = self.field()?;
        if field.remaining.len() != expected {
            return Err(ZkX509WitnessCodecErrorV1::NonCanonicalField);
        }
        Ok(field.remaining)
    }
    fn scalar<T: DecodeFromSlice<'a>>(&mut self) -> Result<T, ZkX509WitnessCodecErrorV1> {
        let field = self.field()?;
        let (value, used) = T::decode_from_slice(field.remaining).map_err(map_norito_error_v1)?;
        if used != field.remaining.len() {
            return Err(ZkX509WitnessCodecErrorV1::NonCanonicalField);
        }
        Ok(value)
    }
    fn sequence_count(
        &mut self,
        minimum: usize,
        maximum: usize,
        error: ZkX509WitnessCodecErrorV1,
    ) -> Result<usize, ZkX509WitnessCodecErrorV1> {
        let (raw, _) = u64::decode_from_slice(self.remaining).map_err(map_norito_error_v1)?;
        let count = usize::try_from(raw).map_err(|_| error)?;
        if !(minimum..=maximum).contains(&count) {
            return Err(error);
        }
        let (count, used) =
            norito::core::read_seq_len_slice(self.remaining).map_err(map_norito_error_v1)?;
        self.take(used)?;
        Ok(count)
    }
    fn byte_sequence(
        &mut self,
        error: ZkX509WitnessCodecErrorV1,
    ) -> Result<&'a [u8], ZkX509WitnessCodecErrorV1> {
        let length =
            self.sequence_count(1, ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1, error)?;
        let bytes = self.take(length)?;
        self.finish()?;
        Ok(bytes)
    }
    fn finish(&self) -> Result<(), ZkX509WitnessCodecErrorV1> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(ZkX509WitnessCodecErrorV1::TrailingBytes)
        }
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
