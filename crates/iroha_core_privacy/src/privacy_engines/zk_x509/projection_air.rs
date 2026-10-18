//! Numeric output-projection AIR for the closed zk-X509 profile.
//!
//! The projection chip does not trust a native hash result. It constructs the exact framed SHA-256
//! preimages for the scoped certificate-key commitment, deterministic certificate nullifier,
//! disclosed attributes, and wallet-ownership challenge. Fixed-size, zero-padded buffers and
//! private message lengths are sent to the SHA segment through byte channels. SHA digests return
//! through the same channel system and are constrained to the verifier's public statement where
//! applicable.
//!
//! Private serial and attribute lengths do not affect the trace topology or proof size. Prefix bits
//! select their canonical bytes, running counters bind the encoded `u64` field lengths, and a
//! transcript-challenged permutation binds sparse source tokens to each compact SHA message. A
//! separate four-lane copy product binds every repeated byte occurrence. Padding rows and unused
//! hash slots are algebraically zero.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::{
    PrivateTableV1, zeroize_field_rows_v1, zeroize_fields_v1, zeroize_words_v1,
};

#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::io_air::{
    ZkX509IoChannelDeclarationV1, ZkX509IoChannelWitnessV1, ZkX509IoEndpointV1,
    ZkX509IoSegmentRoleV1,
};
use super::profile::{
    ZK_X509_ATTRIBUTE_DOMAIN_V1, ZK_X509_ATTRIBUTE_SALT_BYTES_V1, ZK_X509_HASH_FRAME_DOMAIN_V1,
    ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1, ZK_X509_MAX_CHAIN_DEPTH_V1, ZK_X509_MAX_SERIAL_BYTES_V1,
    ZK_X509_NULLIFIER_DOMAIN_V1, ZK_X509_OWNERSHIP_DOMAIN_V1, ZK_X509_RELATION_VERSION_V1,
    ZK_X509_SCOPED_KEY_DOMAIN_V1, ZK_X509_SOURCE_PROFILE_V1, ZK_X509_SUITE_V1,
};
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_MODULUS_V1, GoldilocksFieldV1 as F, PolynomialAirFieldV1,
};
use iroha_data_model::privacy::{
    IrohaZkX509StarkP256StatementV1, PrivacyStatementV1, ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
/// Exact manifest descriptor for the projection chip.
#[cfg(test)]
pub const ZK_X509_PROJECTION_AIR_DESCRIPTOR_V1: &[u8] = b"zk-x509-projection-air-v1:trace=32768:base-width=17:aux-width=32:hash-slots=7:sha-buffer=2048:private-length-prefix:source-compaction-permutation-4lane:byte-copy-dual-products-4lane:governance-scoped-leaf-spki+stable-issuer-serial-nullifier+4-disclosures+ownership:fixed-three-spki-input-channels:optional-third-slot-canonical-zero:verifier-fixed-public-digests:zero-padding:first-release";
/// Fixed projection trace size.
pub const ZK_X509_PROJECTION_TRACE_SIZE_V1: usize = 1 << 15;
/// Fixed maximum SHA preimage buffer per projection hash.
pub const ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1: usize = 2_048;
/// Number of fixed hash slots: scoped key, nullifier, four attributes, ownership.
pub const ZK_X509_PROJECTION_HASH_SLOTS_V1: usize = 7;
/// Exact DER width of the sole admitted uncompressed P-256 SPKI.
pub const ZK_X509_PROJECTION_SPKI_DER_BYTES_V1: usize = 91;
/// Projection base-trace width.
pub const ZK_X509_PROJECTION_BASE_WIDTH_V1: usize = 17;
/// Projection challenge-dependent auxiliary width.
pub const ZK_X509_PROJECTION_COPY_LANES_V1: usize = 4;
pub const ZK_X509_PROJECTION_AUX_WIDTH_V1: usize = 8 * ZK_X509_PROJECTION_COPY_LANES_V1;
/// Verifier-preprocessed numeric fixed width used by the aggregate STARK.
pub const ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1: usize = 25;
/// Exact fixed-width opened-row residue vector used by the aggregate STARK.
pub const ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1: usize =
    243 + 14 * ZK_X509_PROJECTION_COPY_LANES_V1;
/// Maximum total algebraic degree, including verifier-fixed selectors.
pub const ZK_X509_PROJECTION_STARK_CONSTRAINT_DEGREE_V1: u8 = 4;
const VALUE: usize = 0;
const VALUE_BITS: usize = 1;
const USED: usize = 9;
const MESSAGE_BEFORE: usize = 10;
const MESSAGE_AFTER: usize = 11;
const DECLARED_LENGTH: usize = 12;
const LENGTH_ACC_BEFORE: usize = 13;
const LENGTH_ACC_AFTER: usize = 14;
const REGION_BEFORE: usize = 15;
const REGION_AFTER: usize = 16;
const COPY_LANES: usize = ZK_X509_PROJECTION_COPY_LANES_V1;
pub(super) const ZK_X509_PROJECTION_CHALLENGE_LABELS_V1: [[&[u8]; 7]; COPY_LANES] = [
    [
        b"zk-x509-projection-lane0-copy-beta-v1",
        b"zk-x509-projection-lane0-copy-gamma-v1",
        b"zk-x509-projection-lane0-compaction-active-v1",
        b"zk-x509-projection-lane0-compaction-invocation-v1",
        b"zk-x509-projection-lane0-compaction-position-v1",
        b"zk-x509-projection-lane0-compaction-value-v1",
        b"zk-x509-projection-lane0-compaction-gamma-v1",
    ],
    [
        b"zk-x509-projection-lane1-copy-beta-v1",
        b"zk-x509-projection-lane1-copy-gamma-v1",
        b"zk-x509-projection-lane1-compaction-active-v1",
        b"zk-x509-projection-lane1-compaction-invocation-v1",
        b"zk-x509-projection-lane1-compaction-position-v1",
        b"zk-x509-projection-lane1-compaction-value-v1",
        b"zk-x509-projection-lane1-compaction-gamma-v1",
    ],
    [
        b"zk-x509-projection-lane2-copy-beta-v1",
        b"zk-x509-projection-lane2-copy-gamma-v1",
        b"zk-x509-projection-lane2-compaction-active-v1",
        b"zk-x509-projection-lane2-compaction-invocation-v1",
        b"zk-x509-projection-lane2-compaction-position-v1",
        b"zk-x509-projection-lane2-compaction-value-v1",
        b"zk-x509-projection-lane2-compaction-gamma-v1",
    ],
    [
        b"zk-x509-projection-lane3-copy-beta-v1",
        b"zk-x509-projection-lane3-copy-gamma-v1",
        b"zk-x509-projection-lane3-compaction-active-v1",
        b"zk-x509-projection-lane3-compaction-invocation-v1",
        b"zk-x509-projection-lane3-compaction-position-v1",
        b"zk-x509-projection-lane3-compaction-value-v1",
        b"zk-x509-projection-lane3-compaction-gamma-v1",
    ],
];
const AUX_COPY_NUMERATOR_BEFORE: usize = 0;
const AUX_COPY_NUMERATOR_AFTER: usize = AUX_COPY_NUMERATOR_BEFORE + COPY_LANES;
const AUX_COPY_DENOMINATOR_BEFORE: usize = AUX_COPY_NUMERATOR_AFTER + COPY_LANES;
const AUX_COPY_DENOMINATOR_AFTER: usize = AUX_COPY_DENOMINATOR_BEFORE + COPY_LANES;
const AUX_SOURCE_BEFORE: usize = AUX_COPY_DENOMINATOR_AFTER + COPY_LANES;
const AUX_SOURCE_AFTER: usize = AUX_SOURCE_BEFORE + COPY_LANES;
const AUX_OUTPUT_BEFORE: usize = AUX_SOURCE_AFTER + COPY_LANES;
const AUX_OUTPUT_AFTER: usize = AUX_OUTPUT_BEFORE + COPY_LANES;
const _: () = assert!(ZK_X509_PROJECTION_AUX_WIDTH_V1 == 32);
const _: () = assert!(ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1 == 299);
const _: () = assert!(AUX_OUTPUT_AFTER + COPY_LANES == ZK_X509_PROJECTION_AUX_WIDTH_V1);
const FIX_INPUT_SPKI: usize = 0;
const FIX_INPUT_LENGTH: usize = 1;
const FIX_INPUT_BYTE: usize = 2;
const FIX_SOURCE: usize = 3;
const FIX_MESSAGE_LENGTH: usize = 4;
const FIX_OUTPUT: usize = 5;
const FIX_DIGEST: usize = 6;
const FIX_PADDING: usize = 7;
const FIX_ACTIVE: usize = 8;
const FIX_FIRST: usize = 9;
const FIX_LAST: usize = 10;
const FIX_SOURCE_CONSTANT: usize = 11;
const FIX_SOURCE_COPY: usize = 12;
const FIX_SOURCE_LENGTH: usize = 13;
const FIX_SOURCE_VARIABLE: usize = 14;
const FIX_SOURCE_UNUSED: usize = 15;
const FIX_TOKEN_FIRST: usize = 16;
const FIX_TOKEN_LAST: usize = 17;
const FIX_EXPECTED_BYTE: usize = 18;
const FIX_INVOCATION: usize = 19;
const FIX_COPY_IDENTITY: usize = 20;
const FIX_COPY_SIGMA: usize = 21;
const FIX_FIRST_ROW: usize = 22;
const FIX_LAST_ROW: usize = 23;
const FIX_USED_MONOTONE_TRANSITION: usize = 24;
/// Wallet-local projection witness extracted by the constrained DER segment.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509ProjectionWitnessV1 {
    /// Exact leaf-to-root SPKI DER values.
    pub(crate) chain_spki_der: Vec<Vec<u8>>,
    /// Exact canonical unsigned leaf serial.
    pub(crate) leaf_serial: Vec<u8>,
    /// Exact DER-content bytes for disclosures in statement order.
    pub(crate) disclosed_attribute_values: Vec<Vec<u8>>,
    /// Private salts for disclosures in statement order.
    pub(crate) attribute_salts: Vec<[u8; ZK_X509_ATTRIBUTE_SALT_BYTES_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509ProjectionWitnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509ProjectionWitnessV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ProjectionWitnessV1 {
    fn drop(&mut self) {
        for value in self
            .chain_spki_der
            .iter_mut()
            .chain(&mut self.disclosed_attribute_values)
        {
            zeroize_words_v1(value);
        }
        zeroize_words_v1(&mut self.leaf_serial);
        zeroize_words_v1(&mut self.attribute_salts);
    }
}
/// Semantic projection hash slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZkX509ProjectionHashV1 {
    /// Governance-scoped leaf subject-key commitment.
    ScopedSubjectKey,
    /// Stable issuer/serial certificate nullifier.
    CertificateNullifier,
    /// One selectively disclosed attribute.
    Attribute(u8),
    /// Public statement and wallet-ownership challenge binding.
    OwnershipChallenge,
}
impl ZkX509ProjectionHashV1 {
    const fn slot(self) -> usize {
        match self {
            Self::ScopedSubjectKey => 0,
            Self::CertificateNullifier => 1,
            Self::Attribute(index) => 2 + index as usize,
            Self::OwnershipChallenge => 6,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PrivateInputV1 {
    Serial,
    Attribute(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CopyKeyV1 {
    Spki { certificate: u8, offset: u16 },
    SerialLength(u8),
    Serial(u8),
    AttributeLength { disclosure: u8, byte: u8 },
    AttributeValue { disclosure: u8, offset: u16 },
    AttributeSalt { disclosure: u8, offset: u8 },
    SourceConstant { invocation: u8, offset: u16 },
    SourceUnused { invocation: u8, offset: u16 },
    MessageLength { invocation: u8, byte: u8 },
    Output { invocation: u8, offset: u16 },
    Digest { invocation: u8, offset: u8 },
    InactiveInput { family: u8, offset: u16 },
    Padding(u16),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceTokenV1 {
    Constant(u8),
    Spki { certificate: u8, offset: u16 },
    SerialLength(u8),
    Serial(u8),
    AttributeLength { disclosure: u8, byte: u8 },
    AttributeValue { disclosure: u8, offset: u16 },
    AttributeSalt { disclosure: u8, offset: u8 },
    Unused,
}
/// One verifier-fixed projection row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkX509ProjectionFixedRowV1 {
    /// Fixed-width private SPKI input from the DER segment.
    InputSpki {
        /// Certificate index in leaf-to-root order.
        certificate: u8,
        /// Byte offset.
        offset: u16,
        /// Whether the verifier-fixed profile activates this certificate slot.
        active: bool,
    },
    /// One byte of a private variable-length input's `u64` length.
    InputLength {
        /// Input family.
        input: u8,
        /// Length-byte offset.
        byte: u8,
        /// Whether this disclosure/input slot is active.
        active: bool,
        /// First length byte.
        first: bool,
        /// Last length byte.
        last: bool,
    },
    /// One padded private serial or attribute byte.
    InputByte {
        /// Input family.
        input: u8,
        /// Padded byte offset.
        offset: u16,
        /// Whether this disclosure/input slot is active.
        active: bool,
        /// First padded byte.
        first: bool,
        /// Last padded byte.
        last: bool,
    },
    /// One sparse source token for a framed SHA preimage.
    Source {
        /// Hash slot.
        invocation: u8,
        /// Sparse source-token offset.
        offset: u16,
        /// Whether the hash slot is active.
        active: bool,
        /// First source token.
        first: bool,
        /// Last source token.
        last: bool,
        /// Token semantics.
        token: ZkX509ProjectionSourceTokenV1,
    },
    /// One byte of the private compacted SHA message length.
    MessageLength {
        /// Hash slot.
        invocation: u8,
        /// Big-endian `u64` byte offset.
        byte: u8,
        /// Whether the hash slot is active.
        active: bool,
        /// First length byte.
        first: bool,
        /// Last length byte.
        last: bool,
    },
    /// One byte of the fixed SHA input buffer.
    Output {
        /// Hash slot.
        invocation: u8,
        /// Buffer byte offset.
        offset: u16,
        /// Whether the hash slot is active.
        active: bool,
        /// First output byte.
        first: bool,
        /// Last output byte.
        last: bool,
    },
    /// One SHA digest byte returned to projection.
    Digest {
        /// Hash slot.
        invocation: u8,
        /// Digest-byte offset.
        offset: u8,
        /// Verifier-fixed expected byte.
        expected: u8,
        /// Whether the hash slot is active.
        active: bool,
    },
    /// Algebraically zero trace padding.
    Padding,
}
/// Public spelling of source-token semantics used by fixed preprocessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkX509ProjectionSourceTokenV1 {
    /// Verifier-known framing or statement byte.
    Constant(u8),
    /// Private fixed-width SPKI byte.
    Spki { certificate: u8, offset: u16 },
    /// Big-endian length byte for the private leaf serial.
    SerialLength(u8),
    /// Private padded serial byte.
    Serial(u8),
    /// Big-endian length byte for one private attribute.
    AttributeLength { disclosure: u8, byte: u8 },
    /// Private padded attribute byte.
    AttributeValue { disclosure: u8, offset: u16 },
    /// Private fixed-width attribute salt byte.
    AttributeSalt { disclosure: u8, offset: u8 },
    /// Inactive fixed-buffer token.
    Unused,
}
impl From<SourceTokenV1> for ZkX509ProjectionSourceTokenV1 {
    fn from(value: SourceTokenV1) -> Self {
        match value {
            SourceTokenV1::Constant(byte) => Self::Constant(byte),
            SourceTokenV1::Spki {
                certificate,
                offset,
            } => Self::Spki {
                certificate,
                offset,
            },
            SourceTokenV1::SerialLength(byte) => Self::SerialLength(byte),
            SourceTokenV1::Serial(offset) => Self::Serial(offset),
            SourceTokenV1::AttributeLength { disclosure, byte } => {
                Self::AttributeLength { disclosure, byte }
            }
            SourceTokenV1::AttributeValue { disclosure, offset } => {
                Self::AttributeValue { disclosure, offset }
            }
            SourceTokenV1::AttributeSalt { disclosure, offset } => {
                Self::AttributeSalt { disclosure, offset }
            }
            SourceTokenV1::Unused => Self::Unused,
        }
    }
}
/// Verifier-built fixed projection trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionFixedTraceV1 {
    /// Exact semantic row schedule.
    pub(crate) rows: Vec<ZkX509ProjectionFixedRowV1>,
    /// Fixed copy identity labels.
    pub(crate) copy_identity: Vec<F>,
    /// Fixed copy-cycle permutation labels.
    pub(crate) copy_sigma: Vec<F>,
}
/// Witness-bearing projection base trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionBaseTraceV1 {
    /// Exact base rows.
    pub(crate) rows: Vec<[F; ZK_X509_PROJECTION_BASE_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ProjectionBaseTraceV1 {
    fn drop(&mut self) {
        zeroize_field_rows_v1(&mut self.rows);
    }
}
/// Challenge-dependent copy and compaction products.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionAuxTraceV1 {
    /// Exact auxiliary rows.
    pub(crate) rows: Vec<[F; ZK_X509_PROJECTION_AUX_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ProjectionAuxTraceV1 {
    fn drop(&mut self) {
        zeroize_field_rows_v1(&mut self.rows);
    }
}
/// One copy-product challenge lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionCopyChallengesV1 {
    /// Identity/permutation label coefficient.
    pub(crate) beta: F,
    /// Tuple offset.
    pub(crate) gamma: F,
}
/// One source-compaction challenge lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionCompactionChallengesV1 {
    /// Active-bit coefficient.
    pub(crate) active: F,
    /// Hash-slot coefficient.
    pub(crate) invocation: F,
    /// Logical-position coefficient.
    pub(crate) position: F,
    /// Byte-value coefficient.
    pub(crate) value: F,
    /// Tuple offset.
    pub(crate) gamma: F,
}
/// Four independent copy and compaction challenge lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionChallengesV1 {
    /// Copy-permutation lanes.
    pub(crate) copy: [ZkX509ProjectionCopyChallengesV1; COPY_LANES],
    /// Source/output compaction lanes.
    pub(crate) compaction: [ZkX509ProjectionCompactionChallengesV1; COPY_LANES],
}
/// One prover-internal I/O channel emitted by projection.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509ProjectionIoChannelV1 {
    /// Semantic producer endpoint.
    pub(crate) producer: ZkX509IoEndpointV1,
    /// Canonically sorted consumer endpoints.
    pub(crate) consumers: Vec<ZkX509IoEndpointV1>,
    /// Private or public channel value.
    pub(crate) value: Vec<u8>,
    /// Verifier-fixed public value, when a public-input consumer exists.
    pub(crate) public_value: Option<Vec<u8>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ProjectionIoChannelV1 {
    fn zeroize_private_v1(&mut self) {
        zeroize_words_v1(&mut self.value);
        self.value.clear();
        if let Some(value) = &mut self.public_value {
            zeroize_words_v1(value);
            value.clear();
        }
    }

    /// Convert plans to the shared sequential channel-witness format.
    ///
    /// # Errors
    ///
    /// Returns a resource error if a channel identifier or byte length does
    /// not fit the fixed wire types.
    pub(crate) fn into_witness(
        mut self,
        channel: u32,
    ) -> Result<ZkX509IoChannelWitnessV1, ZkX509ProjectionAirErrorV1> {
        let byte_len =
            u32::try_from(self.value.len()).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        // Establish the returned clearing owner before any consumer-copy
        // allocation can fail. The source relinquishes only transferred cells.
        let mut witness = ZkX509IoChannelWitnessV1 {
            declaration: ZkX509IoChannelDeclarationV1 {
                channel,
                producer: self.producer,
                consumers: core::mem::take(&mut self.consumers),
                byte_len,
                public_value: self.public_value.take(),
            },
            producer_value: core::mem::take(&mut self.value),
            consumer_values: Vec::new(),
        };
        witness
            .consumer_values
            .try_reserve_exact(witness.declaration.consumers.len())
            .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        for _ in &witness.declaration.consumers {
            witness.consumer_values.push(witness.producer_value.clone());
        }
        Ok(witness)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ProjectionIoChannelV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Complete projection witness material.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509ProjectionTraceV1 {
    /// Verifier-derived fixed trace.
    pub(crate) fixed: ZkX509ProjectionFixedTraceV1,
    /// Witness-bearing base trace.
    pub(crate) base: ZkX509ProjectionBaseTraceV1,
    /// Prover-internal cross-segment channel values.
    pub(crate) io_channels: Vec<ZkX509ProjectionIoChannelV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509ProjectionTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509ProjectionTraceV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ProjectionTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ProjectionTraceV1 {
    /// Overwrite every witness-bearing projection row and private channel.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn zeroize_private_v1(&mut self) {
        for row in &mut self.base.rows {
            zeroize_fields_v1(row);
        }
        self.base.rows.clear();
        for channel in &mut self.io_channels {
            channel.zeroize_private_v1();
        }
        self.io_channels.clear();
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.base.rows.is_empty() && self.io_channels.is_empty()
    }
}
/// Projection trace construction or algebraic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509ProjectionAirErrorV1 {
    /// Public statement or private witness shape is outside the closed profile.
    #[error("zk-X509 projection shape is invalid")]
    Shape,
    /// A public projection does not equal the constrained private relation.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 projection output mismatch")]
    ProjectionMismatch,
    /// Canonical statement or hash framing failed.
    #[error("zk-X509 projection encoding failed")]
    Encoding,
    /// Fixed topology, padding, or copy cycles are invalid.
    #[error("zk-X509 projection topology is invalid")]
    Topology,
    /// A base or auxiliary field is not canonical Goldilocks.
    #[error("zk-X509 projection field encoding is non-canonical")]
    NonCanonicalField,
    /// Fiat-Shamir challenges are invalid or repeated.
    #[error("zk-X509 projection challenge set is invalid")]
    Challenge,
    /// One or more algebraic constraint residues are non-zero.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 projection algebraic constraint failed")]
    Constraint,
    /// Fixed resource arithmetic or allocation failed.
    #[error("zk-X509 projection resource bound is exceeded")]
    Resource,
}
#[derive(Clone)]
enum FrameFieldV1 {
    Fixed(Vec<u8>),
    Spki(u8),
    Serial,
    AttributeValue(u8),
    AttributeSalt(u8),
}
#[derive(Clone)]
struct InvocationSpecV1 {
    kind: ZkX509ProjectionHashV1,
    active: bool,
    tokens: Vec<SourceTokenV1>,
    expected_digest: [u8; 32],
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    public_digest: bool,
}
#[derive(Clone)]
struct FixedRowSpecV1 {
    row: ZkX509ProjectionFixedRowV1,
    key: CopyKeyV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn endpoint(role: ZkX509IoSegmentRoleV1, instance: u16) -> ZkX509IoEndpointV1 {
    ZkX509IoEndpointV1 { role, instance }
}
fn checked_u16(value: usize) -> Result<u16, ZkX509ProjectionAirErrorV1> {
    u16::try_from(value).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)
}
fn input_tag(input: PrivateInputV1) -> u8 {
    match input {
        PrivateInputV1::Serial => 3,
        PrivateInputV1::Attribute(index) => 4 + index,
    }
}
fn append_fixed(tokens: &mut Vec<SourceTokenV1>, bytes: &[u8]) {
    tokens.extend(bytes.iter().copied().map(SourceTokenV1::Constant));
}
fn append_field_length(
    tokens: &mut Vec<SourceTokenV1>,
    field: &FrameFieldV1,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    match field {
        FrameFieldV1::Serial => {
            tokens.extend((0_u8..8).map(SourceTokenV1::SerialLength));
        }
        FrameFieldV1::AttributeValue(disclosure) => {
            tokens.extend((0_u8..8).map(|byte| SourceTokenV1::AttributeLength {
                disclosure: *disclosure,
                byte,
            }));
        }
        FrameFieldV1::Fixed(bytes) => append_fixed(
            tokens,
            &u64::try_from(bytes.len())
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes(),
        ),
        FrameFieldV1::Spki(_) => append_fixed(
            tokens,
            &u64::try_from(ZK_X509_PROJECTION_SPKI_DER_BYTES_V1)
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes(),
        ),
        FrameFieldV1::AttributeSalt(_) => append_fixed(
            tokens,
            &u64::try_from(ZK_X509_ATTRIBUTE_SALT_BYTES_V1)
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes(),
        ),
    }
    Ok(())
}
fn append_field_bytes(
    tokens: &mut Vec<SourceTokenV1>,
    field: FrameFieldV1,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    match field {
        FrameFieldV1::Fixed(bytes) => append_fixed(tokens, &bytes),
        FrameFieldV1::Spki(certificate) => {
            for offset in 0..ZK_X509_PROJECTION_SPKI_DER_BYTES_V1 {
                tokens.push(SourceTokenV1::Spki {
                    certificate,
                    offset: checked_u16(offset)?,
                });
            }
        }
        FrameFieldV1::Serial => {
            for offset in 0..ZK_X509_MAX_SERIAL_BYTES_V1 {
                tokens.push(SourceTokenV1::Serial(
                    u8::try_from(offset).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?,
                ));
            }
        }
        FrameFieldV1::AttributeValue(disclosure) => {
            for offset in 0..ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1 {
                tokens.push(SourceTokenV1::AttributeValue {
                    disclosure,
                    offset: checked_u16(offset)?,
                });
            }
        }
        FrameFieldV1::AttributeSalt(disclosure) => {
            for offset in 0..ZK_X509_ATTRIBUTE_SALT_BYTES_V1 {
                tokens.push(SourceTokenV1::AttributeSalt {
                    disclosure,
                    offset: u8::try_from(offset)
                        .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?,
                });
            }
        }
    }
    Ok(())
}
fn frame_tokens_v1(
    domain: &[u8],
    fields: Vec<FrameFieldV1>,
) -> Result<Vec<SourceTokenV1>, ZkX509ProjectionAirErrorV1> {
    let domain_len =
        u16::try_from(domain.len()).map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?;
    let field_count =
        u16::try_from(fields.len()).map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?;
    let mut tokens = Vec::new();
    append_fixed(&mut tokens, ZK_X509_HASH_FRAME_DOMAIN_V1);
    append_fixed(&mut tokens, &domain_len.to_be_bytes());
    append_fixed(&mut tokens, domain);
    append_fixed(&mut tokens, &field_count.to_be_bytes());
    for field in fields {
        append_field_length(&mut tokens, &field)?;
        append_field_bytes(&mut tokens, field)?;
    }
    if tokens.len() > ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1 {
        return Err(ZkX509ProjectionAirErrorV1::Resource);
    }
    Ok(tokens)
}
fn hash_public_frame_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], ZkX509ProjectionAirErrorV1> {
    let domain_len =
        u16::try_from(domain.len()).map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?;
    let field_count =
        u16::try_from(fields.len()).map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?;
    let mut hash = Sha256::new();
    hash.update(ZK_X509_HASH_FRAME_DOMAIN_V1);
    hash.update(domain_len.to_be_bytes());
    hash.update(domain);
    hash.update(field_count.to_be_bytes());
    for field in fields {
        hash.update(
            u64::try_from(field.len())
                .map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?
                .to_be_bytes(),
        );
        hash.update(field);
    }
    Ok(hash.finalize().into())
}
fn fixed_field(bytes: &[u8]) -> FrameFieldV1 {
    FrameFieldV1::Fixed(bytes.to_vec())
}
fn compile_invocations_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<Vec<InvocationSpecV1>, ZkX509ProjectionAirErrorV1> {
    let relation_version = ZK_X509_RELATION_VERSION_V1.to_be_bytes();
    let mut scoped_fields = vec![
        fixed_field(ZK_X509_SUITE_V1),
        fixed_field(ZK_X509_SOURCE_PROFILE_V1),
        fixed_field(&relation_version),
        fixed_field(statement.trust_anchor_id.as_bytes()),
        fixed_field(statement.certificate_policy_id.as_bytes()),
        fixed_field(statement.trust_anchor_record_digest.as_bytes()),
        fixed_field(statement.certificate_policy_record_digest.as_bytes()),
    ];
    scoped_fields.push(FrameFieldV1::Spki(0));
    let scoped = InvocationSpecV1 {
        kind: ZkX509ProjectionHashV1::ScopedSubjectKey,
        active: true,
        tokens: frame_tokens_v1(ZK_X509_SCOPED_KEY_DOMAIN_V1, scoped_fields)?,
        expected_digest: *statement.subject_public_key_digest.as_bytes(),
        #[cfg(any(test, feature = "privacy-release-evidence"))]
        public_digest: true,
    };
    let nullifier = InvocationSpecV1 {
        kind: ZkX509ProjectionHashV1::CertificateNullifier,
        active: true,
        tokens: frame_tokens_v1(
            ZK_X509_NULLIFIER_DOMAIN_V1,
            vec![
                fixed_field(ZK_X509_SUITE_V1),
                fixed_field(statement.trust_anchor_id.as_bytes()),
                fixed_field(statement.certificate_policy_id.as_bytes()),
                FrameFieldV1::Spki(1),
                FrameFieldV1::Serial,
            ],
        )?,
        expected_digest: *statement.certificate_nullifier.as_bytes(),
        #[cfg(any(test, feature = "privacy-release-evidence"))]
        public_digest: true,
    };
    let mut invocations = Vec::with_capacity(ZK_X509_PROJECTION_HASH_SLOTS_V1);
    invocations.push(scoped);
    invocations.push(nullifier);
    for disclosure in 0..ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
        let disclosure_u8 =
            u8::try_from(disclosure).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        if let Some(disclosed) = statement.disclosed_attributes.get(disclosure) {
            let index = [disclosed.index];
            invocations.push(InvocationSpecV1 {
                kind: ZkX509ProjectionHashV1::Attribute(disclosure_u8),
                active: true,
                tokens: frame_tokens_v1(
                    ZK_X509_ATTRIBUTE_DOMAIN_V1,
                    vec![
                        fixed_field(ZK_X509_SUITE_V1),
                        fixed_field(statement.trust_anchor_id.as_bytes()),
                        fixed_field(statement.certificate_policy_id.as_bytes()),
                        fixed_field(&index),
                        FrameFieldV1::AttributeValue(disclosure_u8),
                        FrameFieldV1::AttributeSalt(disclosure_u8),
                    ],
                )?,
                expected_digest: *disclosed.attribute_digest.as_bytes(),
                #[cfg(any(test, feature = "privacy-release-evidence"))]
                public_digest: true,
            });
        } else {
            invocations.push(InvocationSpecV1 {
                kind: ZkX509ProjectionHashV1::Attribute(disclosure_u8),
                active: false,
                tokens: Vec::new(),
                expected_digest: [0; 32],
                #[cfg(any(test, feature = "privacy-release-evidence"))]
                public_digest: false,
            });
        }
    }
    let statement_digest = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone())
        .digest()
        .map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?;
    let account = norito::to_bytes(&statement.wallet_account)
        .map_err(|_| ZkX509ProjectionAirErrorV1::Encoding)?;
    let ownership_fields = [
        ZK_X509_SUITE_V1,
        ZK_X509_SOURCE_PROFILE_V1,
        relation_version.as_slice(),
        statement_digest.as_bytes().as_slice(),
        account.as_slice(),
        statement.wallet_challenge.as_bytes().as_slice(),
        statement
            .context
            .transaction_intent_digest
            .as_bytes()
            .as_slice(),
    ];
    let ownership_digest = hash_public_frame_v1(ZK_X509_OWNERSHIP_DOMAIN_V1, &ownership_fields)?;
    invocations.push(InvocationSpecV1 {
        kind: ZkX509ProjectionHashV1::OwnershipChallenge,
        active: true,
        tokens: frame_tokens_v1(
            ZK_X509_OWNERSHIP_DOMAIN_V1,
            vec![
                fixed_field(ZK_X509_SUITE_V1),
                fixed_field(ZK_X509_SOURCE_PROFILE_V1),
                fixed_field(&relation_version),
                fixed_field(statement_digest.as_bytes()),
                FrameFieldV1::Fixed(account),
                fixed_field(statement.wallet_challenge.as_bytes()),
                fixed_field(statement.context.transaction_intent_digest.as_bytes()),
            ],
        )?,
        expected_digest: ownership_digest,
        #[cfg(any(test, feature = "privacy-release-evidence"))]
        public_digest: false,
    });
    if invocations.len() != ZK_X509_PROJECTION_HASH_SLOTS_V1
        || invocations
            .iter()
            .enumerate()
            .any(|(slot, invocation)| invocation.kind.slot() != slot)
    {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    Ok(invocations)
}
fn token_key_v1(invocation: u8, offset: u16, token: SourceTokenV1) -> CopyKeyV1 {
    match token {
        SourceTokenV1::Constant(_) => CopyKeyV1::SourceConstant { invocation, offset },
        SourceTokenV1::Spki {
            certificate,
            offset,
        } => CopyKeyV1::Spki {
            certificate,
            offset,
        },
        SourceTokenV1::SerialLength(byte) => CopyKeyV1::SerialLength(byte),
        SourceTokenV1::Serial(offset) => CopyKeyV1::Serial(offset),
        SourceTokenV1::AttributeLength { disclosure, byte } => {
            CopyKeyV1::AttributeLength { disclosure, byte }
        }
        SourceTokenV1::AttributeValue { disclosure, offset } => {
            CopyKeyV1::AttributeValue { disclosure, offset }
        }
        SourceTokenV1::AttributeSalt { disclosure, offset } => {
            CopyKeyV1::AttributeSalt { disclosure, offset }
        }
        SourceTokenV1::Unused => CopyKeyV1::SourceUnused { invocation, offset },
    }
}
fn push_input_fixed_rows_v1(
    specs: &mut Vec<FixedRowSpecV1>,
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    for certificate in 0..ZK_X509_MAX_CHAIN_DEPTH_V1 {
        let certificate_u8 =
            u8::try_from(certificate).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        for offset in 0..ZK_X509_PROJECTION_SPKI_DER_BYTES_V1 {
            let offset_u16 = checked_u16(offset)?;
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::InputSpki {
                    certificate: certificate_u8,
                    offset: offset_u16,
                    active: true,
                },
                key: CopyKeyV1::Spki {
                    certificate: certificate_u8,
                    offset: offset_u16,
                },
            });
        }
    }
    let serial = PrivateInputV1::Serial;
    for byte in 0_u8..8 {
        specs.push(FixedRowSpecV1 {
            row: ZkX509ProjectionFixedRowV1::InputLength {
                input: input_tag(serial),
                byte,
                active: true,
                first: byte == 0,
                last: byte == 7,
            },
            key: CopyKeyV1::SerialLength(byte),
        });
    }
    for offset in 0..ZK_X509_MAX_SERIAL_BYTES_V1 {
        let offset_u8 = u8::try_from(offset).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        specs.push(FixedRowSpecV1 {
            row: ZkX509ProjectionFixedRowV1::InputByte {
                input: input_tag(serial),
                offset: u16::from(offset_u8),
                active: true,
                first: offset == 0,
                last: offset + 1 == ZK_X509_MAX_SERIAL_BYTES_V1,
            },
            key: CopyKeyV1::Serial(offset_u8),
        });
    }
    for disclosure in 0..ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 {
        let disclosure_u8 =
            u8::try_from(disclosure).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        let input = PrivateInputV1::Attribute(disclosure_u8);
        let active = disclosure < statement.disclosed_attributes.len();
        for byte in 0_u8..8 {
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::InputLength {
                    input: input_tag(input),
                    byte,
                    active,
                    first: byte == 0,
                    last: byte == 7,
                },
                key: if active {
                    CopyKeyV1::AttributeLength {
                        disclosure: disclosure_u8,
                        byte,
                    }
                } else {
                    CopyKeyV1::InactiveInput {
                        family: input_tag(input),
                        offset: u16::from(byte),
                    }
                },
            });
        }
        for offset in 0..ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1 {
            let offset_u16 = checked_u16(offset)?;
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::InputByte {
                    input: input_tag(input),
                    offset: offset_u16,
                    active,
                    first: offset == 0,
                    last: offset + 1 == ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1,
                },
                key: if active {
                    CopyKeyV1::AttributeValue {
                        disclosure: disclosure_u8,
                        offset: offset_u16,
                    }
                } else {
                    CopyKeyV1::InactiveInput {
                        family: input_tag(input),
                        offset: offset_u16.saturating_add(8),
                    }
                },
            });
        }
    }
    Ok(())
}
fn fixed_specs_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(Vec<FixedRowSpecV1>, Vec<InvocationSpecV1>), ZkX509ProjectionAirErrorV1> {
    validate_public_shape_v1(statement)?;
    let invocations = compile_invocations_v1(statement)?;
    let mut specs = Vec::new();
    specs
        .try_reserve_exact(ZK_X509_PROJECTION_TRACE_SIZE_V1)
        .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
    push_input_fixed_rows_v1(&mut specs, statement)?;
    for (invocation_index, invocation) in invocations.iter().enumerate() {
        let invocation_u8 =
            u8::try_from(invocation_index).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
        for offset in 0..ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1 {
            let offset_u16 = checked_u16(offset)?;
            let token = invocation
                .tokens
                .get(offset)
                .copied()
                .unwrap_or(SourceTokenV1::Unused);
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::Source {
                    invocation: invocation_u8,
                    offset: offset_u16,
                    active: invocation.active,
                    first: offset == 0,
                    last: offset + 1 == ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1,
                    token: token.into(),
                },
                key: token_key_v1(invocation_u8, offset_u16, token),
            });
        }
        for byte in 0_u8..8 {
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::MessageLength {
                    invocation: invocation_u8,
                    byte,
                    active: invocation.active,
                    first: byte == 0,
                    last: byte == 7,
                },
                key: CopyKeyV1::MessageLength {
                    invocation: invocation_u8,
                    byte,
                },
            });
        }
        for offset in 0..ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1 {
            let offset_u16 = checked_u16(offset)?;
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::Output {
                    invocation: invocation_u8,
                    offset: offset_u16,
                    active: invocation.active,
                    first: offset == 0,
                    last: offset + 1 == ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1,
                },
                key: CopyKeyV1::Output {
                    invocation: invocation_u8,
                    offset: offset_u16,
                },
            });
        }
        for offset in 0_u8..32 {
            specs.push(FixedRowSpecV1 {
                row: ZkX509ProjectionFixedRowV1::Digest {
                    invocation: invocation_u8,
                    offset,
                    expected: invocation.expected_digest[usize::from(offset)],
                    active: invocation.active,
                },
                key: CopyKeyV1::Digest {
                    invocation: invocation_u8,
                    offset,
                },
            });
        }
    }
    if specs.len() > ZK_X509_PROJECTION_TRACE_SIZE_V1 {
        return Err(ZkX509ProjectionAirErrorV1::Resource);
    }
    let padding = ZK_X509_PROJECTION_TRACE_SIZE_V1 - specs.len();
    for offset in 0..padding {
        specs.push(FixedRowSpecV1 {
            row: ZkX509ProjectionFixedRowV1::Padding,
            key: CopyKeyV1::Padding(checked_u16(offset)?),
        });
    }
    Ok((specs, invocations))
}
fn compile_fixed_trace_v1(
    specs: &[FixedRowSpecV1],
) -> Result<ZkX509ProjectionFixedTraceV1, ZkX509ProjectionAirErrorV1> {
    if specs.len() != ZK_X509_PROJECTION_TRACE_SIZE_V1 {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    let mut groups: BTreeMap<CopyKeyV1, Vec<usize>> = BTreeMap::new();
    for (index, spec) in specs.iter().enumerate() {
        groups.entry(spec.key).or_default().push(index);
    }
    let mut identity = Vec::with_capacity(specs.len());
    for index in 0..specs.len() {
        identity.push(F(
            u64::try_from(index + 1).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
        ));
    }
    let mut sigma = vec![F::ZERO; specs.len()];
    for indices in groups.values() {
        for (position, index) in indices.iter().copied().enumerate() {
            let successor = indices[(position + 1) % indices.len()];
            sigma[index] = identity[successor];
        }
    }
    if sigma.iter().any(|value| *value == F::ZERO) {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    Ok(ZkX509ProjectionFixedTraceV1 {
        rows: specs.iter().map(|spec| spec.row).collect(),
        copy_identity: identity,
        copy_sigma: sigma,
    })
}
fn validate_public_shape_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    if statement.disclosed_attributes.len() > ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1
        || statement.presentation_window().validate().is_err()
        || statement
            .disclosed_attributes
            .iter()
            .any(|disclosed| disclosed.index > 3 || disclosed.attribute_digest.is_zero())
        || statement
            .disclosed_attributes
            .windows(2)
            .any(|pair| pair[0].index >= pair[1].index)
        || statement.subject_public_key_digest.is_zero()
        || statement.certificate_nullifier.is_zero()
    {
        return Err(ZkX509ProjectionAirErrorV1::Shape);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_witness_shape_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    if !(2..=ZK_X509_MAX_CHAIN_DEPTH_V1).contains(&witness.chain_spki_der.len())
        || (witness.chain_spki_der.len() == ZK_X509_MAX_CHAIN_DEPTH_V1
            && witness.chain_spki_der[ZK_X509_MAX_CHAIN_DEPTH_V1 - 1]
                .iter()
                .all(|byte| *byte == 0))
        || witness
            .chain_spki_der
            .iter()
            .any(|spki| spki.len() != ZK_X509_PROJECTION_SPKI_DER_BYTES_V1)
        || witness.leaf_serial.is_empty()
        || witness.leaf_serial.len() > ZK_X509_MAX_SERIAL_BYTES_V1
        || witness.leaf_serial[0] == 0
        || witness.disclosed_attribute_values.len() != statement.disclosed_attributes.len()
        || witness.attribute_salts.len() != statement.disclosed_attributes.len()
        || witness
            .disclosed_attribute_values
            .iter()
            .any(|value| value.is_empty() || value.len() > ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1)
    {
        return Err(ZkX509ProjectionAirErrorV1::Shape);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn empty_base_row_v1() -> [F; ZK_X509_PROJECTION_BASE_WIDTH_V1] {
    [F::ZERO; ZK_X509_PROJECTION_BASE_WIDTH_V1]
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn chain_spki_byte_v1(
    witness: &ZkX509ProjectionWitnessV1,
    certificate: usize,
    offset: usize,
) -> Result<u8, ZkX509ProjectionAirErrorV1> {
    if certificate >= ZK_X509_MAX_CHAIN_DEPTH_V1 || offset >= ZK_X509_PROJECTION_SPKI_DER_BYTES_V1 {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    witness
        .chain_spki_der
        .get(certificate)
        .map(|spki| {
            spki.get(offset)
                .copied()
                .ok_or(ZkX509ProjectionAirErrorV1::Shape)
        })
        .unwrap_or(Ok(0))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn set_byte_v1(row: &mut [F; ZK_X509_PROJECTION_BASE_WIDTH_V1], value: u8) {
    row[VALUE] = F(u64::from(value));
    for bit in 0..8 {
        row[VALUE_BITS + bit] = F(u64::from((value >> bit) & 1));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn f_usize_v1(value: usize) -> Result<F, ZkX509ProjectionAirErrorV1> {
    Ok(F(
        u64::try_from(value).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
    ))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn length_accumulators_v1(bytes: [u8; 8], byte: usize) -> (u64, u64) {
    let before = bytes[..byte].iter().fold(0_u64, |accumulator, value| {
        accumulator * 256 + u64::from(*value)
    });
    (before, before * 256 + u64::from(bytes[byte]))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn input_length_v1(
    input: u8,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<usize, ZkX509ProjectionAirErrorV1> {
    match input {
        3 => Ok(witness.leaf_serial.len()),
        4..=7 => witness
            .disclosed_attribute_values
            .get(usize::from(input - 4))
            .map(Vec::len)
            .ok_or(ZkX509ProjectionAirErrorV1::Shape),
        _ => Err(ZkX509ProjectionAirErrorV1::Topology),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn input_value_v1(
    input: u8,
    offset: usize,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<u8, ZkX509ProjectionAirErrorV1> {
    match input {
        3 => Ok(witness.leaf_serial.get(offset).copied().unwrap_or(0)),
        4..=7 => witness
            .disclosed_attribute_values
            .get(usize::from(input - 4))
            .map(|value| value.get(offset).copied().unwrap_or(0))
            .ok_or(ZkX509ProjectionAirErrorV1::Shape),
        _ => Err(ZkX509ProjectionAirErrorV1::Topology),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_length_row_v1(
    row: &mut [F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    length: usize,
    byte: usize,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    let encoded = u64::try_from(length)
        .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
        .to_be_bytes();
    let (before, after) = length_accumulators_v1(encoded, byte);
    set_byte_v1(row, encoded[byte]);
    row[DECLARED_LENGTH] = f_usize_v1(length)?;
    row[LENGTH_ACC_BEFORE] = F(before);
    row[LENGTH_ACC_AFTER] = F(after);
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_variable_row_v1(
    row: &mut [F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    value: u8,
    offset: usize,
    length: usize,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    let used = usize::from(offset < length);
    set_byte_v1(row, if used == 1 { value } else { 0 });
    row[USED] = f_usize_v1(used)?;
    row[DECLARED_LENGTH] = f_usize_v1(length)?;
    row[REGION_BEFORE] = f_usize_v1(offset.min(length))?;
    row[REGION_AFTER] = f_usize_v1((offset + 1).min(length))?;
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_input_row_v1(
    fixed: ZkX509ProjectionFixedRowV1,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<[F; ZK_X509_PROJECTION_BASE_WIDTH_V1], ZkX509ProjectionAirErrorV1> {
    let mut row = empty_base_row_v1();
    match fixed {
        ZkX509ProjectionFixedRowV1::InputSpki {
            certificate,
            offset,
            active,
        } => {
            if active {
                let value =
                    chain_spki_byte_v1(witness, usize::from(certificate), usize::from(offset))?;
                set_byte_v1(&mut row, value);
                row[USED] = F::ONE;
            }
        }
        ZkX509ProjectionFixedRowV1::InputLength {
            input,
            byte,
            active,
            ..
        } => {
            if active {
                fill_length_row_v1(
                    &mut row,
                    input_length_v1(input, witness)?,
                    usize::from(byte),
                )?;
            }
        }
        ZkX509ProjectionFixedRowV1::InputByte {
            input,
            offset,
            active,
            ..
        } => {
            if active {
                let length = input_length_v1(input, witness)?;
                fill_variable_row_v1(
                    &mut row,
                    input_value_v1(input, usize::from(offset), witness)?,
                    usize::from(offset),
                    length,
                )?;
            }
        }
        _ => return Err(ZkX509ProjectionAirErrorV1::Topology),
    }
    Ok(row)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn source_token_material_v1(
    token: ZkX509ProjectionSourceTokenV1,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<(u8, bool, Option<(usize, usize, usize)>), ZkX509ProjectionAirErrorV1> {
    match token {
        ZkX509ProjectionSourceTokenV1::Constant(value) => Ok((value, true, None)),
        ZkX509ProjectionSourceTokenV1::Spki {
            certificate,
            offset,
        } => Ok((
            chain_spki_byte_v1(witness, usize::from(certificate), usize::from(offset))?,
            true,
            None,
        )),
        ZkX509ProjectionSourceTokenV1::SerialLength(byte) => {
            let length = witness.leaf_serial.len();
            let encoded = u64::try_from(length)
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes();
            Ok((
                encoded[usize::from(byte)],
                true,
                Some((length, usize::from(byte), 0)),
            ))
        }
        ZkX509ProjectionSourceTokenV1::Serial(offset) => {
            let length = witness.leaf_serial.len();
            let offset = usize::from(offset);
            Ok((
                witness.leaf_serial.get(offset).copied().unwrap_or(0),
                offset < length,
                Some((length, offset, 1)),
            ))
        }
        ZkX509ProjectionSourceTokenV1::AttributeLength { disclosure, byte } => {
            let length = witness
                .disclosed_attribute_values
                .get(usize::from(disclosure))
                .map(Vec::len)
                .ok_or(ZkX509ProjectionAirErrorV1::Shape)?;
            let encoded = u64::try_from(length)
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes();
            Ok((
                encoded[usize::from(byte)],
                true,
                Some((length, usize::from(byte), 0)),
            ))
        }
        ZkX509ProjectionSourceTokenV1::AttributeValue { disclosure, offset } => {
            let value = witness
                .disclosed_attribute_values
                .get(usize::from(disclosure))
                .ok_or(ZkX509ProjectionAirErrorV1::Shape)?;
            let offset = usize::from(offset);
            Ok((
                value.get(offset).copied().unwrap_or(0),
                offset < value.len(),
                Some((value.len(), offset, 1)),
            ))
        }
        ZkX509ProjectionSourceTokenV1::AttributeSalt { disclosure, offset } => Ok((
            *witness
                .attribute_salts
                .get(usize::from(disclosure))
                .and_then(|salt| salt.get(usize::from(offset)))
                .ok_or(ZkX509ProjectionAirErrorV1::Shape)?,
            true,
            None,
        )),
        ZkX509ProjectionSourceTokenV1::Unused => Ok((0, false, None)),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_base_trace_v1(
    fixed: &ZkX509ProjectionFixedTraceV1,
    invocations: &[InvocationSpecV1],
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<
    (
        ZkX509ProjectionBaseTraceV1,
        PrivateTableV1<Vec<u8>>,
        PrivateTableV1<[u8; 32]>,
    ),
    ZkX509ProjectionAirErrorV1,
> {
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    rows.try_reserve_exact(fixed.rows.len())
        .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
    let mut messages = PrivateTableV1::new(
        vec![Vec::new(); ZK_X509_PROJECTION_HASH_SLOTS_V1],
        |messages| {
            for message in messages {
                zeroize_words_v1(message);
            }
        },
    );
    // Reserve the fixed public bound before writing bytes: growing a private
    // Vec would otherwise leave its prior allocation outside the clearing owner.
    for message in messages.iter_mut() {
        message
            .try_reserve_exact(ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1)
            .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
    }
    let mut digests = PrivateTableV1::new(
        vec![[0_u8; 32]; ZK_X509_PROJECTION_HASH_SLOTS_V1],
        zeroize_words_v1,
    );
    let mut source_counts = [0_usize; ZK_X509_PROJECTION_HASH_SLOTS_V1];
    let mut output_counts = [0_usize; ZK_X509_PROJECTION_HASH_SLOTS_V1];
    for fixed_row in fixed.rows.iter().copied() {
        let mut row = empty_base_row_v1();
        match fixed_row {
            row_kind @ (ZkX509ProjectionFixedRowV1::InputSpki { .. }
            | ZkX509ProjectionFixedRowV1::InputLength { .. }
            | ZkX509ProjectionFixedRowV1::InputByte { .. }) => {
                row = fill_input_row_v1(row_kind, witness)?;
            }
            ZkX509ProjectionFixedRowV1::Source {
                invocation,
                active,
                token,
                ..
            } => {
                let invocation_index = usize::from(invocation);
                let before = source_counts[invocation_index];
                let (raw_value, token_used, variable) = if active {
                    source_token_material_v1(token, witness)?
                } else {
                    (0, false, None)
                };
                let used = active && token_used;
                let value = if used { raw_value } else { 0 };
                set_byte_v1(&mut row, value);
                row[USED] = F(u64::from(used));
                row[MESSAGE_BEFORE] = f_usize_v1(before)?;
                if used {
                    if messages[invocation_index].len() == ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1 {
                        return Err(ZkX509ProjectionAirErrorV1::Topology);
                    }
                    source_counts[invocation_index] = before
                        .checked_add(1)
                        .ok_or(ZkX509ProjectionAirErrorV1::Resource)?;
                    messages[invocation_index].push(value);
                }
                row[MESSAGE_AFTER] = f_usize_v1(source_counts[invocation_index])?;
                if let Some((length, offset, kind)) = variable {
                    row[DECLARED_LENGTH] = f_usize_v1(length)?;
                    if kind == 0 {
                        let encoded = u64::try_from(length)
                            .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                            .to_be_bytes();
                        let (acc_before, acc_after) = length_accumulators_v1(encoded, offset);
                        row[LENGTH_ACC_BEFORE] = F(acc_before);
                        row[LENGTH_ACC_AFTER] = F(acc_after);
                    } else {
                        row[REGION_BEFORE] = f_usize_v1(offset.min(length))?;
                        row[REGION_AFTER] = f_usize_v1((offset + 1).min(length))?;
                    }
                }
            }
            ZkX509ProjectionFixedRowV1::MessageLength {
                invocation,
                byte,
                active,
                ..
            } => {
                if active {
                    fill_length_row_v1(
                        &mut row,
                        source_counts[usize::from(invocation)],
                        usize::from(byte),
                    )?;
                }
            }
            ZkX509ProjectionFixedRowV1::Output {
                invocation,
                offset,
                active,
                ..
            } => {
                let invocation_index = usize::from(invocation);
                let offset = usize::from(offset);
                let message = &messages[invocation_index];
                let used = active && offset < message.len();
                let value = if used { message[offset] } else { 0 };
                set_byte_v1(&mut row, value);
                row[USED] = F(u64::from(used));
                row[DECLARED_LENGTH] = f_usize_v1(message.len())?;
                row[MESSAGE_BEFORE] = f_usize_v1(output_counts[invocation_index])?;
                if used {
                    output_counts[invocation_index] = output_counts[invocation_index]
                        .checked_add(1)
                        .ok_or(ZkX509ProjectionAirErrorV1::Resource)?;
                }
                row[MESSAGE_AFTER] = f_usize_v1(output_counts[invocation_index])?;
            }
            ZkX509ProjectionFixedRowV1::Digest {
                expected, active, ..
            } => {
                set_byte_v1(&mut row, if active { expected } else { 0 });
                row[USED] = F(u64::from(active));
            }
            ZkX509ProjectionFixedRowV1::Padding => {}
        }
        rows.push(row);
    }
    for (index, invocation) in invocations.iter().enumerate() {
        if invocation.active {
            if messages[index].is_empty()
                || messages[index].len() > ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1
                || output_counts[index] != messages[index].len()
            {
                return Err(ZkX509ProjectionAirErrorV1::Topology);
            }
            let digest: [u8; 32] = Sha256::digest(&messages[index]).into();
            if digest != invocation.expected_digest {
                return Err(ZkX509ProjectionAirErrorV1::ProjectionMismatch);
            }
            digests[index] = digest;
        } else if !messages[index].is_empty() || output_counts[index] != 0 {
            return Err(ZkX509ProjectionAirErrorV1::Topology);
        }
    }
    Ok((
        ZkX509ProjectionBaseTraceV1 {
            rows: rows.into_vec(),
        },
        messages,
        digests,
    ))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn padded_v1(value: &[u8], length: usize) -> Result<Vec<u8>, ZkX509ProjectionAirErrorV1> {
    if value.len() > length {
        return Err(ZkX509ProjectionAirErrorV1::Resource);
    }
    let mut padded = Vec::new();
    padded
        .try_reserve_exact(length)
        .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
    padded.extend_from_slice(value);
    padded.resize(length, 0);
    Ok(padded)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_io_channel_v1(
    channels: &mut Vec<ZkX509ProjectionIoChannelV1>,
    producer: ZkX509IoEndpointV1,
    mut consumers: Vec<ZkX509IoEndpointV1>,
    value: Vec<u8>,
    public: bool,
) {
    consumers.sort_unstable();
    channels.push(ZkX509ProjectionIoChannelV1 {
        producer,
        consumers,
        public_value: public.then(|| value.clone()),
        value,
    });
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_io_channels_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    witness: &ZkX509ProjectionWitnessV1,
    invocations: &[InvocationSpecV1],
    messages: &[Vec<u8>],
    digests: &[[u8; 32]],
) -> Result<Vec<ZkX509ProjectionIoChannelV1>, ZkX509ProjectionAirErrorV1> {
    let strict_der = endpoint(ZkX509IoSegmentRoleV1::StrictDer, 0);
    let sha = endpoint(ZkX509IoSegmentRoleV1::Sha256, 0);
    let p256 = endpoint(ZkX509IoSegmentRoleV1::P256, 0);
    let projection = endpoint(ZkX509IoSegmentRoleV1::Projection, 0);
    let public = endpoint(ZkX509IoSegmentRoleV1::PublicInput, 0);
    let mut channels = Vec::new();
    for certificate in 0..ZK_X509_MAX_CHAIN_DEPTH_V1 {
        let spki = witness
            .chain_spki_der
            .get(certificate)
            .cloned()
            .unwrap_or_else(|| vec![0; ZK_X509_PROJECTION_SPKI_DER_BYTES_V1]);
        push_io_channel_v1(&mut channels, strict_der, vec![projection], spki, false);
    }
    push_io_channel_v1(
        &mut channels,
        strict_der,
        vec![projection],
        witness
            .leaf_serial
            .len()
            .try_into()
            .map(u64::to_be_bytes)
            .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
            .to_vec(),
        false,
    );
    push_io_channel_v1(
        &mut channels,
        strict_der,
        vec![projection],
        padded_v1(&witness.leaf_serial, ZK_X509_MAX_SERIAL_BYTES_V1)?,
        false,
    );
    for value in &witness.disclosed_attribute_values {
        push_io_channel_v1(
            &mut channels,
            strict_der,
            vec![projection],
            u64::try_from(value.len())
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes()
                .to_vec(),
            false,
        );
        push_io_channel_v1(
            &mut channels,
            strict_der,
            vec![projection],
            padded_v1(value, ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1)?,
            false,
        );
    }
    for (index, invocation) in invocations.iter().enumerate() {
        if !invocation.active {
            continue;
        }
        push_io_channel_v1(
            &mut channels,
            projection,
            vec![sha],
            padded_v1(
                messages
                    .get(index)
                    .ok_or(ZkX509ProjectionAirErrorV1::Topology)?,
                ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1,
            )?,
            false,
        );
        push_io_channel_v1(
            &mut channels,
            projection,
            vec![sha],
            u64::try_from(messages[index].len())
                .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?
                .to_be_bytes()
                .to_vec(),
            false,
        );
        let consumers = if invocation.public_digest {
            vec![projection, public]
        } else {
            vec![p256, projection]
        };
        push_io_channel_v1(
            &mut channels,
            sha,
            consumers,
            digests
                .get(index)
                .ok_or(ZkX509ProjectionAirErrorV1::Topology)?
                .to_vec(),
            invocation.public_digest,
        );
    }
    if statement.disclosed_attributes.len() != witness.disclosed_attribute_values.len() {
        return Err(ZkX509ProjectionAirErrorV1::Shape);
    }
    Ok(channels)
}
/// Compile the verifier-fixed projection schedule for a statement.
///
/// # Errors
///
/// Returns a shape, encoding, topology, or resource error if the public
/// statement cannot instantiate the sole fixed profile.
pub fn compile_zk_x509_projection_fixed_trace_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<ZkX509ProjectionFixedTraceV1, ZkX509ProjectionAirErrorV1> {
    let (specs, _) = fixed_specs_v1(statement)?;
    compile_fixed_trace_v1(&specs)
}
fn projection_stark_fixed_row_v1(
    row: ZkX509ProjectionFixedRowV1,
    copy_identity: F,
    copy_sigma: F,
    row_index: usize,
) -> [F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1] {
    let mut fixed = [F::ZERO; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1];
    let set_flag = |fixed: &mut [F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1], index| {
        fixed[index] = F::ONE;
    };
    match row {
        ZkX509ProjectionFixedRowV1::InputSpki { active, .. } => {
            set_flag(&mut fixed, FIX_INPUT_SPKI);
            fixed[FIX_ACTIVE] = F(u64::from(active));
        }
        ZkX509ProjectionFixedRowV1::InputLength {
            active,
            first,
            last,
            ..
        } => {
            set_flag(&mut fixed, FIX_INPUT_LENGTH);
            fixed[FIX_ACTIVE] = F(u64::from(active));
            fixed[FIX_FIRST] = F(u64::from(first));
            fixed[FIX_LAST] = F(u64::from(last));
        }
        ZkX509ProjectionFixedRowV1::InputByte {
            active,
            first,
            last,
            ..
        } => {
            set_flag(&mut fixed, FIX_INPUT_BYTE);
            fixed[FIX_ACTIVE] = F(u64::from(active));
            fixed[FIX_FIRST] = F(u64::from(first));
            fixed[FIX_LAST] = F(u64::from(last));
            fixed[FIX_USED_MONOTONE_TRANSITION] = F(u64::from(active && !last));
        }
        ZkX509ProjectionFixedRowV1::Source {
            invocation,
            active,
            first,
            last,
            token,
            ..
        } => {
            set_flag(&mut fixed, FIX_SOURCE);
            fixed[FIX_ACTIVE] = F(u64::from(active));
            fixed[FIX_FIRST] = F(u64::from(first));
            fixed[FIX_LAST] = F(u64::from(last));
            fixed[FIX_INVOCATION] = F(u64::from(invocation) + 1);
            match token {
                ZkX509ProjectionSourceTokenV1::Constant(expected) => {
                    set_flag(&mut fixed, FIX_SOURCE_CONSTANT);
                    fixed[FIX_EXPECTED_BYTE] = F(u64::from(expected));
                }
                ZkX509ProjectionSourceTokenV1::Spki { .. }
                | ZkX509ProjectionSourceTokenV1::AttributeSalt { .. } => {
                    set_flag(&mut fixed, FIX_SOURCE_COPY);
                }
                ZkX509ProjectionSourceTokenV1::SerialLength(_)
                | ZkX509ProjectionSourceTokenV1::AttributeLength { .. } => {
                    set_flag(&mut fixed, FIX_SOURCE_LENGTH);
                    if let Some((_, first, last)) = source_length_position_v1(token) {
                        fixed[FIX_TOKEN_FIRST] = F(u64::from(first));
                        fixed[FIX_TOKEN_LAST] = F(u64::from(last));
                    }
                }
                ZkX509ProjectionSourceTokenV1::Serial(_)
                | ZkX509ProjectionSourceTokenV1::AttributeValue { .. } => {
                    set_flag(&mut fixed, FIX_SOURCE_VARIABLE);
                    if let Some((_, _, first, last)) = source_variable_position_v1(token) {
                        fixed[FIX_TOKEN_FIRST] = F(u64::from(first));
                        fixed[FIX_TOKEN_LAST] = F(u64::from(last));
                        fixed[FIX_USED_MONOTONE_TRANSITION] = F(u64::from(active && !last));
                    }
                }
                ZkX509ProjectionSourceTokenV1::Unused => {
                    set_flag(&mut fixed, FIX_SOURCE_UNUSED);
                }
            }
        }
        ZkX509ProjectionFixedRowV1::MessageLength {
            invocation,
            active,
            first,
            last,
            ..
        } => {
            set_flag(&mut fixed, FIX_MESSAGE_LENGTH);
            fixed[FIX_ACTIVE] = F(u64::from(active));
            fixed[FIX_FIRST] = F(u64::from(first));
            fixed[FIX_LAST] = F(u64::from(last));
            fixed[FIX_INVOCATION] = F(u64::from(invocation) + 1);
        }
        ZkX509ProjectionFixedRowV1::Output {
            invocation,
            active,
            first,
            last,
            ..
        } => {
            set_flag(&mut fixed, FIX_OUTPUT);
            fixed[FIX_ACTIVE] = F(u64::from(active));
            fixed[FIX_FIRST] = F(u64::from(first));
            fixed[FIX_LAST] = F(u64::from(last));
            fixed[FIX_INVOCATION] = F(u64::from(invocation) + 1);
            fixed[FIX_USED_MONOTONE_TRANSITION] = F(u64::from(active && !last));
        }
        ZkX509ProjectionFixedRowV1::Digest {
            invocation,
            expected,
            active,
            ..
        } => {
            set_flag(&mut fixed, FIX_DIGEST);
            fixed[FIX_ACTIVE] = F(u64::from(active));
            fixed[FIX_EXPECTED_BYTE] = F(u64::from(expected));
            fixed[FIX_INVOCATION] = F(u64::from(invocation) + 1);
        }
        ZkX509ProjectionFixedRowV1::Padding => {
            set_flag(&mut fixed, FIX_PADDING);
        }
    }
    fixed[FIX_COPY_IDENTITY] = copy_identity;
    fixed[FIX_COPY_SIGMA] = copy_sigma;
    fixed[FIX_FIRST_ROW] = F(u64::from(row_index == 0));
    fixed[FIX_LAST_ROW] = F(u64::from(row_index + 1 == ZK_X509_PROJECTION_TRACE_SIZE_V1));
    fixed
}
/// Compile the exact numeric preprocessing rows consumed by the aggregate verifier. The proof never
/// supplies any selector, expected output byte, or permutation label.
pub fn compile_zk_x509_projection_stark_fixed_rows_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<Vec<[F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1]>, ZkX509ProjectionAirErrorV1> {
    let fixed = compile_zk_x509_projection_fixed_trace_v1(statement)?;
    if fixed.rows.len() != ZK_X509_PROJECTION_TRACE_SIZE_V1
        || fixed.copy_identity.len() != fixed.rows.len()
        || fixed.copy_sigma.len() != fixed.rows.len()
    {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    Ok(fixed
        .rows
        .iter()
        .copied()
        .zip(fixed.copy_identity.iter().copied())
        .zip(fixed.copy_sigma.iter().copied())
        .enumerate()
        .map(|(index, ((row, identity), sigma))| {
            projection_stark_fixed_row_v1(row, identity, sigma, index)
        })
        .collect())
}
/// Build a complete projection witness trace and prover-internal I/O plan.
///
/// # Errors
///
/// Returns a strict shape, projection, encoding, topology, or resource error.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_projection_trace_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<ZkX509ProjectionTraceV1, ZkX509ProjectionAirErrorV1> {
    validate_public_shape_v1(statement)?;
    validate_witness_shape_v1(statement, witness)?;
    let (specs, invocations) = fixed_specs_v1(statement)?;
    let fixed = compile_fixed_trace_v1(&specs)?;
    let (base, messages, digests) = build_base_trace_v1(&fixed, &invocations, witness)?;
    let io_channels = build_io_channels_v1(statement, witness, &invocations, &messages, &digests)?;
    Ok(ZkX509ProjectionTraceV1 {
        fixed,
        base,
        io_channels,
    })
}
/// Convert a projection I/O plan to globally numbered shared witnesses.
///
/// # Errors
///
/// Returns a resource error on channel-id or length overflow.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn projection_io_witnesses_v1(
    channels: Vec<ZkX509ProjectionIoChannelV1>,
    first_channel: u32,
) -> Result<Vec<ZkX509IoChannelWitnessV1>, ZkX509ProjectionAirErrorV1> {
    channels
        .into_iter()
        .enumerate()
        .map(|(index, channel)| {
            channel.into_witness(
                first_channel
                    .checked_add(
                        u32::try_from(index).map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?,
                    )
                    .ok_or(ZkX509ProjectionAirErrorV1::Resource)?,
            )
        })
        .collect()
}
impl ZkX509ProjectionChallengesV1 {
    pub(crate) fn validate(self) -> Result<(), ZkX509ProjectionAirErrorV1> {
        let canonical_nonzero = |value: F| {
            value.0 != 0 && value.0 < GOLDILOCKS_MODULUS_V1 && F::canonical(value.0).is_some()
        };
        for lane in 0..COPY_LANES {
            let copy = self.copy[lane];
            let compact = self.compaction[lane];
            if !canonical_nonzero(copy.beta)
                || !canonical_nonzero(copy.gamma)
                || !canonical_nonzero(compact.active)
                || !canonical_nonzero(compact.invocation)
                || !canonical_nonzero(compact.position)
                || !canonical_nonzero(compact.value)
                || !canonical_nonzero(compact.gamma)
            {
                return Err(ZkX509ProjectionAirErrorV1::Challenge);
            }
        }
        if (0..COPY_LANES).any(|lane| {
            (0..lane).any(|prior| {
                self.copy[lane] == self.copy[prior]
                    || self.compaction[lane] == self.compaction[prior]
            })
        }) {
            return Err(ZkX509ProjectionAirErrorV1::Challenge);
        }
        Ok(())
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compaction_term_v1(
    challenge: ZkX509ProjectionCompactionChallengesV1,
    row: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    invocation: u8,
) -> F {
    let used = row[USED];
    let tuple = challenge
        .active
        .add(challenge.invocation.mul(F(u64::from(invocation) + 1)))
        .add(challenge.position.mul(row[MESSAGE_BEFORE]))
        .add(challenge.value.mul(row[VALUE]));
    challenge.gamma.add(used.mul(tuple))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fixed_compaction_role_v1(row: ZkX509ProjectionFixedRowV1) -> Option<(bool, u8)> {
    match row {
        ZkX509ProjectionFixedRowV1::Source { invocation, .. } => Some((true, invocation)),
        ZkX509ProjectionFixedRowV1::Output { invocation, .. } => Some((false, invocation)),
        _ => None,
    }
}
/// Build the challenge-dependent copy and source-compaction products.
///
/// # Errors
///
/// Returns a shape, challenge, non-canonical-field, or algebraic error if the
/// committed base/fixed traces cannot satisfy the products.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_projection_aux_trace_v1(
    base: &ZkX509ProjectionBaseTraceV1,
    fixed: &ZkX509ProjectionFixedTraceV1,
    challenges: ZkX509ProjectionChallengesV1,
) -> Result<ZkX509ProjectionAuxTraceV1, ZkX509ProjectionAirErrorV1> {
    challenges.validate()?;
    if base.rows.len() != ZK_X509_PROJECTION_TRACE_SIZE_V1
        || fixed.rows.len() != base.rows.len()
        || fixed.copy_identity.len() != base.rows.len()
        || fixed.copy_sigma.len() != base.rows.len()
    {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    if base
        .rows
        .iter()
        .flatten()
        .chain(fixed.copy_identity.iter())
        .chain(fixed.copy_sigma.iter())
        .any(|value| value.0 >= GOLDILOCKS_MODULUS_V1)
    {
        return Err(ZkX509ProjectionAirErrorV1::NonCanonicalField);
    }
    let mut copy_numerator = [F::ONE; COPY_LANES];
    let mut copy_denominator = [F::ONE; COPY_LANES];
    let mut source = [F::ONE; COPY_LANES];
    let mut output = [F::ONE; COPY_LANES];
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    rows.try_reserve_exact(base.rows.len())
        .map_err(|_| ZkX509ProjectionAirErrorV1::Resource)?;
    for index in 0..base.rows.len() {
        let base_row = &base.rows[index];
        let mut aux = [F::ZERO; ZK_X509_PROJECTION_AUX_WIDTH_V1];
        aux[AUX_COPY_NUMERATOR_BEFORE..AUX_COPY_NUMERATOR_BEFORE + COPY_LANES]
            .copy_from_slice(&copy_numerator);
        aux[AUX_COPY_DENOMINATOR_BEFORE..AUX_COPY_DENOMINATOR_BEFORE + COPY_LANES]
            .copy_from_slice(&copy_denominator);
        aux[AUX_SOURCE_BEFORE..AUX_SOURCE_BEFORE + COPY_LANES].copy_from_slice(&source);
        aux[AUX_OUTPUT_BEFORE..AUX_OUTPUT_BEFORE + COPY_LANES].copy_from_slice(&output);
        for lane in 0..COPY_LANES {
            let copy_challenge = challenges.copy[lane];
            let identity_term = copy_challenge
                .gamma
                .add(base_row[VALUE])
                .add(copy_challenge.beta.mul(fixed.copy_identity[index]));
            let sigma_term = copy_challenge
                .gamma
                .add(base_row[VALUE])
                .add(copy_challenge.beta.mul(fixed.copy_sigma[index]));
            copy_numerator[lane] = copy_numerator[lane].mul(sigma_term);
            copy_denominator[lane] = copy_denominator[lane].mul(identity_term);
            if let Some((is_source, invocation)) = fixed_compaction_role_v1(fixed.rows[index]) {
                let term = compaction_term_v1(challenges.compaction[lane], base_row, invocation);
                if is_source {
                    source[lane] = source[lane].mul(term);
                } else {
                    output[lane] = output[lane].mul(term);
                }
            }
        }
        aux[AUX_COPY_NUMERATOR_AFTER..AUX_COPY_NUMERATOR_AFTER + COPY_LANES]
            .copy_from_slice(&copy_numerator);
        aux[AUX_COPY_DENOMINATOR_AFTER..AUX_COPY_DENOMINATOR_AFTER + COPY_LANES]
            .copy_from_slice(&copy_denominator);
        aux[AUX_SOURCE_AFTER..AUX_SOURCE_AFTER + COPY_LANES].copy_from_slice(&source);
        aux[AUX_OUTPUT_AFTER..AUX_OUTPUT_AFTER + COPY_LANES].copy_from_slice(&output);
        rows.push(aux);
    }
    let last = rows.last().ok_or(ZkX509ProjectionAirErrorV1::Topology)?;
    if last[AUX_COPY_NUMERATOR_AFTER..AUX_COPY_NUMERATOR_AFTER + COPY_LANES]
        != last[AUX_COPY_DENOMINATOR_AFTER..AUX_COPY_DENOMINATOR_AFTER + COPY_LANES]
        || last[AUX_SOURCE_AFTER..AUX_SOURCE_AFTER + COPY_LANES]
            != last[AUX_OUTPUT_AFTER..AUX_OUTPUT_AFTER + COPY_LANES]
    {
        return Err(ZkX509ProjectionAirErrorV1::Constraint);
    }
    Ok(ZkX509ProjectionAuxTraceV1 {
        rows: rows.into_vec(),
    })
}
#[cfg(test)]
fn add_residue_v1(residues: &mut Vec<F>, left: F, right: F) {
    residues.push(left.sub(right));
}
#[cfg(test)]
fn add_zero_v1(residues: &mut Vec<F>, value: F) {
    residues.push(value);
}
#[cfg(test)]
fn add_boolean_v1(residues: &mut Vec<F>, value: F) {
    residues.push(value.mul(value.sub(F::ONE)));
}
#[cfg(test)]
fn enforce_auxiliary_zero_v1(
    residues: &mut Vec<F>,
    row: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    keep_message: bool,
    keep_length: bool,
    keep_region: bool,
) {
    if !keep_message {
        add_zero_v1(residues, row[MESSAGE_BEFORE]);
        add_zero_v1(residues, row[MESSAGE_AFTER]);
    }
    if !keep_length {
        add_zero_v1(residues, row[DECLARED_LENGTH]);
        add_zero_v1(residues, row[LENGTH_ACC_BEFORE]);
        add_zero_v1(residues, row[LENGTH_ACC_AFTER]);
    }
    if !keep_region {
        add_zero_v1(residues, row[REGION_BEFORE]);
        add_zero_v1(residues, row[REGION_AFTER]);
    }
}
#[cfg(test)]
fn source_token_is_length_v1(token: ZkX509ProjectionSourceTokenV1) -> bool {
    matches!(
        token,
        ZkX509ProjectionSourceTokenV1::SerialLength(_)
            | ZkX509ProjectionSourceTokenV1::AttributeLength { .. }
    )
}
#[cfg(test)]
fn source_token_is_variable_v1(token: ZkX509ProjectionSourceTokenV1) -> bool {
    matches!(
        token,
        ZkX509ProjectionSourceTokenV1::Serial(_)
            | ZkX509ProjectionSourceTokenV1::AttributeValue { .. }
    )
}
#[cfg(test)]
fn source_token_constant_v1(token: ZkX509ProjectionSourceTokenV1) -> Option<u8> {
    match token {
        ZkX509ProjectionSourceTokenV1::Constant(value) => Some(value),
        _ => None,
    }
}
fn source_length_position_v1(token: ZkX509ProjectionSourceTokenV1) -> Option<(u8, bool, bool)> {
    match token {
        ZkX509ProjectionSourceTokenV1::SerialLength(byte)
        | ZkX509ProjectionSourceTokenV1::AttributeLength { byte, .. } => {
            Some((byte, byte == 0, byte == 7))
        }
        _ => None,
    }
}
fn source_variable_position_v1(
    token: ZkX509ProjectionSourceTokenV1,
) -> Option<(usize, usize, bool, bool)> {
    match token {
        ZkX509ProjectionSourceTokenV1::Serial(offset) => {
            let offset = usize::from(offset);
            Some((
                offset,
                ZK_X509_MAX_SERIAL_BYTES_V1,
                offset == 0,
                offset + 1 == ZK_X509_MAX_SERIAL_BYTES_V1,
            ))
        }
        ZkX509ProjectionSourceTokenV1::AttributeValue { offset, .. } => {
            let offset = usize::from(offset);
            Some((
                offset,
                ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1,
                offset == 0,
                offset + 1 == ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1,
            ))
        }
        _ => None,
    }
}
#[cfg(test)]
fn same_source_variable_group_v1(
    left: ZkX509ProjectionSourceTokenV1,
    right: ZkX509ProjectionSourceTokenV1,
) -> bool {
    match (left, right) {
        (ZkX509ProjectionSourceTokenV1::Serial(_), ZkX509ProjectionSourceTokenV1::Serial(_)) => {
            true
        }
        (
            ZkX509ProjectionSourceTokenV1::AttributeValue {
                disclosure: left, ..
            },
            ZkX509ProjectionSourceTokenV1::AttributeValue {
                disclosure: right, ..
            },
        ) => left == right,
        _ => false,
    }
}
#[cfg(test)]
fn same_source_length_group_v1(
    left: ZkX509ProjectionSourceTokenV1,
    right: ZkX509ProjectionSourceTokenV1,
) -> bool {
    match (left, right) {
        (
            ZkX509ProjectionSourceTokenV1::SerialLength(_),
            ZkX509ProjectionSourceTokenV1::SerialLength(_),
        ) => true,
        (
            ZkX509ProjectionSourceTokenV1::AttributeLength {
                disclosure: left, ..
            },
            ZkX509ProjectionSourceTokenV1::AttributeLength {
                disclosure: right, ..
            },
        ) => left == right,
        _ => false,
    }
}
#[cfg(test)]
fn matching_length_to_variable_v1(
    length: ZkX509ProjectionSourceTokenV1,
    variable: ZkX509ProjectionSourceTokenV1,
) -> bool {
    match (length, variable) {
        (
            ZkX509ProjectionSourceTokenV1::SerialLength(7),
            ZkX509ProjectionSourceTokenV1::Serial(0),
        ) => true,
        (
            ZkX509ProjectionSourceTokenV1::AttributeLength {
                disclosure: left,
                byte: 7,
            },
            ZkX509ProjectionSourceTokenV1::AttributeValue {
                disclosure: right,
                offset: 0,
            },
        ) => left == right,
        _ => false,
    }
}
#[cfg(test)]
fn constrain_length_row_v1(
    residues: &mut Vec<F>,
    current: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next: Option<&[F; ZK_X509_PROJECTION_BASE_WIDTH_V1]>,
    first: bool,
    last: bool,
    next_is_variable: bool,
) {
    if first {
        add_zero_v1(residues, current[LENGTH_ACC_BEFORE]);
    }
    add_residue_v1(
        residues,
        current[LENGTH_ACC_AFTER],
        current[LENGTH_ACC_BEFORE].mul(F(256)).add(current[VALUE]),
    );
    if last {
        add_residue_v1(
            residues,
            current[LENGTH_ACC_AFTER],
            current[DECLARED_LENGTH],
        );
        if next_is_variable {
            if let Some(next) = next {
                add_residue_v1(residues, next[DECLARED_LENGTH], current[DECLARED_LENGTH]);
                add_zero_v1(residues, next[REGION_BEFORE]);
            }
        }
    } else if let Some(next) = next {
        add_residue_v1(residues, next[LENGTH_ACC_BEFORE], current[LENGTH_ACC_AFTER]);
        add_residue_v1(residues, next[DECLARED_LENGTH], current[DECLARED_LENGTH]);
    }
}
#[cfg(test)]
fn constrain_variable_row_v1(
    residues: &mut Vec<F>,
    current: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next: Option<&[F; ZK_X509_PROJECTION_BASE_WIDTH_V1]>,
    first: bool,
    last: bool,
    same_next_group: bool,
) {
    add_residue_v1(
        residues,
        current[REGION_AFTER],
        current[REGION_BEFORE].add(current[USED]),
    );
    add_zero_v1(residues, current[VALUE].mul(F::ONE.sub(current[USED])));
    if first {
        add_zero_v1(residues, current[REGION_BEFORE]);
        add_residue_v1(residues, current[USED], F::ONE);
    }
    if last {
        add_residue_v1(residues, current[REGION_AFTER], current[DECLARED_LENGTH]);
    } else if same_next_group {
        if let Some(next) = next {
            add_residue_v1(residues, next[REGION_BEFORE], current[REGION_AFTER]);
            add_residue_v1(residues, next[DECLARED_LENGTH], current[DECLARED_LENGTH]);
            add_zero_v1(residues, next[USED].mul(F::ONE.sub(current[USED])));
        }
    }
}
#[cfg(test)]
fn all_zero_base_v1(residues: &mut Vec<F>, row: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1]) {
    residues.extend(row.iter().copied());
}
#[cfg(test)]
fn next_input_length_v1(
    current_input: u8,
    current_byte: u8,
    next: Option<ZkX509ProjectionFixedRowV1>,
) -> (bool, bool) {
    match next {
        Some(ZkX509ProjectionFixedRowV1::InputLength {
            input,
            byte,
            active: true,
            ..
        }) if input == current_input && byte == current_byte + 1 => (true, false),
        Some(ZkX509ProjectionFixedRowV1::InputByte {
            input,
            offset: 0,
            active: true,
            ..
        }) if input == current_input && current_byte == 7 => (false, true),
        _ => (false, false),
    }
}
#[cfg(test)]
fn next_input_byte_same_v1(
    current_input: u8,
    current_offset: u16,
    next: Option<ZkX509ProjectionFixedRowV1>,
) -> bool {
    matches!(
        next,
        Some(ZkX509ProjectionFixedRowV1::InputByte {
            input,
            offset,
            active: true,
            ..
        }) if input == current_input && offset == current_offset + 1
    )
}
#[cfg(test)]
fn ensure_canonical_rows_v1(
    base: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next_base: Option<&[F; ZK_X509_PROJECTION_BASE_WIDTH_V1]>,
    aux: &[F; ZK_X509_PROJECTION_AUX_WIDTH_V1],
    next_aux: Option<&[F; ZK_X509_PROJECTION_AUX_WIDTH_V1]>,
    copy_identity: F,
    copy_sigma: F,
) -> Result<(), ZkX509ProjectionAirErrorV1> {
    if base
        .iter()
        .chain(next_base.into_iter().flatten())
        .chain(aux)
        .chain(next_aux.into_iter().flatten())
        .chain([&copy_identity, &copy_sigma])
        .any(|value| value.0 >= GOLDILOCKS_MODULUS_V1)
    {
        return Err(ZkX509ProjectionAirErrorV1::NonCanonicalField);
    }
    Ok(())
}
/// Evaluate all base-domain projection constraint residues for one opened row.
///
/// Fixed rows, identity labels, and sigma labels are verifier preprocessing,
/// never proof-supplied metadata. A valid row returns only zero residues.
///
/// # Errors
///
/// Returns an error only for malformed challenges or non-canonical field
/// encodings. Algebraic violations are returned as non-zero residues.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn evaluate_zk_x509_projection_constraint_residues_v1(
    current: &[F; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next: Option<&[F; ZK_X509_PROJECTION_BASE_WIDTH_V1]>,
    current_aux: &[F; ZK_X509_PROJECTION_AUX_WIDTH_V1],
    next_aux: Option<&[F; ZK_X509_PROJECTION_AUX_WIDTH_V1]>,
    fixed: ZkX509ProjectionFixedRowV1,
    next_fixed: Option<ZkX509ProjectionFixedRowV1>,
    copy_identity: F,
    copy_sigma: F,
    challenges: ZkX509ProjectionChallengesV1,
    first_row: bool,
    last_row: bool,
) -> Result<Vec<F>, ZkX509ProjectionAirErrorV1> {
    challenges.validate()?;
    ensure_canonical_rows_v1(
        current,
        next,
        current_aux,
        next_aux,
        copy_identity,
        copy_sigma,
    )?;
    let mut residues = Vec::with_capacity(96);
    add_boolean_v1(&mut residues, current[USED]);
    let mut reconstructed = F::ZERO;
    for bit in 0..8 {
        let value = current[VALUE_BITS + bit];
        add_boolean_v1(&mut residues, value);
        reconstructed = reconstructed.add(value.mul(F(1_u64 << bit)));
    }
    add_residue_v1(&mut residues, current[VALUE], reconstructed);
    match fixed {
        ZkX509ProjectionFixedRowV1::InputSpki { active, .. } => {
            if active {
                add_residue_v1(&mut residues, current[USED], F::ONE);
                enforce_auxiliary_zero_v1(&mut residues, current, false, false, false);
            } else {
                all_zero_base_v1(&mut residues, current);
            }
        }
        ZkX509ProjectionFixedRowV1::InputLength {
            input,
            byte,
            active,
            first,
            last,
        } => {
            if active {
                add_zero_v1(&mut residues, current[USED]);
                enforce_auxiliary_zero_v1(&mut residues, current, false, true, false);
                let (same_length, next_variable) = next_input_length_v1(input, byte, next_fixed);
                constrain_length_row_v1(&mut residues, current, next, first, last, next_variable);
                if !last && !same_length {
                    residues.push(F::ONE);
                }
            } else {
                all_zero_base_v1(&mut residues, current);
            }
        }
        ZkX509ProjectionFixedRowV1::InputByte {
            input,
            offset,
            active,
            first,
            last,
        } => {
            if active {
                enforce_auxiliary_zero_v1(&mut residues, current, false, true, true);
                let same = next_input_byte_same_v1(input, offset, next_fixed);
                constrain_variable_row_v1(&mut residues, current, next, first, last, same);
                if !last && !same {
                    residues.push(F::ONE);
                }
            } else {
                all_zero_base_v1(&mut residues, current);
            }
        }
        ZkX509ProjectionFixedRowV1::Source {
            invocation,
            active,
            first,
            last,
            token,
            ..
        } => {
            add_residue_v1(
                &mut residues,
                current[MESSAGE_AFTER],
                current[MESSAGE_BEFORE].add(current[USED]),
            );
            if first {
                add_zero_v1(&mut residues, current[MESSAGE_BEFORE]);
            }
            if last {
                match (next, next_fixed) {
                    (
                        Some(next),
                        Some(ZkX509ProjectionFixedRowV1::MessageLength {
                            invocation: next_invocation,
                            byte: 0,
                            active: next_active,
                            ..
                        }),
                    ) if next_invocation == invocation && next_active == active => {
                        add_residue_v1(
                            &mut residues,
                            next[DECLARED_LENGTH],
                            current[MESSAGE_AFTER],
                        );
                    }
                    _ => residues.push(F::ONE),
                }
            } else {
                match (next, next_fixed) {
                    (
                        Some(next),
                        Some(ZkX509ProjectionFixedRowV1::Source {
                            invocation: next_invocation,
                            ..
                        }),
                    ) if next_invocation == invocation => {
                        add_residue_v1(&mut residues, next[MESSAGE_BEFORE], current[MESSAGE_AFTER]);
                    }
                    _ => residues.push(F::ONE),
                }
            }
            if !active {
                add_zero_v1(&mut residues, current[USED]);
                add_zero_v1(&mut residues, current[VALUE]);
                add_zero_v1(&mut residues, current[DECLARED_LENGTH]);
                add_zero_v1(&mut residues, current[LENGTH_ACC_BEFORE]);
                add_zero_v1(&mut residues, current[LENGTH_ACC_AFTER]);
                add_zero_v1(&mut residues, current[REGION_BEFORE]);
                add_zero_v1(&mut residues, current[REGION_AFTER]);
            } else if let Some(expected) = source_token_constant_v1(token) {
                add_residue_v1(&mut residues, current[USED], F::ONE);
                add_residue_v1(&mut residues, current[VALUE], F(u64::from(expected)));
                enforce_auxiliary_zero_v1(&mut residues, current, true, false, false);
            } else if matches!(
                token,
                ZkX509ProjectionSourceTokenV1::Spki { .. }
                    | ZkX509ProjectionSourceTokenV1::AttributeSalt { .. }
            ) {
                add_residue_v1(&mut residues, current[USED], F::ONE);
                enforce_auxiliary_zero_v1(&mut residues, current, true, false, false);
            } else if source_token_is_length_v1(token) {
                add_residue_v1(&mut residues, current[USED], F::ONE);
                add_zero_v1(&mut residues, current[REGION_BEFORE]);
                add_zero_v1(&mut residues, current[REGION_AFTER]);
                let (_, length_first, length_last) =
                    source_length_position_v1(token).ok_or(ZkX509ProjectionAirErrorV1::Topology)?;
                let next_is_variable = next_fixed.is_some_and(|next_fixed| {
                    if let ZkX509ProjectionFixedRowV1::Source {
                        token: next_token, ..
                    } = next_fixed
                    {
                        matching_length_to_variable_v1(token, next_token)
                    } else {
                        false
                    }
                });
                constrain_length_row_v1(
                    &mut residues,
                    current,
                    next,
                    length_first,
                    length_last,
                    next_is_variable,
                );
                if !length_last {
                    let same = next_fixed.is_some_and(|next_fixed| {
                        if let ZkX509ProjectionFixedRowV1::Source {
                            token: next_token, ..
                        } = next_fixed
                        {
                            same_source_length_group_v1(token, next_token)
                        } else {
                            false
                        }
                    });
                    if !same {
                        residues.push(F::ONE);
                    }
                } else if !next_is_variable {
                    residues.push(F::ONE);
                }
            } else if source_token_is_variable_v1(token) {
                add_zero_v1(&mut residues, current[LENGTH_ACC_BEFORE]);
                add_zero_v1(&mut residues, current[LENGTH_ACC_AFTER]);
                let (_, _, variable_first, variable_last) = source_variable_position_v1(token)
                    .ok_or(ZkX509ProjectionAirErrorV1::Topology)?;
                let same = next_fixed.is_some_and(|next_fixed| {
                    if let ZkX509ProjectionFixedRowV1::Source {
                        token: next_token, ..
                    } = next_fixed
                    {
                        same_source_variable_group_v1(token, next_token)
                    } else {
                        false
                    }
                });
                constrain_variable_row_v1(
                    &mut residues,
                    current,
                    next,
                    variable_first,
                    variable_last,
                    same,
                );
                if !variable_last && !same {
                    residues.push(F::ONE);
                }
            } else {
                add_zero_v1(&mut residues, current[USED]);
                add_zero_v1(&mut residues, current[VALUE]);
                enforce_auxiliary_zero_v1(&mut residues, current, true, false, false);
            }
        }
        ZkX509ProjectionFixedRowV1::MessageLength {
            invocation,
            byte,
            active,
            first,
            last,
        } => {
            if active {
                add_zero_v1(&mut residues, current[USED]);
                enforce_auxiliary_zero_v1(&mut residues, current, false, true, false);
                constrain_length_row_v1(&mut residues, current, next, first, last, false);
                if last {
                    match (next, next_fixed) {
                        (
                            Some(next),
                            Some(ZkX509ProjectionFixedRowV1::Output {
                                invocation: next_invocation,
                                offset: 0,
                                active: true,
                                ..
                            }),
                        ) if next_invocation == invocation => {
                            add_residue_v1(
                                &mut residues,
                                next[DECLARED_LENGTH],
                                current[DECLARED_LENGTH],
                            );
                            add_zero_v1(&mut residues, next[MESSAGE_BEFORE]);
                        }
                        _ => residues.push(F::ONE),
                    }
                } else if !matches!(
                    next_fixed,
                    Some(ZkX509ProjectionFixedRowV1::MessageLength {
                        invocation: next_invocation,
                        byte: next_byte,
                        active: true,
                        ..
                    }) if next_invocation == invocation && next_byte == byte + 1
                ) {
                    residues.push(F::ONE);
                }
            } else {
                all_zero_base_v1(&mut residues, current);
            }
        }
        ZkX509ProjectionFixedRowV1::Output {
            invocation,
            active,
            first,
            last,
            ..
        } => {
            if active {
                add_residue_v1(
                    &mut residues,
                    current[MESSAGE_AFTER],
                    current[MESSAGE_BEFORE].add(current[USED]),
                );
                add_zero_v1(&mut residues, current[VALUE].mul(F::ONE.sub(current[USED])));
                add_zero_v1(&mut residues, current[LENGTH_ACC_BEFORE]);
                add_zero_v1(&mut residues, current[LENGTH_ACC_AFTER]);
                add_zero_v1(&mut residues, current[REGION_BEFORE]);
                add_zero_v1(&mut residues, current[REGION_AFTER]);
                if first {
                    add_zero_v1(&mut residues, current[MESSAGE_BEFORE]);
                    add_residue_v1(&mut residues, current[USED], F::ONE);
                }
                if last {
                    add_residue_v1(
                        &mut residues,
                        current[MESSAGE_AFTER],
                        current[DECLARED_LENGTH],
                    );
                } else {
                    match (next, next_fixed) {
                        (
                            Some(next),
                            Some(ZkX509ProjectionFixedRowV1::Output {
                                invocation: next_invocation,
                                active: true,
                                ..
                            }),
                        ) if next_invocation == invocation => {
                            add_residue_v1(
                                &mut residues,
                                next[MESSAGE_BEFORE],
                                current[MESSAGE_AFTER],
                            );
                            add_residue_v1(
                                &mut residues,
                                next[DECLARED_LENGTH],
                                current[DECLARED_LENGTH],
                            );
                            add_zero_v1(&mut residues, next[USED].mul(F::ONE.sub(current[USED])));
                        }
                        _ => residues.push(F::ONE),
                    }
                }
            } else {
                all_zero_base_v1(&mut residues, current);
            }
        }
        ZkX509ProjectionFixedRowV1::Digest {
            expected, active, ..
        } => {
            if active {
                add_residue_v1(&mut residues, current[USED], F::ONE);
                add_residue_v1(&mut residues, current[VALUE], F(u64::from(expected)));
                enforce_auxiliary_zero_v1(&mut residues, current, false, false, false);
            } else {
                all_zero_base_v1(&mut residues, current);
            }
        }
        ZkX509ProjectionFixedRowV1::Padding => {
            all_zero_base_v1(&mut residues, current);
        }
    }
    for lane in 0..COPY_LANES {
        let copy = challenges.copy[lane];
        let identity_term = copy
            .gamma
            .add(current[VALUE])
            .add(copy.beta.mul(copy_identity));
        let sigma_term = copy
            .gamma
            .add(current[VALUE])
            .add(copy.beta.mul(copy_sigma));
        add_residue_v1(
            &mut residues,
            current_aux[AUX_COPY_NUMERATOR_AFTER + lane],
            current_aux[AUX_COPY_NUMERATOR_BEFORE + lane].mul(sigma_term),
        );
        add_residue_v1(
            &mut residues,
            current_aux[AUX_COPY_DENOMINATOR_AFTER + lane],
            current_aux[AUX_COPY_DENOMINATOR_BEFORE + lane].mul(identity_term),
        );
        let (source_factor, output_factor) =
            if let Some((is_source, invocation)) = fixed_compaction_role_v1(fixed) {
                let term = compaction_term_v1(challenges.compaction[lane], current, invocation);
                if is_source {
                    (term, F::ONE)
                } else {
                    (F::ONE, term)
                }
            } else {
                (F::ONE, F::ONE)
            };
        add_residue_v1(
            &mut residues,
            current_aux[AUX_SOURCE_AFTER + lane],
            current_aux[AUX_SOURCE_BEFORE + lane].mul(source_factor),
        );
        add_residue_v1(
            &mut residues,
            current_aux[AUX_OUTPUT_AFTER + lane],
            current_aux[AUX_OUTPUT_BEFORE + lane].mul(output_factor),
        );
        if first_row {
            add_residue_v1(
                &mut residues,
                current_aux[AUX_COPY_NUMERATOR_BEFORE + lane],
                F::ONE,
            );
            add_residue_v1(
                &mut residues,
                current_aux[AUX_COPY_DENOMINATOR_BEFORE + lane],
                F::ONE,
            );
            add_residue_v1(&mut residues, current_aux[AUX_SOURCE_BEFORE + lane], F::ONE);
            add_residue_v1(&mut residues, current_aux[AUX_OUTPUT_BEFORE + lane], F::ONE);
        }
        if last_row {
            add_residue_v1(
                &mut residues,
                current_aux[AUX_COPY_NUMERATOR_AFTER + lane],
                current_aux[AUX_COPY_DENOMINATOR_AFTER + lane],
            );
            add_residue_v1(
                &mut residues,
                current_aux[AUX_SOURCE_AFTER + lane],
                current_aux[AUX_OUTPUT_AFTER + lane],
            );
        } else if let Some(next_aux) = next_aux {
            add_residue_v1(
                &mut residues,
                next_aux[AUX_COPY_NUMERATOR_BEFORE + lane],
                current_aux[AUX_COPY_NUMERATOR_AFTER + lane],
            );
            add_residue_v1(
                &mut residues,
                next_aux[AUX_COPY_DENOMINATOR_BEFORE + lane],
                current_aux[AUX_COPY_DENOMINATOR_AFTER + lane],
            );
            add_residue_v1(
                &mut residues,
                next_aux[AUX_SOURCE_BEFORE + lane],
                current_aux[AUX_SOURCE_AFTER + lane],
            );
            add_residue_v1(
                &mut residues,
                next_aux[AUX_OUTPUT_BEFORE + lane],
                current_aux[AUX_OUTPUT_AFTER + lane],
            );
        } else {
            residues.push(F::ONE);
        }
    }
    Ok(residues)
}
fn push_projection_stark_residue_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    residue: A,
) {
    residues.push(gate.mul(residue));
}
fn push_projection_stark_zero_base_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    row: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
) {
    for value in row {
        push_projection_stark_residue_v1(residues, gate, *value);
    }
}
fn push_projection_stark_zero_fields_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    row: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    fields: &[usize],
) {
    for field in fields {
        push_projection_stark_residue_v1(residues, gate, row[*field]);
    }
}
fn push_projection_stark_length_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    first: A,
    last: A,
    current: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
) {
    let not_last = A::ONE.sub(last);
    push_projection_stark_residue_v1(residues, gate.mul(first), current[LENGTH_ACC_BEFORE]);
    push_projection_stark_residue_v1(
        residues,
        gate,
        current[LENGTH_ACC_AFTER].sub(
            current[LENGTH_ACC_BEFORE]
                .mul(A::from_base(F(256)))
                .add(current[VALUE]),
        ),
    );
    push_projection_stark_residue_v1(
        residues,
        gate.mul(last),
        current[LENGTH_ACC_AFTER].sub(current[DECLARED_LENGTH]),
    );
    push_projection_stark_residue_v1(
        residues,
        gate.mul(last),
        next[DECLARED_LENGTH].sub(current[DECLARED_LENGTH]),
    );
    push_projection_stark_residue_v1(residues, gate.mul(last), next[REGION_BEFORE]);
    push_projection_stark_residue_v1(
        residues,
        gate.mul(not_last),
        next[LENGTH_ACC_BEFORE].sub(current[LENGTH_ACC_AFTER]),
    );
    push_projection_stark_residue_v1(
        residues,
        gate.mul(not_last),
        next[DECLARED_LENGTH].sub(current[DECLARED_LENGTH]),
    );
}
fn push_projection_stark_variable_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    first: A,
    last: A,
    monotone_transition: A,
    current: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
) {
    let not_last = A::ONE.sub(last);
    push_projection_stark_residue_v1(
        residues,
        gate,
        current[REGION_AFTER].sub(current[REGION_BEFORE].add(current[USED])),
    );
    push_projection_stark_residue_v1(
        residues,
        gate,
        current[VALUE].mul(A::ONE.sub(current[USED])),
    );
    push_projection_stark_residue_v1(residues, gate.mul(first), current[REGION_BEFORE]);
    push_projection_stark_residue_v1(residues, gate.mul(first), current[USED].sub(A::ONE));
    push_projection_stark_residue_v1(
        residues,
        gate.mul(last),
        current[REGION_AFTER].sub(current[DECLARED_LENGTH]),
    );
    push_projection_stark_residue_v1(
        residues,
        gate.mul(not_last),
        next[REGION_BEFORE].sub(current[REGION_AFTER]),
    );
    push_projection_stark_residue_v1(
        residues,
        gate.mul(not_last),
        next[DECLARED_LENGTH].sub(current[DECLARED_LENGTH]),
    );
    push_projection_stark_residue_v1(
        residues,
        monotone_transition,
        next[USED].mul(A::ONE.sub(current[USED])),
    );
}
/// Evaluate the projection AIR as one fixed-width polynomial vector.
///
/// Unlike the test-only native projection constraint evaluator, this evaluator has no native
/// fixed-row branch. Every branch selector, public output byte, copy label, and boundary flag is a
/// verifier-preprocessed polynomial opening. The same polynomial implementation
/// evaluates both base-field queries and genuine Fp4 out-of-domain points.
///
/// # Errors
///
/// Returns an error for malformed challenge or field encodings, or if the
/// compiled fixed-width constraint inventory changes unexpectedly.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_zk_x509_projection_stark_residues_v1<A: PolynomialAirFieldV1>(
    current: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    next: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1],
    current_aux: &[A; ZK_X509_PROJECTION_AUX_WIDTH_V1],
    next_aux: &[A; ZK_X509_PROJECTION_AUX_WIDTH_V1],
    fixed: &[A; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1],
    challenges: ZkX509ProjectionChallengesV1,
) -> Result<Vec<A>, ZkX509ProjectionAirErrorV1> {
    challenges.validate()?;
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509ProjectionAirErrorV1::NonCanonicalField);
    }
    let mut residues = Vec::with_capacity(ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1);
    let active = fixed[FIX_ACTIVE];
    let inactive = A::ONE.sub(active);
    let first = fixed[FIX_FIRST];
    let last = fixed[FIX_LAST];
    let not_last = A::ONE.sub(last);
    residues.push(current[USED].mul(current[USED].sub(A::ONE)));
    let mut reconstructed = A::ZERO;
    for bit in 0..8 {
        let value = current[VALUE_BITS + bit];
        residues.push(value.mul(value.sub(A::ONE)));
        reconstructed = reconstructed.add(value.mul(A::from_base(F(1_u64 << bit))));
    }
    residues.push(current[VALUE].sub(reconstructed));
    let input_spki = fixed[FIX_INPUT_SPKI];
    let input_spki_active = input_spki.mul(active);
    push_projection_stark_residue_v1(&mut residues, input_spki_active, current[USED].sub(A::ONE));
    push_projection_stark_zero_fields_v1(
        &mut residues,
        input_spki_active,
        current,
        &[
            MESSAGE_BEFORE,
            MESSAGE_AFTER,
            DECLARED_LENGTH,
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    push_projection_stark_zero_base_v1(&mut residues, input_spki.mul(inactive), current);
    let input_length = fixed[FIX_INPUT_LENGTH];
    let input_length_active = input_length.mul(active);
    push_projection_stark_zero_fields_v1(
        &mut residues,
        input_length_active,
        current,
        &[
            USED,
            MESSAGE_BEFORE,
            MESSAGE_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    push_projection_stark_length_v1(
        &mut residues,
        input_length_active,
        first,
        last,
        current,
        next,
    );
    push_projection_stark_zero_base_v1(&mut residues, input_length.mul(inactive), current);
    let input_byte = fixed[FIX_INPUT_BYTE];
    let input_byte_active = input_byte.mul(active);
    push_projection_stark_zero_fields_v1(
        &mut residues,
        input_byte_active,
        current,
        &[MESSAGE_BEFORE, MESSAGE_AFTER],
    );
    push_projection_stark_variable_v1(
        &mut residues,
        input_byte_active,
        first,
        last,
        fixed[FIX_USED_MONOTONE_TRANSITION],
        current,
        next,
    );
    push_projection_stark_zero_base_v1(&mut residues, input_byte.mul(inactive), current);
    let source = fixed[FIX_SOURCE];
    push_projection_stark_residue_v1(
        &mut residues,
        source,
        current[MESSAGE_AFTER].sub(current[MESSAGE_BEFORE].add(current[USED])),
    );
    push_projection_stark_residue_v1(&mut residues, source.mul(first), current[MESSAGE_BEFORE]);
    push_projection_stark_residue_v1(
        &mut residues,
        source.mul(last),
        next[DECLARED_LENGTH].sub(current[MESSAGE_AFTER]),
    );
    push_projection_stark_residue_v1(
        &mut residues,
        source.mul(not_last),
        next[MESSAGE_BEFORE].sub(current[MESSAGE_AFTER]),
    );
    let source_inactive = source.mul(inactive);
    push_projection_stark_zero_fields_v1(
        &mut residues,
        source_inactive,
        current,
        &[
            USED,
            VALUE,
            DECLARED_LENGTH,
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    let source_constant = active.mul(fixed[FIX_SOURCE_CONSTANT]);
    push_projection_stark_residue_v1(&mut residues, source_constant, current[USED].sub(A::ONE));
    push_projection_stark_residue_v1(
        &mut residues,
        source_constant,
        current[VALUE].sub(fixed[FIX_EXPECTED_BYTE]),
    );
    push_projection_stark_zero_fields_v1(
        &mut residues,
        source_constant,
        current,
        &[
            DECLARED_LENGTH,
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    let source_copy = active.mul(fixed[FIX_SOURCE_COPY]);
    push_projection_stark_residue_v1(&mut residues, source_copy, current[USED].sub(A::ONE));
    push_projection_stark_zero_fields_v1(
        &mut residues,
        source_copy,
        current,
        &[
            DECLARED_LENGTH,
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    let source_length = active.mul(fixed[FIX_SOURCE_LENGTH]);
    push_projection_stark_residue_v1(&mut residues, source_length, current[USED].sub(A::ONE));
    push_projection_stark_zero_fields_v1(
        &mut residues,
        source_length,
        current,
        &[REGION_BEFORE, REGION_AFTER],
    );
    push_projection_stark_length_v1(
        &mut residues,
        source_length,
        fixed[FIX_TOKEN_FIRST],
        fixed[FIX_TOKEN_LAST],
        current,
        next,
    );
    let source_variable = active.mul(fixed[FIX_SOURCE_VARIABLE]);
    push_projection_stark_zero_fields_v1(
        &mut residues,
        source_variable,
        current,
        &[LENGTH_ACC_BEFORE, LENGTH_ACC_AFTER],
    );
    push_projection_stark_variable_v1(
        &mut residues,
        source_variable,
        fixed[FIX_TOKEN_FIRST],
        fixed[FIX_TOKEN_LAST],
        fixed[FIX_USED_MONOTONE_TRANSITION],
        current,
        next,
    );
    let source_unused = active.mul(fixed[FIX_SOURCE_UNUSED]);
    push_projection_stark_zero_fields_v1(
        &mut residues,
        source_unused,
        current,
        &[
            USED,
            VALUE,
            DECLARED_LENGTH,
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    let message_length = fixed[FIX_MESSAGE_LENGTH];
    let message_length_active = message_length.mul(active);
    push_projection_stark_zero_fields_v1(
        &mut residues,
        message_length_active,
        current,
        &[
            USED,
            MESSAGE_BEFORE,
            MESSAGE_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    push_projection_stark_length_v1(
        &mut residues,
        message_length_active,
        first,
        last,
        current,
        next,
    );
    push_projection_stark_zero_base_v1(&mut residues, message_length.mul(inactive), current);
    let output = fixed[FIX_OUTPUT];
    let output_active = output.mul(active);
    push_projection_stark_residue_v1(
        &mut residues,
        output_active,
        current[MESSAGE_AFTER].sub(current[MESSAGE_BEFORE].add(current[USED])),
    );
    push_projection_stark_residue_v1(
        &mut residues,
        output_active,
        current[VALUE].mul(A::ONE.sub(current[USED])),
    );
    push_projection_stark_zero_fields_v1(
        &mut residues,
        output_active,
        current,
        &[
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    push_projection_stark_residue_v1(
        &mut residues,
        output_active.mul(first),
        current[MESSAGE_BEFORE],
    );
    push_projection_stark_residue_v1(
        &mut residues,
        output_active.mul(first),
        current[USED].sub(A::ONE),
    );
    push_projection_stark_residue_v1(
        &mut residues,
        output_active.mul(last),
        current[MESSAGE_AFTER].sub(current[DECLARED_LENGTH]),
    );
    push_projection_stark_residue_v1(
        &mut residues,
        output_active.mul(not_last),
        next[MESSAGE_BEFORE].sub(current[MESSAGE_AFTER]),
    );
    push_projection_stark_residue_v1(
        &mut residues,
        output_active.mul(not_last),
        next[DECLARED_LENGTH].sub(current[DECLARED_LENGTH]),
    );
    push_projection_stark_residue_v1(
        &mut residues,
        fixed[FIX_USED_MONOTONE_TRANSITION],
        next[USED].mul(A::ONE.sub(current[USED])),
    );
    push_projection_stark_zero_base_v1(&mut residues, output.mul(inactive), current);
    let digest = fixed[FIX_DIGEST];
    let digest_active = digest.mul(active);
    push_projection_stark_residue_v1(&mut residues, digest_active, current[USED].sub(A::ONE));
    push_projection_stark_residue_v1(
        &mut residues,
        digest_active,
        current[VALUE].sub(fixed[FIX_EXPECTED_BYTE]),
    );
    push_projection_stark_zero_fields_v1(
        &mut residues,
        digest_active,
        current,
        &[
            MESSAGE_BEFORE,
            MESSAGE_AFTER,
            DECLARED_LENGTH,
            LENGTH_ACC_BEFORE,
            LENGTH_ACC_AFTER,
            REGION_BEFORE,
            REGION_AFTER,
        ],
    );
    push_projection_stark_zero_base_v1(&mut residues, digest.mul(inactive), current);
    push_projection_stark_zero_base_v1(&mut residues, fixed[FIX_PADDING], current);
    for lane in 0..COPY_LANES {
        let copy = challenges.copy[lane];
        let identity_term = A::from_base(copy.gamma)
            .add(current[VALUE])
            .add(A::from_base(copy.beta).mul(fixed[FIX_COPY_IDENTITY]));
        let sigma_term = A::from_base(copy.gamma)
            .add(current[VALUE])
            .add(A::from_base(copy.beta).mul(fixed[FIX_COPY_SIGMA]));
        residues.push(
            current_aux[AUX_COPY_NUMERATOR_AFTER + lane]
                .sub(current_aux[AUX_COPY_NUMERATOR_BEFORE + lane].mul(sigma_term)),
        );
        residues.push(
            current_aux[AUX_COPY_DENOMINATOR_AFTER + lane]
                .sub(current_aux[AUX_COPY_DENOMINATOR_BEFORE + lane].mul(identity_term)),
        );
        let compact = challenges.compaction[lane];
        let tuple = A::from_base(compact.active)
            .add(A::from_base(compact.invocation).mul(fixed[FIX_INVOCATION]))
            .add(A::from_base(compact.position).mul(current[MESSAGE_BEFORE]))
            .add(A::from_base(compact.value).mul(current[VALUE]));
        let term = A::from_base(compact.gamma).add(current[USED].mul(tuple));
        let source_factor = A::ONE.add(source.mul(term.sub(A::ONE)));
        let output_factor = A::ONE.add(output.mul(term.sub(A::ONE)));
        residues.push(
            current_aux[AUX_SOURCE_AFTER + lane]
                .sub(current_aux[AUX_SOURCE_BEFORE + lane].mul(source_factor)),
        );
        residues.push(
            current_aux[AUX_OUTPUT_AFTER + lane]
                .sub(current_aux[AUX_OUTPUT_BEFORE + lane].mul(output_factor)),
        );
        let first_row = fixed[FIX_FIRST_ROW];
        residues.push(first_row.mul(current_aux[AUX_COPY_NUMERATOR_BEFORE + lane].sub(A::ONE)));
        residues.push(first_row.mul(current_aux[AUX_COPY_DENOMINATOR_BEFORE + lane].sub(A::ONE)));
        residues.push(first_row.mul(current_aux[AUX_SOURCE_BEFORE + lane].sub(A::ONE)));
        residues.push(first_row.mul(current_aux[AUX_OUTPUT_BEFORE + lane].sub(A::ONE)));
        let last_row = fixed[FIX_LAST_ROW];
        residues.push(
            last_row.mul(
                current_aux[AUX_COPY_NUMERATOR_AFTER + lane]
                    .sub(current_aux[AUX_COPY_DENOMINATOR_AFTER + lane]),
            ),
        );
        residues.push(
            last_row.mul(
                current_aux[AUX_SOURCE_AFTER + lane].sub(current_aux[AUX_OUTPUT_AFTER + lane]),
            ),
        );
        let transition = A::ONE.sub(last_row);
        residues.push(
            transition.mul(
                next_aux[AUX_COPY_NUMERATOR_BEFORE + lane]
                    .sub(current_aux[AUX_COPY_NUMERATOR_AFTER + lane]),
            ),
        );
        residues.push(
            transition.mul(
                next_aux[AUX_COPY_DENOMINATOR_BEFORE + lane]
                    .sub(current_aux[AUX_COPY_DENOMINATOR_AFTER + lane]),
            ),
        );
        residues.push(
            transition
                .mul(next_aux[AUX_SOURCE_BEFORE + lane].sub(current_aux[AUX_SOURCE_AFTER + lane])),
        );
        residues.push(
            transition
                .mul(next_aux[AUX_OUTPUT_BEFORE + lane].sub(current_aux[AUX_OUTPUT_AFTER + lane])),
        );
    }
    if residues.len() != ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    Ok(residues)
}
/// Validate every row of a complete base/aux projection trace.
///
/// # Errors
///
/// Returns a strict topology, challenge, field, or algebraic error.
#[cfg(test)]
pub fn validate_zk_x509_projection_trace_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    trace: &ZkX509ProjectionTraceV1,
    challenges: ZkX509ProjectionChallengesV1,
) -> Result<ZkX509ProjectionAuxTraceV1, ZkX509ProjectionAirErrorV1> {
    let expected_fixed = compile_zk_x509_projection_fixed_trace_v1(statement)?;
    if trace.fixed != expected_fixed || trace.base.rows.len() != ZK_X509_PROJECTION_TRACE_SIZE_V1 {
        return Err(ZkX509ProjectionAirErrorV1::Topology);
    }
    let aux = build_zk_x509_projection_aux_trace_v1(&trace.base, &trace.fixed, challenges)?;
    for index in 0..ZK_X509_PROJECTION_TRACE_SIZE_V1 {
        let next_index = index + 1;
        let residues = evaluate_zk_x509_projection_constraint_residues_v1(
            &trace.base.rows[index],
            trace.base.rows.get(next_index),
            &aux.rows[index],
            aux.rows.get(next_index),
            trace.fixed.rows[index],
            trace.fixed.rows.get(next_index).copied(),
            trace.fixed.copy_identity[index],
            trace.fixed.copy_sigma[index],
            challenges,
            index == 0,
            next_index == ZK_X509_PROJECTION_TRACE_SIZE_V1,
        )?;
        if residues.iter().any(|residue| *residue != F::ZERO) {
            return Err(ZkX509ProjectionAirErrorV1::Constraint);
        }
    }
    Ok(aux)
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::io_air::build_zk_x509_io_base_tables_v1;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        block::BlockHeader,
        privacy::{
            PrivacyAttributeDigestV1, PrivacyCertificateKeyDigestV1, PrivacyChallengeV1,
            PrivacyEngineManifestDigestV1, PrivacyIssuerIdV1, PrivacyNullifierV1,
            PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPolicyIdV1, PrivacyRootV1,
            PrivacyStatementContextV1, PrivacyStatementSchemaDigestV1,
            PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1,
            PrivacyX509ExtendedKeyUsageV1, PrivacyX509KeyUsageV1,
            PrivacyZkX509CertificatePolicyRecordDigestV1, PrivacyZkX509CrlRecordDigestV1,
            PrivacyZkX509DisclosedAttributeV1, PrivacyZkX509TrustAnchorRecordDigestV1,
        },
    };
    fn raw(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    pub fn account(seed: u8) -> AccountId {
        let key_pair =
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("fixed account seed");
        AccountId::new(key_pair.public_key().clone())
    }
    pub(super) fn challenges() -> ZkX509ProjectionChallengesV1 {
        ZkX509ProjectionChallengesV1 {
            copy: [
                ZkX509ProjectionCopyChallengesV1 {
                    beta: F(3),
                    gamma: F(5),
                },
                ZkX509ProjectionCopyChallengesV1 {
                    beta: F(7),
                    gamma: F(11),
                },
                ZkX509ProjectionCopyChallengesV1 {
                    beta: F(13),
                    gamma: F(17),
                },
                ZkX509ProjectionCopyChallengesV1 {
                    beta: F(83),
                    gamma: F(89),
                },
            ],
            compaction: [
                ZkX509ProjectionCompactionChallengesV1 {
                    active: F(19),
                    invocation: F(23),
                    position: F(29),
                    value: F(31),
                    gamma: F(37),
                },
                ZkX509ProjectionCompactionChallengesV1 {
                    active: F(41),
                    invocation: F(43),
                    position: F(47),
                    value: F(53),
                    gamma: F(59),
                },
                ZkX509ProjectionCompactionChallengesV1 {
                    active: F(61),
                    invocation: F(67),
                    position: F(71),
                    value: F(73),
                    gamma: F(79),
                },
                ZkX509ProjectionCompactionChallengesV1 {
                    active: F(97),
                    invocation: F(101),
                    position: F(103),
                    value: F(107),
                    gamma: F(109),
                },
            ],
        }
    }
    pub fn fixture() -> (IrohaZkX509StarkP256StatementV1, ZkX509ProjectionWitnessV1) {
        let witness = ZkX509ProjectionWitnessV1 {
            chain_spki_der: vec![
                (0..ZK_X509_PROJECTION_SPKI_DER_BYTES_V1)
                    .map(|offset| 0x20_u8.wrapping_add(offset as u8))
                    .collect(),
                (0..ZK_X509_PROJECTION_SPKI_DER_BYTES_V1)
                    .map(|offset| 0x80_u8.wrapping_add(offset as u8))
                    .collect(),
            ],
            leaf_serial: vec![1, 0xA4, 0x5C],
            disclosed_attribute_values: vec![b"IL".to_vec(), b"Alice".to_vec()],
            attribute_salts: vec![[0xD1; 32], [0xE2; 32]],
        };
        let mut statement = IrohaZkX509StarkP256StatementV1 {
            context: PrivacyStatementContextV1 {
                network_id: NetworkId::from_genesis_hash(
                    HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(raw(0x91))),
                ),
                action_index: 2,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(1)),
                parameter_id: PrivacyParameterIdV1::new(raw(2)),
                parameter_digest: PrivacyParameterDigestV1::new(raw(3)),
                verifier_digest: PrivacyVerifierDigestV1::new(raw(4)),
                statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(5)),
                engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(6)),
            },
            trust_anchor_id: PrivacyIssuerIdV1::new(raw(7)),
            certificate_policy_id: PrivacyPolicyIdV1::new(raw(8)),
            trust_anchor_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1::new(raw(9)),
            trust_anchor_record_epoch: 1,
            certificate_policy_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1::new(
                raw(10),
            ),
            certificate_policy_record_epoch: 1,
            crl_record_digest: PrivacyZkX509CrlRecordDigestV1::new(raw(11)),
            crl_record_epoch: 1,
            subject_public_key_digest: PrivacyCertificateKeyDigestV1::new(raw(12)),
            ca_membership_root: PrivacyRootV1::new(raw(13)),
            ca_membership_root_epoch: 1,
            key_usage: PrivacyX509KeyUsageV1 {
                digital_signature: true.into(),
                content_commitment: false.into(),
                key_encipherment: false.into(),
                key_agreement: false.into(),
            },
            extended_key_usages: vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            disclosed_attributes: vec![
                PrivacyZkX509DisclosedAttributeV1 {
                    index: 0,
                    attribute_digest: PrivacyAttributeDigestV1::new(raw(15)),
                },
                PrivacyZkX509DisclosedAttributeV1 {
                    index: 3,
                    attribute_digest: PrivacyAttributeDigestV1::new(raw(16)),
                },
            ],
            presentation_not_before_unix_seconds: 1_800_000_000,
            presentation_not_after_unix_seconds: 1_800_000_300,
            wallet_account: account(17),
            wallet_challenge: PrivacyChallengeV1::new(raw(18)),
            certificate_nullifier: PrivacyNullifierV1::new(raw(19)),
        };
        let relation_version = ZK_X509_RELATION_VERSION_V1.to_be_bytes();
        statement.subject_public_key_digest = PrivacyCertificateKeyDigestV1::new(
            hash_public_frame_v1(
                ZK_X509_SCOPED_KEY_DOMAIN_V1,
                &[
                    ZK_X509_SUITE_V1,
                    ZK_X509_SOURCE_PROFILE_V1,
                    &relation_version,
                    statement.trust_anchor_id.as_bytes(),
                    statement.certificate_policy_id.as_bytes(),
                    statement.trust_anchor_record_digest.as_bytes(),
                    statement.certificate_policy_record_digest.as_bytes(),
                    &witness.chain_spki_der[0],
                ],
            )
            .expect("scoped digest"),
        );
        statement.certificate_nullifier = PrivacyNullifierV1::new(
            hash_public_frame_v1(
                ZK_X509_NULLIFIER_DOMAIN_V1,
                &[
                    ZK_X509_SUITE_V1,
                    statement.trust_anchor_id.as_bytes(),
                    statement.certificate_policy_id.as_bytes(),
                    &witness.chain_spki_der[1],
                    &witness.leaf_serial,
                ],
            )
            .expect("nullifier"),
        );
        for disclosure in 0..statement.disclosed_attributes.len() {
            let index = [statement.disclosed_attributes[disclosure].index];
            statement.disclosed_attributes[disclosure].attribute_digest =
                PrivacyAttributeDigestV1::new(
                    hash_public_frame_v1(
                        ZK_X509_ATTRIBUTE_DOMAIN_V1,
                        &[
                            ZK_X509_SUITE_V1,
                            statement.trust_anchor_id.as_bytes(),
                            statement.certificate_policy_id.as_bytes(),
                            &index,
                            &witness.disclosed_attribute_values[disclosure],
                            &witness.attribute_salts[disclosure],
                        ],
                    )
                    .expect("attribute digest"),
                );
        }
        (statement, witness)
    }
    fn row_index(
        trace: &ZkX509ProjectionTraceV1,
        predicate: impl Fn(ZkX509ProjectionFixedRowV1) -> bool,
    ) -> usize {
        trace
            .fixed
            .rows
            .iter()
            .copied()
            .position(predicate)
            .expect("fixed row exists")
    }
    #[test]
    fn canonical_projection_trace_and_io_are_complete() {
        let (statement, witness) = fixture();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        let aux = validate_zk_x509_projection_trace_v1(&statement, &trace, challenges())
            .expect("all algebraic rows");
        assert_eq!(trace.base.rows.len(), ZK_X509_PROJECTION_TRACE_SIZE_V1);
        assert_eq!(trace.fixed.rows.len(), ZK_X509_PROJECTION_TRACE_SIZE_V1);
        assert_eq!(aux.rows.len(), ZK_X509_PROJECTION_TRACE_SIZE_V1);
        assert_eq!(
            trace
                .fixed
                .rows
                .iter()
                .filter(|row| matches!(row, ZkX509ProjectionFixedRowV1::Padding))
                .count(),
            ZK_X509_PROJECTION_TRACE_SIZE_V1
                - (3 * ZK_X509_PROJECTION_SPKI_DER_BYTES_V1
                    + 8
                    + ZK_X509_MAX_SERIAL_BYTES_V1
                    + ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1
                        * (8 + ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1)
                    + ZK_X509_PROJECTION_HASH_SLOTS_V1
                        * (2 * ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1 + 8 + 32))
        );
        let shared =
            projection_io_witnesses_v1(trace.io_channels.clone(), 0).expect("shared I/O witnesses");
        build_zk_x509_io_base_tables_v1(&shared).expect("canonical cross-segment channels");
        let public_values = shared
            .iter()
            .filter_map(|channel| channel.declaration.public_value.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(public_values.len(), 4);
        assert!(public_values.iter().all(|value| value.len() == 32));
        assert!(
            public_values
                .iter()
                .all(|value| !value.windows(32).any(|window| window == [0xD1; 32]))
        );
        assert_eq!(
            trace.io_channels[..ZK_X509_MAX_CHAIN_DEPTH_V1]
                .iter()
                .map(|channel| channel.value.len())
                .collect::<Vec<_>>(),
            vec![ZK_X509_PROJECTION_SPKI_DER_BYTES_V1; ZK_X509_MAX_CHAIN_DEPTH_V1]
        );
        assert_eq!(
            trace.io_channels[ZK_X509_MAX_CHAIN_DEPTH_V1 - 1].value,
            vec![0; ZK_X509_PROJECTION_SPKI_DER_BYTES_V1],
            "the absent third certificate has one canonical private encoding"
        );
    }
    #[test]
    fn scoped_subject_key_is_leaf_only_and_private_depth_has_one_fixed_topology() {
        let (statement, witness) = fixture();
        for offset in 0..ZK_X509_PROJECTION_SPKI_DER_BYTES_V1 {
            let mut changed = witness.clone();
            changed.chain_spki_der[0][offset] ^= 1;
            assert_eq!(
                build_zk_x509_projection_trace_v1(&statement, &changed),
                Err(ZkX509ProjectionAirErrorV1::ProjectionMismatch),
                "leaf SPKI byte {offset} must be bound by the public digest"
            );
        }
        let baseline =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("depth-two trace");
        let mut depth_three = witness.clone();
        depth_three.chain_spki_der.push(
            (0..ZK_X509_PROJECTION_SPKI_DER_BYTES_V1)
                .map(|offset| 0xC0_u8.wrapping_add(offset as u8))
                .collect(),
        );
        let depth_three_trace = build_zk_x509_projection_trace_v1(&statement, &depth_three)
            .expect("parent-only depth change does not alter leaf digest");
        assert_eq!(
            baseline.fixed.copy_identity,
            depth_three_trace.fixed.copy_identity
        );
        assert_eq!(
            baseline.fixed.copy_sigma,
            depth_three_trace.fixed.copy_sigma
        );
        assert_eq!(
            baseline.io_channels.len(),
            depth_three_trace.io_channels.len()
        );
        assert_eq!(
            baseline
                .io_channels
                .iter()
                .map(|channel| {
                    (
                        channel.producer,
                        channel.consumers.clone(),
                        channel.value.len(),
                        channel.public_value.is_some(),
                    )
                })
                .collect::<Vec<_>>(),
            depth_three_trace
                .io_channels
                .iter()
                .map(|channel| {
                    (
                        channel.producer,
                        channel.consumers.clone(),
                        channel.value.len(),
                        channel.public_value.is_some(),
                    )
                })
                .collect::<Vec<_>>(),
            "private depth cannot change channel topology or lengths"
        );
        let mut one_slot = witness.clone();
        one_slot.chain_spki_der.pop();
        assert_eq!(
            build_zk_x509_projection_trace_v1(&statement, &one_slot),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
        let mut four_slots = depth_three;
        four_slots
            .chain_spki_der
            .push(vec![0xA5; ZK_X509_PROJECTION_SPKI_DER_BYTES_V1]);
        assert_eq!(
            build_zk_x509_projection_trace_v1(&statement, &four_slots),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
        let mut noncanonical_dummy = witness;
        noncanonical_dummy
            .chain_spki_der
            .push(vec![0; ZK_X509_PROJECTION_SPKI_DER_BYTES_V1]);
        assert_eq!(
            build_zk_x509_projection_trace_v1(&statement, &noncanonical_dummy),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
    }
    #[test]
    fn aggregate_numeric_fixed_evaluator_matches_every_canonical_row() {
        let (statement, witness) = fixture();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        let challenges = challenges();
        let aux = build_zk_x509_projection_aux_trace_v1(&trace.base, &trace.fixed, challenges)
            .expect("projection aux");
        let fixed =
            compile_zk_x509_projection_stark_fixed_rows_v1(&statement).expect("numeric fixed rows");
        assert_eq!(fixed.len(), ZK_X509_PROJECTION_TRACE_SIZE_V1);
        for index in 0..ZK_X509_PROJECTION_TRACE_SIZE_V1 {
            let next = (index + 1) % ZK_X509_PROJECTION_TRACE_SIZE_V1;
            let residues = evaluate_zk_x509_projection_stark_residues_v1(
                &trace.base.rows[index],
                &trace.base.rows[next],
                &aux.rows[index],
                &aux.rows[next],
                &fixed[index],
                challenges,
            )
            .expect("numeric residues");
            assert_eq!(residues.len(), ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1);
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "numeric aggregate row {index} must satisfy every residue"
            );
        }
    }
    #[test]
    fn combined_monotone_gate_is_exact_and_keeps_the_fri_degree_bounded() {
        let (statement, _) = fixture();
        let semantic =
            compile_zk_x509_projection_fixed_trace_v1(&statement).expect("semantic fixed rows");
        let numeric =
            compile_zk_x509_projection_stark_fixed_rows_v1(&statement).expect("numeric fixed rows");
        assert_eq!(ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1, 25);
        assert_eq!(ZK_X509_PROJECTION_STARK_CONSTRAINT_DEGREE_V1, 4);
        for (index, row) in semantic.rows.iter().copied().enumerate() {
            let expected = match row {
                ZkX509ProjectionFixedRowV1::InputByte { active, last, .. }
                | ZkX509ProjectionFixedRowV1::Output { active, last, .. } => active && !last,
                ZkX509ProjectionFixedRowV1::Source { active, token, .. } => {
                    active
                        && source_variable_position_v1(token).is_some_and(|(_, _, _, last)| !last)
                }
                _ => false,
            };
            assert_eq!(
                numeric[index][FIX_USED_MONOTONE_TRANSITION],
                F(u64::from(expected)),
                "combined monotone gate at row {index}"
            );
        }
    }
    #[test]
    fn zero_disclosure_statement_keeps_the_fixed_topology() {
        let (mut statement, mut witness) = fixture();
        statement.disclosed_attributes.clear();
        witness.disclosed_attribute_values.clear();
        witness.attribute_salts.clear();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        validate_zk_x509_projection_trace_v1(&statement, &trace, challenges())
            .expect("all algebraic rows");
        assert_eq!(trace.base.rows.len(), ZK_X509_PROJECTION_TRACE_SIZE_V1);
        assert_eq!(
            trace
                .io_channels
                .iter()
                .filter(|channel| channel.public_value.is_some())
                .count(),
            2
        );
        assert_eq!(
            trace
                .fixed
                .rows
                .iter()
                .filter(|row| matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::Source {
                        invocation: 2..=5,
                        active: false,
                        ..
                    }
                ))
                .count(),
            4 * ZK_X509_PROJECTION_HASH_BUFFER_BYTES_V1
        );
    }
    #[test]
    fn every_projection_row_family_fails_closed_under_mutation() {
        let (statement, witness) = fixture();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        let indices = [
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::InputSpki {
                        active: true,
                        offset: 0,
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::InputLength {
                        active: true,
                        byte: 7,
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::InputByte {
                        active: true,
                        offset: 0,
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::Source {
                        token: ZkX509ProjectionSourceTokenV1::Constant(_),
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::Source {
                        token: ZkX509ProjectionSourceTokenV1::Serial(_),
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::MessageLength {
                        active: true,
                        byte: 7,
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(
                    row,
                    ZkX509ProjectionFixedRowV1::Output {
                        active: true,
                        offset: 0,
                        ..
                    }
                )
            }),
            row_index(&trace, |row| {
                matches!(row, ZkX509ProjectionFixedRowV1::Digest { active: true, .. })
            }),
            row_index(&trace, |row| {
                matches!(row, ZkX509ProjectionFixedRowV1::Padding)
            }),
        ];
        for (mutation, index) in indices.into_iter().enumerate() {
            let mut changed = trace.clone();
            let column = if mutation % 2 == 0 { VALUE } else { USED };
            changed.base.rows[index][column] = changed.base.rows[index][column].add(F::ONE);
            assert!(
                validate_zk_x509_projection_trace_v1(&statement, &changed, challenges()).is_err(),
                "mutation {mutation} at row {index} must fail"
            );
        }
        let mut noncanonical = trace.clone();
        noncanonical.base.rows[0][VALUE] = F(GOLDILOCKS_MODULUS_V1);
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&statement, &noncanonical, challenges()),
            Err(ZkX509ProjectionAirErrorV1::NonCanonicalField)
        );
    }
    #[test]
    fn fixed_topology_copy_cycles_and_padding_are_not_prover_selectable() {
        let (statement, witness) = fixture();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        let mut changed_sigma = trace.clone();
        changed_sigma.fixed.copy_sigma.swap(0, 1);
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&statement, &changed_sigma, challenges()),
            Err(ZkX509ProjectionAirErrorV1::Topology)
        );
        let mut changed_fixed = trace.clone();
        let digest = row_index(&changed_fixed, |row| {
            matches!(row, ZkX509ProjectionFixedRowV1::Digest { active: true, .. })
        });
        if let ZkX509ProjectionFixedRowV1::Digest { expected, .. } =
            &mut changed_fixed.fixed.rows[digest]
        {
            *expected ^= 1;
        }
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&statement, &changed_fixed, challenges()),
            Err(ZkX509ProjectionAirErrorV1::Topology)
        );
        let mut truncated = trace.clone();
        truncated.base.rows.pop();
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&statement, &truncated, challenges()),
            Err(ZkX509ProjectionAirErrorV1::Topology)
        );
    }
    #[test]
    fn statement_and_private_length_replays_fail_closed() {
        let (statement, witness) = fixture();
        let mut reordered = statement.clone();
        reordered.disclosed_attributes.swap(0, 1);
        assert_eq!(
            build_zk_x509_projection_trace_v1(&reordered, &witness),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
        let mut cross_policy = statement.clone();
        cross_policy.certificate_policy_id = PrivacyPolicyIdV1::new(raw(0xA0));
        assert_eq!(
            build_zk_x509_projection_trace_v1(&cross_policy, &witness),
            Err(ZkX509ProjectionAirErrorV1::ProjectionMismatch)
        );
        let mut cross_transaction = statement.clone();
        cross_transaction.context.transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new(raw(0xA1));
        let old_trace = build_zk_x509_projection_trace_v1(&statement, &witness).expect("old trace");
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&cross_transaction, &old_trace, challenges()),
            Err(ZkX509ProjectionAirErrorV1::Topology)
        );
        let mut leading_zero = witness.clone();
        leading_zero.leaf_serial[0] = 0;
        assert_eq!(
            build_zk_x509_projection_trace_v1(&statement, &leading_zero),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
        let mut oversized = witness.clone();
        oversized.disclosed_attribute_values[0] =
            vec![0x55; ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1 + 1];
        assert_eq!(
            build_zk_x509_projection_trace_v1(&statement, &oversized),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
        let mut wrong_spki = witness.clone();
        wrong_spki.chain_spki_der[0].pop();
        assert_eq!(
            build_zk_x509_projection_trace_v1(&statement, &wrong_spki),
            Err(ZkX509ProjectionAirErrorV1::Shape)
        );
    }
    #[test]
    fn challenge_substitution_and_auxiliary_product_mutations_fail() {
        let (statement, witness) = fixture();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        let mut invalid = challenges();
        invalid.copy[0].beta = F::ZERO;
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&statement, &trace, invalid),
            Err(ZkX509ProjectionAirErrorV1::Challenge)
        );
        let mut repeated = challenges();
        repeated.compaction[1] = repeated.compaction[0];
        assert_eq!(
            validate_zk_x509_projection_trace_v1(&statement, &trace, repeated),
            Err(ZkX509ProjectionAirErrorV1::Challenge)
        );
        let aux = build_zk_x509_projection_aux_trace_v1(&trace.base, &trace.fixed, challenges())
            .expect("aux");
        let index = row_index(&trace, |row| {
            matches!(row, ZkX509ProjectionFixedRowV1::Source { active: true, .. })
        });
        let mut changed_aux = aux.clone();
        changed_aux.rows[index][AUX_SOURCE_AFTER] =
            changed_aux.rows[index][AUX_SOURCE_AFTER].add(F::ONE);
        let residues = evaluate_zk_x509_projection_constraint_residues_v1(
            &trace.base.rows[index],
            trace.base.rows.get(index + 1),
            &changed_aux.rows[index],
            changed_aux.rows.get(index + 1),
            trace.fixed.rows[index],
            trace.fixed.rows.get(index + 1).copied(),
            trace.fixed.copy_identity[index],
            trace.fixed.copy_sigma[index],
            challenges(),
            index == 0,
            index + 1 == trace.base.rows.len(),
        )
        .expect("residues");
        assert!(residues.iter().any(|residue| *residue != F::ZERO));
    }
    #[test]
    fn copy_product_is_total_at_a_challenge_collision_and_rejects_a_bad_multiset() {
        let (statement, witness) = fixture();
        let trace =
            build_zk_x509_projection_trace_v1(&statement, &witness).expect("projection trace");
        let mut collision = challenges();
        let beta = collision.copy[0].beta;
        let collision_index = (0..trace.base.rows.len())
            .find(|index| {
                trace.base.rows[*index][VALUE].add(beta.mul(trace.fixed.copy_identity[*index]))
                    != F::ZERO
            })
            .expect("a non-zero copy denominator without gamma");
        collision.copy[0].gamma = F::ZERO.sub(
            trace.base.rows[collision_index][VALUE]
                .add(beta.mul(trace.fixed.copy_identity[collision_index])),
        );
        collision
            .validate()
            .expect("valid distinct challenge lanes");
        validate_zk_x509_projection_trace_v1(&statement, &trace, collision)
            .expect("dual products cannot abort when one denominator factor is zero");
        let zero_numerator_index = (0..trace.base.rows.len())
            .find(|index| {
                collision.copy[0]
                    .gamma
                    .add(trace.base.rows[*index][VALUE])
                    .add(beta.mul(trace.fixed.copy_sigma[*index]))
                    == F::ZERO
            })
            .expect("the valid permutation has a matching zero numerator");
        let mut malformed_fixed = trace.fixed.clone();
        malformed_fixed.copy_sigma[zero_numerator_index] =
            malformed_fixed.copy_sigma[zero_numerator_index].add(F::ONE);
        assert_eq!(
            build_zk_x509_projection_aux_trace_v1(&trace.base, &malformed_fixed, collision,),
            Err(ZkX509ProjectionAirErrorV1::Constraint),
            "the independent non-colliding lanes must reject a malformed copy multiset",
        );
    }
}

#[cfg(test)]
#[path = "projection_air_fp4_tests.rs"]
mod fp4_tests;

#[cfg(test)]
#[path = "projection_air_cleanup_tests.rs"]
mod cleanup_tests;
