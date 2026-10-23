//! Canonical native commitments: unkeyed BLAKE3-256 over the frozen V1 frame.
//!
//! This owner implements `native.commitment.blake3-256.frame-v1`. It retains
//! every domain position, payload boundary and coordinate. Algorithm and digest
//! profile labels are fixed; there is no alternate hash or compatibility mode.
//! The output contains all 32 raw bytes, without the ledger [`crate::Hash`] marker.
//!
//! A frame is a borrowed, validated view. Validation and hashing allocate no
//! payload storage. Callers still enforce their own admission/work ceilings:
//! protocol length bounds are not permission to allocate their maximum size.
//!
//! Consumers migrate with their complete proof profiles and wire fixtures.
//! This encoder alone does not qualify a proof system. Proof-internal hashes
//! and the deferred spentness construction have separate owners and must not
//! be replaced with this digest.

use core::fmt;
use fastpq_isi::semantic_profile::{
    SemanticProfileErrorV1, SemanticProfileKindV1, SemanticProfileV1, SemanticProfileValueV1,
};

/// Frozen semantic profile name, independent of builds and source revisions.
pub const NATIVE_COMMITMENT_PROFILE_NAME_V1: &str = "native.commitment.blake3-256.frame-v1";
/// Complete frame magic, including the zero terminator.
pub const NATIVE_COMMITMENT_MAGIC_V1: &[u8; 33] = b"iroha:native-commitment:frame:v1\0";
/// Algorithm label written at tag 1.
pub const NATIVE_COMMITMENT_ALGORITHM_V1: &str = "blake3-256";
/// Digest profile label written at tag 4.
pub const NATIVE_COMMITMENT_PROFILE_V1: &str = "native-commitment-blake3-256-v1";
/// Maximum length of each labelled domain field.
pub const NATIVE_COMMITMENT_MAX_DOMAIN_BYTES_V1: usize = 4096;
/// Maximum number of ordered payload fields.
pub const NATIVE_COMMITMENT_MAX_FIELDS_V1: usize = 65_535;
/// Maximum length of one payload field; its frame length still uses a `u64`.
pub const NATIVE_COMMITMENT_MAX_FIELD_BYTES_V1: u64 = u32::MAX as u64;

const FRAME_LAYOUT: &str = "1:magic:magic;2:algorithm:bytes-u32-le:tag=1;3:catalog:bytes-u32-le:tag=2;4:protocol:bytes-u32-le:tag=3;5:profile:bytes-u32-le:tag=4;6:role:bytes-u32-le:tag=5;7:phase:bytes-u32-le:tag=6;8:level:u64-le:tag=7;9:index:u64-le:tag=8;10:counter:u64-le:tag=9;11:field_count:count-u32-le:tag=10;12:fields:each-bytes-u64-le:tag=11";

/// Recompute the frozen semantic identity from the encoder's typed parameters.
///
/// This SHA3-256 descriptor identity is distinct from a native commitment. It
/// grants no authority and contains no source, build or measurement digest.
///
/// # Errors
/// Returns a semantic-profile encoding error if the fixed descriptor is invalid.
pub fn native_commitment_profile_v1() -> Result<SemanticProfileV1, SemanticProfileErrorV1> {
    use SemanticProfileValueV1::{Bytes, Text, U64};
    SemanticProfileV1::new(
        SemanticProfileKindV1::NativeCommitment,
        NATIVE_COMMITMENT_PROFILE_NAME_V1,
        &[
            ("profile_version", U64(1)),
            ("algorithm", Text("BLAKE3:unkeyed:default-32-byte-output")),
            (
                "mode",
                Text("plain-hash-of-the-whole-frame:no-key:no-derive-key"),
            ),
            ("output_bytes", U64(NativeCommitmentDigestV1::BYTES as u64)),
            ("frame_version", U64(1)),
            ("frame_magic", Bytes(NATIVE_COMMITMENT_MAGIC_V1)),
            (
                "frame_algorithm_field",
                Text(NATIVE_COMMITMENT_ALGORITHM_V1),
            ),
            ("frame_profile_field", Text(NATIVE_COMMITMENT_PROFILE_V1)),
            ("frame_layout", Text(FRAME_LAYOUT)),
            (
                "domain_field_max_bytes",
                U64(NATIVE_COMMITMENT_MAX_DOMAIN_BYTES_V1 as u64),
            ),
            (
                "payload_field_count_max",
                U64(NATIVE_COMMITMENT_MAX_FIELDS_V1 as u64),
            ),
            (
                "payload_field_max_bytes",
                U64(NATIVE_COMMITMENT_MAX_FIELD_BYTES_V1),
            ),
            (
                "absent_fields",
                Text("every-position-encoded:empty-is-length-zero:no-omission"),
            ),
        ],
    )
}

/// Consumer-owned domain of one native commitment.
///
/// All positions are encoded, even when empty or zero. The profile position is
/// always [`NATIVE_COMMITMENT_PROFILE_V1`]. A consumer binds its complete proof
/// context through these exact domain bytes and its ordered payload fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCommitmentDomainV1<'a> {
    /// Exact catalog identity.
    pub catalog: &'a [u8],
    /// Exact protocol identity.
    pub protocol: &'a [u8],
    /// Consumer role, such as a catalog commitment or an authorization identity.
    pub role: &'a [u8],
    /// Phase within the role.
    pub phase: &'a [u8],
    /// Tree level, or zero when the consumer has no tree coordinate.
    pub level: u64,
    /// Position, or zero when not applicable.
    pub index: u64,
    /// Counter, or zero when not applicable.
    pub counter: u64,
}

/// Why a native frame or expected digest was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCommitmentErrorV1 {
    /// A labelled domain field exceeds 4096 bytes.
    DomainTooLong,
    /// The ordered payload count exceeds 65535.
    TooManyFields,
    /// A payload field exceeds the V1 32-bit byte ceiling.
    FieldTooLong,
    /// The stream supplied fewer or more fields than its declared exact count.
    FieldCountMismatch,
    /// The provided frame buffer does not have the exact complete length.
    FrameLength,
    /// An expected digest is not exactly 32 bytes.
    DigestLength,
    /// An expected full-width digest does not match this exact frame.
    DigestMismatch,
}

impl fmt::Display for NativeCommitmentErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DomainTooLong => "native commitment domain exceeds 4096 bytes",
            Self::TooManyFields => "native commitment has more than 65535 fields",
            Self::FieldTooLong => "native commitment field exceeds the V1 byte ceiling",
            Self::FieldCountMismatch => "native commitment stream has the wrong field count",
            Self::FrameLength => "native commitment frame buffer has the wrong length",
            Self::DigestLength => "native commitment digest must contain exactly 32 bytes",
            Self::DigestMismatch => "native commitment digest does not match its exact frame",
        })
    }
}

impl std::error::Error for NativeCommitmentErrorV1 {}

/// Full raw BLAKE3-256 output of a validated native frame.
///
/// This type does not use a ledger hash marker, expose a truncated projection,
/// authenticate a proof, or establish authority for the committed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeCommitmentDigestV1([u8; Self::BYTES]);

impl NativeCommitmentDigestV1 {
    /// Complete digest size; shorter projections are not commitments.
    pub const BYTES: usize = 32;

    /// Borrow every raw digest byte without applying a marker or reduction.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }
}

/// Move-only incremental owner of the same canonical frame as a borrowed view.
///
/// Each append consumes one complete field, including an empty field. There is
/// no raw chunk interface or intermediate digest. A refused append permanently
/// prevents completion, even if its error is ignored. Scalar bytes can be
/// emitted directly from the stack without retaining a whole payload frame.
pub struct NativeCommitmentBuilderV1 {
    hasher: blake3::Hasher,
    remaining_fields: usize,
    failure: Option<NativeCommitmentErrorV1>,
}

impl fmt::Debug for NativeCommitmentBuilderV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCommitmentBuilderV1")
            .field("remaining_fields", &self.remaining_fields)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl NativeCommitmentBuilderV1 {
    /// Validate the complete domain and exact field count before hashing.
    ///
    /// # Errors
    /// Rejects an oversized domain or field count before creating hash state.
    pub fn new(
        domain: NativeCommitmentDomainV1<'_>,
        field_count: usize,
    ) -> Result<Self, NativeCommitmentErrorV1> {
        frame_header_len(domain, field_count)?;
        let mut hasher = blake3::Hasher::new();
        emit_header(domain, field_count, |bytes| {
            hasher.update(bytes);
        });
        Ok(Self {
            hasher,
            remaining_fields: field_count,
            failure: None,
        })
    }

    /// Append one complete, ordered field without allocating payload storage.
    ///
    /// # Errors
    /// Refuses excess fields or a field above the frozen byte ceiling. The
    /// first refusal is retained and every later append and finish also fails.
    pub fn push_field(&mut self, field: &[u8]) -> Result<(), NativeCommitmentErrorV1> {
        self.admit_field_len(field.len() as u64)?;
        emit_field(field, |bytes| {
            self.hasher.update(bytes);
        });
        Ok(())
    }

    /// Consume the owner and return all raw bytes only after exact completion.
    ///
    /// # Errors
    /// Refuses an incomplete stream or any prior field refusal.
    pub fn finish(self) -> Result<NativeCommitmentDigestV1, NativeCommitmentErrorV1> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.remaining_fields != 0 {
            return Err(NativeCommitmentErrorV1::FieldCountMismatch);
        }
        Ok(NativeCommitmentDigestV1(*self.hasher.finalize().as_bytes()))
    }

    fn admit_field_len(&mut self, field_len: u64) -> Result<(), NativeCommitmentErrorV1> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let error = if self.remaining_fields == 0 {
            Some(NativeCommitmentErrorV1::FieldCountMismatch)
        } else if field_len > NATIVE_COMMITMENT_MAX_FIELD_BYTES_V1 {
            Some(NativeCommitmentErrorV1::FieldTooLong)
        } else {
            None
        };
        if let Some(error) = error {
            self.failure = Some(error);
            return Err(error);
        }
        self.remaining_fields -= 1;
        Ok(())
    }
}

/// Validated borrowed input to the single canonical frame encoder.
#[derive(Clone, Copy)]
pub struct NativeCommitmentFrameV1<'a> {
    domain: NativeCommitmentDomainV1<'a>,
    fields: &'a [&'a [u8]],
    encoded_len: u64,
}

impl fmt::Debug for NativeCommitmentFrameV1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCommitmentFrameV1")
            .field("field_count", &self.fields.len())
            .field("encoded_len", &self.encoded_len)
            .finish_non_exhaustive()
    }
}

impl<'a> NativeCommitmentFrameV1<'a> {
    /// Validate all domain and payload lengths without allocating or hashing.
    ///
    /// # Errors
    /// Rejects a domain, payload count or payload length outside the frozen bounds.
    pub fn new(
        domain: NativeCommitmentDomainV1<'a>,
        fields: &'a [&'a [u8]],
    ) -> Result<Self, NativeCommitmentErrorV1> {
        let encoded_len = frame_len(domain, fields.len(), fields.iter().map(|field| field.len()))?;
        Ok(Self {
            domain,
            fields,
            encoded_len,
        })
    }

    /// Compute the exact frame size before admitting or allocating payload storage.
    ///
    /// # Errors
    /// Rejects the same domain, count and individual lengths as [`Self::new`].
    pub fn encoded_len_for_field_lengths(
        domain: NativeCommitmentDomainV1<'_>,
        field_lengths: &[usize],
    ) -> Result<u64, NativeCommitmentErrorV1> {
        frame_len(domain, field_lengths.len(), field_lengths.iter().copied())
    }

    /// Exact complete frame length, not an allocation authorization.
    #[must_use]
    pub const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }

    /// Write the complete frame into an exactly sized caller-owned buffer.
    ///
    /// # Errors
    /// Refuses a shorter or longer buffer without modifying it.
    pub fn write_frame(&self, output: &mut [u8]) -> Result<(), NativeCommitmentErrorV1> {
        if output.len() as u64 != self.encoded_len {
            return Err(NativeCommitmentErrorV1::FrameLength);
        }
        let mut offset = 0;
        self.emit(|bytes| {
            output[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        });
        Ok(())
    }

    /// Hash the whole canonical frame without allocating a frame buffer.
    #[must_use]
    pub fn digest(&self) -> NativeCommitmentDigestV1 {
        let mut hasher = blake3::Hasher::new();
        self.emit(|bytes| {
            hasher.update(bytes);
        });
        NativeCommitmentDigestV1(*hasher.finalize().as_bytes())
    }

    /// Require an exact full-width digest of this domain and ordered payload.
    ///
    /// # Errors
    /// Rejects truncated/extended digests and any role, context, coordinate or
    /// payload mismatch. Success establishes correspondence only, not authority.
    pub fn verify_digest(
        &self,
        expected: &[u8],
    ) -> Result<NativeCommitmentDigestV1, NativeCommitmentErrorV1> {
        if expected.len() != NativeCommitmentDigestV1::BYTES {
            return Err(NativeCommitmentErrorV1::DigestLength);
        }
        let digest = self.digest();
        if digest.as_bytes().as_slice() != expected {
            return Err(NativeCommitmentErrorV1::DigestMismatch);
        }
        Ok(digest)
    }

    fn emit(&self, mut write: impl FnMut(&[u8])) {
        emit_header(self.domain, self.fields.len(), &mut write);
        for field in self.fields {
            emit_field(field, &mut write);
        }
    }
}

fn emit_header(
    domain: NativeCommitmentDomainV1<'_>,
    field_count: usize,
    mut write: impl FnMut(&[u8]),
) {
    write(NATIVE_COMMITMENT_MAGIC_V1);
    for (tag, bytes) in (1_u8..=6).zip(domain_fields(domain)) {
        write(&[tag]);
        // Construction checked the 4096-byte ceiling for every domain field.
        write(
            &u32::try_from(bytes.len())
                .expect("validated domain length")
                .to_le_bytes(),
        );
        write(bytes);
    }
    for (tag, coordinate) in (7_u8..=9).zip([domain.level, domain.index, domain.counter]) {
        write(&[tag]);
        write(&coordinate.to_le_bytes());
    }
    write(&[10]);
    // Construction checked the 65535-field ceiling.
    write(
        &u32::try_from(field_count)
            .expect("validated field count")
            .to_le_bytes(),
    );
}

fn emit_field(field: &[u8], mut write: impl FnMut(&[u8])) {
    write(&[11]);
    write(&(field.len() as u64).to_le_bytes());
    write(field);
}

fn domain_fields(domain: NativeCommitmentDomainV1<'_>) -> [&[u8]; 6] {
    [
        NATIVE_COMMITMENT_ALGORITHM_V1.as_bytes(),
        domain.catalog,
        domain.protocol,
        NATIVE_COMMITMENT_PROFILE_V1.as_bytes(),
        domain.role,
        domain.phase,
    ]
}

fn frame_len(
    domain: NativeCommitmentDomainV1<'_>,
    field_count: usize,
    field_lengths: impl Iterator<Item = usize>,
) -> Result<u64, NativeCommitmentErrorV1> {
    let mut total = frame_header_len(domain, field_count)?;
    for len in field_lengths {
        if len as u64 > NATIVE_COMMITMENT_MAX_FIELD_BYTES_V1 {
            return Err(NativeCommitmentErrorV1::FieldTooLong);
        }
        // The bounded count times the bounded length plus framing is below 2^49.
        total += 9 + len as u64;
    }
    Ok(total)
}

fn frame_header_len(
    domain: NativeCommitmentDomainV1<'_>,
    field_count: usize,
) -> Result<u64, NativeCommitmentErrorV1> {
    if field_count > NATIVE_COMMITMENT_MAX_FIELDS_V1 {
        return Err(NativeCommitmentErrorV1::TooManyFields);
    }
    let mut total = NATIVE_COMMITMENT_MAGIC_V1.len() as u64 + 3 * 9 + 5;
    for bytes in domain_fields(domain) {
        if bytes.len() > NATIVE_COMMITMENT_MAX_DOMAIN_BYTES_V1 {
            return Err(NativeCommitmentErrorV1::DomainTooLong);
        }
        total += 5 + bytes.len() as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::test_allocations::without_allocations;

    fn domain() -> NativeCommitmentDomainV1<'static> {
        NativeCommitmentDomainV1 {
            catalog: b"iroha.zk-ams.v1.mkhe",
            protocol: b"iroha.zk-ams.v1",
            role: b"source-receipt-identity",
            phase: b"iroha.zk-ams.v1.mkhe.rns-native-source-receipt",
            level: 0,
            index: 0,
            counter: 0,
        }
    }

    fn decode(value: &str) -> Vec<u8> {
        if value == "-" {
            Vec::new()
        } else {
            hex::decode(value).unwrap()
        }
    }

    #[test]
    fn streaming_matches_every_frozen_native_vector_without_allocating() {
        let mut checked = 0;
        for line in include_str!("hash_native_candidate_vectors.txt")
            .lines()
            .filter(|line| line.starts_with("example "))
        {
            let row = line.split(' ').collect::<Vec<_>>();
            let algorithm = decode(row[2]);
            let labels: [Vec<u8>; 5] = core::array::from_fn(|index| decode(row[index + 3]));
            if algorithm != NATIVE_COMMITMENT_ALGORITHM_V1.as_bytes()
                || labels[2] != NATIVE_COMMITMENT_PROFILE_V1.as_bytes()
            {
                continue;
            }
            let count: usize = row[11].parse().unwrap();
            let fields: Vec<_> = row[12..12 + count]
                .iter()
                .map(|value| decode(value))
                .collect();
            let expected = decode(row[13 + count]);
            let domain = NativeCommitmentDomainV1 {
                catalog: &labels[0],
                protocol: &labels[1],
                role: &labels[3],
                phase: &labels[4],
                level: row[8].parse().unwrap(),
                index: row[9].parse().unwrap(),
                counter: row[10].parse().unwrap(),
            };
            let digest = without_allocations(|| {
                let mut builder = NativeCommitmentBuilderV1::new(domain, fields.len()).unwrap();
                for field in &fields {
                    builder.push_field(field).unwrap();
                }
                builder.finish().unwrap()
            });
            assert_eq!(digest.as_bytes().as_slice(), expected, "{}", row[1]);
            checked += 1;
        }
        assert_eq!(checked, 10);
    }

    #[test]
    fn streamed_fields_preserve_empty_and_hash_block_boundaries() {
        let payload: Vec<_> = (0..2049)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        for length in [0, 1, 31, 32, 63, 64, 65, 1023, 1024, 1025, 2048, 2049] {
            let fields: [&[u8]; 3] = [b"", &payload[..length], b"tail"];
            let frame = NativeCommitmentFrameV1::new(domain(), &fields).unwrap();
            let mut encoded = vec![0; usize::try_from(frame.encoded_len()).unwrap()];
            frame.write_frame(&mut encoded).unwrap();
            let actual = without_allocations(|| {
                let mut builder = NativeCommitmentBuilderV1::new(domain(), fields.len()).unwrap();
                for field in fields {
                    builder.push_field(field).unwrap();
                }
                builder.finish().unwrap()
            });
            assert_eq!(actual, frame.digest());
            assert_eq!(actual.as_bytes(), blake3::hash(&encoded).as_bytes());
        }
    }

    #[test]
    fn exact_field_count_refuses_missing_excess_and_post_refusal_recovery() {
        let empty = NativeCommitmentBuilderV1::new(domain(), 0)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(
            empty,
            NativeCommitmentFrameV1::new(domain(), &[])
                .unwrap()
                .digest()
        );
        assert_eq!(
            NativeCommitmentBuilderV1::new(domain(), 1)
                .unwrap()
                .finish(),
            Err(NativeCommitmentErrorV1::FieldCountMismatch)
        );
        let mut builder = NativeCommitmentBuilderV1::new(domain(), 1).unwrap();
        builder.push_field(b"first").unwrap();
        assert_eq!(
            builder.push_field(b""),
            Err(NativeCommitmentErrorV1::FieldCountMismatch)
        );
        assert_eq!(
            builder.push_field(b"recovery"),
            Err(NativeCommitmentErrorV1::FieldCountMismatch)
        );
        assert_eq!(
            builder.finish(),
            Err(NativeCommitmentErrorV1::FieldCountMismatch)
        );
    }

    #[test]
    fn streaming_bounds_refuse_before_emission_and_retain_the_first_error() {
        let oversized_domain = vec![0; NATIVE_COMMITMENT_MAX_DOMAIN_BYTES_V1 + 1];
        assert!(matches!(
            NativeCommitmentBuilderV1::new(
                NativeCommitmentDomainV1 {
                    phase: &oversized_domain,
                    ..domain()
                },
                0
            ),
            Err(NativeCommitmentErrorV1::DomainTooLong)
        ));
        assert!(matches!(
            NativeCommitmentBuilderV1::new(domain(), NATIVE_COMMITMENT_MAX_FIELDS_V1 + 1),
            Err(NativeCommitmentErrorV1::TooManyFields)
        ));
        let mut builder = NativeCommitmentBuilderV1::new(domain(), 1).unwrap();
        let before = *builder.hasher.finalize().as_bytes();
        assert_eq!(
            builder.admit_field_len(NATIVE_COMMITMENT_MAX_FIELD_BYTES_V1 + 1),
            Err(NativeCommitmentErrorV1::FieldTooLong)
        );
        assert_eq!(*builder.hasher.finalize().as_bytes(), before);
        assert_eq!(builder.remaining_fields, 1);
        assert_eq!(
            builder.push_field(b"valid but too late"),
            Err(NativeCommitmentErrorV1::FieldTooLong)
        );
        assert_eq!(builder.finish(), Err(NativeCommitmentErrorV1::FieldTooLong));
    }

    #[test]
    fn maximum_exact_field_count_finishes_without_allocating() {
        let fields = vec![b"".as_slice(); NATIVE_COMMITMENT_MAX_FIELDS_V1];
        let expected = NativeCommitmentFrameV1::new(domain(), &fields)
            .unwrap()
            .digest();
        let actual = without_allocations(|| {
            let mut builder = NativeCommitmentBuilderV1::new(domain(), fields.len()).unwrap();
            for field in &fields {
                builder.push_field(field).unwrap();
            }
            builder.finish().unwrap()
        });
        assert_eq!(actual, expected);
    }

    #[test]
    fn streaming_preserves_every_context_axis_and_ordered_field_boundary() {
        fn commit(
            domain: NativeCommitmentDomainV1<'_>,
            fields: &[&[u8]],
        ) -> NativeCommitmentDigestV1 {
            let mut builder = NativeCommitmentBuilderV1::new(domain, fields.len()).unwrap();
            for field in fields {
                builder.push_field(field).unwrap();
            }
            builder.finish().unwrap()
        }
        let original = commit(domain(), &[b"a", b"bc"]);
        for changed in [
            NativeCommitmentDomainV1 {
                catalog: b"other",
                ..domain()
            },
            NativeCommitmentDomainV1 {
                protocol: b"other",
                ..domain()
            },
            NativeCommitmentDomainV1 {
                role: b"other",
                ..domain()
            },
            NativeCommitmentDomainV1 {
                phase: b"other",
                ..domain()
            },
            NativeCommitmentDomainV1 {
                level: 1,
                ..domain()
            },
            NativeCommitmentDomainV1 {
                index: 1,
                ..domain()
            },
            NativeCommitmentDomainV1 {
                counter: 1,
                ..domain()
            },
        ] {
            assert_ne!(commit(changed, &[b"a", b"bc"]), original);
        }
        for fields in [
            &[b"bc".as_slice(), b"a"][..],
            &[b"ab".as_slice(), b"c"],
            &[b"abc".as_slice()],
        ] {
            assert_ne!(commit(domain(), fields), original);
        }
        let fields: [&[u8]; 2] = [b"a", b"bc"];
        let frame = NativeCommitmentFrameV1::new(domain(), &fields).unwrap();
        assert_eq!(
            frame.verify_digest(&original.as_bytes()[..31]),
            Err(NativeCommitmentErrorV1::DigestLength)
        );
        assert_eq!(
            frame.verify_digest(&[0; 33]),
            Err(NativeCommitmentErrorV1::DigestLength)
        );
    }
}
