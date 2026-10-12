//! Canonical SHA3 commitments and atomic SHAKE tapes for the q77 compact profile.
//!
//! The exact logical input is a complete canonical public prefix followed by a
//! canonical body. Prefix state caching never substitutes a digest for context.
//! All private body bytes and permutation scratch have clearing owners.
//!
//! The prefix carries the name of the frozen transcript construction and the
//! complete canonical bytes of the typed profile descriptor
//! ([`transcript_profile`](super::transcript_profile)), so every commitment and
//! every challenge binds the whole profile, not a digest or a label of it.
use super::secret_polynomial::SecretPolynomial;
use fastpq_isi::{
    FASTPQ_CATALOG_V1,
    compact_challenge::{RawTapeErrorV1, RawTapeRoundV1, RawTapeV1},
    keccak256::{Sha3_256V1, Sha3Digest256V1 as Digest, Shake256V1},
};
use norito::NoritoSerialize;
use std::sync::Arc;
/// Longest statement context one prefix binds; part of the profile's declared envelope.
pub(super) const MAX_CONTEXT_BYTES: usize = 256 * 1024;
/// Largest prepared complete tree body; OOD framing has its separate exact bound.
pub(super) const MAX_PREPARED_HASH_FRAME_BYTES: usize = 8 * 1024;
/// Canonical framing, bounded allocation, or finite tape failure.
#[derive(Debug, thiserror::Error)]
pub(super) enum CandidateError {
    /// Public context has another fixed envelope.
    #[error("compact context is empty or exceeds its fixed byte ceiling")]
    Context,
    /// Private frame storage cannot be reserved or a public size overflows.
    #[error("compact private framing allocation failed")]
    Allocation,
    /// Canonical framing failed.
    #[error(transparent)]
    Encode(#[from] norito::core::Error),
    /// Whole-tape generation failed without extending its fixed extent.
    #[error(transparent)]
    Tape(#[from] RawTapeErrorV1),
}
type Result<T> = std::result::Result<T, CandidateError>;
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_sha3::PrefixFrame",
    frame = "fastpq_prover::compact_sha3::ProfileContextV1"
)]
struct PrefixFrame {
    /// Framing version of the prefix and body layouts.
    version: u16,
    catalog: Vec<u8>,
    /// Name of the frozen transcript construction.
    construction: Vec<u8>,
    /// Complete canonical bytes of the typed profile descriptor.
    profile: Vec<u8>,
    context: Vec<u8>,
}

/// Nominal Norito frame of the prefix, as the profile descriptor names it.
pub(super) fn prefix_frame_name() -> String {
    use norito::schema::identity::NoritoSchema as _;
    PrefixFrame::frame_name()
}

/// Nominal Norito frame of every body, as the profile descriptor names it.
pub(super) fn body_frame_name() -> String {
    use norito::schema::identity::NoritoSchema as _;
    Frame::frame_name()
}
#[derive(Debug)]
struct AbsorbedPrefix {
    encoded: Box<[u8]>,
    hash: Sha3_256V1,
    xof: Shake256V1,
}
/// One immutable attempt's complete public context and exact cached prefix states.
#[derive(Clone, Debug)]
pub(super) struct Context {
    prefix: Arc<AbsorbedPrefix>,
}
// These payload-only views preserve Vec<Vec<u8>> bytes without owning copies.
// The protocol has exactly one leaf/predecessor field or two child/tape-root fields.
/// Borrowed canonical body fields shared by the closed internal protocol owners.
#[derive(Clone, Copy, Debug)]
pub(super) enum BodyFields<'a> {
    /// One complete leaf or predecessor.
    One(&'a [u8]),
    /// Two complete children, or a whole tape followed by its committed root.
    Two(&'a [u8], &'a [u8]),
}

#[derive(Clone, Copy)]
struct ByteField<'a>(&'a [u8]);

impl norito::core::SerializePayload for ByteField<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::core::Error> {
        // Vec<u8>'s specialization writes a fixed u64 count and the raw bytes.
        let length =
            u64::try_from(self.0.len()).map_err(|_| norito::core::Error::LengthMismatch)?;
        norito::core::write_seq_len(writer, length)?;
        writer.write_all(self.0)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.len().checked_add(8)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.len().checked_add(8)
    }
}

impl norito::core::SerializePayload for BodyFields<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::core::Error> {
        // Use Norito's existing sequence owner for counts, element lengths and
        // checked emission. Both variants are stack arrays of borrowed views.
        match self {
            Self::One(field) => {
                norito::core::write_element_sequence::<ByteField<'_>, _>(writer, [ByteField(field)])
            }
            Self::Two(first, second) => norito::core::write_element_sequence::<ByteField<'_>, _>(
                writer,
                [ByteField(first), ByteField(second)],
            ),
        }
    }
}

/// The sole canonical typed body layout; including the profile-specific schema identity.
#[derive(Clone, Debug, NoritoSerialize)]
pub(super) struct Frame<'a> {
    kind: u8,
    oracle: u8,
    round: u8,
    level: u32,
    position: u32,
    output_bytes: u32,
    fields: BodyFields<'a>,
}

// Count without output-sized scratch, allocate under unconditional clearing,
// then serialize directly into an exact slice. Neither a failed writer nor a
// successful private row hash drops an unguarded encoded-payload Vec.
pub(super) fn encode_private_frame(
    frame: &Frame<'_>,
) -> Result<super::secret_polynomial::SecretPolynomial<u8>> {
    let bytes = norito::canonical_frame_len(frame)?;
    let mut encoded = super::secret_polynomial::SecretPolynomial::zeroed(bytes)
        .map_err(|_| CandidateError::Allocation)?;
    let mut remaining = &mut encoded[..];
    norito::core::write_canonical_to_writer(frame, &mut remaining)?;
    if !remaining.is_empty() {
        return Err(CandidateError::Encode(norito::Error::LengthMismatch));
    }
    Ok(encoded)
}

// A lifetime is only an ownership detail. Preserve both existing identities;
// the schema derive would append its lifetime placeholder to the nominal name.
impl norito::NoritoSchema for Frame<'_> {
    fn nominal_name() -> String {
        "fastpq_prover::backend::compact_sha3::Frame".to_owned()
    }

    fn frame_name() -> String {
        "fastpq_prover::compact_sha3::BodyV1".to_owned()
    }
}

/// Bounded clearing private frame and its exact SHA3 prefix state.
#[cfg_attr(
    not(any(test, feature = "fastpq-gpu", feature = "simd")),
    expect(
        dead_code,
        reason = "CPU builds charge the exact reusable prepared owner but hash directly"
    )
)]
pub(super) struct PreparedHashFrame {
    prefix: Sha3_256V1,
    encoded: SecretPolynomial<u8>,
}
#[cfg(any(test, feature = "fastpq-gpu", feature = "simd"))]
impl PreparedHashFrame {
    /// Borrow the canonical continuation; no new body or context encoding.
    pub(super) fn job(&self) -> crate::keccak_batch::Job<'_> {
        crate::keccak_batch::Job::new(&self.prefix, &self.encoded)
    }
    /// Independent scalar reference retained only by native parity tests.
    #[cfg(test)]
    pub(super) fn hash_cpu(&self) -> Digest {
        let mut hash = self.prefix.clone();
        hash.update(&self.encoded);
        hash.finalize()
    }
}
impl Context {
    /// Build exactly one prefix; the framing version, catalog, construction name,
    /// complete profile descriptor and full statement context are bound.
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        Self::with_prefix(&PrefixFrame {
            version: super::transcript_profile::FRAMING_VERSION,
            catalog: FASTPQ_CATALOG_V1.as_bytes().to_vec(),
            construction: super::transcript_profile::CONSTRUCTION.as_bytes().to_vec(),
            profile: super::transcript_profile::profile().as_bytes().to_vec(),
            context: bytes.to_vec(),
        })
    }

    /// Prefix with another version, catalog, construction name or profile
    /// descriptor than the frozen ones, for binding-mutation tests only. No
    /// production path can select these values.
    #[cfg(test)]
    pub(super) fn with_prefix_for_test(
        version: u16,
        catalog: &[u8],
        construction: &[u8],
        profile: &[u8],
        context: &[u8],
    ) -> Result<Self> {
        Self::with_prefix(&PrefixFrame {
            version,
            catalog: catalog.to_vec(),
            construction: construction.to_vec(),
            profile: profile.to_vec(),
            context: context.to_vec(),
        })
    }

    fn with_prefix(prefix: &PrefixFrame) -> Result<Self> {
        if prefix.context.is_empty() || prefix.context.len() > MAX_CONTEXT_BYTES {
            return Err(CandidateError::Context);
        }
        let encoded = norito::encode_canonical(prefix)?.into_boxed_slice();
        let mut hash = Sha3_256V1::new();
        hash.update(&encoded);
        let mut xof = Shake256V1::new();
        xof.update(&encoded);
        Ok(Self {
            prefix: Arc::new(AbsorbedPrefix { encoded, hash, xof }),
        })
    }
    /// Only explicit clones share an attempt capability.
    pub(super) fn same_attempt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.prefix, &other.prefix)
    }
    /// Actual fixed public prefix owners, allocation bytes and Arc counters.
    pub(super) fn maximum_retained_payload_bytes(&self) -> Result<usize> {
        self.prefix
            .encoded
            .len()
            .checked_add(size_of::<AbsorbedPrefix>())
            .and_then(|v| v.checked_add(2 * size_of::<usize>()))
            .ok_or(CandidateError::Allocation)
    }
    /// Full absorbed public-prefix permutations for both resident H/G caches.
    pub(super) fn prefix_permutations(&self) -> usize {
        2 * (self.prefix.encoded.len() / crate::keccak_batch::RATE)
    }
    /// Exact continuation permutations for a body of a public canonical length.
    /// Both H and G share rate136 and the same absorbed prefix position.
    pub(super) fn body_permutations(&self, bytes: usize) -> Result<usize> {
        self.prefix.hash.with_absorbed_state_v1(|_, position| {
            position
                .checked_add(bytes)
                .map(|n| n / crate::keccak_batch::RATE + 1)
                .ok_or(CandidateError::Allocation)
        })
    }
    /// Hash an exact canonical complete body. SHA3's 0x06 suffix separates H from G.
    pub(super) fn hash_frame(&self, frame: &Frame<'_>) -> Result<Digest> {
        let encoded = encode_private_frame(frame)?;
        let mut hash = self.prefix.hash.clone();
        hash.update(&encoded);
        let digest = hash.finalize();
        #[cfg(test)]
        observer::hash(&self.prefix, frame, &encoded, digest);
        Ok(digest)
    }
    /// Materialize exactly one raw SHAKE tape; no reader escapes this operation.
    pub(super) fn tape(&self, round: RawTapeRoundV1, body: &[u8]) -> Result<RawTapeV1> {
        let tape = RawTapeV1::derive(round, &self.prefix.xof, body)?;
        #[cfg(test)]
        observer::tape(&self.prefix, round, body, tape.as_bytes());
        Ok(tape)
    }
    /// Own the exact bounded private body before any reusable hash batch executes.
    #[cfg(any(test, feature = "fastpq-gpu", feature = "simd"))]
    pub(super) fn prepare_hash_frame(&self, frame: &Frame<'_>) -> crate::Result<PreparedHashFrame> {
        let length = norito::canonical_frame_len(frame)?;
        if length > MAX_PREPARED_HASH_FRAME_BYTES {
            return Err(crate::Error::InvalidTraceShape {
                details: "compact prepared tree frame exceeds fixed bound".into(),
            });
        }
        let encoded = encode_private_frame(frame).map_err(|e| crate::Error::InvalidTraceShape {
            details: e.to_string(),
        })?;
        Ok(PreparedHashFrame {
            prefix: self.prefix.hash.clone(),
            encoded,
        })
    }
    /// Construct the closed canonical body shared by all commitment and tape operations.
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per canonical body field"
    )]
    #[allow(
        clippy::unused_self,
        reason = "body construction remains within its framing owner"
    )]
    pub(super) fn frame<'a>(
        &self,
        kind: u8,
        oracle: u8,
        round: u8,
        level: u32,
        position: u32,
        output_bytes: usize,
        fields: BodyFields<'a>,
    ) -> Frame<'a> {
        Frame {
            kind,
            oracle,
            round,
            level,
            position,
            output_bytes: u32::try_from(output_bytes).expect("fixed tape extent fits u32"),
            fields,
        }
    }
}
#[cfg(test)]
#[path = "compact_sha3/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compact_sha3/observer.rs"]
mod observer;
#[cfg(test)]
#[path = "compact_sha3/retirement_tests.rs"]
mod retirement_tests;
