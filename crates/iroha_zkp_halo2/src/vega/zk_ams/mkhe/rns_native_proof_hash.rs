//! Single six-lane commitment and transcript owner for the native RNS proof.
//!
//! The catalog is the same lower-owned Exact12 identity used by the model.
//! Parameter context is reconstructed by the existing native profile owner;
//! proof bytes cannot supply a catalog, profile, or hash implementation.

#[cfg(test)]
use fastpq_isi::hash_bytes_384_v1;
use fastpq_isi::{GOLDILOCKS_DIGEST384_BYTES_V1, GoldilocksDigest384V1};
#[cfg(test)]
use fastpq_isi::{
    GoldilocksDigest384FrameV1, GoldilocksDigest384LastFieldStreamV1, GoldilocksDigestDomainV1,
};
#[cfg(test)]
use iroha_crypto::privacy::PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1;

#[cfg(test)]
use super::rns_native_qpcs_initial::canonical_parameter_digest_v1;

#[cfg(test)]
const PROTOCOL_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rns-native-qpcs";

/// Canonical native proof commitment, transcript state, or challenge seed.
///
/// The sole representation is all six canonical Goldilocks words in48 bytes.
/// Its bytes cannot be mutated after validation. Public32-byte metadata has a
/// separate type and cannot be passed where this proof digest is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RnsNativeProofDigestV1([u8; GOLDILOCKS_DIGEST384_BYTES_V1]);

impl RnsNativeProofDigestV1 {
    /// Canonical zero used only for initialization; root admission rejects it.
    pub const ZERO: Self = Self([0; GOLDILOCKS_DIGEST384_BYTES_V1]);

    /// Preserve the complete canonical output of the shared six-lane owner.
    #[must_use]
    pub fn from_shared(digest: GoldilocksDigest384V1) -> Self {
        Self(digest.to_le_bytes())
    }

    /// Decode exactly six canonical little-endian Goldilocks words.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; GOLDILOCKS_DIGEST384_BYTES_V1]) -> Option<Self> {
        GoldilocksDigest384V1::from_le_bytes(bytes).map(Self::from_shared)
    }

    /// Return all48 canonical wire bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; GOLDILOCKS_DIGEST384_BYTES_V1] {
        self.0
    }

    /// Borrow all48 canonical wire bytes without allocation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; GOLDILOCKS_DIGEST384_BYTES_V1] {
        &self.0
    }

    /// Return the six canonical field elements in their fixed lane order.
    #[must_use]
    pub fn words(self) -> [u64; 6] {
        core::array::from_fn(|lane| {
            let offset = lane * 8;
            u64::from_le_bytes(core::array::from_fn(|byte| self.0[offset + byte]))
        })
    }
}

impl Default for RnsNativeProofDigestV1 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl AsRef<[u8]> for RnsNativeProofDigestV1 {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::ops::Deref for RnsNativeProofDigestV1 {
    type Target = [u8; GOLDILOCKS_DIGEST384_BYTES_V1];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

/// Separate identities in bounded registries; widths are never padded or guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RnsNativeDigestIdentityV1 {
    /// A public source, curve-commitment, profile, or exact transport identity.
    Public32([u8; 32]),
    /// A canonical six-lane proof commitment or transcript state.
    Proof384(RnsNativeProofDigestV1),
}

impl RnsNativeDigestIdentityV1 {
    pub(super) const EMPTY: Self = Self::Public32([0; 32]);

    pub(super) fn is_zero(self) -> bool {
        match self {
            Self::Public32(bytes) => bytes == [0; 32],
            Self::Proof384(digest) => digest == RnsNativeProofDigestV1::ZERO,
        }
    }

    #[cfg(test)]
    pub(super) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Public32(bytes) => bytes,
            Self::Proof384(digest) => digest.as_bytes(),
        }
    }
}

impl From<[u8; 32]> for RnsNativeDigestIdentityV1 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::Public32(bytes)
    }
}

impl From<RnsNativeProofDigestV1> for RnsNativeDigestIdentityV1 {
    fn from(digest: RnsNativeProofDigestV1) -> Self {
        Self::Proof384(digest)
    }
}

/// Exact proof-oracle or Fiat-Shamir role; this is not an algorithm selector.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeProofHashRoleV1 {
    /// Initial authenticated codeword tree.
    Initial,
    /// Opening-quotient authenticated codeword tree.
    Quotient,
    /// Correlated FRI authenticated codeword tree.
    Fri,
    /// One move-only stage of the global proof transcript.
    Transcript,
    /// Native transcript commitment to a successfully verified T256 bridge.
    TerminalBridge,
    /// Complete canonical packed payload, before its index-bound leaf digest.
    OraclePayload,
}

#[cfg(test)]
impl RnsNativeProofHashRoleV1 {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Initial => b"initial-tree",
            Self::Quotient => b"quotient-tree",
            Self::Fri => b"fri-tree",
            Self::Transcript => b"transcript",
            Self::TerminalBridge => b"terminal-bridge",
            Self::OraclePayload => b"oracle-payload",
        }
    }
}

/// Exact operation within a verifier-owned proof role.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeProofHashPhaseV1 {
    /// Initial transcript state after fixed public context.
    Initial,
    /// Absorb a complete ordered proof-stage object.
    Absorb,
    /// Absorb an ordered opening commitment.
    Opening,
    /// Sample a field challenge at an exact coordinate and attempt.
    Challenge,
    /// Ratchet the transcript after deriving a challenge.
    Ratchet,
    /// Commit a complete canonical oracle leaf.
    Leaf,
    /// Commit two complete ordered child roots.
    Node,
    /// Bind a complete derived proof-stage object.
    Binding,
}

#[cfg(test)]
impl RnsNativeProofHashPhaseV1 {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Initial => b"initial",
            Self::Absorb => b"absorb",
            Self::Opening => b"opening",
            Self::Challenge => b"challenge",
            Self::Ratchet => b"ratchet",
            Self::Leaf => b"leaf",
            Self::Node => b"node",
            Self::Binding => b"binding",
        }
    }
}

/// Invalid exact profile, hash frame, or canonical digest encoding.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "profile and digest rejections come only from test-only hash entry points"
    )
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeProofHashErrorV1 {
    /// The current native parameter owner failed reconstruction.
    Profile,
    /// The shared canonical frame exceeds its fixed framing limit.
    Frame,
    /// The input has another digest length or a noncanonical field word.
    Digest,
}

/// Arithmetic work of the current shared dense-MDS canonical hash frame.
/// Counts describe primitive work, not CPU time, aggregate proof work or RSS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RnsNativeProofHashWorkV1 {
    pub(super) words_per_lane: u64,
    pub(super) lane_permutations: u64,
    pub(super) poseidon_rounds: u64,
    pub(super) field_multiplications: u64,
    pub(super) field_additions: u64,
}

impl RnsNativeProofHashWorkV1 {
    /// Count the exact shared frame, which already includes termination/padding.
    #[cfg(test)]
    pub(super) fn from_frame(
        frame: &GoldilocksDigest384FrameV1<'_>,
    ) -> Result<Self, RnsNativeProofHashErrorV1> {
        Self::from_word_count(frame.word_count())
    }

    /// Count an owned fixed frame length; hash callers compare this with the actual frame.
    pub(super) const fn from_word_count(words: usize) -> Result<Self, RnsNativeProofHashErrorV1> {
        let words = words as u64;
        let rate = fastpq_isi::poseidon::RATE as u64;
        let lanes = fastpq_isi::GOLDILOCKS_DIGEST384_LANES_V1 as u64;
        let width = fastpq_isi::poseidon::STATE_WIDTH as u64;
        let rounds = fastpq_isi::GOLDILOCKS_DIGEST384_ROUNDS_V1 as u64;
        // The bound parameter asset fixes8 full and57 partial rounds. Pow7
        // uses4 multiplications; dense MDS folds3 terms from zero in each row.
        let s_boxes = 8 * width + rounds - 8;
        let multiplications_per_permutation = 4 * s_boxes + rounds * width * width;
        let additions_per_permutation = rounds * (width + width * width) + rate;
        if words == 0 || !words.is_multiple_of(rate) {
            return Err(RnsNativeProofHashErrorV1::Frame);
        }
        let Some(lane_permutations) = (words / rate).checked_mul(lanes) else {
            return Err(RnsNativeProofHashErrorV1::Frame);
        };
        let Some(poseidon_rounds) = lane_permutations.checked_mul(rounds) else {
            return Err(RnsNativeProofHashErrorV1::Frame);
        };
        let Some(field_multiplications) =
            lane_permutations.checked_mul(multiplications_per_permutation)
        else {
            return Err(RnsNativeProofHashErrorV1::Frame);
        };
        let Some(field_additions) = lane_permutations.checked_mul(additions_per_permutation) else {
            return Err(RnsNativeProofHashErrorV1::Frame);
        };
        Ok(Self {
            words_per_lane: words,
            lane_permutations,
            poseidon_rounds,
            field_multiplications,
            field_additions,
        })
    }
}

/// Exact tree position and monotonic challenge attempt.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RnsNativeProofHashPositionV1 {
    /// Oracle or Merkle layer, derived by the verifier.
    pub(super) level: u64,
    /// Leaf, node, or challenge index, derived by the verifier.
    pub(super) index: u64,
    /// Monotonic attempt or transcript counter.
    pub(super) counter: u64,
}

/// Reconstructed exact catalog/profile context shared by all proof hash calls.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct RnsNativeProofHashContextV1 {
    parameter_digest: [u8; 32],
    catalog: [u8; 32],
}

#[cfg(test)]
impl RnsNativeProofHashContextV1 {
    /// Reconstruct context from the current native owner, without caller overrides.
    pub(super) fn canonical() -> Result<Self, RnsNativeProofHashErrorV1> {
        static CONTEXT: std::sync::OnceLock<
            Result<RnsNativeProofHashContextV1, RnsNativeProofHashErrorV1>,
        > = std::sync::OnceLock::new();
        *CONTEXT.get_or_init(Self::reconstruct)
    }

    fn reconstruct() -> Result<Self, RnsNativeProofHashErrorV1> {
        let parameter_digest =
            canonical_parameter_digest_v1().map_err(|_| RnsNativeProofHashErrorV1::Profile)?;
        let catalog = PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1;
        Ok(Self {
            parameter_digest,
            catalog,
        })
    }

    /// Return public parameter identity for exact comparison with the current wire.
    pub(super) const fn parameter_digest(&self) -> [u8; 32] {
        self.parameter_digest
    }

    fn domain(
        &self,
        role: RnsNativeProofHashRoleV1,
        phase: RnsNativeProofHashPhaseV1,
        position: RnsNativeProofHashPositionV1,
    ) -> GoldilocksDigestDomainV1<'_> {
        GoldilocksDigestDomainV1 {
            catalog: &self.catalog,
            protocol: PROTOCOL_V1,
            profile: &self.parameter_digest,
            role: role.label(),
            phase: phase.label(),
            level: position.level,
            index: position.index,
            counter: position.counter,
        }
    }

    /// Construct the exact shared frame for hashing and resource accounting.
    pub(super) fn frame<'a>(
        &'a self,
        role: RnsNativeProofHashRoleV1,
        phase: RnsNativeProofHashPhaseV1,
        position: RnsNativeProofHashPositionV1,
        fields: &'a [&'a [u8]],
    ) -> Result<GoldilocksDigest384FrameV1<'a>, RnsNativeProofHashErrorV1> {
        GoldilocksDigest384FrameV1::new(self.domain(role, phase, position), fields)
            .ok_or(RnsNativeProofHashErrorV1::Frame)
    }

    /// Stream the exact last field of that same canonical shared frame.
    /// Prefix fields are absorbed before this returns; no caller borrow or
    /// source re-traversal is retained, and exact final length is mandatory.
    pub(super) fn last_field_stream(
        &self,
        role: RnsNativeProofHashRoleV1,
        phase: RnsNativeProofHashPhaseV1,
        position: RnsNativeProofHashPositionV1,
        prefix_fields: &[&[u8]],
        final_field_len: usize,
    ) -> Result<GoldilocksDigest384LastFieldStreamV1, RnsNativeProofHashErrorV1> {
        GoldilocksDigest384LastFieldStreamV1::new(
            self.domain(role, phase, position),
            prefix_fields,
            final_field_len,
        )
        .map_err(|_| RnsNativeProofHashErrorV1::Frame)
    }

    /// Hash complete, separately length-framed fields under one exact proof role.
    pub(super) fn hash(
        &self,
        role: RnsNativeProofHashRoleV1,
        phase: RnsNativeProofHashPhaseV1,
        position: RnsNativeProofHashPositionV1,
        fields: &[&[u8]],
    ) -> Result<RnsNativeProofDigestV1, RnsNativeProofHashErrorV1> {
        self.frame(role, phase, position, fields)
            .map(|frame| RnsNativeProofDigestV1::from_shared(frame.hash()))
    }
}

/// Decode the only proof digest representation: six canonical little-endian words.
#[cfg(test)]
pub(super) fn decode_proof_digest_v1(
    bytes: &[u8],
) -> Result<RnsNativeProofDigestV1, RnsNativeProofHashErrorV1> {
    let bytes = bytes
        .try_into()
        .map_err(|_| RnsNativeProofHashErrorV1::Digest)?;
    RnsNativeProofDigestV1::from_le_bytes(bytes).ok_or(RnsNativeProofHashErrorV1::Digest)
}

/// Deterministic test-only label commitment through the actual canonical owner.
#[cfg(test)]
pub(super) fn test_proof_digest_v1(label: &[u8], position: u64) -> RnsNativeProofDigestV1 {
    RnsNativeProofHashContextV1::canonical()
        .unwrap()
        .hash(
            RnsNativeProofHashRoleV1::Transcript,
            RnsNativeProofHashPhaseV1::Binding,
            RnsNativeProofHashPositionV1 {
                level: u64::MAX,
                index: position,
                counter: 0,
            },
            &[b"native-rns-test-fixture", label],
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_proof_hash_uses_the_actual_shared_owner_and_one_catalog() {
        let context = RnsNativeProofHashContextV1::canonical().unwrap();
        assert_eq!(
            context.parameter_digest(),
            canonical_parameter_digest_v1().unwrap()
        );
        let fields: &[&[u8]] = &[b"complete field one", b"complete field two"];
        let actual = context
            .hash(
                RnsNativeProofHashRoleV1::Fri,
                RnsNativeProofHashPhaseV1::Node,
                RnsNativeProofHashPositionV1 {
                    level: 7,
                    index: 11,
                    counter: 0,
                },
                fields,
            )
            .unwrap();
        let expected = hash_bytes_384_v1(
            GoldilocksDigestDomainV1 {
                catalog: &context.catalog,
                protocol: PROTOCOL_V1,
                profile: &context.parameter_digest,
                role: b"fri-tree",
                phase: b"node",
                level: 7,
                index: 11,
                counter: 0,
            },
            fields,
        )
        .unwrap();
        assert_eq!(actual, RnsNativeProofDigestV1::from_shared(expected));
        assert_eq!(decode_proof_digest_v1(&actual.to_le_bytes()), Ok(actual));
        assert_eq!(context.catalog, PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1);
    }

    #[test]
    fn roles_phases_coordinates_and_field_boundaries_are_distinct() {
        let context = RnsNativeProofHashContextV1::canonical().unwrap();
        let base = context
            .hash(
                RnsNativeProofHashRoleV1::Initial,
                RnsNativeProofHashPhaseV1::Leaf,
                RnsNativeProofHashPositionV1 {
                    level: 1,
                    index: 2,
                    counter: 3,
                },
                &[b"ab", b"c"],
            )
            .unwrap();
        for role in [
            RnsNativeProofHashRoleV1::Quotient,
            RnsNativeProofHashRoleV1::Fri,
            RnsNativeProofHashRoleV1::Transcript,
            RnsNativeProofHashRoleV1::TerminalBridge,
            RnsNativeProofHashRoleV1::OraclePayload,
        ] {
            assert_ne!(
                base,
                context
                    .hash(
                        role,
                        RnsNativeProofHashPhaseV1::Leaf,
                        RnsNativeProofHashPositionV1 {
                            level: 1,
                            index: 2,
                            counter: 3
                        },
                        &[b"ab", b"c"]
                    )
                    .unwrap()
            );
        }
        for (phase, level, index, counter) in [
            (RnsNativeProofHashPhaseV1::Node, 1, 2, 3),
            (RnsNativeProofHashPhaseV1::Leaf, 2, 2, 3),
            (RnsNativeProofHashPhaseV1::Leaf, 1, 3, 3),
            (RnsNativeProofHashPhaseV1::Leaf, 1, 2, 4),
        ] {
            assert_ne!(
                base,
                context
                    .hash(
                        RnsNativeProofHashRoleV1::Initial,
                        phase,
                        RnsNativeProofHashPositionV1 {
                            level,
                            index,
                            counter
                        },
                        &[b"ab", b"c"]
                    )
                    .unwrap()
            );
        }
        assert_ne!(
            base,
            context
                .hash(
                    RnsNativeProofHashRoleV1::Initial,
                    RnsNativeProofHashPhaseV1::Leaf,
                    RnsNativeProofHashPositionV1 {
                        level: 1,
                        index: 2,
                        counter: 3
                    },
                    &[b"a", b"bc"]
                )
                .unwrap()
        );
        assert_ne!(
            base,
            context
                .hash(
                    RnsNativeProofHashRoleV1::Initial,
                    RnsNativeProofHashPhaseV1::Leaf,
                    RnsNativeProofHashPositionV1 {
                        level: 1,
                        index: 2,
                        counter: 3
                    },
                    &[b"abc"]
                )
                .unwrap()
        );
        for phase in [
            RnsNativeProofHashPhaseV1::Initial,
            RnsNativeProofHashPhaseV1::Absorb,
            RnsNativeProofHashPhaseV1::Opening,
            RnsNativeProofHashPhaseV1::Challenge,
            RnsNativeProofHashPhaseV1::Ratchet,
            RnsNativeProofHashPhaseV1::Binding,
        ] {
            assert_ne!(
                base,
                context
                    .hash(
                        RnsNativeProofHashRoleV1::Initial,
                        phase,
                        RnsNativeProofHashPositionV1 {
                            level: 1,
                            index: 2,
                            counter: 3
                        },
                        &[b"ab", b"c"]
                    )
                    .unwrap()
            );
        }
    }

    #[test]
    fn old_digest_widths_and_each_noncanonical_lane_are_rejected() {
        for length in 0..=64 {
            if length != GOLDILOCKS_DIGEST384_BYTES_V1 {
                assert_eq!(
                    decode_proof_digest_v1(&vec![0; length]),
                    Err(RnsNativeProofHashErrorV1::Digest)
                );
            }
        }
        let mut bytes = [0_u8; GOLDILOCKS_DIGEST384_BYTES_V1];
        for lane in 0..6 {
            bytes.fill(0);
            bytes[lane * 8..lane * 8 + 8]
                .copy_from_slice(&fastpq_isi::poseidon::FIELD_MODULUS.to_le_bytes());
            assert_eq!(
                decode_proof_digest_v1(&bytes),
                Err(RnsNativeProofHashErrorV1::Digest)
            );
        }
        assert_eq!(
            decode_proof_digest_v1(&[0; 48]),
            Ok(RnsNativeProofDigestV1::ZERO)
        );
    }
    #[test]
    fn typed_proof_digests_preserve_every_lane_and_registry_identity_kind() {
        let words = [0, 1, 2, 3, 4, fastpq_isi::poseidon::FIELD_MODULUS - 1];
        let shared = GoldilocksDigest384V1::new(words).unwrap();
        let digest = RnsNativeProofDigestV1::from_shared(shared);
        assert_eq!(digest.words(), words);
        assert_eq!(digest.as_bytes(), &shared.to_le_bytes());
        assert_eq!(
            RnsNativeProofDigestV1::from_le_bytes(digest.to_le_bytes()),
            Some(digest)
        );
        assert_eq!(core::mem::size_of::<RnsNativeProofDigestV1>(), 48);
        let public: [u8; 32] = digest.as_bytes()[..32].try_into().unwrap();
        let public_identity = RnsNativeDigestIdentityV1::from(public);
        let proof_identity = RnsNativeDigestIdentityV1::from(digest);
        assert_ne!(public_identity, proof_identity);
        assert_eq!(public_identity.as_bytes(), public.as_slice());
        assert_eq!(proof_identity.as_bytes(), digest.as_bytes());
        assert!(!proof_identity.is_zero());
        assert!(RnsNativeDigestIdentityV1::EMPTY.is_zero());
        assert!(RnsNativeDigestIdentityV1::from(RnsNativeProofDigestV1::ZERO).is_zero());
        assert_eq!(
            RnsNativeProofDigestV1::default(),
            RnsNativeProofDigestV1::ZERO
        );
        assert_ne!(
            test_proof_digest_v1(b"fixture", 0),
            test_proof_digest_v1(b"fixture", 1)
        );
        assert_ne!(
            test_proof_digest_v1(b"fixture", 0),
            test_proof_digest_v1(b"other", 0)
        );
    }
    #[test]
    fn native_stream_matches_canonical_frame_for_every_chunk_boundary_and_exact_length() {
        let context = RnsNativeProofHashContextV1::canonical().unwrap();
        let payload = core::array::from_fn::<_, 137, _>(|index| index as u8);
        let position = RnsNativeProofHashPositionV1 {
            level: 4,
            index: 0,
            counter: 0,
        };
        let prefix: &[&[u8]] = &[b"stream-parity", b"fixed-prefix"];
        let fields: &[&[u8]] = &[prefix[0], prefix[1], &payload];
        let expected = context
            .hash(
                RnsNativeProofHashRoleV1::Transcript,
                RnsNativeProofHashPhaseV1::Binding,
                position,
                fields,
            )
            .unwrap();
        assert!(core::mem::size_of::<GoldilocksDigest384LastFieldStreamV1>() <= 256);
        for chunk in [1, 2, 6, 7, 8, 13, 41, 137] {
            let mut stream = context
                .last_field_stream(
                    RnsNativeProofHashRoleV1::Transcript,
                    RnsNativeProofHashPhaseV1::Binding,
                    position,
                    prefix,
                    payload.len(),
                )
                .unwrap();
            assert_eq!(stream.expected_len(), payload.len());
            stream.update(&[]).unwrap();
            for part in payload.chunks(chunk) {
                stream.update(part).unwrap();
            }
            assert_eq!(stream.received_len(), payload.len());
            assert_eq!(stream.remaining_len(), 0);
            assert_eq!(
                RnsNativeProofDigestV1::from_shared(stream.finalize().unwrap()),
                expected
            );
        }
        let mut overrun = context
            .last_field_stream(
                RnsNativeProofHashRoleV1::Transcript,
                RnsNativeProofHashPhaseV1::Binding,
                position,
                prefix,
                payload.len(),
            )
            .unwrap();
        assert!(overrun.update(&[0; 138]).is_err());
        assert_eq!(overrun.received_len(), 0);
        overrun.update(&payload).unwrap();
        assert_eq!(
            RnsNativeProofDigestV1::from_shared(overrun.finalize().unwrap()),
            expected
        );
        let mut underrun = context
            .last_field_stream(
                RnsNativeProofHashRoleV1::Transcript,
                RnsNativeProofHashPhaseV1::Binding,
                position,
                prefix,
                payload.len(),
            )
            .unwrap();
        underrun.update(&payload[..136]).unwrap();
        assert!(underrun.finalize().is_err());
        let empty = context
            .last_field_stream(
                RnsNativeProofHashRoleV1::Transcript,
                RnsNativeProofHashPhaseV1::Binding,
                position,
                prefix,
                0,
            )
            .unwrap();
        assert_eq!(
            RnsNativeProofDigestV1::from_shared(empty.finalize().unwrap()),
            context
                .hash(
                    RnsNativeProofHashRoleV1::Transcript,
                    RnsNativeProofHashPhaseV1::Binding,
                    position,
                    &[prefix[0], prefix[1], b""]
                )
                .unwrap()
        );
    }
    #[test]
    fn shared_frame_work_counts_actual_rounds_sboxes_mds_and_absorption() {
        let context = RnsNativeProofHashContextV1::canonical().unwrap();
        let fields: &[&[u8]] = &[b"work-frame", &[0; 48], &[0; 32]];
        let frame = context
            .frame(
                RnsNativeProofHashRoleV1::Transcript,
                RnsNativeProofHashPhaseV1::Binding,
                RnsNativeProofHashPositionV1::default(),
                fields,
            )
            .unwrap();
        let work = RnsNativeProofHashWorkV1::from_frame(&frame).unwrap();
        assert_eq!(work.words_per_lane, frame.word_count() as u64);
        assert_eq!(work.lane_permutations, frame.word_count() as u64 / 2 * 6);
        assert_eq!(work.poseidon_rounds, work.lane_permutations * 65);
        assert_eq!(work.field_multiplications, work.lane_permutations * 909);
        assert_eq!(work.field_additions, work.lane_permutations * 782);
        assert!(RnsNativeProofHashWorkV1::from_word_count(0).is_err());
        assert!(RnsNativeProofHashWorkV1::from_word_count(1).is_err());
        if usize::BITS == 64 {
            assert!(RnsNativeProofHashWorkV1::from_word_count(usize::MAX - 1).is_err());
        }
        // These exact cost equations depend on the bound shared scalar owner;
        // changing that owner requires re-auditing resource counts as well.
        let primitive = include_str!("../../../../../fastpq_isi/src/poseidon_digest384.rs");
        assert!(primitive.contains("const FULL_ROUNDS_HALF_V1: usize = 4;"));
        assert!(primitive.contains("const PARTIAL_ROUNDS_V1: usize = 57;"));
        assert!(primitive.contains("multiply_v1(multiply_v1(fourth, square), value)"));
        assert!(primitive.contains(".fold(0_u64, |sum, (column, value)|"));
    }
}
