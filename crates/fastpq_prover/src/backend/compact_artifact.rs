//! Bounded model artifact adapters for the fixed masked SHA3/SHAKE DEEP profile.
//!
//! Public expectations and all AXT context come from the caller. Transport facts
//! are exact-compared before any child proof is decoded. One enclosing Norito
//! scope charges the artifact, carrier and every child cumulatively. This does
//! not authenticate the caller or qualify a production profile.
//! TODO: Independently qualify the protocol and authenticated production caller.

use iroha_crypto::Hash;
use iroha_data_model::fastpq::{
    FastpqArtifactIdentityDescriptionV1, FastpqAxtCompactArtifactV1, FastpqCommitmentDescriptionV1,
    FastpqCompactArtifactDecodeError, FastpqCompactArtifactDecodeLimits, FastpqCompactProfileIdV1,
    FastpqOrderedCompactAirCommitmentsV1, FastpqOrdinaryCompactArtifactV1, FastpqProofKindV1,
    FastpqPublicTransferStatementV1, FastpqQuantityUnits,
};
use norito::{NoritoSerialize, core::DecodeLimits};
use sha2::{Digest as _, Sha256};

use crate::{
    Error, ProofSemantics,
    backend::{
        compact_bundle::{
            BundleLimits, VerifiedBundle, verify_axt_transfer_bundle_with_allocation,
        },
        compact_public_api::AxtVerificationContext,
        compact_public_columns::{COMMITTED_COLUMN_COUNT, LAYOUT_ID},
        compact_value_domain::CompactTransferValue,
        deep_binding::{self, fixed_u32},
        deep_geometry::{
            CONSTRAINTS, COSET_OFFSET, FRI_ARITIES, FRI_DEGREES, FRI_LENGTHS, LDE_ROOT, LDE_ROWS,
            QUERY_CANDIDATES, QUERY_COUNT, TRACE_ROWS,
        },
        deep_proof::DeepProof,
    },
    gadgets::public_transfer_statement::PublicTransferLimits,
    proof::PublicIO,
};

// Exact prior u64 diagnostic identity: immutable negative-fixture data only.
// It selects no retired implementation, layout, decoder, or production profile.
#[cfg(test)]
const PREDECESSOR_U64_PROFILE: [u8; 32] = [
    0x0f, 0x1f, 0xcc, 0x22, 0x66, 0x30, 0xbb, 0xf6, 0xf8, 0x9e, 0x84, 0xdc, 0x6a, 0x48, 0x41, 0x86,
    0x8e, 0x48, 0x35, 0xb8, 0xd4, 0xa5, 0xd6, 0xa9, 0x26, 0x1f, 0x05, 0x71, 0x94, 0xa7, 0x06, 0x76,
];

/// Explicit caller ceilings at every decoded layer and across the whole request.
#[derive(Clone, Copy, Debug)]
pub(in crate::backend) struct ArtifactLimits {
    /// Bounded canonical transport, including its opaque child frame.
    pub(in crate::backend) transport: FastpqCompactArtifactDecodeLimits,
    /// Bounded conversion and validation of public transfer facts.
    pub(in crate::backend) public_statement: PublicTransferLimits,
    /// Cumulative carrier and per-segment policy.
    pub(in crate::backend) bundle: BundleLimits,
    /// Allocation charges permitted for each complete candidate child decode.
    pub(in crate::backend) max_segment_decode_allocation_charges: usize,
    /// Shared budget spanning transport, carrier and every child proof decode.
    pub(in crate::backend) total_decode: DecodeLimits,
}

/// Failure before returning an all-or-nothing candidate relation result.
#[derive(Debug, thiserror::Error)]
pub(in crate::backend) enum ArtifactError {
    /// Bounded transport or fixed diagnostic profile equality failed.
    #[error(transparent)]
    Transport(#[from] FastpqCompactArtifactDecodeError),
    /// Caller equality, public preparation or complete proof verification failed.
    #[error(transparent)]
    Verify(#[from] Error),
}

/// Complete mathematical verification and recomputed canonical content identity.
/// Private fields prevent constructing a result from an advertised description.
/// This type grants no caller authority, source finality or production qualification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backend) struct VerifiedArtifact {
    bundle: VerifiedBundle,
    identity: FastpqArtifactIdentityDescriptionV1,
}

impl VerifiedArtifact {
    /// The complete bundle result whose child commitments populate this identity.
    pub(in crate::backend) fn bundle(&self) -> &VerifiedBundle {
        &self.bundle
    }
    /// Recomputed canonical digests and full authenticated ordered AIR commitments.
    pub(in crate::backend) fn identity(&self) -> &FastpqArtifactIdentityDescriptionV1 {
        &self.identity
    }
}

fn statement_digest(
    statement: &FastpqPublicTransferStatementV1,
    max_bytes: usize,
) -> crate::Result<[u8; 32]> {
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let encoded = match norito::core::to_bytes_bounded(statement, max_bytes) {
        Ok(bytes) => bytes,
        Err(norito::core::BoundedEncodeError::FrameTooLarge {
            encoded_bytes,
            max_bytes,
        }) => {
            return Err(Error::VerifierLimitExceeded {
                limit: "max_compact_identity_statement_bytes",
                actual: encoded_bytes,
                max: max_bytes,
            });
        }
        Err(norito::core::BoundedEncodeError::Serialization(error)) => {
            return Err(Error::Encode(error));
        }
        Err(error) => return Err(Error::Encode(norito::Error::Message(error.to_string()))),
    };
    Ok(Hash::new(&encoded).into())
}

fn finish_artifact<V: CompactTransferValue>(
    kind: FastpqProofKindV1,
    statement_digest: [u8; 32],
    wrapper: &[u8],
    inner: &[u8],
    bundle: VerifiedBundle,
) -> crate::Result<VerifiedArtifact> {
    finish_artifact_for_profile(
        kind,
        profile_id_for::<V>(),
        statement_digest,
        wrapper,
        inner,
        bundle,
    )
}

fn finish_artifact_for_profile(
    kind: FastpqProofKindV1,
    profile_id: FastpqCompactProfileIdV1,
    statement_digest: [u8; 32],
    wrapper: &[u8],
    inner: &[u8],
    bundle: VerifiedBundle,
) -> crate::Result<VerifiedArtifact> {
    // Both lengths are checked by the transport before any verification work;
    // checked conversion also preserves correctness on wider future usize hosts.
    let artifact_bytes =
        u64::try_from(wrapper.len()).map_err(|_| Error::Encode(norito::Error::LengthMismatch))?;
    let segment_count = u64::try_from(bundle.segments())
        .map_err(|_| Error::Encode(norito::Error::LengthMismatch))?;
    let identity = FastpqArtifactIdentityDescriptionV1 {
        proof_kind: kind,
        profile_id,
        public_statement_digest: statement_digest,
        artifact_digest: Hash::new(wrapper).into(),
        inner_bundle_digest: Hash::new(inner).into(),
        artifact_bytes,
        commitments: FastpqCommitmentDescriptionV1::OrderedCompactAir(
            FastpqOrderedCompactAirCommitmentsV1 {
                segment_count,
                segment_air_row_roots: bundle.row_roots().to_vec(),
            },
        ),
    };
    Ok(VerifiedArtifact { bundle, identity })
}

/// Test-only predecessor identity for rejection and diagnostic fixtures.
#[cfg(test)]
pub(in crate::backend) fn diagnostic_profile_id() -> FastpqCompactProfileIdV1 {
    profile_id_for::<u64>()
}

/// Complete fixed DEEP descriptor, independent of untrusted artifact contents.
///
/// Quantity encodings and outer relation identities retain their existing
/// meaning. This distinct nominal frame identifies the replacement proof
/// protocol, including its actual geometry and canonical child-frame identity.
#[derive(Clone, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_model_statement::candidate_artifact::DeepQuantityArtifactProfile",
    frame = "fastpq_prover::deep_compact::QuantityArtifactProfileV1"
)]
struct DeepQuantityArtifactProfile {
    version: u16,
    catalog: &'static str,
    /// Complete canonical bytes of the typed transcript profile descriptor,
    /// the same bytes every commitment and challenge absorbs.
    transcript_profile: Vec<u8>,
    trace_rows: u32,
    trace_root: u64,
    lde_rows: u32,
    lde_root: u64,
    coset_offset: u64,
    committed_columns: u32,
    public_column_layout: &'static str,
    constraints: u32,
    modulus: u64,
    extension_degree: u8,
    extension_nonresidue: u64,
    extension_schema: String,
    extension_bytes: u32,
    commitment_algorithm: &'static str,
    commitment_bytes: u32,
    transcript_algorithm: &'static str,
    trace_mask_coefficients: u32,
    quotient_mask_coefficients: u32,
    fiber_encoding: &'static str,
    fri_arities: [u32; 5],
    fri_lengths: [u32; 6],
    fri_degrees: [u32; 6],
    query_count: u32,
    query_candidates: u32,
    tape_bytes: [u32; 10],
    proof_frame_schema: String,
    proof_frame_hash: [u8; 16],
    quantity_value_schema: &'static str,
    quantity_context_schema: &'static str,
    value_hash_domain: Vec<u8>,
    relation_identities: [&'static str; 2],
}

impl DeepQuantityArtifactProfile {
    fn fixed() -> Self {
        use norito::schema::identity::NoritoSchema as _;

        Self {
            version: 1,
            catalog: fastpq_isi::FASTPQ_CATALOG_V1,
            transcript_profile: crate::backend::transcript_profile::profile()
                .as_bytes()
                .to_vec(),
            trace_rows: fixed_u32(TRACE_ROWS),
            trace_root: fastpq_isi::FASTPQ_FINAL_V1.trace_root,
            lde_rows: fixed_u32(LDE_ROWS),
            lde_root: LDE_ROOT,
            coset_offset: COSET_OFFSET,
            committed_columns: fixed_u32(COMMITTED_COLUMN_COUNT),
            public_column_layout: LAYOUT_ID,
            constraints: fixed_u32(CONSTRAINTS),
            modulus: crate::field::GOLDILOCKS_MODULUS_V1,
            extension_degree: 4,
            extension_nonresidue: deep_binding::EXTENSION_NONRESIDUE,
            extension_schema: crate::GoldilocksFp4V1::frame_name(),
            extension_bytes: fixed_u32(crate::GoldilocksFp4V1::BYTES),
            commitment_algorithm: "FIPS202:SHA3-256:suffix06",
            commitment_bytes: 32,
            transcript_algorithm: "FIPS202:SHAKE256:suffix1f:atomic-raw-tapes",
            trace_mask_coefficients: fixed_u32(
                fastpq_isi::compact_challenge::TRACE_MASK_COEFFICIENTS,
            ),
            quotient_mask_coefficients: fixed_u32(
                fastpq_isi::compact_challenge::QUOTIENT_MASK_COEFFICIENTS,
            ),
            fiber_encoding: "arity-tag:omit-smallest-known-incoming-coordinate",
            fri_arities: FRI_ARITIES.map(fixed_u32),
            fri_lengths: FRI_LENGTHS.map(fixed_u32),
            fri_degrees: FRI_DEGREES.map(fixed_u32),
            query_count: fixed_u32(QUERY_COUNT),
            query_candidates: fixed_u32(QUERY_CANDIDATES),
            tape_bytes: core::array::from_fn(|round| {
                let round = u8::try_from(round + 1).expect("fixed DEEP round index fits u8");
                fixed_u32(
                    deep_binding::Round::new(round)
                        .expect("fixed DEEP round")
                        .tape_bytes(),
                )
            }),
            proof_frame_schema: DeepProof::frame_name(),
            proof_frame_hash: norito::schema::identity::frame_hash::<DeepProof>(),
            quantity_value_schema: "fastpq_prover::public_transfer::QuantityValueV1",
            quantity_context_schema: "fastpq_prover::compact_v1::QuantityTransferContextV1",
            value_hash_domain: b"fastpq:quantity:v1:smt:value|".to_vec(),
            relation_identities: [
                FastpqQuantityUnits::BATCH_IDENTITY,
                FastpqQuantityUnits::AXT_BATCH_IDENTITY,
            ],
        }
    }

    fn profile_id(&self) -> FastpqCompactProfileIdV1 {
        FastpqCompactProfileIdV1(
            Sha256::digest(
                norito::encode_canonical(self).expect("bounded fixed profile description"),
            )
            .into(),
        )
    }
}

/// Canonical masked Quantity profile identity; identity alone grants no authority.
pub(in crate::backend) fn quantity_diagnostic_profile_id() -> FastpqCompactProfileIdV1 {
    DeepQuantityArtifactProfile::fixed().profile_id()
}

fn profile_id_for<V: CompactTransferValue>() -> FastpqCompactProfileIdV1 {
    // The predecessor u64 fixture identity exists only in diagnostic tests.
    // Normal artifact construction and decoding share exactly one fixed profile.
    #[cfg(test)]
    if !V::QUANTITY_CONTEXT {
        return FastpqCompactProfileIdV1(PREDECESSOR_U64_PROFILE);
    }
    quantity_diagnostic_profile_id()
}

/// Verify AXT model bytes against every independently supplied caller expectation.
/// The artifact cannot substitute its own binding, mirrors, metadata or preimages.
#[cfg(test)]
#[allow(
    clippy::large_types_passed_by_value,
    reason = "keeps the by-value `Copy` context/limits contract of `tests` and `quantity_tests`"
)]
pub(in crate::backend) fn verify_axt_artifact(
    bytes: &[u8],
    expected: &PublicIO,
    context: AxtVerificationContext<'_>,
    limits: ArtifactLimits,
) -> Result<VerifiedArtifact, ArtifactError> {
    verify_axt_artifact_for::<u64>(bytes, expected, None, &context, &limits)
}

/// Verify a complete AXT `QuantityValueV1` artifact with independent caller context.
/// All binding, mirrors and remote preimages remain mandatory under this route.
#[cfg(test)]
#[allow(
    clippy::large_types_passed_by_value,
    reason = "keeps the by-value `Copy` context/limits contract of its `quantity_tests` callers"
)]
pub(in crate::backend) fn verify_quantity_axt_artifact(
    bytes: &[u8],
    expected: &PublicIO,
    context: AxtVerificationContext<'_>,
    limits: ArtifactLimits,
) -> Result<VerifiedArtifact, ArtifactError> {
    verify_axt_artifact_for::<FastpqQuantityUnits>(bytes, expected, None, &context, &limits)
}

/// Verify the fixed AXT quantity route with a mandatory independent statement digest.
/// All AXT context and complete statement identity remain caller expectations.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "keeps the by-value `Copy` context/limits contract of the offline facade and tests"
)]
pub(in crate::backend) fn verify_bound_quantity_axt_artifact(
    bytes: &[u8],
    expected: &PublicIO,
    expected_statement_digest: [u8; 32],
    context: AxtVerificationContext<'_>,
    limits: ArtifactLimits,
) -> Result<VerifiedArtifact, ArtifactError> {
    verify_axt_artifact_for::<FastpqQuantityUnits>(
        bytes,
        expected,
        Some(expected_statement_digest),
        &context,
        &limits,
    )
}

fn verify_axt_artifact_for<V: CompactTransferValue>(
    bytes: &[u8],
    expected: &PublicIO,
    expected_statement_digest: Option<[u8; 32]>,
    context: &AxtVerificationContext<'_>,
    limits: &ArtifactLimits,
) -> Result<VerifiedArtifact, ArtifactError> {
    norito::core::with_decode_limits_scope(limits.total_decode, || {
        let artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            profile_id_for::<V>(),
            limits.transport,
        )?;
        validate_axt_advertisement(&artifact, *context)?;
        let (bundle, digest) = super::with_prepared_statement_as::<V, _>(
            &artifact.statement,
            expected,
            ProofSemantics::AxtTransferClaim,
            limits.public_statement,
            |prepared| {
                let digest = statement_digest(
                    &artifact.statement,
                    limits.public_statement.max_public_bytes,
                )?;
                if expected_statement_digest.is_some_and(|expected| digest != expected) {
                    return Err(Error::PublicIoMismatch {
                        field: "compact_artifact_public_statement_digest",
                    });
                }
                let bundle = verify_axt_transfer_bundle_with_allocation(
                    prepared,
                    expected,
                    *context,
                    &artifact.bundle_frame,
                    limits.bundle,
                    limits.max_segment_decode_allocation_charges,
                )?;
                Ok((bundle, digest))
            },
        )?;
        finish_artifact::<V>(
            FastpqProofKindV1::AxtCompact,
            digest,
            bytes,
            &artifact.bundle_frame,
            bundle,
        )
        .map_err(ArtifactError::Verify)
    })
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "keeps the by-value `Copy` context contract of its `tests` child-module callers"
)]
fn validate_axt_advertisement(
    artifact: &FastpqAxtCompactArtifactV1,
    context: AxtVerificationContext<'_>,
) -> crate::Result<()> {
    let advertised = &artifact.metadata;
    let expected = context.metadata;
    let mirrors = artifact.mirrors;
    for (field, matches) in [
        (
            "compact_artifact_binding",
            artifact.binding == *context.binding,
        ),
        (
            "compact_artifact_parameter",
            advertised.parameter == expected.parameter,
        ),
        (
            "compact_artifact_entry_hash",
            advertised.entry_hash.as_slice() == expected.entry_hash,
        ),
        (
            "compact_artifact_amount_bytes",
            advertised
                .committed_amount
                .as_ref()
                .map(<[u8; 16]>::as_slice)
                == expected.committed_amount,
        ),
        (
            "compact_artifact_expiry_bytes",
            advertised.expiry_slot.as_slice() == expected.expiry_slot,
        ),
        (
            "compact_artifact_manifest_bytes",
            advertised.manifest_root.as_slice() == expected.manifest_root,
        ),
        (
            "compact_artifact_source_occurrences",
            advertised.source_transfer_occurrences.as_slice()
                == expected.source_transfer_occurrences,
        ),
        (
            "compact_artifact_da_bytes",
            advertised.da_commitment.as_slice() == expected.da_commitment,
        ),
        (
            "compact_artifact_mirror_dsid",
            mirrors.dsid == context.mirrors.dsid,
        ),
        (
            "compact_artifact_mirror_manifest",
            mirrors.manifest_root == context.mirrors.manifest_root,
        ),
        (
            "compact_artifact_mirror_da",
            mirrors.da_commitment == context.mirrors.da_commitment,
        ),
        (
            "compact_artifact_mirror_amount",
            mirrors.committed_amount == context.mirrors.committed_amount,
        ),
        (
            "compact_artifact_mirror_expiry",
            mirrors.expiry_slot == context.mirrors.expiry_slot,
        ),
        (
            "compact_artifact_remote_claims",
            artifact.remote_spend_claims.as_deref() == context.remote_spend_claims,
        ),
    ] {
        if !matches {
            return Err(Error::PublicIoMismatch { field });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "compact_artifact_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compact_quantity_artifact_tests.rs"]
mod quantity_tests;

#[path = "compact_artifact/execution_effect_profile.rs"]
mod execution_effect_profile;
pub(in crate::backend) use execution_effect_profile::execution_effect_profile_id;

#[path = "compact_artifact/execution_effect.rs"]
pub(in crate::backend) mod execution_effect;

#[cfg(test)]
#[path = "compact_effect_test_support.rs"]
pub(in crate::backend) mod effect_test_support;
