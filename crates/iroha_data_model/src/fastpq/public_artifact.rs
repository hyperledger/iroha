//! Path-free public FASTPQ transport statements and untrusted artifact descriptions.
//!
//! These nominal V1 codecs do not prepare a relation, authenticate ledger state,
//! verify proofs, qualify a profile, or grant spend authority. The inner bundle
//! frame is opaque at this boundary. Only the prover's typed, validated public
//! constructor may translate a statement into a relation.
//!
//! TODO: Qualify a compact profile and implement the authenticated execution-state
//! bridge before admitting either compact artifact in production. Identity
//! descriptions must be checked against bounded parsed proofs at that boundary;
//! decoding a description does not derive or authenticate its advertised roots.

use super::{
    FastpqExecutionEffectStatementV1, FastpqOrdinarySourceStatementLeafV1, FastpqPublicInputs,
    FastpqStateTransition, TransferDeltaTranscript, TransferTranscript,
};
use crate::{
    account::AccountId,
    asset::id::AssetDefinitionId,
    nexus::{AxtFastpqBinding, AxtRemoteSpendClaimV1, AxtSourceTransferOccurrenceV1},
    privacy::GoldilocksDigest384V1,
};
use iroha_crypto::Hash;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::{DecodeLimits, NoritoDeserialize, NoritoSerialize};

/// Exact ordinary compact artifact schema; recognition does not qualify a profile.
pub const FASTPQ_ORDINARY_COMPACT_ARTIFACT_V1_SCHEMA_NAME: &str =
    "iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1";
/// Exact AXT compact artifact schema; recognition does not qualify a profile.
pub const FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME: &str =
    "iroha_data_model::fastpq::FastpqAxtCompactArtifactV1";

/// One exact public transfer occurrence, with no sparse-Merkle witnesses.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqPublicTransferDeltaV1",
    frame = "iroha_data_model::fastpq::FastpqPublicTransferDeltaV1"
)]
pub struct FastpqPublicTransferDeltaV1 {
    /// Source account, independent of domain routing or aliases.
    pub from_account: AccountId,
    /// Destination account, independent of domain routing or aliases.
    pub to_account: AccountId,
    /// Asset definition transferred.
    pub asset_definition: AssetDefinitionId,
    /// Original exact transfer quantity; no normalization occurs during projection.
    pub amount: Quantity,
    /// Original sender quantity before this occurrence.
    pub from_balance_before: Quantity,
    /// Original sender quantity after this occurrence.
    pub from_balance_after: Quantity,
    /// Original receiver quantity before this occurrence.
    pub to_balance_before: Quantity,
    /// Original receiver quantity after this occurrence.
    pub to_balance_after: Quantity,
}

impl From<&TransferDeltaTranscript> for FastpqPublicTransferDeltaV1 {
    fn from(delta: &TransferDeltaTranscript) -> Self {
        Self {
            from_account: delta.from_account.clone(),
            to_account: delta.to_account.clone(),
            asset_definition: delta.asset_definition.clone(),
            amount: delta.amount.clone(),
            from_balance_before: delta.from_balance_before.clone(),
            from_balance_after: delta.from_balance_after.clone(),
            to_balance_before: delta.to_balance_before.clone(),
            to_balance_after: delta.to_balance_after.clone(),
        }
    }
}

/// Original ordered public transcript; equal hashes retain separate occurrences.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqPublicTransferTranscriptV1",
    frame = "iroha_data_model::fastpq::FastpqPublicTransferTranscriptV1"
)]
pub struct FastpqPublicTransferTranscriptV1 {
    /// Original execution entrypoint hash.
    pub batch_hash: Hash,
    /// Original ordered deltas; duplicates are not merged.
    pub deltas: Vec<FastpqPublicTransferDeltaV1>,
    /// Public authority-set commitment, not evidence of authenticated authority.
    pub authority_digest: Hash,
    /// Original optional Poseidon preimage digest.
    pub poseidon_preimage_digest: Option<Hash>,
}

impl From<&TransferTranscript> for FastpqPublicTransferTranscriptV1 {
    fn from(transcript: &TransferTranscript) -> Self {
        Self {
            batch_hash: transcript.batch_hash,
            deltas: transcript
                .deltas
                .iter()
                .map(FastpqPublicTransferDeltaV1::from)
                .collect(),
            authority_digest: transcript.authority_digest,
            poseidon_preimage_digest: transcript.poseidon_preimage_digest,
        }
    }
}

/// Nominal public transfer statement, before native preparation and authentication.
///
/// The six model inputs plus `ordering_hash` preserve all seven verifier inputs.
/// Wire bytes of this DTO are distinct from the existing prepared AIR statement.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqPublicTransferStatementV1",
    frame = "iroha_data_model::fastpq::FastpqPublicTransferStatementV1"
)]
pub struct FastpqPublicTransferStatementV1 {
    /// Advertised six model public inputs; trusted expectations arrive separately.
    pub public_inputs: FastpqPublicInputs,
    /// Seventh public input: original complete canonical transition ordering hash.
    pub ordering_hash: [u8; 32],
    /// Complete original canonical public transition table, never a delta slice.
    pub transitions: Vec<FastpqStateTransition>,
    /// Complete original ordered public transcripts, with occurrence multiplicity.
    pub transcripts: Vec<FastpqPublicTransferTranscriptV1>,
}

/// Exact identifier for a profile's schema, geometry, transcript and resource policy.
///
/// No value is registered or qualified by this transport type. A future verifier
/// must resolve it through its own reviewed registry before any proof admission.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqCompactProfileIdV1",
    frame = "iroha_data_model::fastpq::FastpqCompactProfileIdV1"
)]
pub struct FastpqCompactProfileIdV1(pub [u8; 32]);

/// Exact original public AXT execution metadata fields, with no arbitrary map.
///
/// Byte arrays preserve the accepted field encodings, including absence versus
/// an explicitly encoded zero. Semantic and mirror validation belongs to the
/// typed AXT public constructor. No completed-proof amount commitment is present.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqAxtPublicMetadataV1",
    frame = "iroha_data_model::fastpq::FastpqAxtPublicMetadataV1"
)]
pub struct FastpqAxtPublicMetadataV1 {
    /// Original execution parameter string.
    pub parameter: String,
    /// Original entrypoint commitment bytes.
    pub entry_hash: [u8; 32],
    /// Optional exact little-endian scalar bytes; not a business quantity.
    pub committed_amount: Option<[u8; 16]>,
    /// Exact little-endian expiry bytes; zero represents absence in the relation.
    pub expiry_slot: [u8; 8],
    /// Original manifest commitment bytes.
    pub manifest_root: [u8; 32],
    /// Exact 33-byte option encoding of the DA commitment.
    pub da_commitment: [u8; 33],
    /// Exact successful source transfer occurrences in claim-commitment order.
    pub source_transfer_occurrences: Vec<AxtSourceTransferOccurrenceV1>,
}

/// Advertised pre-proof AXT outer mirrors; callers must authenticate their own values.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqAxtPreProofMirrorsV1",
    frame = "iroha_data_model::fastpq::FastpqAxtPreProofMirrorsV1"
)]
pub struct FastpqAxtPreProofMirrorsV1 {
    /// Advertised enclosing dataspace.
    pub dsid: DataSpaceId,
    /// Advertised enclosing manifest root.
    pub manifest_root: [u8; 32],
    /// Advertised enclosing DA commitment option.
    pub da_commitment: Option<[u8; 32]>,
    /// Advertised enclosing scalar option.
    pub committed_amount: Option<u128>,
    /// Advertised enclosing expiry option.
    pub expiry_slot: Option<u64>,
}

/// Unverified ordinary compact artifact under a route-specific nominal schema.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqOrdinaryCompactArtifactV1",
    frame = "iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1"
)]
pub struct FastpqOrdinaryCompactArtifactV1 {
    /// Advertised exact compact profile identifier.
    pub profile_id: FastpqCompactProfileIdV1,
    /// Complete advertised D7 source leaf; the verifier supplies its independent
    /// authenticated expectation and checks exact equality before preparation.
    pub source: FastpqOrdinarySourceStatementLeafV1,
    /// Complete ordered typed quantity effects and canonical public transitions.
    pub statement: FastpqExecutionEffectStatementV1,
    /// Advertised canonical ordinary effect bundle frame; this codec leaves it opaque.
    pub bundle_frame: Vec<u8>,
}

/// Unverified AXT compact artifact with complete explicit public binding inputs.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqAxtCompactArtifactV1",
    frame = "iroha_data_model::fastpq::FastpqAxtCompactArtifactV1"
)]
pub struct FastpqAxtCompactArtifactV1 {
    /// Advertised exact compact profile identifier.
    pub profile_id: FastpqCompactProfileIdV1,
    /// Complete original public transfer statement.
    pub statement: FastpqPublicTransferStatementV1,
    /// Complete canonical receipt/effect binding; no context byte escape hatch.
    pub binding: AxtFastpqBinding,
    /// Exact original execution metadata, excluding private transcript metadata.
    pub metadata: FastpqAxtPublicMetadataV1,
    /// Separately advertised outer mirrors to be compared to caller expectations.
    pub mirrors: FastpqAxtPreProofMirrorsV1,
    /// Exact ordered remote preimages; absent and present-empty remain distinct.
    pub remote_spend_claims: Option<Vec<AxtRemoteSpendClaimV1>>,
    /// Advertised canonical AXT bundle frame; this codec leaves it opaque.
    pub bundle_frame: Vec<u8>,
}

/// Proof-kind description; this enum never selects a verifier by itself.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqProofKindV1",
    frame = "iroha_data_model::fastpq::FastpqProofKindV1"
)]
pub enum FastpqProofKindV1 {
    /// Existing replay-based proof, whose commitment covers preprocessing rows.
    #[codec(index = 0)]
    LegacyReplay,
    /// Ordinary compact complete-effect bundle, currently unqualified.
    #[codec(index = 1)]
    OrdinaryCompact,
    /// AXT compact transfer bundle, currently unqualified.
    #[codec(index = 2)]
    AxtCompact,
}

/// Advertised compact AIR row roots in chronological segment order.
///
/// Decoding preserves these claims; it does not check them against opaque proofs.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqOrderedCompactAirCommitmentsV1",
    frame = "iroha_data_model::fastpq::FastpqOrderedCompactAirCommitmentsV1"
)]
pub struct FastpqOrderedCompactAirCommitmentsV1 {
    /// Advertised exact segment count, to be checked against roots and frames.
    pub segment_count: u64,
    /// Advertised opaque SHA3-256 compact row roots in chronological segment order.
    pub segment_air_row_roots: Vec<super::FastpqCommitmentV1>,
}

/// Untrusted commitment description with explicit, non-interchangeable meanings.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqCommitmentDescriptionV1",
    frame = "iroha_data_model::fastpq::FastpqCommitmentDescriptionV1"
)]
pub enum FastpqCommitmentDescriptionV1 {
    /// Advertised legacy preprocessing commitment; not a compact AIR row root.
    #[codec(index = 0)]
    LegacyPreprocessing(GoldilocksDigest384V1),
    /// Advertised ordered compact AIR row-root claims for every segment occurrence.
    #[codec(index = 1)]
    OrderedCompactAir(FastpqOrderedCompactAirCommitmentsV1),
}

/// Untrusted content identity description, never an authenticated proof result.
///
/// A consumer must independently recompute the canonical wrapper, public statement
/// and inner-frame digests, byte length and bounded commitment list. This DTO has
/// no constructor that claims to extract roots from opaque child proof bytes.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::public_artifact::FastpqArtifactIdentityDescriptionV1",
    frame = "iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1"
)]
pub struct FastpqArtifactIdentityDescriptionV1 {
    /// Advertised proof kind, to be compared to the nominal artifact schema.
    pub proof_kind: FastpqProofKindV1,
    /// Advertised exact profile; it does not establish qualification.
    pub profile_id: FastpqCompactProfileIdV1,
    /// Advertised hash of the canonical nominal public statement frame.
    pub public_statement_digest: [u8; 32],
    /// Advertised hash of the complete canonical nominal artifact wrapper.
    pub artifact_digest: [u8; 32],
    /// Advertised hash of the exact inner bundle frame, distinct from the wrapper.
    pub inner_bundle_digest: [u8; 32],
    /// Advertised complete canonical artifact byte length.
    pub artifact_bytes: u64,
    /// Advertised commitment meaning and ordered values, requiring verification.
    pub commitments: FastpqCommitmentDescriptionV1,
}

/// Explicit caller policy for offline transport decoding, with no production default.
///
/// Norito caps fields, sequences, aggregate elements, allocation charges and depth
/// before its allocations. `max_bundle_frame_bytes` additionally bounds the opaque
/// returned blob; it does not parse or validate the child proof. An enclosing Norito
/// scope remains active and retains cumulative charges across sequential decodes.
#[derive(Debug, Clone, Copy)]
pub struct FastpqCompactArtifactDecodeLimits {
    /// Maximum complete canonical artifact bytes, checked before header inspection.
    pub max_wire_bytes: usize,
    /// Maximum returned opaque inner bundle frame bytes.
    pub max_bundle_frame_bytes: usize,
    /// Complete caller-supplied Norito resource budget.
    pub norito: DecodeLimits,
}

/// Offline transport decode error; even success is not proof admission.
#[derive(Debug, thiserror::Error)]
pub enum FastpqCompactArtifactDecodeError {
    /// Complete wrapper exceeds the caller's raw byte cap.
    #[error("compact artifact has {actual} bytes, exceeding the caller limit {max}")]
    WireBytes {
        /// Actual complete wrapper byte length.
        actual: usize,
        /// Caller-supplied maximum byte length.
        max: usize,
    },
    /// Inner opaque frame exceeds the caller's explicit blob cap.
    #[error("compact bundle frame has {actual} bytes, exceeding the caller limit {max}")]
    BundleBytes {
        /// Actual inner frame byte length.
        actual: usize,
        /// Caller-supplied maximum byte length.
        max: usize,
    },
    /// Advertised profile differs from the caller's explicit offline expectation.
    #[error("compact artifact profile differs from the requested offline profile")]
    ProfileMismatch,
    /// Schema, canonicality or resource validation failed in Norito.
    #[error(transparent)]
    Norito(#[from] norito::Error),
}

impl FastpqOrdinaryCompactArtifactV1 {
    /// Decode one exact ordinary transport frame under explicit caller limits.
    ///
    /// `expected_profile` is only an offline equality filter, not a qualified-profile
    /// registry. Production dispatch must reject every unqualified compact schema
    /// before invoking a body decoder. No child frame is decoded here.
    ///
    /// # Errors
    /// Returns an error for an oversized, noncanonical, wrong-schema or over-budget
    /// frame, or when its profile differs from `expected_profile`.
    pub fn decode_canonical_with_limits(
        bytes: &[u8],
        expected_profile: FastpqCompactProfileIdV1,
        limits: FastpqCompactArtifactDecodeLimits,
    ) -> Result<Self, FastpqCompactArtifactDecodeError> {
        preflight_raw(bytes, limits)?;
        let artifact: Self = norito::decode_canonical_with_limits(bytes, limits.norito)?;
        check_profile_and_bundle(
            artifact.profile_id,
            expected_profile,
            artifact.bundle_frame.len(),
            limits,
        )?;
        Ok(artifact)
    }
}

impl FastpqAxtCompactArtifactV1 {
    /// Decode one exact AXT transport frame under explicit caller limits.
    ///
    /// Equality with `expected_profile` grants no qualification or authority; all
    /// bindings, metadata, mirrors, preimages and opaque child proofs remain unverified.
    ///
    /// # Errors
    /// Returns an error for an oversized, noncanonical, wrong-schema or over-budget
    /// frame, or when its profile differs from `expected_profile`.
    pub fn decode_canonical_with_limits(
        bytes: &[u8],
        expected_profile: FastpqCompactProfileIdV1,
        limits: FastpqCompactArtifactDecodeLimits,
    ) -> Result<Self, FastpqCompactArtifactDecodeError> {
        preflight_raw(bytes, limits)?;
        let artifact: Self = norito::decode_canonical_with_limits(bytes, limits.norito)?;
        check_profile_and_bundle(
            artifact.profile_id,
            expected_profile,
            artifact.bundle_frame.len(),
            limits,
        )?;
        Ok(artifact)
    }
}

fn preflight_raw(
    bytes: &[u8],
    limits: FastpqCompactArtifactDecodeLimits,
) -> Result<(), FastpqCompactArtifactDecodeError> {
    if bytes.len() > limits.max_wire_bytes {
        return Err(FastpqCompactArtifactDecodeError::WireBytes {
            actual: bytes.len(),
            max: limits.max_wire_bytes,
        });
    }
    Ok(())
}

fn check_profile_and_bundle(
    profile: FastpqCompactProfileIdV1,
    expected: FastpqCompactProfileIdV1,
    bundle_bytes: usize,
    limits: FastpqCompactArtifactDecodeLimits,
) -> Result<(), FastpqCompactArtifactDecodeError> {
    if profile != expected {
        return Err(FastpqCompactArtifactDecodeError::ProfileMismatch);
    }
    if bundle_bytes > limits.max_bundle_frame_bytes {
        return Err(FastpqCompactArtifactDecodeError::BundleBytes {
            actual: bundle_bytes,
            max: limits.max_bundle_frame_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NetworkId,
        asset::AssetBalanceScope,
        fastpq::{
            FastpqExecutionAssetV1, FastpqExecutionBalanceV1, FastpqExecutionEffectContextV1,
            FastpqExecutionEffectKindV1, FastpqExecutionEffectV1, FastpqExecutionEffectsV1,
            FastpqExecutionSupplyChangeV1, FastpqExecutionTransferV1, FastpqOperationKind,
            FastpqSourceExecutionEntryV1, FastpqSourceExecutionKindV1, FastpqSourceRouteV1,
            FastpqSourceStatementContextV1, TransferSmtWitness, execution_effects_digest_v1,
        },
        nexus::{
            AxtAssetIncarnationV1, AxtHandleIssuerContextV1, AxtHandleReplayKey,
            compute_remote_spend_claim_commitment_v1,
        },
    };
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::LaneId;
    use iroha_primitives::numeric::Numeric;

    const PROFILE: FastpqCompactProfileIdV1 = FastpqCompactProfileIdV1([0x42; 32]);

    fn limits() -> FastpqCompactArtifactDecodeLimits {
        FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: 128 * 1024,
            max_bundle_frame_bytes: 32 * 1024,
            norito: DecodeLimits::new(64 * 1024, 128 * 1024, 256 * 1024, 16 * 1024 * 1024, 32),
        }
    }

    fn quantity(mantissa: u64, scale: u32) -> Quantity {
        Quantity::try_from_numeric(Numeric::new(mantissa, scale)).unwrap()
    }

    fn transcript() -> TransferTranscript {
        let alice = KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519);
        let bob = KeyPair::from_seed(vec![2; 32], Algorithm::Ed25519);
        let delta = TransferDeltaTranscript {
            from_account: AccountId::new(alice.public_key().clone()),
            to_account: AccountId::new(bob.public_key().clone()),
            asset_definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            amount: quantity(123, 2),
            from_balance_before: quantity(500, 1),
            from_balance_after: quantity(4877, 2),
            to_balance_before: quantity(251, 1),
            to_balance_after: quantity(2633, 2),
            from_smt_witness: TransferSmtWitness::new(
                [7; 32],
                [8; 32],
                vec![9; 32],
                vec![[10; 32]; 64],
            ),
            to_smt_witness: TransferSmtWitness::new(
                [8; 32],
                [11; 32],
                vec![12; 32],
                vec![[13; 32]; 64],
            ),
        };
        TransferTranscript {
            batch_hash: Hash::prehashed([14; 32]),
            deltas: vec![delta.clone(), delta],
            authority_digest: Hash::prehashed([15; 32]),
            poseidon_preimage_digest: Some(Hash::prehashed([16; 32])),
        }
    }

    fn transfer_statement() -> FastpqPublicTransferStatementV1 {
        let public = FastpqPublicTransferTranscriptV1::from(&transcript());
        FastpqPublicTransferStatementV1 {
            public_inputs: FastpqPublicInputs {
                dsid: [1; 16],
                slot: 2,
                old_root: [3; 32],
                new_root: [4; 32],
                perm_root: [5; 32],
                tx_set_hash: [6; 32],
            },
            ordering_hash: [7; 32],
            transitions: vec![FastpqStateTransition {
                key: b"public balance key".to_vec(),
                pre_value: vec![8],
                post_value: vec![9],
                operation: FastpqOperationKind::Transfer,
            }],
            transcripts: vec![public.clone(), public],
        }
    }

    fn ordinary() -> FastpqOrdinaryCompactArtifactV1 {
        // This transport fixture preserves untrusted full claims; only the backend
        // checks complete arithmetic, transitions, source equality and proofs.
        let transfer = transfer_statement();
        let delta = &transfer.transcripts[0].deltas[0];
        let asset = FastpqExecutionAssetV1 {
            definition: delta.asset_definition.clone(),
            incarnation: AxtAssetIncarnationV1::try_from_bytes(
                Hash::new(b"artifact lifecycle").into(),
            )
            .unwrap(),
        };
        let balance = FastpqExecutionBalanceV1 {
            asset: asset.clone(),
            account: delta.from_account.clone(),
            scope: AssetBalanceScope::Global,
        };
        let supply = FastpqExecutionSupplyChangeV1 {
            balance: balance.clone(),
            amount: quantity(5, 0),
            balance_before: quantity(9, 0),
            balance_after: quantity(14, 0),
            supply_before: quantity(10, 0),
            supply_after: quantity(15, 0),
        };
        let context = FastpqExecutionEffectContextV1 {
            source: FastpqSourceStatementContextV1 {
                network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"artifact network"),
                )),
                height: 9,
            },
            entry: FastpqSourceExecutionEntryV1 {
                entry_hash: Hash::new(b"artifact original entry"),
                execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
                route: FastpqSourceRouteV1::Unrouted,
                dataspace_id: DataSpaceId::UNIVERSAL,
            },
        };
        let kinds = [
            FastpqExecutionEffectKindV1::Transfer(FastpqExecutionTransferV1 {
                source: balance.clone(),
                destination: FastpqExecutionBalanceV1 {
                    account: delta.to_account.clone(),
                    ..balance
                },
                amount: delta.amount.clone(),
                source_before: delta.from_balance_before.clone(),
                source_after: delta.from_balance_after.clone(),
                destination_before: delta.to_balance_before.clone(),
                destination_after: delta.to_balance_after.clone(),
            }),
            FastpqExecutionEffectKindV1::Mint(supply.clone()),
            FastpqExecutionEffectKindV1::Burn(supply),
            FastpqExecutionEffectKindV1::Retire(asset),
        ];
        let effects = FastpqExecutionEffectsV1 {
            context,
            effects: kinds
                .into_iter()
                .enumerate()
                .map(|(ordinal, kind)| FastpqExecutionEffectV1 {
                    ordinal: u32::try_from(ordinal).unwrap(),
                    authority_digest: Hash::new(b"artifact authority"),
                    authorization_context: Hash::new(b"artifact original authorization"),
                    kind,
                })
                .collect(),
        };
        let source = FastpqOrdinarySourceStatementLeafV1 {
            source: context.source,
            statement_index: 2,
            entry_index: 4,
            effect_count: 4,
            entry_hash: context.entry.entry_hash,
            execution_kind: context.entry.execution_kind,
            route: context.entry.route,
            dataspace_id: context.entry.dataspace_id,
            effects_digest: execution_effects_digest_v1(&effects).unwrap().into(),
            slot: transfer.public_inputs.slot,
            perm_root: transfer.public_inputs.perm_root,
            tx_set_hash: transfer.public_inputs.tx_set_hash,
        };
        FastpqOrdinaryCompactArtifactV1 {
            profile_id: PROFILE,
            source,
            statement: FastpqExecutionEffectStatementV1 {
                public_inputs: transfer.public_inputs,
                ordering_hash: transfer.ordering_hash,
                transitions: transfer.transitions,
                effects,
            },
            bundle_frame: norito::encode_canonical(&vec![0x31_u8; 4096]).unwrap(),
        }
    }

    fn axt() -> FastpqAxtCompactArtifactV1 {
        let statement = transfer_statement();
        let delta = &statement.transcripts[0].deltas[0];
        let claim = AxtRemoteSpendClaimV1::new(
            AxtHandleReplayKey::from_parts(
                DataSpaceId::new(7),
                AxtHandleIssuerContextV1::default().asset_definition_incarnation,
                [8; 32],
                1,
                2,
                LaneId::new(0),
            ),
            delta.asset_definition.clone(),
            "transfer",
            delta.from_account.to_string(),
            delta.to_account.to_string(),
            delta.amount.clone(),
        );
        FastpqAxtCompactArtifactV1 {
            profile_id: PROFILE,
            statement,
            binding: AxtFastpqBinding {
                parameter: "fastpq-state-transition-stark-v1".into(),
                source_dsid: 7,
                source_dataspace: "source".into(),
                source_receipt_id: "receipt".into(),
                source_tx_commitment: "ab".repeat(32),
                claim_type: "tx_predicate".into(),
                claim_digest: "bc".repeat(32),
                witness_commitment: "cd".repeat(32),
                policy_commitment: "de".repeat(32),
                verified_effect_type: "transfer".into(),
                corridor: "corridor".into(),
                verifier_id: "fastpq".into(),
                verifier_version: "v1".into(),
                target_dsids: vec![8, 9],
                effect_binding: None,
                remote_spend_intent_commitments: vec![compute_remote_spend_claim_commitment_v1(
                    &claim,
                )],
            },
            metadata: FastpqAxtPublicMetadataV1 {
                source_transfer_occurrences: Vec::new(),
                parameter: "fastpq-state-transition-stark-v1".into(),
                entry_hash: [14; 32],
                committed_amount: Some(123_u128.to_le_bytes()),
                expiry_slot: 456_u64.to_le_bytes(),
                manifest_root: [17; 32],
                da_commitment: core::array::from_fn(|i| if i == 0 { 1 } else { 18 }),
            },
            mirrors: FastpqAxtPreProofMirrorsV1 {
                dsid: DataSpaceId::new(7),
                manifest_root: [17; 32],
                da_commitment: Some([18; 32]),
                committed_amount: Some(123),
                expiry_slot: Some(456),
            },
            remote_spend_claims: Some(vec![claim]),
            bundle_frame: norito::encode_canonical(&vec![0x31_u8; 4096]).unwrap(),
        }
    }

    #[test]
    fn public_projection_preserves_exact_quantities_order_and_occurrences_without_paths() {
        let original = transcript();
        let projected = FastpqPublicTransferTranscriptV1::from(&original);
        assert_eq!(projected.batch_hash, original.batch_hash);
        assert_eq!(projected.authority_digest, original.authority_digest);
        assert_eq!(
            projected.poseidon_preimage_digest,
            original.poseidon_preimage_digest
        );
        assert_eq!(projected.deltas.len(), 2);
        for (actual, expected) in projected.deltas.iter().zip(&original.deltas) {
            assert_eq!(actual.from_account, expected.from_account);
            assert_eq!(actual.to_account, expected.to_account);
            assert_eq!(actual.asset_definition, expected.asset_definition);
            assert_eq!(actual.amount, expected.amount);
            assert_eq!(actual.from_balance_before, expected.from_balance_before);
            assert_eq!(actual.from_balance_after, expected.from_balance_after);
            assert_eq!(actual.to_balance_before, expected.to_balance_before);
            assert_eq!(actual.to_balance_after, expected.to_balance_after);
        }
        let mut different_paths = original;
        for delta in &mut different_paths.deltas {
            delta.from_smt_witness = TransferSmtWitness::default();
            delta.to_smt_witness = TransferSmtWitness::default();
        }
        assert_eq!(
            FastpqPublicTransferTranscriptV1::from(&different_paths),
            projected
        );
        let bytes = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqPublicTransferTranscriptV1>(&bytes).unwrap(),
            projected
        );
    }

    #[test]
    fn ordinary_roundtrip_preserves_all_seven_inputs_and_ambient_flags() {
        let original = ordinary();
        let raw = norito::encode_canonical(&original).unwrap();
        let ambient =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _flags = norito::core::DecodeFlagsGuard::enter(ambient);
        let decoded =
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, limits())
                .unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.statement.effects.effects.len(), 4);
        assert_eq!(decoded.source.effect_count, 4);
        assert_eq!(norito::core::effective_decode_flags(), Some(ambient));
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), raw);
        for index in 0..7 {
            let mut changed = original.clone();
            match index {
                0 => changed.statement.public_inputs.dsid[0] ^= 1,
                1 => changed.statement.public_inputs.slot += 1,
                2 => changed.statement.public_inputs.old_root[0] ^= 1,
                3 => changed.statement.public_inputs.new_root[0] ^= 1,
                4 => changed.statement.public_inputs.perm_root[0] ^= 1,
                5 => changed.statement.public_inputs.tx_set_hash[0] ^= 1,
                6 => changed.statement.ordering_hash[0] ^= 1,
                _ => unreachable!(),
            }
            assert_ne!(
                norito::encode_canonical(&changed).unwrap(),
                raw,
                "input {index}"
            );
        }
    }

    #[test]
    fn ordinary_wire_preserves_full_source_effect_order_and_all_operation_kinds() {
        let original = ordinary();
        let raw = norito::encode_canonical(&original).unwrap();
        for mutation in 0..24 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.source.source.height += 1,
                1 => changed.source.statement_index += 1,
                2 => changed.source.entry_index += 1,
                3 => changed.source.effect_count += 1,
                4 => changed.source.entry_hash = Hash::new(b"different source entry"),
                5 => changed.source.execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
                6 => changed.source.dataspace_id = DataSpaceId::new(8),
                7 => changed.source.effects_digest[0] ^= 1,
                8 => changed.source.slot += 1,
                9 => changed.source.perm_root[0] ^= 1,
                10 => changed.source.tx_set_hash[0] ^= 1,
                11 => changed.statement.effects.context.source.height += 1,
                12 => {
                    changed.statement.effects.context.entry.entry_hash =
                        Hash::new(b"different tape entry")
                }
                13 => {
                    changed.statement.effects.effects[0].authority_digest =
                        Hash::new(b"different authority")
                }
                14 => {
                    changed.statement.effects.effects[0].authorization_context =
                        Hash::new(b"different authorization")
                }
                15 => changed.statement.effects.effects.swap(0, 1),
                16 => changed.statement.effects.effects[0].ordinal += 1,
                17 => changed
                    .statement
                    .effects
                    .effects
                    .push(changed.statement.effects.effects[0].clone()),
                18 => {
                    changed.source.source.network_id = NetworkId::from_genesis_hash(
                        HashOf::from_untyped_unchecked(Hash::new(b"different source network")),
                    )
                }
                19 => {
                    changed.source.route =
                        super::super::FastpqSourceRouteV1::Lane(super::super::FastpqSourceLaneV1 {
                            lane_id: LaneId::new(3),
                            lane_incarnation: Hash::new(b"different source lane incarnation"),
                        })
                }
                20 => {
                    changed.statement.effects.context.source.network_id =
                        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                            b"different tape network",
                        )))
                }
                21 => changed.statement.effects.context.entry.dataspace_id = DataSpaceId::new(9),
                22 => {
                    let FastpqExecutionEffectKindV1::Transfer(value) =
                        &mut changed.statement.effects.effects[0].kind
                    else {
                        unreachable!()
                    };
                    value.amount = quantity(124, 2);
                }
                23 => {
                    let FastpqExecutionEffectKindV1::Retire(asset) =
                        &mut changed.statement.effects.effects[3].kind
                    else {
                        unreachable!()
                    };
                    asset.incarnation = AxtAssetIncarnationV1::try_from_bytes(
                        Hash::new(b"different lifecycle").into(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let bytes = norito::encode_canonical(&changed).unwrap();
            assert_ne!(bytes, raw, "mutation {mutation}");
            assert_eq!(
                FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                    &bytes,
                    PROFILE,
                    limits()
                )
                .unwrap(),
                changed
            );
        }
        assert!(matches!(
            original.statement.effects.effects[0].kind,
            FastpqExecutionEffectKindV1::Transfer(_)
        ));
        assert!(matches!(
            original.statement.effects.effects[1].kind,
            FastpqExecutionEffectKindV1::Mint(_)
        ));
        assert!(matches!(
            original.statement.effects.effects[2].kind,
            FastpqExecutionEffectKindV1::Burn(_)
        ));
        assert!(matches!(
            original.statement.effects.effects[3].kind,
            FastpqExecutionEffectKindV1::Retire(_)
        ));
    }

    #[test]
    fn retired_three_field_transfer_body_cannot_decode_as_complete_effect_artifact() {
        #[derive(NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "test::RelabeledTransferBody",
            frame = "iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1"
        )]
        struct RelabeledBody {
            profile_id: FastpqCompactProfileIdV1,
            source: FastpqOrdinarySourceStatementLeafV1,
            statement: FastpqPublicTransferStatementV1,
            bundle_frame: Vec<u8>,
        }
        // An adversarial historical body is test data, never an alternate decoder.
        #[derive(NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "test::RetiredOrdinaryTransferBody",
            frame = "iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1"
        )]
        struct RetiredBody {
            profile_id: FastpqCompactProfileIdV1,
            statement: FastpqPublicTransferStatementV1,
            bundle_frame: Vec<u8>,
        }
        let retired = RetiredBody {
            profile_id: PROFILE,
            statement: transfer_statement(),
            bundle_frame: ordinary().bundle_frame,
        };
        let raw = norito::encode_canonical(&retired).unwrap();
        assert!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, limits())
                .is_err()
        );
        // Even inserting an advertised source cannot relabel the transfer-only statement.
        let relabeled = RelabeledBody {
            profile_id: PROFILE,
            source: ordinary().source,
            statement: transfer_statement(),
            bundle_frame: ordinary().bundle_frame,
        };
        assert!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                &norito::encode_canonical(&relabeled).unwrap(),
                PROFILE,
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn axt_roundtrip_retains_every_preproof_field_and_absent_empty_distinctions() {
        let original = axt();
        let raw = norito::encode_canonical(&original).unwrap();
        let decoded =
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, limits())
                .unwrap();
        // Preserve the original transfer-fixture occurrence assertions on its retained AXT route.
        assert_eq!(decoded.statement.transcripts.len(), 2);
        assert_eq!(decoded.statement.transcripts[0].deltas.len(), 2);
        assert_eq!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, limits())
                .unwrap(),
            original
        );
        let mut absent = original.clone();
        absent.remote_spend_claims = None;
        let mut empty = absent.clone();
        empty.remote_spend_claims = Some(vec![]);
        let mut zero = original.clone();
        zero.metadata.committed_amount = Some([0; 16]);
        let mut no_amount = zero.clone();
        no_amount.metadata.committed_amount = None;
        for (left, right) in [(&absent, &empty), (&zero, &no_amount)] {
            let left_raw = norito::encode_canonical(left).unwrap();
            let right_raw = norito::encode_canonical(right).unwrap();
            assert_ne!(left_raw, right_raw);
            assert_eq!(
                FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
                    &left_raw,
                    PROFILE,
                    limits()
                )
                .unwrap(),
                *left
            );
            assert_eq!(
                FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
                    &right_raw,
                    PROFILE,
                    limits()
                )
                .unwrap(),
                *right
            );
        }
        // Offline decoding intentionally does not authenticate duplicated mirrors.
        let mut changed = original;
        changed.mirrors.manifest_root[0] ^= 1;
        let changed_raw = norito::encode_canonical(&changed).unwrap();
        assert_ne!(changed_raw, raw);
        assert_eq!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
                &changed_raw,
                PROFILE,
                limits()
            )
            .unwrap(),
            changed
        );
    }

    #[test]
    fn nominal_schemas_routes_profiles_and_full_consumption_are_enforced() {
        let ordinary = ordinary();
        let axt = axt();
        let raw = norito::encode_canonical(&ordinary).unwrap();
        let axt_raw = norito::encode_canonical(&axt).unwrap();
        assert_eq!(
            norito::schema::identity::frame_hash::<FastpqOrdinaryCompactArtifactV1>(),
            norito::core::schema_hash_for_name(FASTPQ_ORDINARY_COMPACT_ARTIFACT_V1_SCHEMA_NAME)
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<FastpqAxtCompactArtifactV1>(),
            norito::core::schema_hash_for_name(FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME)
        );
        assert_ne!(
            norito::schema::identity::frame_hash::<FastpqOrdinaryCompactArtifactV1>(),
            norito::schema::identity::frame_hash::<FastpqAxtCompactArtifactV1>()
        );
        assert!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, limits())
                .is_err()
        );
        assert!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                &axt_raw,
                PROFILE,
                limits()
            )
            .is_err()
        );
        for bytes in [&raw, &axt_raw] {
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(
                FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                    &trailing,
                    PROFILE,
                    limits()
                )
                .is_err()
            );
            assert!(
                FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
                    &trailing,
                    PROFILE,
                    limits()
                )
                .is_err()
            );
        }
        let other = FastpqCompactProfileIdV1([0x43; 32]);
        assert!(matches!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(&raw, other, limits()),
            Err(FastpqCompactArtifactDecodeError::ProfileMismatch)
        ));
        assert!(matches!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&axt_raw, other, limits()),
            Err(FastpqCompactArtifactDecodeError::ProfileMismatch)
        ));
        let (bare, flags) = norito::codec::encode_with_header_flags(&ordinary);
        let relabeled =
            norito::core::frame_bare_with_header_flags::<FastpqAxtCompactArtifactV1>(&bare, flags)
                .unwrap();
        assert!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&relabeled, PROFILE, limits())
                .is_err()
        );
        let mut reserved_flags = raw;
        reserved_flags[39] |= 0x08; // reserved header bit
        assert!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                &reserved_flags,
                PROFILE,
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn raw_and_bundle_limits_are_inclusive_and_raw_cap_precedes_header_reads() {
        let ordinary = ordinary();
        let raw = norito::encode_canonical(&ordinary).unwrap();
        let axt = axt();
        let axt_raw = norito::encode_canonical(&axt).unwrap();
        let zero = FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: 0,
            ..limits()
        };
        assert!(matches!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(&[0xff], PROFILE, zero),
            Err(FastpqCompactArtifactDecodeError::WireBytes { actual: 1, max: 0 })
        ));
        assert!(matches!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&[0xff], PROFILE, zero),
            Err(FastpqCompactArtifactDecodeError::WireBytes { actual: 1, max: 0 })
        ));
        let exact = FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: raw.len(),
            max_bundle_frame_bytes: ordinary.bundle_frame.len(),
            ..limits()
        };
        assert!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, exact)
                .is_ok()
        );
        assert!(matches!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                &raw,
                PROFILE,
                FastpqCompactArtifactDecodeLimits {
                    max_wire_bytes: raw.len() - 1,
                    ..exact
                }
            ),
            Err(FastpqCompactArtifactDecodeError::WireBytes { .. })
        ));
        assert!(matches!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                &raw,
                PROFILE,
                FastpqCompactArtifactDecodeLimits {
                    max_bundle_frame_bytes: ordinary.bundle_frame.len() - 1,
                    ..exact
                }
            ),
            Err(FastpqCompactArtifactDecodeError::BundleBytes { .. })
        ));
        let exact = FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: axt_raw.len(),
            max_bundle_frame_bytes: axt.bundle_frame.len(),
            ..limits()
        };
        assert!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&axt_raw, PROFILE, exact)
                .is_ok()
        );
        assert!(matches!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
                &axt_raw,
                PROFILE,
                FastpqCompactArtifactDecodeLimits {
                    max_bundle_frame_bytes: axt.bundle_frame.len() - 1,
                    ..exact
                }
            ),
            Err(FastpqCompactArtifactDecodeError::BundleBytes { .. })
        ));
    }

    #[test]
    fn norito_field_element_allocation_and_depth_budgets_are_inherited() {
        let raw = norito::encode_canonical(&ordinary()).unwrap();
        let axt_raw = norito::encode_canonical(&axt()).unwrap();
        for cap in [
            DecodeLimits::new(1, usize::MAX, usize::MAX, usize::MAX, 32),
            DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 32),
            DecodeLimits::new(usize::MAX, usize::MAX, 1, usize::MAX, 32),
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 32),
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 1),
        ] {
            norito::core::with_decode_limits_scope(cap, || {
                assert!(
                    FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                        &raw,
                        PROFILE,
                        limits()
                    )
                    .is_err()
                );
                assert!(
                    FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
                        &axt_raw,
                        PROFILE,
                        limits()
                    )
                    .is_err()
                );
            });
        }
        assert!(
            FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(&raw, PROFILE, limits())
                .is_ok()
        );
        assert!(
            FastpqAxtCompactArtifactV1::decode_canonical_with_limits(&axt_raw, PROFILE, limits())
                .is_ok()
        );
    }

    #[test]
    fn outer_and_sequential_child_decodes_share_one_cumulative_allocation_budget() {
        let raw = norito::encode_canonical(&ordinary()).unwrap();
        let run = || -> Result<(), FastpqCompactArtifactDecodeError> {
            let artifact = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                &raw,
                PROFILE,
                limits(),
            )?;
            let child: Vec<u8> =
                norito::decode_canonical_with_limits(&artifact.bundle_frame, limits().norito)?;
            assert_eq!(child, vec![0x31; 4096]);
            Ok(())
        };
        let (result, measured) = norito::core::with_decode_limits_measured(limits().norito, run);
        result.unwrap();
        let charged = measured.total_allocated_bytes();
        assert!(charged > 0);
        let exact = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, charged, 32);
        norito::core::with_decode_limits_scope(exact, || {
            run().unwrap();
            assert!(
                run().is_err(),
                "a later outer decode must not reset the parent's charges"
            );
        });
        let short = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, charged - 1, 32);
        assert!(norito::core::with_decode_limits_scope(short, run).is_err());
        run().unwrap();
    }

    #[test]
    fn checksummed_oversized_count_headers_are_rejected_before_allocation() {
        let original = ordinary();
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (bare, flags) = norito::codec::encode_with_header_flags(&original);
        let mut offset = 0;
        for _ in 0..3 {
            let (length, prefix) =
                norito::core::read_len_from_slice_with_flags(&bare[offset..], flags).unwrap();
            offset += prefix + length;
        }
        let (length, prefix) =
            norito::core::read_len_from_slice_with_flags(&bare[offset..], flags).unwrap();
        let start = offset + prefix;
        let (count, count_prefix) =
            norito::core::inspect_seq_len_slice(&bare[start..start + length]).unwrap();
        assert_eq!(count, original.bundle_frame.len());
        assert_eq!(count_prefix, 8);
        for position in [offset, start] {
            let mut hostile = bare.clone();
            hostile[position..position + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            let frame =
                norito::core::frame_bare_with_header_flags::<FastpqOrdinaryCompactArtifactV1>(
                    &hostile, flags,
                )
                .unwrap();
            assert!(
                FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
                    &frame,
                    PROFILE,
                    limits()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn identity_description_keeps_kind_profile_all_digests_count_and_root_order_distinct() {
        let artifact = ordinary();
        let raw = norito::encode_canonical(&artifact).unwrap();
        let statement = norito::encode_canonical(&artifact.statement).unwrap();
        let identity = FastpqArtifactIdentityDescriptionV1 {
            proof_kind: FastpqProofKindV1::OrdinaryCompact,
            profile_id: PROFILE,
            public_statement_digest: Hash::new(&statement).into(),
            artifact_digest: Hash::new(&raw).into(),
            inner_bundle_digest: Hash::new(&artifact.bundle_frame).into(),
            artifact_bytes: raw.len().try_into().unwrap(),
            commitments: FastpqCommitmentDescriptionV1::OrderedCompactAir(
                FastpqOrderedCompactAirCommitmentsV1 {
                    segment_count: 2,
                    segment_air_row_roots: vec![
                        super::super::FastpqCommitmentV1::from_bytes([1; 32]),
                        super::super::FastpqCommitmentV1::from_bytes([2; 32]),
                    ],
                },
            ),
        };
        assert_ne!(identity.artifact_digest, identity.inner_bundle_digest);
        assert_ne!(identity.artifact_digest, identity.public_statement_digest);
        let encoded = norito::encode_canonical(&identity).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqArtifactIdentityDescriptionV1>(&encoded).unwrap(),
            identity
        );
        for mutation in 0..9 {
            let mut changed = identity.clone();
            match mutation {
                0 => changed.proof_kind = FastpqProofKindV1::AxtCompact,
                1 => changed.profile_id.0[0] ^= 1,
                2 => changed.public_statement_digest[0] ^= 1,
                3 => changed.artifact_digest[0] ^= 1,
                4 => changed.inner_bundle_digest[0] ^= 1,
                5 => changed.artifact_bytes += 1,
                6 => {
                    changed.commitments = FastpqCommitmentDescriptionV1::OrderedCompactAir(
                        FastpqOrderedCompactAirCommitmentsV1 {
                            segment_count: 2,
                            segment_air_row_roots: vec![
                                super::super::FastpqCommitmentV1::from_bytes([2; 32]),
                                super::super::FastpqCommitmentV1::from_bytes([1; 32]),
                            ],
                        },
                    )
                }
                7 => {
                    changed.commitments = FastpqCommitmentDescriptionV1::OrderedCompactAir(
                        FastpqOrderedCompactAirCommitmentsV1 {
                            segment_count: 3,
                            segment_air_row_roots: vec![
                                super::super::FastpqCommitmentV1::from_bytes([1; 32]),
                                super::super::FastpqCommitmentV1::from_bytes([2; 32]),
                            ],
                        },
                    )
                }
                8 => {
                    changed.proof_kind = FastpqProofKindV1::LegacyReplay;
                    changed.commitments = FastpqCommitmentDescriptionV1::LegacyPreprocessing(
                        GoldilocksDigest384V1::new([1; 6]).unwrap(),
                    );
                }
                _ => unreachable!(),
            }
            assert_ne!(
                norito::encode_canonical(&changed).unwrap(),
                encoded,
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn commitment_descriptions_reject_noncanonical_words_without_truncating_roots() {
        let canonical = GoldilocksDigest384V1::new([1, 2, 3, 4, 5, 6]).unwrap();
        {
            let (commitment, expected_roots) = (
                FastpqCommitmentDescriptionV1::LegacyPreprocessing(canonical),
                1,
            );
            let raw = norito::encode_canonical(&commitment).unwrap();
            assert_eq!(
                norito::decode_canonical::<FastpqCommitmentDescriptionV1>(&raw).unwrap(),
                commitment
            );
            let header = norito::core::Header::read(&mut raw.as_slice()).unwrap();
            let mut hostile = raw[norito::core::Header::SIZE..].to_vec();
            let root_offsets: Vec<_> = hostile
                .windows(48)
                .enumerate()
                .filter_map(|(offset, bytes)| (bytes == canonical.to_le_bytes()).then_some(offset))
                .collect();
            assert_eq!(root_offsets.len(), expected_roots);
            let last_word = root_offsets.last().unwrap() + 40;
            hostile[last_word..last_word + 8]
                .copy_from_slice(&0xffff_ffff_0000_0001_u64.to_le_bytes());
            // Keep the actual typed layout and repair the checksum so only the
            // sixth field word violates the canonical digest representation.
            let frame =
                norito::core::frame_bare_with_header_flags::<FastpqCommitmentDescriptionV1>(
                    &hostile,
                    header.flags,
                )
                .unwrap();
            assert!(norito::decode_canonical::<FastpqCommitmentDescriptionV1>(&frame).is_err());
        }
    }

    #[test]
    fn compact_commitment_descriptions_preserve_all_opaque_bits_and_exact_root_order() {
        let roots = vec![
            super::super::FastpqCommitmentV1::from_bytes([0xff; 32]),
            super::super::FastpqCommitmentV1::from_bytes([0x80; 32]),
        ];
        let commitment = FastpqCommitmentDescriptionV1::OrderedCompactAir(
            FastpqOrderedCompactAirCommitmentsV1 {
                segment_count: 2,
                segment_air_row_roots: roots.clone(),
            },
        );
        let raw = norito::encode_canonical(&commitment).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqCommitmentDescriptionV1>(&raw).unwrap(),
            commitment
        );
        for root in roots {
            assert_eq!(
                raw.windows(32)
                    .filter(|bytes| *bytes == root.as_bytes())
                    .count(),
                1
            );
        }
        let mut reversed = commitment.clone();
        if let FastpqCommitmentDescriptionV1::OrderedCompactAir(ref mut c) = reversed {
            c.segment_air_row_roots.reverse();
        }
        assert_ne!(norito::encode_canonical(&reversed).unwrap(), raw);
    }

    #[test]
    fn negative_quantity_cannot_enter_the_path_free_delta_codec() {
        #[derive(NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "test::iroha_data_model::ForgedDelta",
            frame = "iroha_data_model::fastpq::FastpqPublicTransferDeltaV1"
        )]
        struct ForgedDelta {
            from_account: AccountId,
            to_account: AccountId,
            asset_definition: AssetDefinitionId,
            amount: Numeric,
            from_balance_before: Quantity,
            from_balance_after: Quantity,
            to_balance_before: Quantity,
            to_balance_after: Quantity,
        }
        let delta = transcript().deltas.remove(0);
        let forged = ForgedDelta {
            from_account: delta.from_account,
            to_account: delta.to_account,
            asset_definition: delta.asset_definition,
            amount: Numeric::new(-123_i32, 2),
            from_balance_before: delta.from_balance_before,
            from_balance_after: delta.from_balance_after,
            to_balance_before: delta.to_balance_before,
            to_balance_after: delta.to_balance_after,
        };
        let raw = norito::encode_canonical(&forged).unwrap();
        assert!(norito::decode_canonical::<FastpqPublicTransferDeltaV1>(&raw).is_err());
    }
}

#[cfg(test)]
mod captured_cutover_identity_tests {
    fn check<T>(nominal: &str, frame: &str, hash: &str)
    where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        assert_eq!(T::nominal_name(), nominal);
        assert_eq!(T::frame_name(), frame);
        assert_eq!(
            hex::encode(norito::schema::identity::frame_hash::<T>()),
            hash
        );
    }

    #[test]
    fn captured_owner_identities() {
        check::<super::FastpqPublicTransferDeltaV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqPublicTransferDeltaV1",
            "iroha_data_model::fastpq::FastpqPublicTransferDeltaV1",
            "979da16441261bf40f67490e06ec6eed",
        );
        check::<super::FastpqPublicTransferTranscriptV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqPublicTransferTranscriptV1",
            "iroha_data_model::fastpq::FastpqPublicTransferTranscriptV1",
            "9248584076d13d12c48b473d98f4a825",
        );
        check::<super::FastpqPublicTransferStatementV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqPublicTransferStatementV1",
            "iroha_data_model::fastpq::FastpqPublicTransferStatementV1",
            "313b4cd0ee947685d49f3a3c698a4b87",
        );
        check::<super::FastpqCompactProfileIdV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqCompactProfileIdV1",
            "iroha_data_model::fastpq::FastpqCompactProfileIdV1",
            "a2547f570ec6e27ca5e6e09db2c8b940",
        );
        check::<super::FastpqAxtPublicMetadataV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqAxtPublicMetadataV1",
            "iroha_data_model::fastpq::FastpqAxtPublicMetadataV1",
            "c26823c05d27299e6cf1fbf1ccbc39cb",
        );
        check::<super::FastpqAxtPreProofMirrorsV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqAxtPreProofMirrorsV1",
            "iroha_data_model::fastpq::FastpqAxtPreProofMirrorsV1",
            "f8b326d71c246cf8d556c75fceb831ee",
        );
        check::<super::FastpqOrdinaryCompactArtifactV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqOrdinaryCompactArtifactV1",
            "iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1",
            "cbe7fa95c951290f8150e1f1d4530aab",
        );
        check::<super::FastpqAxtCompactArtifactV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqAxtCompactArtifactV1",
            "iroha_data_model::fastpq::FastpqAxtCompactArtifactV1",
            "b6a7547776f8603a47d39c2a911a30bb",
        );
        check::<super::FastpqProofKindV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqProofKindV1",
            "iroha_data_model::fastpq::FastpqProofKindV1",
            "7473d5902b4074340f2866aece4ab520",
        );
        check::<super::FastpqOrderedCompactAirCommitmentsV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqOrderedCompactAirCommitmentsV1",
            "iroha_data_model::fastpq::FastpqOrderedCompactAirCommitmentsV1",
            "3ffb6be7b03f410a7065f101463c12c5",
        );
        check::<super::FastpqCommitmentDescriptionV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqCommitmentDescriptionV1",
            "iroha_data_model::fastpq::FastpqCommitmentDescriptionV1",
            "121e0f8bbc60014240065d0a0bece355",
        );
        check::<super::FastpqArtifactIdentityDescriptionV1>(
            "iroha_data_model::fastpq::public_artifact::FastpqArtifactIdentityDescriptionV1",
            "iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1",
            "bf062c0828e208bb8189f0c38dac1154",
        );
    }
}
