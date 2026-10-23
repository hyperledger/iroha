//! Moderation model, reproducibility, and ballot schemas (MINFO-1b / SFM-4).
//!
//! These types capture the governance-signed fingerprints that allow gateways to verify moderation
//! runners, model artefacts, and threshold parameters, and the `SoraFS`-specific ballot context
//! used by moderation panels. Validators use explicit helpers to enforce schema versioning,
//! signature coverage, and commit/reveal binding before accepting moderation evidence.

pub(crate) use crate::json_helpers::fixed_bytes::option as json_option_digest32;

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use blake2::digest::Digest;
use iroha_crypto::{Algorithm, Blake2b256, PublicKey, SignatureOf};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::BTreeSet;
use thiserror::Error;
mod trust_validation;
/// Schema version for `ModerationReproManifestV1`.
pub const MODERATION_REPRO_MANIFEST_VERSION_V1: u16 = 1;
/// Maximum model weight and threshold value in basis points.
pub const MODERATION_REPRO_MAX_BPS: u16 = 10_000;
/// Schema version for [`ModerationModelArtifactV1`].
pub const MODERATION_MODEL_ARTIFACT_VERSION_V1: u16 = 1;
/// Number of integer features consumed by the first-release model engine.
pub const MODERATION_MODEL_FEATURE_COUNT_V1: usize = 512;
/// Exact fixed working set, in bytes, required by the first-release model engine.
pub const MODERATION_MODEL_WORKING_MEMORY_BYTES_V1: u32 = 4_096;
/// Maximum number of models admitted by one reproducibility manifest.
pub const MODERATION_MODEL_MAX_MODELS_V1: usize = 16;
/// Maximum canonical encoded size of one model artefact.
pub const MODERATION_MODEL_MAX_ARTIFACT_BYTES_V1: u64 = 1024 * 1024;
/// Maximum aggregate model artefact size admitted by one manifest.
pub const MODERATION_MODEL_MAX_TOTAL_ARTIFACT_BYTES_V1: u64 =
    MODERATION_MODEL_MAX_ARTIFACT_BYTES_V1 * MODERATION_MODEL_MAX_MODELS_V1 as u64;
/// Maximum payload size accepted by the first-release model engine.
pub const MODERATION_MODEL_MAX_INPUT_BYTES_V1: u32 = 16 * 1024 * 1024;
/// Maximum number of piecewise-linear calibration knots in one model.
pub const MODERATION_MODEL_MAX_CALIBRATION_KNOTS_V1: usize = 64;
/// Maximum byte length of a portable relative artefact path.
pub const MODERATION_MODEL_MAX_ARTIFACT_PATH_BYTES_V1: usize = 512;
/// Maximum accepted runner version string length.
pub const MODERATION_REPRO_MAX_RUNTIME_VERSION_BYTES_V1: usize = 128;
/// Maximum accepted seed-domain string length.
pub const MODERATION_REPRO_MAX_SEED_DOMAIN_BYTES_V1: usize = 128;
/// Maximum accepted optional governance-note length.
pub const MODERATION_REPRO_MAX_NOTES_BYTES_V1: usize = 4096;
/// Maximum accepted signature-role label length.
pub const MODERATION_REPRO_MAX_SIGNATURE_ROLE_BYTES_V1: usize = 64;
/// Maximum number of signatures admitted by one manifest.
pub const MODERATION_REPRO_MAX_SIGNATURES_V1: usize = 32;
/// Schema version for [`ModerationTrustPolicyV1`].
pub const MODERATION_TRUST_POLICY_VERSION_V1: u16 = 1;
/// Schema version for [`ModerationSignedScreeningResultV1`].
pub const MODERATION_SIGNED_RESULT_VERSION_V1: u16 = 1;
/// Schema version for [`ModerationCommitteeAggregateV1`].
pub const MODERATION_COMMITTEE_AGGREGATE_VERSION_V1: u16 = 1;
/// Schema version for [`ModerationProvenanceLogV1`].
pub const MODERATION_PROVENANCE_LOG_VERSION_V1: u16 = 1;
/// Maximum trusted runner signers in one policy.
pub const MODERATION_TRUST_MAX_SIGNERS_V1: usize = 64;
/// Maximum governance signatures on one trust policy.
pub const MODERATION_TRUST_MAX_SIGNATURES_V1: usize = 32;
/// Maximum result age admitted by a first-release trust policy.
pub const MODERATION_TRUST_MAX_RESULT_AGE_SECS_V1: u64 = 7 * 24 * 60 * 60;
/// Maximum signed result lifetime admitted by a first-release trust policy.
pub const MODERATION_TRUST_MAX_RESULT_TTL_SECS_V1: u64 = 24 * 60 * 60;
/// Maximum clock skew admitted by a first-release trust policy.
pub const MODERATION_TRUST_MAX_CLOCK_SKEW_SECS_V1: u64 = 5 * 60;
/// Maximum subject identifier bytes in a signed screening result.
pub const MODERATION_SIGNED_RESULT_MAX_SUBJECT_BYTES_V1: usize = 1024;
/// Maximum signed results admitted into one committee aggregate.
pub const MODERATION_COMMITTEE_MAX_RESULTS_V1: usize = 64;
/// Maximum entries admitted into one persisted provenance segment.
pub const MODERATION_PROVENANCE_MAX_ENTRIES_V1: usize = 4096;
const MODERATION_MODEL_BEHAVIOUR_DIGEST_DOMAIN_V1: &[u8] = b"sorafs:moderation:model-behaviour:v1";
const MODERATION_REPRO_BODY_DIGEST_DOMAIN_V1: &[u8] = b"sorafs:moderation:repro-body:v1";
const MODERATION_TRUST_POLICY_DIGEST_DOMAIN_V1: &[u8] = b"sorafs:moderation:trust-policy:v1";
const MODERATION_SIGNED_RESULT_DIGEST_DOMAIN_V1: &[u8] = b"sorafs:moderation:signed-result:v1";
const MODERATION_COMMITTEE_AGGREGATE_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs:moderation:committee-aggregate:v1";
const MODERATION_PROVENANCE_ENTRY_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs:moderation:provenance-entry:v1";
const MODERATION_SCREENING_POLICY_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.moderation.local-runner.policy-digest.v1";
const MODERATION_BALLOT_COMMITMENT_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.moderation.ballot.commitment.v1";
/// Schema version for [`SoraFsModerationBallotContextV1`].
pub const SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1: u16 = 1;
/// Schema version for [`SoraFsModerationBallotCommitV1`].
pub const SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1: u16 = 1;
/// Schema version for [`SoraFsModerationBallotRevealV1`].
pub const SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1: u16 = 1;
/// Deterministic bounded integer inference engine used by first-release models.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationModelEngineV1")]
pub enum ModerationModelEngineV1 {
    /// Fixed-point linear model followed by monotonic piecewise-linear calibration.
    #[norito(rename = "deterministic_linear_v1")]
    DeterministicLinearV1,
}
/// Deterministic feature extraction profile used by first-release models.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationFeatureProfileV1")]
pub enum ModerationFeatureProfileV1 {
    /// 256 byte-frequency bins followed by 256 stable adjacent-byte bins.
    #[norito(rename = "byte_histogram_bigram_v1")]
    ByteHistogramAndBigramV1,
}
/// One point in a monotonic, piecewise-linear calibration curve.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationCalibrationKnotV1")]
pub struct ModerationCalibrationKnotV1 {
    /// Raw signed linear-model output at this point.
    pub input: i64,
    /// Calibrated risk score in basis points.
    pub score_bps: u16,
}
/// Canonical model artefact executed by the bounded integer moderation engine.
///
/// The artefact intentionally contains no executable code, floating-point values,
/// external tokenizer state, or implementation-selected operator set. Its exact
/// operation and memory budgets are committed into the signed manifest.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationModelArtifactV1")]
pub struct ModerationModelArtifactV1 {
    /// Artefact schema version; must equal [`MODERATION_MODEL_ARTIFACT_VERSION_V1`].
    pub schema_version: u16,
    /// Inference engine required to execute this artefact.
    pub engine: ModerationModelEngineV1,
    /// Feature extraction profile required by the weights.
    pub feature_profile: ModerationFeatureProfileV1,
    /// Model UUID, which must match its manifest fingerprint.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub model_id: [u8; 16],
    /// Maximum payload size accepted by this model.
    pub max_input_bytes: u32,
    /// Exact worst-case operation budget for `max_input_bytes`.
    pub max_operations: u64,
    /// Exact fixed working-memory budget.
    pub working_memory_bytes: u32,
    /// Signed linear-model intercept.
    pub bias: i64,
    /// Exactly [`MODERATION_MODEL_FEATURE_COUNT_V1`] signed fixed-point weights.
    pub weights: Vec<i32>,
    /// Strictly input-ordered, score-monotonic calibration curve.
    pub calibration: Vec<ModerationCalibrationKnotV1>,
}
/// A score emitted for one manifest-bound moderation model.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationModelScoreV1")]
pub struct ModerationModelScoreV1 {
    /// Model UUID.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub model_id: [u8; 16],
    /// Digest of the exact canonical artefact bytes used for inference.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub artifact_digest: [u8; 32],
    /// Calibrated model risk score in basis points.
    pub score_bps: u16,
}
/// Validation errors for canonical moderation model artefacts.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ModerationModelArtifactError {
    /// Artefact uses an unsupported schema version.
    #[error("unsupported moderation model artefact version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Expected schema version.
        expected: u16,
        /// Version found in the artefact.
        found: u16,
    },
    /// Model UUID is all zeros.
    #[error("moderation model artefact has a zero model id")]
    MissingModelId,
    /// Input bound is zero or exceeds the engine hard limit.
    #[error("moderation model max input {found} is outside 1..={maximum}")]
    InvalidMaxInput {
        /// Bound found in the artefact.
        found: u32,
        /// Engine hard limit.
        maximum: u32,
    },
    /// Weight vector does not match the feature profile.
    #[error("moderation model has {found} weights; expected {expected}")]
    InvalidWeightCount {
        /// Required count.
        expected: usize,
        /// Count found in the artefact.
        found: usize,
    },
    /// Calibration curve has an invalid number of knots.
    #[error("moderation model has {found} calibration knots; expected 2..={maximum}")]
    InvalidCalibrationCount {
        /// Count found in the artefact.
        found: usize,
        /// Maximum permitted count.
        maximum: usize,
    },
    /// Calibration inputs are not strictly increasing.
    #[error("moderation calibration input at index {index} is not strictly increasing")]
    CalibrationInputOrder {
        /// Index of the invalid knot.
        index: usize,
    },
    /// Calibration scores decrease or exceed 10,000 basis points.
    #[error("moderation calibration score {score_bps} at index {index} is invalid")]
    InvalidCalibrationScore {
        /// Index of the invalid knot.
        index: usize,
        /// Score found at that index.
        score_bps: u16,
    },
    /// Declared fixed working-memory budget is not exact.
    #[error("moderation model working-memory budget {found} does not equal {expected}")]
    InvalidWorkingMemory {
        /// Exact required budget.
        expected: u32,
        /// Budget declared in the artefact.
        found: u32,
    },
    /// Declared operation budget is not exact.
    #[error("moderation model operation budget {found} does not equal {expected}")]
    InvalidOperationBudget {
        /// Exact required budget.
        expected: u64,
        /// Budget declared in the artefact.
        found: u64,
    },
    /// The full signed linear range cannot fit in an `i64`.
    #[error("moderation model linear accumulator can exceed the signed 64-bit range")]
    AccumulatorOverflow,
}
/// Return the exact first-release operation budget for an input bound and curve.
///
/// The budget counts one unigram update per input byte, one adjacent-byte update
/// after the first byte, 512 normalizations, 512 multiply-accumulates, and one
/// bounded calibration comparison per knot.
#[must_use]
pub fn moderation_model_required_operations_v1(
    max_input_bytes: u32,
    calibration_knot_count: usize,
) -> Option<u64> {
    let input = u64::from(max_input_bytes);
    let bigrams = input.saturating_sub(1);
    let knots = u64::try_from(calibration_knot_count).ok()?;
    input
        .checked_add(bigrams)?
        .checked_add((MODERATION_MODEL_FEATURE_COUNT_V1 as u64).checked_mul(2)?)?
        .checked_add(knots)
}
impl ModerationModelArtifactV1 {
    /// Validate all shape, range, and declared resource-budget invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationModelArtifactError`] when the version, dimensions,
    /// bounds, model bytes, or declared resource budget is invalid.
    pub fn validate(&self) -> Result<(), ModerationModelArtifactError> {
        if self.schema_version != MODERATION_MODEL_ARTIFACT_VERSION_V1 {
            return Err(ModerationModelArtifactError::UnsupportedVersion {
                expected: MODERATION_MODEL_ARTIFACT_VERSION_V1,
                found: self.schema_version,
            });
        }
        if self.model_id == [0; 16] {
            return Err(ModerationModelArtifactError::MissingModelId);
        }
        if self.max_input_bytes == 0 || self.max_input_bytes > MODERATION_MODEL_MAX_INPUT_BYTES_V1 {
            return Err(ModerationModelArtifactError::InvalidMaxInput {
                found: self.max_input_bytes,
                maximum: MODERATION_MODEL_MAX_INPUT_BYTES_V1,
            });
        }
        if self.weights.len() != MODERATION_MODEL_FEATURE_COUNT_V1 {
            return Err(ModerationModelArtifactError::InvalidWeightCount {
                expected: MODERATION_MODEL_FEATURE_COUNT_V1,
                found: self.weights.len(),
            });
        }
        if !(2..=MODERATION_MODEL_MAX_CALIBRATION_KNOTS_V1).contains(&self.calibration.len()) {
            return Err(ModerationModelArtifactError::InvalidCalibrationCount {
                found: self.calibration.len(),
                maximum: MODERATION_MODEL_MAX_CALIBRATION_KNOTS_V1,
            });
        }
        for (index, knot) in self.calibration.iter().enumerate() {
            if knot.score_bps > MODERATION_REPRO_MAX_BPS
                || index > 0 && knot.score_bps < self.calibration[index - 1].score_bps
            {
                return Err(ModerationModelArtifactError::InvalidCalibrationScore {
                    index,
                    score_bps: knot.score_bps,
                });
            }
            if index > 0 && knot.input <= self.calibration[index - 1].input {
                return Err(ModerationModelArtifactError::CalibrationInputOrder { index });
            }
        }
        if self.working_memory_bytes != MODERATION_MODEL_WORKING_MEMORY_BYTES_V1 {
            return Err(ModerationModelArtifactError::InvalidWorkingMemory {
                expected: MODERATION_MODEL_WORKING_MEMORY_BYTES_V1,
                found: self.working_memory_bytes,
            });
        }
        let expected_operations =
            moderation_model_required_operations_v1(self.max_input_bytes, self.calibration.len())
                .ok_or(ModerationModelArtifactError::AccumulatorOverflow)?;
        if self.max_operations != expected_operations {
            return Err(ModerationModelArtifactError::InvalidOperationBudget {
                expected: expected_operations,
                found: self.max_operations,
            });
        }
        let (minimum, maximum) = self.weights.iter().fold(
            (i128::from(self.bias), i128::from(self.bias)),
            |(minimum, maximum), weight| {
                let contribution = i128::from(*weight) * i128::from(MODERATION_REPRO_MAX_BPS);
                if *weight < 0 {
                    (minimum + contribution, maximum)
                } else {
                    (minimum, maximum + contribution)
                }
            },
        );
        if minimum < i128::from(i64::MIN) || maximum > i128::from(i64::MAX) {
            return Err(ModerationModelArtifactError::AccumulatorOverflow);
        }
        Ok(())
    }
    /// Compute the digest binding every value that can affect model behaviour.
    #[must_use]
    pub fn behaviour_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_MODEL_BEHAVIOUR_DIGEST_DOMAIN_V1);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&[match self.engine {
            ModerationModelEngineV1::DeterministicLinearV1 => 1,
        }]);
        hasher.update(&[match self.feature_profile {
            ModerationFeatureProfileV1::ByteHistogramAndBigramV1 => 1,
        }]);
        hasher.update(&self.model_id);
        hasher.update(&self.max_input_bytes.to_le_bytes());
        hasher.update(&self.max_operations.to_le_bytes());
        hasher.update(&self.working_memory_bytes.to_le_bytes());
        hasher.update(&self.bias.to_le_bytes());
        for weight in &self.weights {
            hasher.update(&weight.to_le_bytes());
        }
        for knot in &self.calibration {
            hasher.update(&knot.input.to_le_bytes());
            hasher.update(&knot.score_bps.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}
/// Governance-signed moderation reproducibility manifest.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationReproManifestV1")]
pub struct ModerationReproManifestV1 {
    /// Canonical payload describing the runner, models, and thresholds.
    pub body: ModerationReproBodyV1,
    /// Signatures issued by the governance council / SRE leads.
    #[norito(default)]
    pub signatures: Vec<ModerationReproSignatureV1>,
}
/// Canonical payload hashed and signed in the reproducibility manifest.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationReproBodyV1")]
pub struct ModerationReproBodyV1 {
    /// Schema version; must equal [`MODERATION_REPRO_MANIFEST_VERSION_V1`].
    pub schema_version: u16,
    /// UUID of the moderation committee manifest this record attests to.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_id: [u8; 16],
    /// BLAKE3 digest of the manifest payload.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_digest: [u8; 32],
    /// BLAKE3 digest of the compiled runner binary.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub runner_hash: [u8; 32],
    /// Runner version string (e.g., `sorafs-ai-runner 0.4.0`).
    pub runtime_version: String,
    /// Unix timestamp (seconds) when the manifest was signed.
    pub issued_at_unix: u64,
    /// Seed/domain information used to derive deterministic RNG inputs.
    pub seed_material: ModerationSeedMaterialV1,
    /// Threshold configuration applied during calibration.
    pub thresholds: ModerationThresholdsV1,
    /// Digests for each moderated model artefact.
    #[norito(default)]
    pub models: Vec<ModerationModelFingerprintV1>,
    /// Optional governance notes included in the release artefact.
    #[norito(default)]
    pub notes: Option<String>,
}
/// Complete execution fingerprint for one model artefact referenced by the runner.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationModelFingerprintV1")]
pub struct ModerationModelFingerprintV1 {
    /// Model UUID.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub model_id: [u8; 16],
    /// Canonical portable path relative to the configured artefact root.
    pub artifact_path: String,
    /// Exact byte length of the canonical encoded artefact.
    pub artifact_bytes: u64,
    /// Digest of the exact canonical encoded artefact bytes.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub artifact_digest: [u8; 32],
    /// Digest binding every value that can affect model behaviour.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub weights_digest: [u8; 32],
    /// Inference engine required to execute the artefact.
    pub engine: ModerationModelEngineV1,
    /// Feature extraction profile required by the weights.
    pub feature_profile: ModerationFeatureProfileV1,
    /// Exact number of calibration knots in the artefact.
    pub calibration_knot_count: u16,
    /// Maximum payload size accepted by this model.
    pub max_input_bytes: u32,
    /// Exact worst-case operation budget for `max_input_bytes`.
    pub max_operations: u64,
    /// Exact fixed working-memory budget.
    pub working_memory_bytes: u32,
    /// Optional weight applied when combining model scores (basis points, 0-10_000).
    #[norito(default)]
    pub weight: Option<u16>,
}
/// Seed derivation metadata used to generate deterministic RNG inputs.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationSeedMaterialV1")]
pub struct ModerationSeedMaterialV1 {
    /// Signed calibration-provenance label; integer inference never consumes it.
    pub domain_tag: String,
    /// Version of the provenance derivation scheme; must be non-zero.
    pub seed_version: u16,
    /// Governance-signed calibration nonce; integer inference never consumes it.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub run_nonce: [u8; 32],
}
/// Threshold values used when aggregating moderation verdicts.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Default,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationThresholdsV1")]
pub struct ModerationThresholdsV1 {
    /// Minimum combined score required to quarantine content (basis points, 0-10_000).
    pub quarantine: u16,
    /// Minimum combined score required to escalate content for review (basis points, 0-10_000).
    pub escalate: u16,
}
/// Signature and signer metadata for a reproducibility manifest.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationReproSignatureV1")]
pub struct ModerationReproSignatureV1 {
    /// Governance role (e.g., `council`, `sre_lead`, `audit`).
    pub role: String,
    /// Public key of the signer.
    pub public_key: PublicKey,
    /// Typed signature covering [`ModerationReproBodyV1`].
    pub signature: SignatureOf<ModerationReproBodyV1>,
}
/// Validation summary returned after checking a reproducibility manifest.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationReproManifestSummary")]
pub struct ModerationReproManifestSummary {
    /// Referenced manifest UUID.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_id: [u8; 16],
    /// Unix timestamp (seconds) when the manifest was issued.
    pub issued_at_unix: u64,
    /// Number of model entries covered by the manifest.
    pub model_count: u32,
    /// Number of valid signatures present.
    pub signer_count: u32,
}
/// Governance-signed runner trust policy bound to one reproducibility manifest.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationTrustPolicyV1")]
pub struct ModerationTrustPolicyV1 {
    /// Canonical policy body.
    pub body: ModerationTrustPolicyBodyV1,
    /// Governance signatures over the body, ordered by public key.
    #[norito(default)]
    pub signatures: Vec<ModerationTrustPolicySignatureV1>,
}
/// Canonical body of a runner trust and freshness policy.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationTrustPolicyBodyV1")]
pub struct ModerationTrustPolicyBodyV1 {
    /// Schema version; must equal [`MODERATION_TRUST_POLICY_VERSION_V1`].
    pub schema_version: u16,
    /// Stable policy identifier.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub policy_id: [u8; 16],
    /// Domain-separated digest of this body with this slot zeroed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub policy_digest: [u8; 32],
    /// Manifest identifier authorized by this policy.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_id: [u8; 16],
    /// Exact manifest digest authorized by this policy.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_digest: [u8; 32],
    /// Exact runner executable hash authorized by this policy.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub runner_hash: [u8; 32],
    /// Policy issue timestamp.
    pub issued_at_unix: u64,
    /// First timestamp at which the policy is active.
    pub valid_from_unix: u64,
    /// Exclusive policy expiry timestamp.
    pub valid_until_unix: u64,
    /// Minimum distinct authorized result signers required by the committee.
    pub result_quorum: u16,
    /// Minimum externally trusted governance signatures required on this policy.
    pub governance_quorum: u16,
    /// Maximum age of an accepted screening result.
    pub max_result_age_secs: u64,
    /// Maximum lifetime a runner may place in a signed result.
    pub max_result_ttl_secs: u64,
    /// Maximum future/past clock skew admitted during result validation.
    pub max_clock_skew_secs: u64,
    /// Canonically ordered trusted runner signers.
    #[norito(default)]
    pub trusted_signers: Vec<ModerationTrustedSignerV1>,
    /// Optional governance note.
    #[norito(default)]
    pub notes: Option<String>,
}
/// One runner signer authorization and its validity/revocation window.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationTrustedSignerV1")]
pub struct ModerationTrustedSignerV1 {
    /// Canonical operational role label.
    pub role: String,
    /// Runner result-signing key.
    pub public_key: PublicKey,
    /// First timestamp at which results from this signer are accepted.
    pub valid_from_unix: u64,
    /// Exclusive signer authorization expiry timestamp.
    pub valid_until_unix: u64,
    /// Optional revocation timestamp; results at or after it are rejected.
    #[norito(default)]
    pub revoked_at_unix: Option<u64>,
}
/// Governance signature over a moderation trust policy body.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationTrustPolicySignatureV1")]
pub struct ModerationTrustPolicySignatureV1 {
    /// Governance role label.
    pub role: String,
    /// Governance signer key.
    pub public_key: PublicKey,
    /// Typed signature covering [`ModerationTrustPolicyBodyV1`].
    pub signature: SignatureOf<ModerationTrustPolicyBodyV1>,
}
/// Canonical runner-signed screening result envelope.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationSignedScreeningResultV1")]
pub struct ModerationSignedScreeningResultV1 {
    /// Signed screening body.
    pub body: ModerationSignedScreeningBodyV1,
    /// Runner key that issued the result.
    pub signer_public_key: PublicKey,
    /// Typed signature covering `body`.
    pub signature: SignatureOf<ModerationSignedScreeningBodyV1>,
}
/// Canonical body signed by an authorized deterministic runner.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationSignedScreeningBodyV1")]
pub struct ModerationSignedScreeningBodyV1 {
    /// Schema version; must equal [`MODERATION_SIGNED_RESULT_VERSION_V1`].
    pub schema_version: u16,
    /// Manifest identifier used for inference.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_id: [u8; 16],
    /// Exact manifest body digest used for inference.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_digest: [u8; 32],
    /// Exact runner executable hash used for inference.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub runner_hash: [u8; 32],
    /// Trust-policy identifier authorizing the signer.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub trust_policy_id: [u8; 16],
    /// Exact trust-policy digest authorizing the signer.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub trust_policy_digest: [u8; 32],
    /// Canonical subject identifier.
    pub subject: String,
    /// Digest of the screened payload.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub subject_digest: [u8; 32],
    /// Per-model scores in manifest order.
    #[norito(default)]
    pub model_scores: Vec<ModerationModelScoreV1>,
    /// Manifest-weighted aggregate score.
    pub combined_score_bps: u16,
    /// Score-derived verdict (`pass`, `quarantine`, or `escalate`).
    pub verdict: String,
    /// Time at which inference completed.
    pub screened_at_unix: u64,
    /// Exclusive expiry of this signed result.
    pub expires_at_unix: u64,
    /// Digest of the active screening policy surface.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub policy_digest: [u8; 32],
    /// Domain-separated digest of this body with this slot zeroed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub evidence_digest: [u8; 32],
    /// Optional canonical operator note.
    #[norito(default)]
    pub notes: Option<String>,
}
/// Successful external trust-policy validation summary.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationTrustPolicySummaryV1")]
pub struct ModerationTrustPolicySummaryV1 {
    /// Number of authorized runner signers.
    pub trusted_signer_count: u16,
    /// Number of externally trusted governance signatures verified.
    pub trusted_governance_signature_count: u16,
    /// Committee result quorum.
    pub result_quorum: u16,
}
/// One authenticated runner contribution committed by a committee aggregate.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationCommitteeMemberV1")]
pub struct ModerationCommitteeMemberV1 {
    /// Distinct policy-authorized runner key.
    pub signer_public_key: PublicKey,
    /// Evidence digest of the exact signed result body.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub evidence_digest: [u8; 32],
    /// Runner aggregate score in basis points.
    pub combined_score_bps: u16,
    /// Score-derived runner verdict.
    pub verdict: String,
    /// Runner completion timestamp.
    pub screened_at_unix: u64,
    /// Exclusive signed-result expiry.
    pub expires_at_unix: u64,
}
/// Deterministic aggregate over distinct, authenticated runner results.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationCommitteeAggregateV1")]
pub struct ModerationCommitteeAggregateV1 {
    /// Schema version; must equal [`MODERATION_COMMITTEE_AGGREGATE_VERSION_V1`].
    pub schema_version: u16,
    /// Manifest identifier shared by every member result.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_id: [u8; 16],
    /// Exact manifest digest shared by every member result.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_digest: [u8; 32],
    /// External trust-policy identifier used for authorization.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub trust_policy_id: [u8; 16],
    /// Exact external trust-policy digest used for authorization.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub trust_policy_digest: [u8; 32],
    /// Canonical subject identifier shared by every result.
    pub subject: String,
    /// Digest of the screened payload shared by every result.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub subject_digest: [u8; 32],
    /// Distinct authenticated member results, ordered by signer key.
    pub members: Vec<ModerationCommitteeMemberV1>,
    /// Policy quorum satisfied by this aggregate.
    pub quorum: u16,
    /// Upper-half-up median of member scores.
    pub aggregated_score_bps: u16,
    /// Score-derived committee verdict.
    pub verdict: String,
    /// Timestamp at which the committee validated the member set.
    pub aggregated_at_unix: u64,
    /// Earliest exclusive expiry across all member results.
    pub expires_at_unix: u64,
    /// Domain-separated digest of this aggregate with this slot zeroed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub aggregate_digest: [u8; 32],
}
/// Payload retained in a tamper-evident moderation provenance record.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationProvenancePayloadV1")]
pub enum ModerationProvenancePayloadV1 {
    /// Exact runner-signed screening result.
    SignedScreeningResult(ModerationSignedScreeningResultV1),
    /// Exact authenticated committee aggregate.
    CommitteeAggregate(ModerationCommitteeAggregateV1),
}
/// One hash-chained moderation provenance entry.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationProvenanceEntryV1")]
pub struct ModerationProvenanceEntryV1 {
    /// Zero-based sequence number.
    pub sequence: u64,
    /// Digest of the preceding entry, or zero for the first entry.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub previous_entry_digest: [u8; 32],
    /// Domain-separated digest of this entry with this slot zeroed.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub entry_digest: [u8; 32],
    /// Local durable-record timestamp.
    pub recorded_at_unix: u64,
    /// Complete canonical evidence payload.
    pub payload: ModerationProvenancePayloadV1,
}
/// Bounded tamper-evident moderation provenance segment.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::ModerationProvenanceLogV1")]
pub struct ModerationProvenanceLogV1 {
    /// Schema version; must equal [`MODERATION_PROVENANCE_LOG_VERSION_V1`].
    pub schema_version: u16,
    /// Operator-assigned non-zero segment identifier.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub log_id: [u8; 16],
    /// Digest of the final entry, or zero for an empty segment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub head_digest: [u8; 32],
    /// Ordered bounded entry inventory.
    pub entries: Vec<ModerationProvenanceEntryV1>,
}
/// Validation errors surfaced when checking reproducibility manifests.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModerationReproValidationError {
    /// Manifest uses an unsupported schema version.
    #[error("unsupported reproducibility schema version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Expected schema version for the manifest.
        expected: u16,
        /// Schema version discovered in the manifest payload.
        found: u16,
    },
    /// Manifest UUID is all zeros.
    #[error("reproducibility manifest has a zero manifest id")]
    MissingManifestId,
    /// Manifest issue timestamp is zero.
    #[error("reproducibility manifest issued_at_unix must be non-zero")]
    MissingIssuedAt,
    /// Seed provenance version is zero.
    #[error("reproducibility manifest seed_version must be non-zero")]
    MissingSeedVersion,
    /// A signed text field is non-canonical or exceeds its bound.
    #[error("reproducibility manifest text field `{field}` is invalid")]
    InvalidText {
        /// Invalid field name.
        field: &'static str,
    },
    /// Canonical body encoding failed during digest verification.
    #[error("failed to encode reproducibility manifest body for digest verification: {reason}")]
    ManifestDigestEncoding {
        /// Encoding failure.
        reason: String,
    },
    /// Signed digest is not derived from the canonical body.
    #[error("reproducibility manifest digest does not match its canonical body")]
    ManifestDigestMismatch {
        /// Canonically derived digest.
        expected: [u8; 32],
        /// Signed digest field.
        found: [u8; 32],
    },
    /// Manifest contains no model entries.
    #[error("reproducibility manifest lists no model digests")]
    MissingModels,
    /// Manifest includes more models than the engine can safely admit.
    #[error("reproducibility manifest lists {found} models; maximum is {maximum}")]
    TooManyModels {
        /// Model count found in the manifest.
        found: usize,
        /// Maximum accepted model count.
        maximum: usize,
    },
    /// Manifest digest is all zeros.
    #[error("reproducibility manifest field `{field}` must be non-zero")]
    MissingDigest {
        /// Name of the digest field.
        field: &'static str,
    },
    /// Model identifier is all zeros.
    #[error("reproducibility manifest includes a zero model id")]
    MissingModelId,
    /// Manifest contains duplicate model identifiers.
    #[error("reproducibility manifest repeats model id {model_id:?}")]
    DuplicateModelId {
        /// Repeated model identifier.
        model_id: [u8; 16],
    },
    /// Manifest models are not in canonical model-id order.
    #[error("reproducibility manifest model ids must be strictly increasing")]
    NonCanonicalModelOrder,
    /// Model artefact path is unsafe or non-canonical.
    #[error("reproducibility manifest model {model_id:?} has invalid artefact path `{path}`")]
    InvalidArtifactPath {
        /// Model identifier carrying the invalid path.
        model_id: [u8; 16],
        /// Rejected path.
        path: String,
    },
    /// Manifest repeats a model artefact path.
    #[error("reproducibility manifest repeats artefact path `{path}`")]
    DuplicateArtifactPath {
        /// Repeated path.
        path: String,
    },
    /// One model artefact size is zero or exceeds the hard limit.
    #[error(
        "reproducibility manifest model {model_id:?} artefact size {found} is outside 1..={maximum}"
    )]
    InvalidArtifactBytes {
        /// Model identifier carrying the invalid size.
        model_id: [u8; 16],
        /// Size found in the fingerprint.
        found: u64,
        /// Maximum admitted size.
        maximum: u64,
    },
    /// Aggregate artefact size exceeds the manifest hard limit.
    #[error("reproducibility manifest artefacts total {found} bytes; maximum is {maximum}")]
    ArtifactBytesOverflow {
        /// Aggregate bytes found or `u64::MAX` when addition overflowed.
        found: u64,
        /// Maximum admitted aggregate size.
        maximum: u64,
    },
    /// Manifest contains duplicate model artefact digests.
    #[error("reproducibility manifest repeats artifact digest for model {model_id:?}")]
    DuplicateArtifactDigest {
        /// Model identifier carrying the repeated artifact digest.
        model_id: [u8; 16],
    },
    /// Manifest contains duplicate model weight digests.
    #[error("reproducibility manifest repeats weights digest for model {model_id:?}")]
    DuplicateWeightsDigest {
        /// Model identifier carrying the repeated weights digest.
        model_id: [u8; 16],
    },
    /// Model digest is all zeros.
    #[error("reproducibility manifest model {model_id:?} field `{field}` must be non-zero")]
    MissingModelDigest {
        /// Model identifier carrying the zero digest.
        model_id: [u8; 16],
        /// Name of the digest field.
        field: &'static str,
    },
    /// Fingerprint has an invalid calibration-knot count.
    #[error("reproducibility manifest model {model_id:?} has {found} calibration knots")]
    InvalidCalibrationCount {
        /// Model identifier carrying the invalid count.
        model_id: [u8; 16],
        /// Count found in the fingerprint.
        found: u16,
    },
    /// Fingerprint input bound is zero or exceeds the hard limit.
    #[error("reproducibility manifest model {model_id:?} max input {found} exceeds {maximum}")]
    InvalidModelMaxInput {
        /// Model identifier carrying the invalid bound.
        model_id: [u8; 16],
        /// Bound found in the fingerprint.
        found: u32,
        /// Maximum admitted bound.
        maximum: u32,
    },
    /// Fingerprint declares a resource budget inconsistent with the engine.
    #[error("reproducibility manifest model {model_id:?} has inconsistent resource budget")]
    InvalidModelResourceBudget {
        /// Model identifier carrying the inconsistent budget.
        model_id: [u8; 16],
    },
    /// Model weight is outside the accepted basis-point range.
    #[error("reproducibility manifest model {model_id:?} weight {weight} exceeds 10000 bps")]
    InvalidModelWeight {
        /// Model identifier carrying the invalid weight.
        model_id: [u8; 16],
        /// Weight declared in the manifest.
        weight: u16,
    },
    /// Every model has zero weight.
    #[error("reproducibility manifest must include at least one positive model weight")]
    MissingPositiveModelWeight,
    /// Threshold is outside the accepted basis-point range.
    #[error("reproducibility manifest threshold `{field}` value {value} exceeds 10000 bps")]
    InvalidThresholdBps {
        /// Threshold field name.
        field: &'static str,
        /// Threshold value.
        value: u16,
    },
    /// Quarantine threshold exceeds the escalate threshold.
    #[error(
        "reproducibility manifest quarantine threshold {quarantine} exceeds escalate threshold {escalate}"
    )]
    InvalidThresholdOrder {
        /// Quarantine threshold in basis points.
        quarantine: u16,
        /// Escalate threshold in basis points.
        escalate: u16,
    },
    /// Manifest is missing signer entries.
    #[error("reproducibility manifest contains no signatures")]
    MissingSignatures,
    /// Manifest contains too many signer entries.
    #[error("reproducibility manifest has {found} signatures; maximum is {maximum}")]
    TooManySignatures {
        /// Count found in the manifest.
        found: usize,
        /// Maximum admitted count.
        maximum: usize,
    },
    /// Manifest includes duplicate signer keys.
    #[error("reproducibility manifest includes duplicate signer keys")]
    DuplicateSigner,
    /// Signer keys are not in canonical ascending order.
    #[error("reproducibility manifest signer keys must be strictly increasing")]
    NonCanonicalSignatureOrder,
    /// Signature verification failed.
    #[error("signature for role `{role}` failed verification: {source}")]
    BadSignature {
        /// Role label attached to the failing signature.
        role: String,
        /// Underlying crypto error.
        #[source]
        source: iroha_crypto::Error,
    },
}
impl ModerationReproManifestV1 {
    /// Compute the canonical domain-separated digest committed by
    /// [`ModerationReproBodyV1::manifest_digest`].
    ///
    /// The digest slot is zeroed before encoding so that it cannot be a
    /// self-referential, operator-selected label. Production loaders must compare
    /// this value with the signed field before accepting any artefact.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical manifest body cannot be encoded.
    pub fn computed_manifest_digest(&self) -> Result<[u8; 32], norito::Error> {
        self.body.computed_manifest_digest()
    }
    /// Validate the manifest signatures and schema constraints.
    ///
    /// Returns a summary containing the manifest identifier, timestamps, and counts on success.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationReproValidationError`] if the schema version mismatches, models or
    /// signatures are missing, duplicate signer keys are present, or signature verification fails.
    pub fn validate(
        &self,
    ) -> Result<ModerationReproManifestSummary, ModerationReproValidationError> {
        validate_repro_body_header(&self.body)?;
        validate_repro_thresholds(self.body.thresholds)?;
        validate_repro_models(&self.body.models)?;
        let computed_digest = self.computed_manifest_digest().map_err(|error| {
            ModerationReproValidationError::ManifestDigestEncoding {
                reason: error.to_string(),
            }
        })?;
        if self.body.manifest_digest != computed_digest {
            return Err(ModerationReproValidationError::ManifestDigestMismatch {
                expected: computed_digest,
                found: self.body.manifest_digest,
            });
        }
        validate_repro_signatures(&self.signatures, &self.body)?;
        moderation_repro_summary(&self.body, self.signatures.len())
    }
}
impl ModerationReproBodyV1 {
    /// Compute the canonical digest of this body with the digest slot zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical body cannot be encoded.
    pub fn computed_manifest_digest(&self) -> Result<[u8; 32], norito::Error> {
        let mut body = self.clone();
        body.manifest_digest = [0; 32];
        let encoded = norito::encode_canonical(&body)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_REPRO_BODY_DIGEST_DOMAIN_V1);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
    /// Replace `manifest_digest` with the canonical domain-separated body digest.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical body cannot be encoded.
    pub fn refresh_manifest_digest(&mut self) -> Result<(), norito::Error> {
        self.manifest_digest = self.computed_manifest_digest()?;
        Ok(())
    }
}
fn validate_repro_body_header(
    body: &ModerationReproBodyV1,
) -> Result<(), ModerationReproValidationError> {
    if body.schema_version != MODERATION_REPRO_MANIFEST_VERSION_V1 {
        return Err(ModerationReproValidationError::UnsupportedVersion {
            expected: MODERATION_REPRO_MANIFEST_VERSION_V1,
            found: body.schema_version,
        });
    }
    if body.manifest_id == [0; 16] {
        return Err(ModerationReproValidationError::MissingManifestId);
    }
    if body.issued_at_unix == 0 {
        return Err(ModerationReproValidationError::MissingIssuedAt);
    }
    if body.seed_material.seed_version == 0 {
        return Err(ModerationReproValidationError::MissingSeedVersion);
    }
    validate_repro_text(
        &body.runtime_version,
        MODERATION_REPRO_MAX_RUNTIME_VERSION_BYTES_V1,
        "runtime_version",
    )?;
    validate_repro_text(
        &body.seed_material.domain_tag,
        MODERATION_REPRO_MAX_SEED_DOMAIN_BYTES_V1,
        "seed_material.domain_tag",
    )?;
    if let Some(notes) = &body.notes {
        validate_repro_text(notes, MODERATION_REPRO_MAX_NOTES_BYTES_V1, "notes")?;
    }
    if body.models.is_empty() {
        return Err(ModerationReproValidationError::MissingModels);
    }
    if body.models.len() > MODERATION_MODEL_MAX_MODELS_V1 {
        return Err(ModerationReproValidationError::TooManyModels {
            found: body.models.len(),
            maximum: MODERATION_MODEL_MAX_MODELS_V1,
        });
    }
    if body.manifest_digest == [0; 32] {
        return Err(ModerationReproValidationError::MissingDigest {
            field: "manifest_digest",
        });
    }
    if body.runner_hash == [0; 32] {
        return Err(ModerationReproValidationError::MissingDigest {
            field: "runner_hash",
        });
    }
    if body.seed_material.run_nonce == [0; 32] {
        return Err(ModerationReproValidationError::MissingDigest { field: "run_nonce" });
    }
    Ok(())
}
fn validate_repro_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ModerationReproValidationError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ModerationReproValidationError::InvalidText { field });
    }
    Ok(())
}
fn validate_repro_thresholds(
    thresholds: ModerationThresholdsV1,
) -> Result<(), ModerationReproValidationError> {
    if thresholds.quarantine > MODERATION_REPRO_MAX_BPS {
        return Err(ModerationReproValidationError::InvalidThresholdBps {
            field: "quarantine",
            value: thresholds.quarantine,
        });
    }
    if thresholds.escalate > MODERATION_REPRO_MAX_BPS {
        return Err(ModerationReproValidationError::InvalidThresholdBps {
            field: "escalate",
            value: thresholds.escalate,
        });
    }
    if thresholds.quarantine > thresholds.escalate {
        return Err(ModerationReproValidationError::InvalidThresholdOrder {
            quarantine: thresholds.quarantine,
            escalate: thresholds.escalate,
        });
    }
    Ok(())
}
fn validate_repro_models(
    models: &[ModerationModelFingerprintV1],
) -> Result<(), ModerationReproValidationError> {
    let mut model_ids = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    let mut artifact_digests = BTreeSet::new();
    let mut weights_digests = BTreeSet::new();
    let mut has_positive_model_weight = false;
    let mut previous_model_id = None;
    let mut total_artifact_bytes = 0_u64;
    for model in models {
        validate_repro_model_uniqueness(model, &mut model_ids)?;
        if previous_model_id.is_some_and(|previous| previous >= model.model_id) {
            return Err(ModerationReproValidationError::NonCanonicalModelOrder);
        }
        previous_model_id = Some(model.model_id);
        validate_repro_model_artifact(model, &mut artifact_paths)?;
        validate_repro_model_digests(model, &mut artifact_digests, &mut weights_digests)?;
        validate_repro_model_shape(model)?;
        total_artifact_bytes = total_artifact_bytes
            .checked_add(model.artifact_bytes)
            .ok_or(ModerationReproValidationError::ArtifactBytesOverflow {
                found: u64::MAX,
                maximum: MODERATION_MODEL_MAX_TOTAL_ARTIFACT_BYTES_V1,
            })?;
        has_positive_model_weight |= model.weight.unwrap_or(MODERATION_REPRO_MAX_BPS) > 0;
    }
    if total_artifact_bytes > MODERATION_MODEL_MAX_TOTAL_ARTIFACT_BYTES_V1 {
        return Err(ModerationReproValidationError::ArtifactBytesOverflow {
            found: total_artifact_bytes,
            maximum: MODERATION_MODEL_MAX_TOTAL_ARTIFACT_BYTES_V1,
        });
    }
    if !has_positive_model_weight {
        return Err(ModerationReproValidationError::MissingPositiveModelWeight);
    }
    Ok(())
}
fn validate_repro_model_artifact(
    model: &ModerationModelFingerprintV1,
    artifact_paths: &mut BTreeSet<String>,
) -> Result<(), ModerationReproValidationError> {
    if !is_canonical_moderation_artifact_path_v1(&model.artifact_path) {
        return Err(ModerationReproValidationError::InvalidArtifactPath {
            model_id: model.model_id,
            path: model.artifact_path.clone(),
        });
    }
    if !artifact_paths.insert(model.artifact_path.clone()) {
        return Err(ModerationReproValidationError::DuplicateArtifactPath {
            path: model.artifact_path.clone(),
        });
    }
    if model.artifact_bytes == 0 || model.artifact_bytes > MODERATION_MODEL_MAX_ARTIFACT_BYTES_V1 {
        return Err(ModerationReproValidationError::InvalidArtifactBytes {
            model_id: model.model_id,
            found: model.artifact_bytes,
            maximum: MODERATION_MODEL_MAX_ARTIFACT_BYTES_V1,
        });
    }
    Ok(())
}
/// Return whether `path` is a canonical platform-independent artefact path.
///
/// Accepted paths are non-empty ASCII slash-separated components containing only letters, digits,
/// `.`, `_`, and `-`. Absolute paths, empty components, traversal components, backslashes, drive
/// prefixes, and control characters are rejected independent of the host platform.
#[must_use]
pub fn is_canonical_moderation_artifact_path_v1(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MODERATION_MODEL_MAX_ARTIFACT_PATH_BYTES_V1
        || !path.is_ascii()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\\')
        || path.contains(':')
    {
        return false;
    }
    path.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}
fn validate_repro_model_uniqueness(
    model: &ModerationModelFingerprintV1,
    model_ids: &mut BTreeSet<[u8; 16]>,
) -> Result<(), ModerationReproValidationError> {
    if model.model_id == [0; 16] {
        return Err(ModerationReproValidationError::MissingModelId);
    }
    if !model_ids.insert(model.model_id) {
        return Err(ModerationReproValidationError::DuplicateModelId {
            model_id: model.model_id,
        });
    }
    Ok(())
}
fn validate_repro_model_digests(
    model: &ModerationModelFingerprintV1,
    artifact_digests: &mut BTreeSet<[u8; 32]>,
    weights_digests: &mut BTreeSet<[u8; 32]>,
) -> Result<(), ModerationReproValidationError> {
    if model.artifact_digest == [0; 32] {
        return Err(ModerationReproValidationError::MissingModelDigest {
            model_id: model.model_id,
            field: "artifact_digest",
        });
    }
    if !artifact_digests.insert(model.artifact_digest) {
        return Err(ModerationReproValidationError::DuplicateArtifactDigest {
            model_id: model.model_id,
        });
    }
    if model.weights_digest == [0; 32] {
        return Err(ModerationReproValidationError::MissingModelDigest {
            model_id: model.model_id,
            field: "weights_digest",
        });
    }
    if !weights_digests.insert(model.weights_digest) {
        return Err(ModerationReproValidationError::DuplicateWeightsDigest {
            model_id: model.model_id,
        });
    }
    Ok(())
}
fn validate_repro_model_shape(
    model: &ModerationModelFingerprintV1,
) -> Result<(), ModerationReproValidationError> {
    if !(2..=MODERATION_MODEL_MAX_CALIBRATION_KNOTS_V1)
        .contains(&usize::from(model.calibration_knot_count))
    {
        return Err(ModerationReproValidationError::InvalidCalibrationCount {
            model_id: model.model_id,
            found: model.calibration_knot_count,
        });
    }
    if model.max_input_bytes == 0 || model.max_input_bytes > MODERATION_MODEL_MAX_INPUT_BYTES_V1 {
        return Err(ModerationReproValidationError::InvalidModelMaxInput {
            model_id: model.model_id,
            found: model.max_input_bytes,
            maximum: MODERATION_MODEL_MAX_INPUT_BYTES_V1,
        });
    }
    let expected_operations = moderation_model_required_operations_v1(
        model.max_input_bytes,
        usize::from(model.calibration_knot_count),
    );
    if model.working_memory_bytes != MODERATION_MODEL_WORKING_MEMORY_BYTES_V1
        || expected_operations != Some(model.max_operations)
    {
        return Err(ModerationReproValidationError::InvalidModelResourceBudget {
            model_id: model.model_id,
        });
    }
    let weight = model.weight.unwrap_or(MODERATION_REPRO_MAX_BPS);
    if weight > MODERATION_REPRO_MAX_BPS {
        return Err(ModerationReproValidationError::InvalidModelWeight {
            model_id: model.model_id,
            weight,
        });
    }
    Ok(())
}
fn validate_repro_signatures(
    signatures: &[ModerationReproSignatureV1],
    body: &ModerationReproBodyV1,
) -> Result<(), ModerationReproValidationError> {
    if signatures.is_empty() {
        return Err(ModerationReproValidationError::MissingSignatures);
    }
    if signatures.len() > MODERATION_REPRO_MAX_SIGNATURES_V1 {
        return Err(ModerationReproValidationError::TooManySignatures {
            found: signatures.len(),
            maximum: MODERATION_REPRO_MAX_SIGNATURES_V1,
        });
    }
    let mut seen = BTreeSet::new();
    let mut previous_key: Option<&PublicKey> = None;
    for signer in signatures {
        validate_repro_text(
            &signer.role,
            MODERATION_REPRO_MAX_SIGNATURE_ROLE_BYTES_V1,
            "signatures.role",
        )?;
        if !seen.insert(signer.public_key.clone()) {
            return Err(ModerationReproValidationError::DuplicateSigner);
        }
        if previous_key.is_some_and(|previous| previous >= &signer.public_key) {
            return Err(ModerationReproValidationError::NonCanonicalSignatureOrder);
        }
        previous_key = Some(&signer.public_key);
        verify_repro_signature(&signer.signature, &signer.public_key, body).map_err(|source| {
            ModerationReproValidationError::BadSignature {
                role: signer.role.clone(),
                source,
            }
        })?;
    }
    Ok(())
}
fn moderation_repro_summary(
    body: &ModerationReproBodyV1,
    signature_count: usize,
) -> Result<ModerationReproManifestSummary, ModerationReproValidationError> {
    let model_count = u32::try_from(body.models.len())
        .map_err(|_| ModerationReproValidationError::MissingModels)?;
    let signer_count = u32::try_from(signature_count)
        .map_err(|_| ModerationReproValidationError::MissingSignatures)?;
    Ok(ModerationReproManifestSummary {
        manifest_id: body.manifest_id,
        issued_at_unix: body.issued_at_unix,
        model_count,
        signer_count,
    })
}
fn verify_repro_signature(
    signature: &SignatureOf<ModerationReproBodyV1>,
    public_key: &PublicKey,
    body: &ModerationReproBodyV1,
) -> Result<(), iroha_crypto::Error> {
    match public_key.try_algorithm() {
        Ok(Algorithm::Ed25519) => {
            iroha_crypto::ed25519_validate_signature_encoding(signature.payload())
                .map_err(iroha_crypto::SignatureEncodingError::into_error)?;
        }
        Ok(Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_validate_signature_encoding(signature.payload())
                .map_err(iroha_crypto::SignatureEncodingError::into_error)?;
        }
        _ => {}
    }
    signature.verify(public_key, body)
}
/// Trust-policy validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModerationTrustPolicyError {
    /// Bound reproducibility manifest is invalid.
    #[error("invalid moderation reproducibility manifest: {0}")]
    InvalidManifest(
        /// Manifest validation failure.
        String,
    ),
    /// Schema version is unsupported.
    #[error("unsupported moderation trust-policy version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Required schema version.
        expected: u16,
        /// Version found in the policy.
        found: u16,
    },
    /// A required identifier or digest is zero.
    #[error("moderation trust-policy field `{field}` must be non-zero")]
    MissingIdentity {
        /// Missing field name.
        field: &'static str,
    },
    /// Canonical policy-body encoding failed.
    #[error("failed to encode moderation trust policy: {0}")]
    Encoding(
        /// Encoding failure.
        String,
    ),
    /// Signed policy digest is not canonically derived.
    #[error("moderation trust-policy digest mismatch")]
    DigestMismatch,
    /// Policy does not bind the loaded reproducibility manifest.
    #[error("moderation trust policy does not bind the loaded reproducibility manifest")]
    ManifestBindingMismatch,
    /// Policy or signer validity window is malformed or inactive.
    #[error("moderation trust-policy time window `{field}` is invalid")]
    InvalidTimeWindow {
        /// Invalid time-window field.
        field: &'static str,
    },
    /// Policy resource/freshness limit is outside the first-release envelope.
    #[error("moderation trust-policy bound `{field}` value {found} exceeds {maximum}")]
    InvalidBound {
        /// Invalid bound field.
        field: &'static str,
        /// Value found in the policy.
        found: u64,
        /// First-release maximum.
        maximum: u64,
    },
    /// Policy quorum cannot be satisfied by its declared inventory.
    #[error("moderation trust-policy quorum `{field}` value {found} is invalid")]
    InvalidQuorum {
        /// Invalid quorum field.
        field: &'static str,
        /// Quorum found in the policy or caller requirement.
        found: u16,
    },
    /// Trusted runner signer inventory is empty or too large.
    #[error("moderation trust policy has {found} runner signers; expected 1..={maximum}")]
    InvalidSignerCount {
        /// Number of declared runner signers.
        found: usize,
        /// Maximum admitted runner signers.
        maximum: usize,
    },
    /// Governance signature inventory is empty or too large.
    #[error("moderation trust policy has {found} signatures; expected 1..={maximum}")]
    InvalidSignatureCount {
        /// Number of policy signatures.
        found: usize,
        /// Maximum admitted policy signatures.
        maximum: usize,
    },
    /// A policy text field is non-canonical.
    #[error("moderation trust-policy text field `{field}` is invalid")]
    InvalidText {
        /// Invalid text field.
        field: &'static str,
    },
    /// Signer or governance-signature keys are not strictly ordered.
    #[error("moderation trust-policy key inventory `{field}` is not strictly ordered")]
    NonCanonicalKeyOrder {
        /// Non-canonical key inventory.
        field: &'static str,
    },
    /// A policy signature is malformed or invalid.
    #[error("moderation trust-policy signature for role `{role}` is invalid: {source}")]
    BadSignature {
        /// Role label attached to the invalid signature.
        role: String,
        /// Signature validation failure.
        #[source]
        source: iroha_crypto::Error,
    },
    /// Signed governance quorum is weaker than the external requirement.
    #[error(
        "moderation trust-policy governance quorum {policy} is below external minimum {minimum}"
    )]
    GovernanceQuorumDowngrade {
        /// Quorum declared by the signed policy.
        policy: u16,
        /// Externally configured minimum quorum.
        minimum: u16,
    },
    /// Too few signatures came from externally trusted governance anchors.
    #[error(
        "moderation trust policy has {found} trusted governance signatures; requires {required}"
    )]
    InsufficientTrustedGovernance {
        /// Number of externally trusted signatures found.
        found: u16,
        /// Number of externally trusted signatures required.
        required: u16,
    },
}
/// Signed screening-result validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModerationSignedResultError {
    /// Schema version is unsupported.
    #[error("unsupported signed moderation result version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Required schema version.
        expected: u16,
        /// Version found in the result.
        found: u16,
    },
    /// Result does not bind the loaded manifest or trust policy.
    #[error("signed moderation result binding `{field}` does not match")]
    BindingMismatch {
        /// Mismatched binding field.
        field: &'static str,
    },
    /// A required result digest is zero.
    #[error("signed moderation result digest `{field}` must be non-zero")]
    MissingDigest {
        /// Missing digest field.
        field: &'static str,
    },
    /// Result body could not be canonically encoded.
    #[error("failed to encode signed moderation result: {0}")]
    Encoding(
        /// Encoding failure.
        String,
    ),
    /// Result evidence digest is not canonically derived.
    #[error("signed moderation result evidence digest mismatch")]
    EvidenceDigestMismatch,
    /// Subject or notes text is non-canonical.
    #[error("signed moderation result text field `{field}` is invalid")]
    InvalidText {
        /// Invalid text field.
        field: &'static str,
    },
    /// Result timestamp or lifetime is invalid.
    #[error("signed moderation result time field `{field}` is invalid")]
    InvalidTime {
        /// Invalid timestamp or lifetime field.
        field: &'static str,
    },
    /// Result is too old, expired, or too far in the future.
    #[error("signed moderation result freshness check failed: {reason}")]
    Freshness {
        /// Freshness rejection reason.
        reason: &'static str,
    },
    /// Per-model score inventory does not match the manifest.
    #[error("signed moderation result model score mismatch at index {index}: {field}")]
    ModelScoreMismatch {
        /// Model-score index.
        index: usize,
        /// Mismatched score field.
        field: &'static str,
    },
    /// Aggregate score does not match manifest-weighted per-model scores.
    #[error("signed moderation result combined score is not derived from model scores")]
    CombinedScoreMismatch,
    /// Verdict does not match manifest thresholds.
    #[error("signed moderation result verdict `{found}` does not match `{expected}`")]
    VerdictMismatch {
        /// Verdict found in the signed result.
        found: String,
        /// Verdict derived from the aggregate score.
        expected: &'static str,
    },
    /// Result signer is absent, outside its validity window, or revoked.
    #[error("signed moderation result signer is not authorized: {reason}")]
    UnauthorizedSigner {
        /// Authorization rejection reason.
        reason: &'static str,
    },
    /// Runner result signature is malformed or invalid.
    #[error("signed moderation result signature is invalid: {0}")]
    BadSignature(
        /// Signature validation failure.
        #[source]
        iroha_crypto::Error,
    ),
}
/// Authenticated committee aggregation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModerationCommitteeAggregateError {
    /// External trust-policy validation failed.
    #[error("moderation trust-policy validation failed: {0}")]
    InvalidTrustPolicy(
        /// Trust-policy failure.
        #[from]
        ModerationTrustPolicyError,
    ),
    /// A runner result failed authenticated validation.
    #[error("moderation result at index {index} is invalid: {source}")]
    InvalidResult {
        /// Input result index.
        index: usize,
        /// Signed-result failure.
        #[source]
        source: ModerationSignedResultError,
    },
    /// Result inventory is empty or exceeds its hard bound.
    #[error("moderation committee has {found} results; expected 1..={maximum}")]
    InvalidResultCount {
        /// Number of supplied results.
        found: usize,
        /// Hard result-count maximum.
        maximum: usize,
    },
    /// Distinct authenticated signers do not satisfy policy quorum.
    #[error("moderation committee has {found} distinct signers; requires {required}")]
    QuorumNotSatisfied {
        /// Distinct authenticated signer count.
        found: usize,
        /// Signed policy quorum.
        required: u16,
    },
    /// The same signer key appears more than once.
    #[error("moderation committee includes duplicate signer key at input index {index}")]
    DuplicateSigner {
        /// Input index carrying the duplicate key.
        index: usize,
    },
    /// Authenticated results do not describe one subject and payload.
    #[error("moderation committee result at index {index} differs in `{field}`")]
    SubjectMismatch {
        /// Input result index.
        index: usize,
        /// Mismatched subject field.
        field: &'static str,
    },
    /// Aggregate timestamp is invalid.
    #[error("moderation committee aggregate timestamp is invalid: {reason}")]
    InvalidTime {
        /// Timestamp rejection reason.
        reason: &'static str,
    },
    /// Checked committee score arithmetic failed.
    #[error("moderation committee score arithmetic overflowed")]
    ArithmeticOverflow,
    /// A bounded committee allocation failed.
    #[error("moderation committee bounded allocation failed")]
    ResourceExhausted,
    /// Aggregate canonical encoding failed.
    #[error("failed to encode moderation committee aggregate: {0}")]
    Encoding(
        /// Encoding failure.
        String,
    ),
}
/// Hash-chained provenance validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModerationProvenanceError {
    /// Provenance segment schema version is unsupported.
    #[error("unsupported moderation provenance version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Required schema version.
        expected: u16,
        /// Version found in the segment.
        found: u16,
    },
    /// Provenance segment identifier is zero.
    #[error("moderation provenance log id must be non-zero")]
    MissingLogId,
    /// Provenance segment exceeds its entry bound.
    #[error("moderation provenance has {found} entries; maximum is {maximum}")]
    TooManyEntries {
        /// Number of entries found.
        found: usize,
        /// Maximum entries admitted.
        maximum: usize,
    },
    /// Entry sequence does not match its position.
    #[error("moderation provenance sequence at index {index} is {found}; expected {expected}")]
    SequenceMismatch {
        /// Entry index.
        index: usize,
        /// Expected sequence number.
        expected: u64,
        /// Sequence number found.
        found: u64,
    },
    /// Entry timestamp is zero or decreases.
    #[error("moderation provenance timestamp at index {index} is invalid")]
    InvalidTimestamp {
        /// Entry index.
        index: usize,
    },
    /// Entry predecessor link is invalid.
    #[error("moderation provenance predecessor digest at index {index} is invalid")]
    PreviousDigestMismatch {
        /// Entry index.
        index: usize,
    },
    /// Entry digest is not canonically derived.
    #[error("moderation provenance entry digest at index {index} is invalid")]
    EntryDigestMismatch {
        /// Entry index.
        index: usize,
    },
    /// Embedded evidence digest is not canonically derived.
    #[error("moderation provenance payload digest at index {index} is invalid")]
    PayloadDigestMismatch {
        /// Entry index.
        index: usize,
    },
    /// Segment head does not match its final entry.
    #[error("moderation provenance head digest is invalid")]
    HeadDigestMismatch,
    /// Canonical encoding failed.
    #[error("failed to encode moderation provenance entry: {0}")]
    Encoding(
        /// Encoding failure.
        String,
    ),
}
impl ModerationTrustPolicyBodyV1 {
    /// Compute the domain-separated policy digest with the digest slot zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical policy body cannot be encoded.
    pub fn computed_policy_digest(&self) -> Result<[u8; 32], norito::Error> {
        let mut body = self.clone();
        body.policy_digest = [0; 32];
        let encoded = norito::encode_canonical(&body)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_TRUST_POLICY_DIGEST_DOMAIN_V1);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
    /// Refresh the canonical policy digest in place.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical policy body cannot be encoded.
    pub fn refresh_policy_digest(&mut self) -> Result<(), norito::Error> {
        self.policy_digest = self.computed_policy_digest()?;
        Ok(())
    }
}
impl ModerationSignedScreeningBodyV1 {
    /// Compute the domain-separated evidence digest with its slot zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical evidence body cannot be encoded.
    pub fn computed_evidence_digest(&self) -> Result<[u8; 32], norito::Error> {
        let mut body = self.clone();
        body.evidence_digest = [0; 32];
        let encoded = norito::encode_canonical(&body)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_SIGNED_RESULT_DIGEST_DOMAIN_V1);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
    /// Refresh the canonical evidence digest in place.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical evidence body cannot be encoded.
    pub fn refresh_evidence_digest(&mut self) -> Result<(), norito::Error> {
        self.evidence_digest = self.computed_evidence_digest()?;
        Ok(())
    }
}
impl ModerationReproBodyV1 {
    /// Compute the deterministic screening-policy digest consumed by signed runner results.
    ///
    /// This digest deliberately covers the complete canonical reproducibility
    /// body, including thresholds and model weights, so a committee cannot
    /// accept a score produced under a silently different policy surface.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical reproducibility body cannot be encoded.
    pub fn computed_screening_policy_digest(&self) -> Result<[u8; 32], norito::Error> {
        let encoded = norito::encode_canonical(self)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_SCREENING_POLICY_DIGEST_DOMAIN_V1);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
}
impl ModerationCommitteeAggregateV1 {
    /// Build a deterministic aggregate from externally authorized, distinct,
    /// fresh runner signatures.
    ///
    /// Policy authentication is intentionally part of this constructor. A caller cannot obtain an
    /// aggregate by validating only policy-internal signatures or by supplying a weaker quorum than
    /// the external trust configuration requires.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationCommitteeAggregateError`] when policy authentication,
    /// result validation, quorum, ordering, time, or aggregate encoding fails.
    pub fn aggregate_authenticated(
        manifest: &ModerationReproManifestV1,
        policy: &ModerationTrustPolicyV1,
        trust_anchors: &BTreeSet<PublicKey>,
        minimum_governance_quorum: u16,
        results: &[ModerationSignedScreeningResultV1],
        now_unix: u64,
    ) -> Result<Self, ModerationCommitteeAggregateError> {
        policy.validate_with_trust_anchors(
            manifest,
            trust_anchors,
            minimum_governance_quorum,
            now_unix,
        )?;
        if now_unix == 0 {
            return Err(ModerationCommitteeAggregateError::InvalidTime {
                reason: "aggregated_at_unix must be non-zero",
            });
        }
        if results.is_empty() || results.len() > MODERATION_COMMITTEE_MAX_RESULTS_V1 {
            return Err(ModerationCommitteeAggregateError::InvalidResultCount {
                found: results.len(),
                maximum: MODERATION_COMMITTEE_MAX_RESULTS_V1,
            });
        }
        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(results.len())
            .map_err(|_| ModerationCommitteeAggregateError::ResourceExhausted)?;
        for (index, result) in results.iter().enumerate() {
            result
                .validate(manifest, policy, now_unix)
                .map_err(|source| ModerationCommitteeAggregateError::InvalidResult {
                    index,
                    source,
                })?;
            ordered.push((index, result));
        }
        ordered.sort_by(|left, right| {
            left.1
                .signer_public_key
                .cmp(&right.1.signer_public_key)
                .then_with(|| left.0.cmp(&right.0))
        });
        for pair in ordered.windows(2) {
            if pair[0].1.signer_public_key == pair[1].1.signer_public_key {
                return Err(ModerationCommitteeAggregateError::DuplicateSigner {
                    index: pair[1].0,
                });
            }
        }
        if ordered.len() < usize::from(policy.body.result_quorum) {
            return Err(ModerationCommitteeAggregateError::QuorumNotSatisfied {
                found: ordered.len(),
                required: policy.body.result_quorum,
            });
        }
        let first_subject = ordered[0].1.body.subject.clone();
        let first_subject_digest = ordered[0].1.body.subject_digest;
        let mut members = Vec::new();
        members
            .try_reserve_exact(ordered.len())
            .map_err(|_| ModerationCommitteeAggregateError::ResourceExhausted)?;
        let mut scores = Vec::new();
        scores
            .try_reserve_exact(ordered.len())
            .map_err(|_| ModerationCommitteeAggregateError::ResourceExhausted)?;
        let mut expires_at_unix = u64::MAX;
        for (index, result) in ordered {
            if result.body.subject != first_subject {
                return Err(ModerationCommitteeAggregateError::SubjectMismatch {
                    index,
                    field: "subject",
                });
            }
            if result.body.subject_digest != first_subject_digest {
                return Err(ModerationCommitteeAggregateError::SubjectMismatch {
                    index,
                    field: "subject_digest",
                });
            }
            expires_at_unix = expires_at_unix.min(result.body.expires_at_unix);
            scores.push(result.body.combined_score_bps);
            members.push(ModerationCommitteeMemberV1 {
                signer_public_key: result.signer_public_key.clone(),
                evidence_digest: result.body.evidence_digest,
                combined_score_bps: result.body.combined_score_bps,
                verdict: result.body.verdict.clone(),
                screened_at_unix: result.body.screened_at_unix,
                expires_at_unix: result.body.expires_at_unix,
            });
        }
        if now_unix >= expires_at_unix {
            return Err(ModerationCommitteeAggregateError::InvalidTime {
                reason: "member result expires at or before aggregation",
            });
        }
        scores.sort_unstable();
        let midpoint = scores.len() / 2;
        let aggregated_score_bps = if scores.len() % 2 == 1 {
            scores[midpoint]
        } else {
            let pair_sum = u32::from(scores[midpoint - 1])
                .checked_add(u32::from(scores[midpoint]))
                .ok_or(ModerationCommitteeAggregateError::ArithmeticOverflow)?;
            u16::try_from(pair_sum.div_ceil(2))
                .map_err(|_| ModerationCommitteeAggregateError::ArithmeticOverflow)?
        };
        let verdict = moderation_verdict_v1(aggregated_score_bps, manifest.body.thresholds);
        let mut aggregate = Self {
            schema_version: MODERATION_COMMITTEE_AGGREGATE_VERSION_V1,
            manifest_id: manifest.body.manifest_id,
            manifest_digest: manifest.body.manifest_digest,
            trust_policy_id: policy.body.policy_id,
            trust_policy_digest: policy.body.policy_digest,
            subject: first_subject,
            subject_digest: first_subject_digest,
            members,
            quorum: policy.body.result_quorum,
            aggregated_score_bps,
            verdict: verdict.to_string(),
            aggregated_at_unix: now_unix,
            expires_at_unix,
            aggregate_digest: [0; 32],
        };
        aggregate
            .refresh_aggregate_digest()
            .map_err(|error| ModerationCommitteeAggregateError::Encoding(error.to_string()))?;
        Ok(aggregate)
    }
    /// Compute the domain-separated aggregate digest with its slot zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical aggregate cannot be encoded.
    pub fn computed_aggregate_digest(&self) -> Result<[u8; 32], norito::Error> {
        let mut aggregate = self.clone();
        aggregate.aggregate_digest = [0; 32];
        let encoded = norito::encode_canonical(&aggregate)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_COMMITTEE_AGGREGATE_DIGEST_DOMAIN_V1);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
    /// Refresh the canonical aggregate digest in place.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical aggregate cannot be encoded.
    pub fn refresh_aggregate_digest(&mut self) -> Result<(), norito::Error> {
        self.aggregate_digest = self.computed_aggregate_digest()?;
        Ok(())
    }
}
impl ModerationProvenanceEntryV1 {
    /// Compute the domain-separated entry digest with its slot zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical provenance entry cannot be encoded.
    pub fn computed_entry_digest(&self) -> Result<[u8; 32], norito::Error> {
        let mut entry = self.clone();
        entry.entry_digest = [0; 32];
        let encoded = norito::encode_canonical(&entry)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MODERATION_PROVENANCE_ENTRY_DIGEST_DOMAIN_V1);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
    /// Refresh the canonical entry digest in place.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] when the canonical provenance entry cannot be encoded.
    pub fn refresh_entry_digest(&mut self) -> Result<(), norito::Error> {
        self.entry_digest = self.computed_entry_digest()?;
        Ok(())
    }
}
impl ModerationProvenanceLogV1 {
    /// Create an empty provenance segment with a non-zero operator identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationProvenanceError::MissingLogId`] when `log_id` is zero.
    pub fn new(log_id: [u8; 16]) -> Result<Self, ModerationProvenanceError> {
        if log_id == [0; 16] {
            return Err(ModerationProvenanceError::MissingLogId);
        }
        Ok(Self {
            schema_version: MODERATION_PROVENANCE_LOG_VERSION_V1,
            log_id,
            head_digest: [0; 32],
            entries: Vec::new(),
        })
    }
    /// Append one complete evidence payload after validating the existing
    /// chain. The durable store remains responsible for validating the payload
    /// against the active manifest and trust policy before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationProvenanceError`] when the existing chain, capacity,
    /// timestamp ordering, sequence, or new entry encoding is invalid.
    pub fn append(
        &mut self,
        payload: ModerationProvenancePayloadV1,
        recorded_at_unix: u64,
    ) -> Result<[u8; 32], ModerationProvenanceError> {
        self.validate_chain()?;
        if self.entries.len() >= MODERATION_PROVENANCE_MAX_ENTRIES_V1 {
            return Err(ModerationProvenanceError::TooManyEntries {
                found: self.entries.len().saturating_add(1),
                maximum: MODERATION_PROVENANCE_MAX_ENTRIES_V1,
            });
        }
        let source_timestamp = match &payload {
            ModerationProvenancePayloadV1::SignedScreeningResult(result) => {
                result.body.screened_at_unix
            }
            ModerationProvenancePayloadV1::CommitteeAggregate(aggregate) => {
                aggregate.aggregated_at_unix
            }
        };
        if recorded_at_unix == 0
            || recorded_at_unix < source_timestamp
            || self
                .entries
                .last()
                .is_some_and(|entry| recorded_at_unix < entry.recorded_at_unix)
        {
            return Err(ModerationProvenanceError::InvalidTimestamp {
                index: self.entries.len(),
            });
        }
        let sequence = u64::try_from(self.entries.len()).map_err(|_| {
            ModerationProvenanceError::TooManyEntries {
                found: self.entries.len(),
                maximum: MODERATION_PROVENANCE_MAX_ENTRIES_V1,
            }
        })?;
        let mut entry = ModerationProvenanceEntryV1 {
            sequence,
            previous_entry_digest: self.head_digest,
            entry_digest: [0; 32],
            recorded_at_unix,
            payload,
        };
        entry
            .refresh_entry_digest()
            .map_err(|error| ModerationProvenanceError::Encoding(error.to_string()))?;
        self.head_digest = entry.entry_digest;
        self.entries.push(entry);
        Ok(self.head_digest)
    }
    /// Validate schema, bounds, ordering, timestamps, every hash-chain link,
    /// every entry digest, and the advertised head digest.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationProvenanceError`] when any log identity, bound,
    /// timestamp, sequence, digest, or hash-chain invariant is invalid.
    pub fn validate_chain(&self) -> Result<(), ModerationProvenanceError> {
        if self.schema_version != MODERATION_PROVENANCE_LOG_VERSION_V1 {
            return Err(ModerationProvenanceError::UnsupportedVersion {
                expected: MODERATION_PROVENANCE_LOG_VERSION_V1,
                found: self.schema_version,
            });
        }
        if self.log_id == [0; 16] {
            return Err(ModerationProvenanceError::MissingLogId);
        }
        if self.entries.len() > MODERATION_PROVENANCE_MAX_ENTRIES_V1 {
            return Err(ModerationProvenanceError::TooManyEntries {
                found: self.entries.len(),
                maximum: MODERATION_PROVENANCE_MAX_ENTRIES_V1,
            });
        }
        let mut previous_digest = [0; 32];
        let mut previous_timestamp = 0_u64;
        for (index, entry) in self.entries.iter().enumerate() {
            let expected_sequence =
                u64::try_from(index).map_err(|_| ModerationProvenanceError::TooManyEntries {
                    found: self.entries.len(),
                    maximum: MODERATION_PROVENANCE_MAX_ENTRIES_V1,
                })?;
            if entry.sequence != expected_sequence {
                return Err(ModerationProvenanceError::SequenceMismatch {
                    index,
                    expected: expected_sequence,
                    found: entry.sequence,
                });
            }
            let source_timestamp = match &entry.payload {
                ModerationProvenancePayloadV1::SignedScreeningResult(result) => {
                    if result.body.schema_version != MODERATION_SIGNED_RESULT_VERSION_V1
                        || result.body.evidence_digest == [0; 32]
                        || result.body.computed_evidence_digest().map_err(|error| {
                            ModerationProvenanceError::Encoding(error.to_string())
                        })? != result.body.evidence_digest
                    {
                        return Err(ModerationProvenanceError::PayloadDigestMismatch { index });
                    }
                    result.body.screened_at_unix
                }
                ModerationProvenancePayloadV1::CommitteeAggregate(aggregate) => {
                    if aggregate.schema_version != MODERATION_COMMITTEE_AGGREGATE_VERSION_V1
                        || aggregate.aggregate_digest == [0; 32]
                        || aggregate.computed_aggregate_digest().map_err(|error| {
                            ModerationProvenanceError::Encoding(error.to_string())
                        })? != aggregate.aggregate_digest
                    {
                        return Err(ModerationProvenanceError::PayloadDigestMismatch { index });
                    }
                    aggregate.aggregated_at_unix
                }
            };
            if entry.recorded_at_unix == 0
                || entry.recorded_at_unix < previous_timestamp
                || entry.recorded_at_unix < source_timestamp
            {
                return Err(ModerationProvenanceError::InvalidTimestamp { index });
            }
            if entry.previous_entry_digest != previous_digest {
                return Err(ModerationProvenanceError::PreviousDigestMismatch { index });
            }
            let computed = entry
                .computed_entry_digest()
                .map_err(|error| ModerationProvenanceError::Encoding(error.to_string()))?;
            if computed != entry.entry_digest {
                return Err(ModerationProvenanceError::EntryDigestMismatch { index });
            }
            previous_digest = entry.entry_digest;
            previous_timestamp = entry.recorded_at_unix;
        }
        if self.head_digest != previous_digest {
            return Err(ModerationProvenanceError::HeadDigestMismatch);
        }
        Ok(())
    }
}
fn moderation_verdict_v1(score_bps: u16, thresholds: ModerationThresholdsV1) -> &'static str {
    if score_bps >= thresholds.escalate {
        "escalate"
    } else if score_bps >= thresholds.quarantine {
        "quarantine"
    } else {
        "pass"
    }
}
/// `SoraFS` moderation-panel vote choices.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "choice", content = "value", rename_all = "kebab-case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::SoraFsModerationVoteChoice")]
pub enum SoraFsModerationVoteChoice {
    /// Keep the original moderation action.
    Uphold,
    /// Reverse the original moderation action.
    Overturn,
    /// Change the moderation action without fully reversing it.
    Modify,
    /// Escalate the case for another review path.
    Escalate,
}
impl SoraFsModerationVoteChoice {
    fn discriminant(self) -> u8 {
        match self {
            Self::Uphold => 1,
            Self::Overturn => 2,
            Self::Modify => 3,
            Self::Escalate => 4,
        }
    }
}
/// Immutable case scope that every moderation commit/reveal payload must bind.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::SoraFsModerationBallotContextV1")]
pub struct SoraFsModerationBallotContextV1 {
    /// Schema version; must equal [`SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1`].
    pub version: u16,
    /// Moderation or appeal case identifier.
    pub case_id: String,
    /// Digest of the evidence bundle reviewed by the panel.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub evidence_bundle_digest: [u8; 32],
    /// Appeal pricing/settlement config version used for this case.
    pub appeal_finance_config_version: String,
    /// Digest of the selected panel roster and failover policy.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub panel_roster_hash: [u8; 32],
    /// Moderation policy reference reviewed by the panel.
    pub policy_reference: String,
    /// Optional transparency or governance DAG reference for the evidence bundle.
    #[norito(default)]
    pub evidence_uri: Option<String>,
}
impl SoraFsModerationBallotContextV1 {
    /// Validate structural fields that bind a moderation ballot to one case scope.
    ///
    /// # Errors
    ///
    /// Returns [`SoraFsModerationBallotError`] when the context has an unsupported
    /// version or misses required case, evidence, finance, roster, or policy data.
    pub fn validate(&self) -> Result<(), SoraFsModerationBallotError> {
        if self.version != SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1 {
            return Err(SoraFsModerationBallotError::UnsupportedContextVersion {
                expected: SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1,
                found: self.version,
            });
        }
        if self.case_id.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingCaseId);
        }
        if is_zero_digest(&self.evidence_bundle_digest) {
            return Err(SoraFsModerationBallotError::MissingEvidenceBundleDigest);
        }
        if self.appeal_finance_config_version.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingAppealFinanceConfigVersion);
        }
        if is_zero_digest(&self.panel_roster_hash) {
            return Err(SoraFsModerationBallotError::MissingPanelRosterHash);
        }
        if self.policy_reference.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingPolicyReference);
        }
        Ok(())
    }
    fn update_hash(&self, hasher: &mut Blake2b256) {
        hasher.update(self.version.to_le_bytes());
        update_hash_string(hasher, &self.case_id);
        hasher.update(self.evidence_bundle_digest);
        update_hash_string(hasher, &self.appeal_finance_config_version);
        hasher.update(self.panel_roster_hash);
        update_hash_string(hasher, &self.policy_reference);
        match self.evidence_uri.as_deref() {
            Some(uri) => {
                hasher.update([1u8]);
                update_hash_string(hasher, uri);
            }
            None => hasher.update([0u8]),
        }
    }
}
/// Juror commitment for a `SoraFS` moderation case.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::SoraFsModerationBallotCommitV1")]
pub struct SoraFsModerationBallotCommitV1 {
    /// Schema version; must equal [`SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1`].
    pub version: u16,
    /// Case scope this commitment is bound to.
    pub context: SoraFsModerationBallotContextV1,
    /// Moderation ballot round identifier.
    pub round_id: String,
    /// Stable juror identifier or pseudonym.
    pub juror_id: String,
    /// Blake2b commitment over context, round, juror, choice, and nonce.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub commitment_blake2b_256: [u8; 32],
    /// UTC timestamp (milliseconds) when the commitment was recorded.
    pub committed_at_unix_ms: u64,
}
impl SoraFsModerationBallotCommitV1 {
    /// Validate this commitment and the supplied reveal against the shared `SoraFS` case context.
    ///
    /// # Errors
    ///
    /// Returns [`SoraFsModerationBallotError`] when either payload is malformed,
    /// references a different case context, or the reveal does not match the commitment.
    pub fn verify_reveal(
        &self,
        reveal: &SoraFsModerationBallotRevealV1,
    ) -> Result<(), SoraFsModerationBallotError> {
        self.validate()?;
        reveal.validate()?;
        if self.context != reveal.context {
            return Err(SoraFsModerationBallotError::ContextMismatch);
        }
        if self.round_id != reveal.round_id {
            return Err(SoraFsModerationBallotError::RoundMismatch {
                commit: self.round_id.clone(),
                reveal: reveal.round_id.clone(),
            });
        }
        if self.juror_id != reveal.juror_id {
            return Err(SoraFsModerationBallotError::JurorMismatch {
                commit: self.juror_id.clone(),
                reveal: reveal.juror_id.clone(),
            });
        }
        if self.commitment_blake2b_256 != reveal.compute_commitment() {
            return Err(SoraFsModerationBallotError::CommitmentMismatch);
        }
        Ok(())
    }
    /// Validate this commitment without requiring a reveal.
    ///
    /// # Errors
    ///
    /// Returns [`SoraFsModerationBallotError`] when the commitment has an
    /// unsupported version, malformed context, blank round id, or blank juror id.
    pub fn validate(&self) -> Result<(), SoraFsModerationBallotError> {
        if self.version != SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1 {
            return Err(SoraFsModerationBallotError::UnsupportedCommitVersion {
                expected: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
                found: self.version,
            });
        }
        self.context.validate()?;
        if self.round_id.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingRoundId);
        }
        if self.juror_id.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingJurorId);
        }
        Ok(())
    }
}
/// Juror reveal for a `SoraFS` moderation case.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::SoraFsModerationBallotRevealV1")]
pub struct SoraFsModerationBallotRevealV1 {
    /// Schema version; must equal [`SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1`].
    pub version: u16,
    /// Case scope this reveal is bound to.
    pub context: SoraFsModerationBallotContextV1,
    /// Moderation ballot round identifier.
    pub round_id: String,
    /// Stable juror identifier or pseudonym.
    pub juror_id: String,
    /// Moderation outcome selected by the juror.
    pub choice: SoraFsModerationVoteChoice,
    /// Random nonce used when generating the commitment.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub nonce: Vec<u8>,
    /// UTC timestamp (milliseconds) when the reveal was recorded.
    pub revealed_at_unix_ms: u64,
}
impl SoraFsModerationBallotRevealV1 {
    /// Compute the canonical commitment digest for this reveal.
    #[must_use]
    pub fn compute_commitment(&self) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(MODERATION_BALLOT_COMMITMENT_DOMAIN_V1);
        self.context.update_hash(&mut hasher);
        update_hash_string(&mut hasher, &self.round_id);
        update_hash_string(&mut hasher, &self.juror_id);
        hasher.update([self.choice.discriminant()]);
        hasher.update((self.nonce.len() as u64).to_le_bytes());
        hasher.update(&self.nonce);
        hasher.finalize().into()
    }
    /// Validate this reveal without requiring a stored commitment.
    ///
    /// # Errors
    ///
    /// Returns [`SoraFsModerationBallotError`] when the reveal has an unsupported
    /// version, malformed context, blank round or juror id, or a short nonce.
    pub fn validate(&self) -> Result<(), SoraFsModerationBallotError> {
        if self.version != SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1 {
            return Err(SoraFsModerationBallotError::UnsupportedRevealVersion {
                expected: SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1,
                found: self.version,
            });
        }
        self.context.validate()?;
        if self.round_id.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingRoundId);
        }
        if self.juror_id.trim().is_empty() {
            return Err(SoraFsModerationBallotError::MissingJurorId);
        }
        if self.nonce.len() < 16 {
            return Err(SoraFsModerationBallotError::NonceTooShort {
                length: self.nonce.len(),
            });
        }
        Ok(())
    }
}
/// Errors surfaced while validating `SoraFS` moderation ballots.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SoraFsModerationBallotError {
    /// Context version mismatch.
    #[error("unsupported SoraFS moderation ballot context version `{found}` (expected {expected})")]
    UnsupportedContextVersion {
        /// Version expected by the verifier.
        expected: u16,
        /// Version observed in the payload.
        found: u16,
    },
    /// Commitment version mismatch.
    #[error("unsupported SoraFS moderation ballot commit version `{found}` (expected {expected})")]
    UnsupportedCommitVersion {
        /// Version expected by the verifier.
        expected: u16,
        /// Version observed in the payload.
        found: u16,
    },
    /// Reveal version mismatch.
    #[error("unsupported SoraFS moderation ballot reveal version `{found}` (expected {expected})")]
    UnsupportedRevealVersion {
        /// Version expected by the verifier.
        expected: u16,
        /// Version observed in the payload.
        found: u16,
    },
    /// Missing moderation case identifier.
    #[error("SoraFS moderation ballot case id is required")]
    MissingCaseId,
    /// Missing evidence bundle digest.
    #[error("SoraFS moderation ballot evidence bundle digest must be nonzero")]
    MissingEvidenceBundleDigest,
    /// Missing appeal finance configuration version.
    #[error("SoraFS moderation ballot appeal finance config version is required")]
    MissingAppealFinanceConfigVersion,
    /// Missing panel roster hash.
    #[error("SoraFS moderation ballot panel roster hash must be nonzero")]
    MissingPanelRosterHash,
    /// Missing moderation policy reference.
    #[error("SoraFS moderation ballot policy reference is required")]
    MissingPolicyReference,
    /// Missing ballot round identifier.
    #[error("SoraFS moderation ballot round id is required")]
    MissingRoundId,
    /// Missing juror identifier.
    #[error("SoraFS moderation ballot juror id is required")]
    MissingJurorId,
    /// Reveal nonce too short for a secure commitment.
    #[error("SoraFS moderation ballot reveal nonce must be >=16 bytes (found {length})")]
    NonceTooShort {
        /// Nonce length observed in the reveal.
        length: usize,
    },
    /// Commit and reveal are not bound to the same context.
    #[error("SoraFS moderation ballot context mismatch")]
    ContextMismatch,
    /// Reveal references a different round identifier.
    #[error("SoraFS moderation ballot round mismatch: commit `{commit}`, reveal `{reveal}`")]
    RoundMismatch {
        /// Round identifier stored in the commit.
        commit: String,
        /// Round identifier supplied by the reveal.
        reveal: String,
    },
    /// Reveal references a different juror identifier.
    #[error("SoraFS moderation ballot juror mismatch: commit `{commit}`, reveal `{reveal}`")]
    JurorMismatch {
        /// Juror identifier stored in the commit.
        commit: String,
        /// Juror identifier supplied by the reveal.
        reveal: String,
    },
    /// Revealed payload does not match the stored commitment.
    #[error("SoraFS moderation ballot commitment mismatch")]
    CommitmentMismatch,
}
fn update_hash_string(hasher: &mut Blake2b256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}
fn is_zero_digest(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}
/// Schema version for [`AdversarialCorpusManifestV1`].
pub const ADVERSARIAL_CORPUS_VERSION_V1: u16 = 1;
/// Governance-signed registry describing adversarial corpus families.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::AdversarialCorpusManifestV1")]
pub struct AdversarialCorpusManifestV1 {
    /// Schema version; must equal [`ADVERSARIAL_CORPUS_VERSION_V1`].
    pub schema_version: u16,
    /// Unix timestamp (seconds) when the manifest was assembled.
    pub issued_at_unix: u64,
    /// Identifier describing the calibration window (e.g., `2026-Q1`).
    #[norito(default)]
    pub cohort_label: Option<String>,
    /// Families included in this corpus release.
    #[norito(default)]
    pub families: Vec<AdversarialPerceptualFamilyV1>,
}
/// Perceptual hash/embedding family describing one moderated cluster.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::AdversarialPerceptualFamilyV1")]
pub struct AdversarialPerceptualFamilyV1 {
    /// Deterministic family identifier (UUID).
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub family_id: [u8; 16],
    /// Free-form description for operator tooling.
    pub description: String,
    /// Variants that belong to this family.
    #[norito(default)]
    pub variants: Vec<AdversarialPerceptualVariantV1>,
}
/// Entry describing a single adversarial variant and its fingerprints.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::moderation::AdversarialPerceptualVariantV1")]
pub struct AdversarialPerceptualVariantV1 {
    /// Variant identifier (UUID).
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub variant_id: [u8; 16],
    /// Attack vector description (`jpeg_jitter`, `mosaic`, `zip_bomb`, …).
    pub attack_vector: String,
    /// Optional reference CID (base64) for operator previews.
    #[norito(default)]
    pub reference_cid_b64: Option<String>,
    /// Optional canonical perceptual hash (BLAKE3-domain separated, 256-bit).
    #[norito(json = "crate::sorafs::moderation::json_option_digest32")]
    #[norito(default)]
    pub perceptual_hash: Option<[u8; 32]>,
    /// Maximum Hamming distance tolerated for perceptual hash matches.
    #[norito(default)]
    pub hamming_radius: u8,
    /// Optional embedding digest (BLAKE3 of quantised embedding vector).
    #[norito(json = "crate::sorafs::moderation::json_option_digest32")]
    #[norito(default)]
    pub embedding_digest: Option<[u8; 32]>,
    /// Optional free-form notes captured during benchmarking.
    #[norito(default)]
    pub notes: Option<String>,
}
/// Validation errors surfaced when checking adversarial corpus manifests.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AdversarialCorpusValidationError {
    /// Manifest uses an unsupported schema version.
    #[error("unsupported adversarial corpus schema version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Expected schema version.
        expected: u16,
        /// Schema version discovered in the manifest.
        found: u16,
    },
    /// Manifest contains no families.
    #[error("adversarial corpus manifest lists no families")]
    MissingFamilies,
    /// Family contains no variants.
    #[error("adversarial corpus manifest lists no variants for family {family_id:?}")]
    MissingVariants {
        /// Identifier of the empty family.
        family_id: [u8; 16],
    },
    /// Manifest repeats a perceptual family identifier.
    #[error("adversarial corpus manifest repeats family id {family_id:?}")]
    DuplicateFamilyId {
        /// Repeated family identifier.
        family_id: [u8; 16],
    },
    /// Manifest repeats a perceptual variant identifier.
    #[error("adversarial corpus manifest repeats variant id {variant_id:?}")]
    DuplicateVariantId {
        /// Repeated variant identifier.
        variant_id: [u8; 16],
    },
    /// Manifest repeats a perceptual hash fingerprint.
    #[error("adversarial corpus manifest repeats perceptual hash for variant {variant_id:?}")]
    DuplicatePerceptualHash {
        /// Identifier of the variant carrying the repeated perceptual hash.
        variant_id: [u8; 16],
    },
    /// Manifest repeats an embedding digest fingerprint.
    #[error("adversarial corpus manifest repeats embedding digest for variant {variant_id:?}")]
    DuplicateEmbeddingDigest {
        /// Identifier of the variant carrying the repeated embedding digest.
        variant_id: [u8; 16],
    },
    /// Variant lacks perceptual hash and embedding fingerprints.
    #[error("variant {variant_id:?} must include a perceptual hash or embedding digest")]
    MissingMatchBasis {
        /// Identifier of the variant missing match information.
        variant_id: [u8; 16],
    },
    /// Declared Hamming radius exceeds the permitted bound.
    #[error("variant {variant_id:?} sets hamming radius {radius} above the 32-bit limit")]
    InvalidHammingRadius {
        /// Identifier of the variant with excessive radius.
        variant_id: [u8; 16],
        /// Radius declared in the manifest.
        radius: u8,
    },
}
impl AdversarialCorpusManifestV1 {
    /// Validate manifest consistency before distributing it to gateways.
    ///
    /// # Errors
    ///
    /// Returns [`AdversarialCorpusValidationError`] when the schema version mismatches,
    /// family/variant identifiers are missing or duplicated, or fingerprint metadata is incomplete.
    pub fn validate(&self) -> Result<(), AdversarialCorpusValidationError> {
        if self.schema_version != ADVERSARIAL_CORPUS_VERSION_V1 {
            return Err(AdversarialCorpusValidationError::UnsupportedVersion {
                expected: ADVERSARIAL_CORPUS_VERSION_V1,
                found: self.schema_version,
            });
        }
        if self.families.is_empty() {
            return Err(AdversarialCorpusValidationError::MissingFamilies);
        }
        let mut family_ids = BTreeSet::new();
        let mut variant_ids = BTreeSet::new();
        let mut perceptual_hashes = BTreeSet::new();
        let mut embedding_digests = BTreeSet::new();
        for family in &self.families {
            if !family_ids.insert(family.family_id) {
                return Err(AdversarialCorpusValidationError::DuplicateFamilyId {
                    family_id: family.family_id,
                });
            }
            if family.variants.is_empty() {
                return Err(AdversarialCorpusValidationError::MissingVariants {
                    family_id: family.family_id,
                });
            }
            for variant in &family.variants {
                if !variant_ids.insert(variant.variant_id) {
                    return Err(AdversarialCorpusValidationError::DuplicateVariantId {
                        variant_id: variant.variant_id,
                    });
                }
                let has_hash = variant.perceptual_hash.is_some();
                let has_embedding = variant.embedding_digest.is_some();
                if !has_hash && !has_embedding {
                    return Err(AdversarialCorpusValidationError::MissingMatchBasis {
                        variant_id: variant.variant_id,
                    });
                }
                if let Some(perceptual_hash) = variant.perceptual_hash
                    && !perceptual_hashes.insert(perceptual_hash)
                {
                    return Err(AdversarialCorpusValidationError::DuplicatePerceptualHash {
                        variant_id: variant.variant_id,
                    });
                }
                if let Some(embedding_digest) = variant.embedding_digest
                    && !embedding_digests.insert(embedding_digest)
                {
                    return Err(AdversarialCorpusValidationError::DuplicateEmbeddingDigest {
                        variant_id: variant.variant_id,
                    });
                }
                if variant.hamming_radius > 32 {
                    return Err(AdversarialCorpusValidationError::InvalidHammingRadius {
                        variant_id: variant.variant_id,
                        radius: variant.hamming_radius,
                    });
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, Signature};
    fn encode_with_alternate_norito_layout<T: norito::NoritoSerialize>(value: &T) -> Vec<u8> {
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(value).expect("encode alternate-layout moderation value")
    }
    /// Named mutation applied to a reproducibility body by validation tests.
    type ReproBodyTextMutation = (&'static str, fn(&mut ModerationReproBodyV1));
    #[test]
    fn repro_verification_borrows_preexisting_signature_under_zero_copy_budget() {
        let pair = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519).unwrap();
        let body = sample_body();
        let signature = checked_signature(&pair, &body);
        let malformed = SignatureOf::from_signature(iroha_crypto::Signature::from_bytes(&[1; 63]));
        let mut changed_body = body.clone();
        changed_body.manifest_id[0] ^= 1;
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        norito::with_decode_limits_scope(limits, || {
            verify_repro_signature(&signature, pair.public_key(), &body).unwrap();
            assert_eq!(
                verify_repro_signature(&signature, pair.public_key(), &changed_body),
                Err(iroha_crypto::Error::BadSignature)
            );
            assert_eq!(
                verify_repro_signature(&malformed, pair.public_key(), &body),
                Err(iroha_crypto::Error::BadSignature)
            );
        });
    }

    fn sample_body() -> ModerationReproBodyV1 {
        let mut body = ModerationReproBodyV1 {
            schema_version: MODERATION_REPRO_MANIFEST_VERSION_V1,
            manifest_id: [0xAA; 16],
            manifest_digest: [0x11; 32],
            runner_hash: [0x22; 32],
            runtime_version: "sorafs-ai-runner 0.4.0".to_string(),
            issued_at_unix: 1_706_000_000,
            seed_material: ModerationSeedMaterialV1 {
                domain_tag: "fastpq:v1:moderation".to_string(),
                seed_version: 1,
                run_nonce: [0x33; 32],
            },
            thresholds: ModerationThresholdsV1 {
                quarantine: 4_200,
                escalate: 7_800,
            },
            models: vec![ModerationModelFingerprintV1 {
                model_id: [0x44; 16],
                artifact_path: "models/model-44.norito".to_string(),
                artifact_bytes: 4096,
                artifact_digest: [0x55; 32],
                weights_digest: [0x66; 32],
                engine: ModerationModelEngineV1::DeterministicLinearV1,
                feature_profile: ModerationFeatureProfileV1::ByteHistogramAndBigramV1,
                calibration_knot_count: 2,
                max_input_bytes: 1024,
                max_operations: moderation_model_required_operations_v1(1024, 2)
                    .expect("operation budget"),
                working_memory_bytes: MODERATION_MODEL_WORKING_MEMORY_BYTES_V1,
                weight: Some(10_000),
            }],
            notes: Some("calibration=2026-02".to_string()),
        };
        body.refresh_manifest_digest()
            .expect("refresh moderation fixture digest");
        body
    }
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked moderation fixture keypair")
    }
    fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
            panic!("{algorithm:?} moderation fixture key generation should succeed: {err}")
        })
    }
    fn checked_signature(
        keypair: &KeyPair,
        body: &ModerationReproBodyV1,
    ) -> SignatureOf<ModerationReproBodyV1> {
        let signature = SignatureOf::try_new(keypair.private_key(), body)
            .expect("sign checked moderation reproducibility fixture");
        signature
            .verify(keypair.public_key(), body)
            .expect("checked moderation reproducibility fixture verifies");
        signature
    }
    fn sign_manifest(mut body: ModerationReproBodyV1, roles: &[&str]) -> ModerationReproManifestV1 {
        body.refresh_manifest_digest()
            .expect("refresh moderation fixture digest before signing");
        let mut signatures = Vec::new();
        for &role in roles {
            let keypair = checked_random_keypair();
            let signature = checked_signature(&keypair, &body);
            signatures.push(ModerationReproSignatureV1 {
                role: role.to_string(),
                public_key: keypair.public_key().clone(),
                signature,
            });
        }
        signatures.sort_by(|left, right| left.public_key.cmp(&right.public_key));
        ModerationReproManifestV1 { body, signatures }
    }
    fn sign_manifest_with_keypair(
        mut body: ModerationReproBodyV1,
        role: &str,
        keypair: &KeyPair,
    ) -> ModerationReproManifestV1 {
        body.refresh_manifest_digest()
            .expect("refresh moderation fixture digest before signing");
        let signature = checked_signature(keypair, &body);
        ModerationReproManifestV1 {
            body,
            signatures: vec![ModerationReproSignatureV1 {
                role: role.to_string(),
                public_key: keypair.public_key().clone(),
                signature,
            }],
        }
    }
    const TRUST_FIXTURE_NOW: u64 = 1_800_000_000;
    fn sample_trust_policy(
        manifest: &ModerationReproManifestV1,
        governance_keys: &[&KeyPair],
        runner_keys: &[&KeyPair],
        result_quorum: u16,
    ) -> ModerationTrustPolicyV1 {
        let mut trusted_signers = runner_keys
            .iter()
            .enumerate()
            .map(|(index, keypair)| ModerationTrustedSignerV1 {
                role: format!("runner-{index}"),
                public_key: keypair.public_key().clone(),
                valid_from_unix: TRUST_FIXTURE_NOW - 1_000,
                valid_until_unix: TRUST_FIXTURE_NOW + 10_000,
                revoked_at_unix: None,
            })
            .collect::<Vec<_>>();
        trusted_signers.sort_by(|left, right| left.public_key.cmp(&right.public_key));
        let mut body = ModerationTrustPolicyBodyV1 {
            schema_version: MODERATION_TRUST_POLICY_VERSION_V1,
            policy_id: [0xB1; 16],
            policy_digest: [0; 32],
            manifest_id: manifest.body.manifest_id,
            manifest_digest: manifest.body.manifest_digest,
            runner_hash: manifest.body.runner_hash,
            issued_at_unix: TRUST_FIXTURE_NOW - 2_000,
            valid_from_unix: TRUST_FIXTURE_NOW - 1_000,
            valid_until_unix: TRUST_FIXTURE_NOW + 10_000,
            result_quorum,
            governance_quorum: u16::try_from(governance_keys.len())
                .expect("governance fixture count fits u16"),
            max_result_age_secs: 3_600,
            max_result_ttl_secs: 600,
            max_clock_skew_secs: 30,
            trusted_signers,
            notes: Some("external anchors required".to_string()),
        };
        body.refresh_policy_digest().expect("policy digest");
        let mut signatures = governance_keys
            .iter()
            .enumerate()
            .map(|(index, keypair)| ModerationTrustPolicySignatureV1 {
                role: format!("governance-{index}"),
                public_key: keypair.public_key().clone(),
                signature: SignatureOf::try_new(keypair.private_key(), &body)
                    .expect("sign trust-policy fixture"),
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.public_key.cmp(&right.public_key));
        ModerationTrustPolicyV1 { body, signatures }
    }
    fn sample_signed_result(
        manifest: &ModerationReproManifestV1,
        policy: &ModerationTrustPolicyV1,
        runner_key: &KeyPair,
        score_bps: u16,
        subject: &str,
        screened_at_unix: u64,
    ) -> ModerationSignedScreeningResultV1 {
        let mut body = ModerationSignedScreeningBodyV1 {
            schema_version: MODERATION_SIGNED_RESULT_VERSION_V1,
            manifest_id: manifest.body.manifest_id,
            manifest_digest: manifest.body.manifest_digest,
            runner_hash: manifest.body.runner_hash,
            trust_policy_id: policy.body.policy_id,
            trust_policy_digest: policy.body.policy_digest,
            subject: subject.to_string(),
            subject_digest: *blake3::hash(subject.as_bytes()).as_bytes(),
            model_scores: manifest
                .body
                .models
                .iter()
                .map(|model| ModerationModelScoreV1 {
                    model_id: model.model_id,
                    artifact_digest: model.artifact_digest,
                    score_bps,
                })
                .collect(),
            combined_score_bps: score_bps,
            verdict: moderation_verdict_v1(score_bps, manifest.body.thresholds).to_string(),
            screened_at_unix,
            expires_at_unix: screened_at_unix + 300,
            policy_digest: manifest
                .body
                .computed_screening_policy_digest()
                .expect("screening policy digest"),
            evidence_digest: [0; 32],
            notes: Some("canonical runner result".to_string()),
        };
        body.refresh_evidence_digest().expect("evidence digest");
        ModerationSignedScreeningResultV1 {
            signer_public_key: runner_key.public_key().clone(),
            signature: SignatureOf::try_new(runner_key.private_key(), &body)
                .expect("sign result fixture"),
            body,
        }
    }
    fn fixture_trust_anchors(governance_keys: &[&KeyPair]) -> BTreeSet<PublicKey> {
        governance_keys
            .iter()
            .map(|keypair| keypair.public_key().clone())
            .collect()
    }
    fn resign_policy(policy: &mut ModerationTrustPolicyV1, governance_keys: &[&KeyPair]) {
        policy
            .body
            .refresh_policy_digest()
            .expect("refresh trust policy digest");
        policy.signatures = governance_keys
            .iter()
            .enumerate()
            .map(|(index, keypair)| ModerationTrustPolicySignatureV1 {
                role: format!("governance-{index}"),
                public_key: keypair.public_key().clone(),
                signature: SignatureOf::try_new(keypair.private_key(), &policy.body)
                    .expect("resign trust policy"),
            })
            .collect();
        policy
            .signatures
            .sort_by(|left, right| left.public_key.cmp(&right.public_key));
    }
    fn resign_result(result: &mut ModerationSignedScreeningResultV1, runner_key: &KeyPair) {
        result
            .body
            .refresh_evidence_digest()
            .expect("refresh signed result digest");
        result.signature = SignatureOf::try_new(runner_key.private_key(), &result.body)
            .expect("resign result fixture");
    }
    fn sample_model_artifact() -> ModerationModelArtifactV1 {
        let calibration = vec![
            ModerationCalibrationKnotV1 {
                input: -10_000,
                score_bps: 0,
            },
            ModerationCalibrationKnotV1 {
                input: 10_000,
                score_bps: 10_000,
            },
        ];
        ModerationModelArtifactV1 {
            schema_version: MODERATION_MODEL_ARTIFACT_VERSION_V1,
            engine: ModerationModelEngineV1::DeterministicLinearV1,
            feature_profile: ModerationFeatureProfileV1::ByteHistogramAndBigramV1,
            model_id: [0xA5; 16],
            max_input_bytes: 1024,
            max_operations: moderation_model_required_operations_v1(1024, calibration.len())
                .expect("model operation budget"),
            working_memory_bytes: MODERATION_MODEL_WORKING_MEMORY_BYTES_V1,
            bias: 17,
            weights: vec![1; MODERATION_MODEL_FEATURE_COUNT_V1],
            calibration,
        }
    }
    #[test]
    fn model_artifact_validates_and_digest_binds_behaviour() {
        let artifact = sample_model_artifact();
        artifact.validate().expect("valid model artefact");
        let digest = artifact.behaviour_digest();
        let mut changed = artifact.clone();
        changed.schema_version += 1;
        assert_ne!(changed.behaviour_digest(), digest);
        changed = artifact.clone();
        changed.model_id[0] ^= 1;
        assert_ne!(changed.behaviour_digest(), digest);
        changed = artifact.clone();
        changed.max_input_bytes += 1;
        assert_ne!(changed.behaviour_digest(), digest);
        changed = artifact.clone();
        changed.max_operations += 1;
        assert_ne!(changed.behaviour_digest(), digest);
        changed = artifact.clone();
        changed.working_memory_bytes += 1;
        assert_ne!(changed.behaviour_digest(), digest);
        let mut changed = artifact.clone();
        changed.weights[511] = 2;
        assert_ne!(changed.behaviour_digest(), digest);
        changed = artifact.clone();
        changed.bias += 1;
        assert_ne!(changed.behaviour_digest(), digest);
        changed = artifact;
        changed.calibration[1].score_bps -= 1;
        assert_ne!(changed.behaviour_digest(), digest);
    }
    #[test]
    fn model_artifact_rejects_shape_and_budget_attacks() {
        let mut artifact = sample_model_artifact();
        artifact.schema_version += 1;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::UnsupportedVersion { .. })
        ));
        let mut artifact = sample_model_artifact();
        artifact.model_id = [0; 16];
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::MissingModelId)
        ));
        for max_input_bytes in [0, MODERATION_MODEL_MAX_INPUT_BYTES_V1 + 1] {
            let mut artifact = sample_model_artifact();
            artifact.max_input_bytes = max_input_bytes;
            assert!(matches!(
                artifact.validate(),
                Err(ModerationModelArtifactError::InvalidMaxInput { .. })
            ));
        }
        let mut artifact = sample_model_artifact();
        artifact.weights.pop();
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::InvalidWeightCount { .. })
        ));
        let mut artifact = sample_model_artifact();
        artifact.calibration[1].input = artifact.calibration[0].input;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::CalibrationInputOrder { .. })
        ));
        let mut artifact = sample_model_artifact();
        artifact.calibration[1].score_bps = MODERATION_REPRO_MAX_BPS + 1;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::InvalidCalibrationScore { .. })
        ));
        let mut artifact = sample_model_artifact();
        artifact.calibration[0].score_bps = 1;
        artifact.calibration[1].score_bps = 0;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::InvalidCalibrationScore { .. })
        ));
        for calibration in [
            vec![ModerationCalibrationKnotV1 {
                input: 0,
                score_bps: 0,
            }],
            (0..=MODERATION_MODEL_MAX_CALIBRATION_KNOTS_V1)
                .map(|index| ModerationCalibrationKnotV1 {
                    input: i64::try_from(index).expect("fixture index fits i64"),
                    score_bps: 0,
                })
                .collect(),
        ] {
            let mut artifact = sample_model_artifact();
            artifact.calibration = calibration;
            assert!(matches!(
                artifact.validate(),
                Err(ModerationModelArtifactError::InvalidCalibrationCount { .. })
            ));
        }
        let mut artifact = sample_model_artifact();
        artifact.max_operations += 1;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::InvalidOperationBudget { .. })
        ));
        let mut artifact = sample_model_artifact();
        artifact.working_memory_bytes += 1;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::InvalidWorkingMemory { .. })
        ));
        let mut artifact = sample_model_artifact();
        artifact.bias = i64::MAX;
        artifact.weights[0] = 1;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::AccumulatorOverflow)
        ));
        let mut artifact = sample_model_artifact();
        artifact.bias = i64::MIN;
        artifact.weights.fill(0);
        artifact
            .validate()
            .expect("exact i64 minimum with zero contributions is valid");
        artifact.weights[0] = -1;
        assert!(matches!(
            artifact.validate(),
            Err(ModerationModelArtifactError::AccumulatorOverflow)
        ));
    }
    #[test]
    fn artifact_path_validation_is_platform_independent() {
        for accepted in ["model.norito", "models/a-1_model.norito"] {
            assert!(is_canonical_moderation_artifact_path_v1(accepted));
        }
        for rejected in [
            "",
            "/model.norito",
            "models/../model.norito",
            "models/./model.norito",
            "models//model.norito",
            "models\\model.norito",
            "C:/model.norito",
            "models/model name.norito",
            "models/model\n.norito",
        ] {
            assert!(
                !is_canonical_moderation_artifact_path_v1(rejected),
                "accepted unsafe path {rejected:?}"
            );
        }
    }
    const SMALL_ORDER_ED25519_SIGNATURE_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_SIGNATURE_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn signature_with_malformed_ed25519_r(
        signature: &SignatureOf<ModerationReproBodyV1>,
        replacement_r: &[u8; 32],
    ) -> SignatureOf<ModerationReproBodyV1> {
        let mut payload = signature.payload().to_vec();
        payload[..replacement_r.len()].copy_from_slice(replacement_r);
        SignatureOf::from_signature(Signature::from_bytes(&payload))
    }
    #[test]
    fn validate_happy_path() {
        let manifest = sign_manifest(sample_body(), &["council", "sre"]);
        let summary = manifest.validate().expect("manifest valid");
        assert_eq!(summary.model_count, 1);
        assert_eq!(summary.signer_count, 2);
        assert_eq!(summary.manifest_id, [0xAA; 16]);
    }
    #[test]
    fn validate_rejects_duplicate_signer() {
        let body = sample_body();
        let keypair = checked_random_keypair();
        let signature = checked_signature(&keypair, &body);
        let manifest = ModerationReproManifestV1 {
            body,
            signatures: vec![
                ModerationReproSignatureV1 {
                    role: "council".to_string(),
                    public_key: keypair.public_key().clone(),
                    signature: signature.clone(),
                },
                ModerationReproSignatureV1 {
                    role: "sre".to_string(),
                    public_key: keypair.public_key().clone(),
                    signature,
                },
            ],
        };
        let err = manifest.validate().expect_err("duplicate signer must fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::DuplicateSigner
        ));
    }
    #[test]
    fn validate_rejects_malformed_ed25519_signature_r() {
        let manifest = sign_manifest(sample_body(), &["council"]);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_SIGNATURE_R),
            ("noncanonical", NONCANONICAL_ED25519_SIGNATURE_R),
        ] {
            let mut invalid_manifest = manifest.clone();
            invalid_manifest.signatures[0].signature = signature_with_malformed_ed25519_r(
                &manifest.signatures[0].signature,
                &replacement_r,
            );
            let err = invalid_manifest
                .validate()
                .expect_err("malformed moderation signature R must fail admission");
            let ModerationReproValidationError::BadSignature { source, .. } = err else {
                panic!("expected bad moderation signature error: {err:?}");
            };
            assert_eq!(
                source,
                iroha_crypto::Error::BadSignature,
                "{label} moderation signature R produced unexpected error"
            );
        }
    }
    #[test]
    fn validate_rejects_malformed_mldsa_signature_lengths() {
        let keypair = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
        let manifest = sign_manifest_with_keypair(sample_body(), "council", &keypair);
        manifest
            .validate()
            .expect("valid ML-DSA moderation manifest verifies");
        let valid_signature = manifest.signatures[0].signature.payload().to_vec();
        for (label, replacement_signature) in [
            (
                "short",
                valid_signature[..valid_signature.len() - 1].to_vec(),
            ),
            ("overlong", {
                let mut payload = valid_signature.clone();
                payload.push(0x5E);
                payload
            }),
        ] {
            let mut invalid_manifest = manifest.clone();
            invalid_manifest.signatures[0].signature =
                SignatureOf::from_signature(Signature::from_bytes(&replacement_signature));
            let err = invalid_manifest
                .validate()
                .expect_err("malformed moderation ML-DSA signature length must fail admission");
            let ModerationReproValidationError::BadSignature { source, .. } = err else {
                panic!("expected bad moderation signature error: {err:?}");
            };
            assert_eq!(
                source,
                iroha_crypto::Error::BadSignature,
                "{label} moderation ML-DSA signature length produced unexpected error"
            );
        }
    }
    #[test]
    fn validate_rejects_missing_models() {
        let mut body = sample_body();
        body.models.clear();
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest.validate().expect_err("missing models should fail");
        assert!(matches!(err, ModerationReproValidationError::MissingModels));
    }
    #[test]
    fn validate_rejects_zero_manifest_digests() {
        let mut manifest = sign_manifest(sample_body(), &["council"]);
        manifest.body.manifest_digest = [0; 32];
        let err = manifest
            .validate()
            .expect_err("zero manifest digest should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingDigest {
                field: "manifest_digest"
            }
        ));
        let mut body = sample_body();
        body.runner_hash = [0; 32];
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("zero runner hash should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingDigest {
                field: "runner_hash"
            }
        ));
        let mut body = sample_body();
        body.seed_material.run_nonce = [0; 32];
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest.validate().expect_err("zero run nonce should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingDigest { field: "run_nonce" }
        ));
    }
    #[test]
    fn validate_rejects_header_and_text_mutations() {
        let mut body = sample_body();
        body.manifest_id = [0; 16];
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::MissingManifestId)
        ));
        let mut body = sample_body();
        body.issued_at_unix = 0;
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::MissingIssuedAt)
        ));
        let mut body = sample_body();
        body.seed_material.seed_version = 0;
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::MissingSeedVersion)
        ));
        let mutations: [ReproBodyTextMutation; 3] = [
            ("runtime_version", |body: &mut ModerationReproBodyV1| {
                body.runtime_version = " runner".to_owned()
            }),
            (
                "seed_material.domain_tag",
                |body: &mut ModerationReproBodyV1| {
                    body.seed_material.domain_tag = "seed\nlabel".to_owned();
                },
            ),
            ("notes", |body: &mut ModerationReproBodyV1| {
                body.notes = Some(" ".to_owned());
            }),
        ];
        for (field, mutate) in mutations {
            let mut body = sample_body();
            mutate(&mut body);
            assert!(matches!(
                sign_manifest(body, &["council"]).validate(),
                Err(ModerationReproValidationError::InvalidText { field: found }) if found == field
            ));
        }
    }
    #[test]
    fn validate_rejects_digest_and_signer_order_mutations() {
        let mut manifest = sign_manifest(sample_body(), &["council"]);
        manifest.body.manifest_digest[0] ^= 1;
        assert!(matches!(
            manifest.validate(),
            Err(ModerationReproValidationError::ManifestDigestMismatch { .. })
        ));
        let mut manifest = sign_manifest(sample_body(), &["council", "sre"]);
        manifest.signatures.reverse();
        assert!(matches!(
            manifest.validate(),
            Err(ModerationReproValidationError::NonCanonicalSignatureOrder)
        ));
        let mut manifest = sign_manifest(sample_body(), &["council"]);
        manifest.signatures[0].role = "bad\nrole".to_owned();
        assert!(matches!(
            manifest.validate(),
            Err(ModerationReproValidationError::InvalidText {
                field: "signatures.role"
            })
        ));
        let mut manifest = sign_manifest(sample_body(), &["council"]);
        manifest.signatures =
            vec![manifest.signatures[0].clone(); MODERATION_REPRO_MAX_SIGNATURES_V1 + 1];
        assert!(matches!(
            manifest.validate(),
            Err(ModerationReproValidationError::TooManySignatures { .. })
        ));
    }
    #[test]
    fn validate_rejects_bad_thresholds() {
        let mut body = sample_body();
        body.thresholds.quarantine = MODERATION_REPRO_MAX_BPS + 1;
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("oversized quarantine threshold should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::InvalidThresholdBps {
                field: "quarantine",
                value: 10_001
            }
        ));
        let mut body = sample_body();
        body.thresholds.escalate = MODERATION_REPRO_MAX_BPS + 1;
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("oversized escalate threshold should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::InvalidThresholdBps {
                field: "escalate",
                value: 10_001
            }
        ));
        let mut body = sample_body();
        body.thresholds = ModerationThresholdsV1 {
            quarantine: 8_000,
            escalate: 7_000,
        };
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("inverted thresholds should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::InvalidThresholdOrder {
                quarantine: 8_000,
                escalate: 7_000
            }
        ));
    }
    #[test]
    fn validate_rejects_duplicate_model_ids_and_digests() {
        let mut body = sample_body();
        let mut duplicate = body.models[0].clone();
        duplicate.artifact_digest = [0x77; 32];
        duplicate.weights_digest = [0x88; 32];
        body.models.push(duplicate);
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("duplicate model id should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::DuplicateModelId { .. }
        ));
        let mut body = sample_body();
        let mut duplicate = body.models[0].clone();
        duplicate.model_id = [0x45; 16];
        duplicate.artifact_path = "models/model-45.norito".to_owned();
        duplicate.weights_digest = [0x88; 32];
        body.models.push(duplicate);
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("duplicate artifact digest should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::DuplicateArtifactDigest { .. }
        ));
        let mut body = sample_body();
        let mut duplicate = body.models[0].clone();
        duplicate.model_id = [0x45; 16];
        duplicate.artifact_path = "models/model-45.norito".to_owned();
        duplicate.artifact_digest = [0x77; 32];
        body.models.push(duplicate);
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("duplicate weights digest should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::DuplicateWeightsDigest { .. }
        ));
    }
    #[test]
    fn validate_rejects_model_path_size_order_and_count_attacks() {
        for invalid_path in [
            "",
            "/model.norito",
            "models/../model.norito",
            "models\\model.norito",
        ] {
            let mut body = sample_body();
            body.models[0].artifact_path = invalid_path.to_owned();
            assert!(matches!(
                sign_manifest(body, &["council"]).validate(),
                Err(ModerationReproValidationError::InvalidArtifactPath { .. })
            ));
        }
        let mut body = sample_body();
        let mut second = body.models[0].clone();
        second.model_id = [0x45; 16];
        second.artifact_digest = [0x77; 32];
        second.weights_digest = [0x88; 32];
        body.models.push(second);
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::DuplicateArtifactPath { .. })
        ));
        for artifact_bytes in [0, MODERATION_MODEL_MAX_ARTIFACT_BYTES_V1 + 1] {
            let mut body = sample_body();
            body.models[0].artifact_bytes = artifact_bytes;
            assert!(matches!(
                sign_manifest(body, &["council"]).validate(),
                Err(ModerationReproValidationError::InvalidArtifactBytes { .. })
            ));
        }
        let mut body = sample_body();
        let mut lower = body.models[0].clone();
        lower.model_id = [0x43; 16];
        lower.artifact_path = "models/model-43.norito".to_owned();
        lower.artifact_digest = [0x77; 32];
        lower.weights_digest = [0x88; 32];
        body.models.push(lower);
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::NonCanonicalModelOrder)
        ));
        let mut body = sample_body();
        body.models = (1_u8..=u8::try_from(MODERATION_MODEL_MAX_MODELS_V1 + 1)
            .expect("model cap fits u8"))
            .map(|index| {
                let mut fixture = sample_body();
                let mut model = fixture.models.remove(0);
                model.model_id = [index; 16];
                model.artifact_path = format!("models/model-{index}.norito");
                model.artifact_digest = [index.saturating_add(32); 32];
                model.weights_digest = [index.saturating_add(64); 32];
                model
            })
            .collect();
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::TooManyModels { .. })
        ));
    }
    #[test]
    fn validate_rejects_every_fingerprint_resource_bound_mutation() {
        for calibration_knot_count in [1, 65] {
            let mut body = sample_body();
            body.models[0].calibration_knot_count = calibration_knot_count;
            assert!(matches!(
                sign_manifest(body, &["council"]).validate(),
                Err(ModerationReproValidationError::InvalidCalibrationCount { .. })
            ));
        }
        for max_input_bytes in [0, MODERATION_MODEL_MAX_INPUT_BYTES_V1 + 1] {
            let mut body = sample_body();
            body.models[0].max_input_bytes = max_input_bytes;
            assert!(matches!(
                sign_manifest(body, &["council"]).validate(),
                Err(ModerationReproValidationError::InvalidModelMaxInput { .. })
            ));
        }
        let mut body = sample_body();
        body.models[0].working_memory_bytes += 1;
        assert!(matches!(
            sign_manifest(body, &["council"]).validate(),
            Err(ModerationReproValidationError::InvalidModelResourceBudget { .. })
        ));
    }
    #[test]
    fn validate_rejects_missing_model_identity_and_digests() {
        let mut body = sample_body();
        body.models[0].model_id = [0; 16];
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest.validate().expect_err("zero model id should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingModelId
        ));
        let mut body = sample_body();
        body.models[0].artifact_digest = [0; 32];
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("zero artifact digest should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingModelDigest {
                field: "artifact_digest",
                ..
            }
        ));
        let mut body = sample_body();
        body.models[0].weights_digest = [0; 32];
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("zero weights digest should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingModelDigest {
                field: "weights_digest",
                ..
            }
        ));
    }
    #[test]
    fn validate_rejects_bad_model_resources_and_weights() {
        let mut body = sample_body();
        body.models[0].max_operations += 1;
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("invalid operation budget should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::InvalidModelResourceBudget { .. }
        ));
        let mut body = sample_body();
        body.models[0].weight = Some(MODERATION_REPRO_MAX_BPS + 1);
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("oversized model weight should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::InvalidModelWeight { weight: 10_001, .. }
        ));
        let mut body = sample_body();
        body.models[0].weight = Some(0);
        let manifest = sign_manifest(body, &["council"]);
        let err = manifest
            .validate()
            .expect_err("all-zero model weights should fail");
        assert!(matches!(
            err,
            ModerationReproValidationError::MissingPositiveModelWeight
        ));
    }
    fn sample_ballot_context() -> SoraFsModerationBallotContextV1 {
        SoraFsModerationBallotContextV1 {
            version: SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1,
            case_id: "SFM-CASE-2026-0007".to_string(),
            evidence_bundle_digest: [0xA7; 32],
            appeal_finance_config_version: "baseline-v1".to_string(),
            panel_roster_hash: [0xB7; 32],
            policy_reference: "gar:moderation:2026-q1".to_string(),
            evidence_uri: Some("sorafs://governance/evidence/case-0007".to_string()),
        }
    }
    fn sample_ballot_reveal(choice: SoraFsModerationVoteChoice) -> SoraFsModerationBallotRevealV1 {
        SoraFsModerationBallotRevealV1 {
            version: SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1,
            context: sample_ballot_context(),
            round_id: "SFM-PANEL-2026-02".to_string(),
            juror_id: "juror:pop:7".to_string(),
            choice,
            nonce: vec![0x42; 32],
            revealed_at_unix_ms: 1_738_001_000_000,
        }
    }
    fn sample_ballot_commit(choice: SoraFsModerationVoteChoice) -> SoraFsModerationBallotCommitV1 {
        let reveal = sample_ballot_reveal(choice);
        SoraFsModerationBallotCommitV1 {
            version: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
            context: reveal.context.clone(),
            round_id: reveal.round_id.clone(),
            juror_id: reveal.juror_id.clone(),
            commitment_blake2b_256: reveal.compute_commitment(),
            committed_at_unix_ms: 1_738_000_000_000,
        }
    }
    #[test]
    fn sorafs_moderation_ballot_commit_reveal_roundtrip() {
        let commit = sample_ballot_commit(SoraFsModerationVoteChoice::Overturn);
        let reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Overturn);
        commit
            .verify_reveal(&reveal)
            .expect("SoraFS moderation reveal matches commitment");
    }
    #[test]
    fn sorafs_moderation_ballot_commitment_is_domain_separated() {
        let reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Overturn);
        let mut legacy = Blake2b256::new();
        reveal.context.update_hash(&mut legacy);
        update_hash_string(&mut legacy, &reveal.round_id);
        update_hash_string(&mut legacy, &reveal.juror_id);
        legacy.update([reveal.choice.discriminant()]);
        legacy.update((reveal.nonce.len() as u64).to_le_bytes());
        legacy.update(&reveal.nonce);
        let legacy: [u8; 32] = legacy.finalize().into();
        assert_ne!(reveal.compute_commitment(), legacy);
    }
    #[test]
    fn sorafs_moderation_ballot_binds_evidence_and_finance_context() {
        let commit = sample_ballot_commit(SoraFsModerationVoteChoice::Modify);
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Modify);
        reveal.context.evidence_bundle_digest = [0xC7; 32];
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("evidence digest mismatch must fail");
        assert!(matches!(err, SoraFsModerationBallotError::ContextMismatch));
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Modify);
        reveal.context.appeal_finance_config_version = "baseline-v2".to_string();
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("finance config version mismatch must fail");
        assert!(matches!(err, SoraFsModerationBallotError::ContextMismatch));
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Modify);
        reveal.context.panel_roster_hash = [0xD7; 32];
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("panel roster hash mismatch must fail");
        assert!(matches!(err, SoraFsModerationBallotError::ContextMismatch));
    }
    #[test]
    fn sorafs_moderation_ballot_rejects_mismatched_choice_and_short_nonce() {
        let commit = sample_ballot_commit(SoraFsModerationVoteChoice::Uphold);
        let reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Escalate);
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("choice mismatch must fail");
        assert!(matches!(
            err,
            SoraFsModerationBallotError::CommitmentMismatch
        ));
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Uphold);
        reveal.nonce = vec![0x01; 8];
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("short nonce must fail");
        assert!(matches!(
            err,
            SoraFsModerationBallotError::NonceTooShort { length: 8 }
        ));
    }
    #[test]
    fn sorafs_moderation_ballot_requires_case_policy_and_roster_scope() {
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Uphold);
        reveal.context.case_id = "  ".to_string();
        let commit = SoraFsModerationBallotCommitV1 {
            version: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
            context: reveal.context.clone(),
            round_id: reveal.round_id.clone(),
            juror_id: reveal.juror_id.clone(),
            commitment_blake2b_256: reveal.compute_commitment(),
            committed_at_unix_ms: 1_738_000_000_000,
        };
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("blank case id must fail");
        assert!(matches!(err, SoraFsModerationBallotError::MissingCaseId));
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Uphold);
        reveal.context.policy_reference.clear();
        let commit = SoraFsModerationBallotCommitV1 {
            version: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
            context: reveal.context.clone(),
            round_id: reveal.round_id.clone(),
            juror_id: reveal.juror_id.clone(),
            commitment_blake2b_256: reveal.compute_commitment(),
            committed_at_unix_ms: 1_738_000_000_000,
        };
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("blank policy reference must fail");
        assert!(matches!(
            err,
            SoraFsModerationBallotError::MissingPolicyReference
        ));
        let mut reveal = sample_ballot_reveal(SoraFsModerationVoteChoice::Uphold);
        reveal.context.panel_roster_hash = [0; 32];
        let commit = SoraFsModerationBallotCommitV1 {
            version: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
            context: reveal.context.clone(),
            round_id: reveal.round_id.clone(),
            juror_id: reveal.juror_id.clone(),
            commitment_blake2b_256: reveal.compute_commitment(),
            committed_at_unix_ms: 1_738_000_000_000,
        };
        let err = commit
            .verify_reveal(&reveal)
            .expect_err("zero roster hash must fail");
        assert!(matches!(
            err,
            SoraFsModerationBallotError::MissingPanelRosterHash
        ));
    }
    fn sample_family_manifest() -> AdversarialCorpusManifestV1 {
        AdversarialCorpusManifestV1 {
            schema_version: ADVERSARIAL_CORPUS_VERSION_V1,
            issued_at_unix: 1_706_000_000,
            cohort_label: Some("2026-Q1".to_string()),
            families: vec![AdversarialPerceptualFamilyV1 {
                family_id: [0x01; 16],
                description: "jpeg jitter corpus".to_string(),
                variants: vec![AdversarialPerceptualVariantV1 {
                    variant_id: [0x02; 16],
                    attack_vector: "jpeg_jitter".to_string(),
                    reference_cid_b64: Some("YmFzZTY0LWNpZA==".to_string()),
                    perceptual_hash: Some([0xAA; 32]),
                    hamming_radius: 4,
                    embedding_digest: None,
                    notes: Some("delta=2".to_string()),
                }],
            }],
        }
    }
    #[test]
    fn adversarial_manifest_validates() {
        let manifest = sample_family_manifest();
        manifest.validate().expect("manifest valid");
    }
    #[test]
    fn adversarial_manifest_rejects_missing_variants() {
        let mut manifest = sample_family_manifest();
        manifest.families[0].variants.clear();
        let err = manifest.validate().expect_err("missing variants");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::MissingVariants { .. }
        ));
    }
    #[test]
    fn adversarial_manifest_rejects_duplicate_family_ids() {
        let mut manifest = sample_family_manifest();
        let mut duplicate = manifest.families[0].clone();
        duplicate.description = "same family id with different rows".to_string();
        duplicate.variants[0].variant_id = [0x03; 16];
        manifest.families.push(duplicate);
        let err = manifest.validate().expect_err("duplicate family id");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::DuplicateFamilyId { .. }
        ));
    }
    #[test]
    fn adversarial_manifest_rejects_duplicate_variant_ids_across_families() {
        let mut manifest = sample_family_manifest();
        let mut second_family = manifest.families[0].clone();
        second_family.family_id = [0x04; 16];
        second_family.description = "same variant id in another family".to_string();
        manifest.families.push(second_family);
        let err = manifest.validate().expect_err("duplicate variant id");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::DuplicateVariantId { .. }
        ));
    }
    #[test]
    fn adversarial_manifest_rejects_duplicate_variant_ids_within_family() {
        let mut manifest = sample_family_manifest();
        let mut duplicate = manifest.families[0].variants[0].clone();
        duplicate.attack_vector = "mosaic".to_string();
        duplicate.perceptual_hash = Some([0xBB; 32]);
        manifest.families[0].variants.push(duplicate);
        let err = manifest.validate().expect_err("duplicate variant id");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::DuplicateVariantId { .. }
        ));
    }
    #[test]
    fn adversarial_manifest_rejects_duplicate_perceptual_hashes() {
        let mut manifest = sample_family_manifest();
        let mut duplicate = manifest.families[0].variants[0].clone();
        duplicate.variant_id = [0x05; 16];
        duplicate.attack_vector = "crop_jitter".to_string();
        manifest.families[0].variants.push(duplicate);
        let err = manifest.validate().expect_err("duplicate perceptual hash");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::DuplicatePerceptualHash { .. }
        ));
    }
    #[test]
    fn adversarial_manifest_rejects_duplicate_embedding_digests() {
        let mut manifest = sample_family_manifest();
        manifest.families[0].variants[0].perceptual_hash = None;
        manifest.families[0].variants[0].embedding_digest = Some([0xCC; 32]);
        let mut duplicate = manifest.families[0].variants[0].clone();
        duplicate.variant_id = [0x06; 16];
        duplicate.attack_vector = "embedding_collision".to_string();
        manifest.families[0].variants.push(duplicate);
        let err = manifest.validate().expect_err("duplicate embedding digest");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::DuplicateEmbeddingDigest { .. }
        ));
    }
    #[test]
    fn adversarial_manifest_requires_match_basis() {
        let mut manifest = sample_family_manifest();
        manifest.families[0].variants[0].perceptual_hash = None;
        manifest.families[0].variants[0].embedding_digest = None;
        let err = manifest.validate().expect_err("missing fingerprints");
        assert!(matches!(
            err,
            AdversarialCorpusValidationError::MissingMatchBasis { .. }
        ));
    }
    #[test]
    fn trust_policy_requires_external_governance_anchors() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance_a = checked_random_keypair();
        let governance_b = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance_a, &governance_b], &[&runner], 1);
        let only_one_anchor = fixture_trust_anchors(&[&governance_a]);
        assert_eq!(
            policy
                .validate_with_trust_anchors(&manifest, &only_one_anchor, 2, TRUST_FIXTURE_NOW)
                .expect_err("one external anchor cannot satisfy a two-anchor policy"),
            ModerationTrustPolicyError::InsufficientTrustedGovernance {
                found: 1,
                required: 2,
            }
        );
        let anchors = fixture_trust_anchors(&[&governance_a, &governance_b]);
        let summary = policy
            .validate_with_trust_anchors(&manifest, &anchors, 2, TRUST_FIXTURE_NOW)
            .expect("two external anchors validate");
        assert_eq!(summary.trusted_governance_signature_count, 2);
        assert_eq!(summary.trusted_signer_count, 1);
    }
    #[test]
    fn trust_policy_rejects_external_quorum_downgrade() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let anchors = fixture_trust_anchors(&[&governance]);
        assert_eq!(
            policy
                .validate_with_trust_anchors(&manifest, &anchors, 2, TRUST_FIXTURE_NOW)
                .expect_err("signed one-of-one policy cannot weaken external quorum two"),
            ModerationTrustPolicyError::GovernanceQuorumDowngrade {
                policy: 1,
                minimum: 2,
            }
        );
    }
    #[test]
    fn trust_policy_rejects_manifest_and_digest_tampering() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let anchors = fixture_trust_anchors(&[&governance]);
        let mut digest_tampered = policy.clone();
        digest_tampered.body.notes = Some("tampered after signing".to_string());
        assert_eq!(
            digest_tampered
                .validate_with_trust_anchors(&manifest, &anchors, 1, TRUST_FIXTURE_NOW)
                .expect_err("body tamper must invalidate canonical digest"),
            ModerationTrustPolicyError::DigestMismatch
        );
        let mut rebound = policy;
        rebound.body.manifest_digest = [0xD0; 32];
        resign_policy(&mut rebound, &[&governance]);
        assert_eq!(
            rebound
                .validate_with_trust_anchors(&manifest, &anchors, 1, TRUST_FIXTURE_NOW)
                .expect_err("validly signed policy for a different manifest is rejected"),
            ModerationTrustPolicyError::ManifestBindingMismatch
        );
    }
    #[test]
    fn trust_policy_rejects_inactive_windows_and_invalid_revocation() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let anchors = fixture_trust_anchors(&[&governance]);
        let mut policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        assert!(matches!(
            policy
                .validate_with_trust_anchors(
                    &manifest,
                    &anchors,
                    1,
                    policy.body.valid_until_unix + policy.body.max_clock_skew_secs,
                )
                .expect_err("expired policy must fail"),
            ModerationTrustPolicyError::InvalidTimeWindow {
                field: "policy_inactive"
            }
        ));
        policy.body.trusted_signers[0].revoked_at_unix =
            Some(policy.body.trusted_signers[0].valid_from_unix);
        resign_policy(&mut policy, &[&governance]);
        assert!(matches!(
            policy
                .validate_with_trust_anchors(&manifest, &anchors, 1, TRUST_FIXTURE_NOW)
                .expect_err("revocation must be strictly inside the signer window"),
            ModerationTrustPolicyError::InvalidTimeWindow {
                field: "trusted_signer"
            }
        ));
    }
    #[test]
    fn signed_result_validates_all_bindings_and_signature() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let result = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            5_000,
            "cid:production-subject",
            TRUST_FIXTURE_NOW,
        );
        result
            .validate(&manifest, &policy, TRUST_FIXTURE_NOW + 1)
            .expect("fully bound signed result validates");
        let mut tampered = result.clone();
        tampered.body.combined_score_bps = 5_001;
        assert_eq!(
            tampered
                .validate(&manifest, &policy, TRUST_FIXTURE_NOW + 1)
                .expect_err("post-signature score tamper fails closed"),
            ModerationSignedResultError::CombinedScoreMismatch
        );
        let mut wrong_policy = result;
        wrong_policy.body.policy_digest = [0xEE; 32];
        resign_result(&mut wrong_policy, &runner);
        assert_eq!(
            wrong_policy
                .validate(&manifest, &policy, TRUST_FIXTURE_NOW + 1)
                .expect_err("alternate screening policy digest is rejected"),
            ModerationSignedResultError::BindingMismatch {
                field: "policy_digest"
            }
        );
    }
    #[test]
    fn signed_result_freshness_ttl_and_expiry_fail_closed() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let mut too_long = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            5_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        too_long.body.expires_at_unix =
            too_long.body.screened_at_unix + policy.body.max_result_ttl_secs + 1;
        resign_result(&mut too_long, &runner);
        assert!(matches!(
            too_long
                .validate(&manifest, &policy, TRUST_FIXTURE_NOW)
                .expect_err("overlong result TTL is rejected"),
            ModerationSignedResultError::InvalidTime {
                field: "expires_at_unix"
            }
        ));
        let expired = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            5_000,
            "cid:subject",
            TRUST_FIXTURE_NOW - 400,
        );
        assert!(matches!(
            expired
                .validate(&manifest, &policy, TRUST_FIXTURE_NOW)
                .expect_err("expired result is rejected"),
            ModerationSignedResultError::Freshness {
                reason: "result expired"
            }
        ));
        let future = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            5_000,
            "cid:subject",
            TRUST_FIXTURE_NOW + policy.body.max_clock_skew_secs + 1,
        );
        assert!(matches!(
            future
                .validate(&manifest, &policy, TRUST_FIXTURE_NOW)
                .expect_err("future-dated result beyond skew is rejected"),
            ModerationSignedResultError::Freshness { .. }
        ));
    }
    #[test]
    fn revoked_signer_cannot_backdate_or_outlive_revocation() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let mut policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let revocation = TRUST_FIXTURE_NOW + 100;
        policy.body.trusted_signers[0].revoked_at_unix = Some(revocation);
        resign_policy(&mut policy, &[&governance]);
        let backdated = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            5_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        assert!(matches!(
            backdated
                .validate(&manifest, &policy, revocation)
                .expect_err("revoked key cannot forge a backdated result"),
            ModerationSignedResultError::UnauthorizedSigner {
                reason: "signer was revoked"
            }
        ));
        assert!(matches!(
            backdated
                .validate(&manifest, &policy, TRUST_FIXTURE_NOW + 1)
                .expect_err("pre-revocation result cannot outlive revocation"),
            ModerationSignedResultError::UnauthorizedSigner {
                reason: "result outlives signer revocation"
            }
        ));
    }
    #[test]
    fn authenticated_committee_is_distinct_deterministic_and_quorum_bound() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner_a = checked_random_keypair();
        let runner_b = checked_random_keypair();
        let runner_c = checked_random_keypair();
        let policy = sample_trust_policy(
            &manifest,
            &[&governance],
            &[&runner_a, &runner_b, &runner_c],
            2,
        );
        let anchors = fixture_trust_anchors(&[&governance]);
        let result_a = sample_signed_result(
            &manifest,
            &policy,
            &runner_a,
            1_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        let result_b = sample_signed_result(
            &manifest,
            &policy,
            &runner_b,
            6_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        let result_c = sample_signed_result(
            &manifest,
            &policy,
            &runner_c,
            9_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        let aggregate = ModerationCommitteeAggregateV1::aggregate_authenticated(
            &manifest,
            &policy,
            &anchors,
            1,
            &[result_c.clone(), result_a.clone(), result_b.clone()],
            TRUST_FIXTURE_NOW + 1,
        )
        .expect("authenticated three-runner committee aggregates");
        assert_eq!(aggregate.aggregated_score_bps, 6_000);
        assert_eq!(aggregate.verdict, "quarantine");
        assert!(
            aggregate
                .members
                .windows(2)
                .all(|pair| pair[0].signer_public_key < pair[1].signer_public_key)
        );
        assert_eq!(
            aggregate.computed_aggregate_digest().unwrap(),
            aggregate.aggregate_digest
        );
        let reordered = ModerationCommitteeAggregateV1::aggregate_authenticated(
            &manifest,
            &policy,
            &anchors,
            1,
            &[result_b.clone(), result_c, result_a.clone()],
            TRUST_FIXTURE_NOW + 1,
        )
        .expect("input order cannot affect aggregate");
        assert_eq!(aggregate, reordered);
        assert!(matches!(
            ModerationCommitteeAggregateV1::aggregate_authenticated(
                &manifest,
                &policy,
                &anchors,
                1,
                &[result_a.clone(), result_a],
                TRUST_FIXTURE_NOW + 1,
            )
            .expect_err("one signer cannot be counted twice"),
            ModerationCommitteeAggregateError::DuplicateSigner { .. }
        ));
    }
    #[test]
    fn moderation_identity_digests_ignore_ambient_norito_layout() {
        let body = sample_body();
        let manifest = sign_manifest(body.clone(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let anchors = fixture_trust_anchors(&[&governance]);
        let result = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            4_000,
            "cid:canonical-subject",
            TRUST_FIXTURE_NOW,
        );
        let aggregate = ModerationCommitteeAggregateV1::aggregate_authenticated(
            &manifest,
            &policy,
            &anchors,
            1,
            std::slice::from_ref(&result),
            TRUST_FIXTURE_NOW + 1,
        )
        .expect("aggregate fixture");
        let mut log = ModerationProvenanceLogV1::new([0xA8; 16]).expect("new log");
        log.append(
            ModerationProvenancePayloadV1::SignedScreeningResult(result.clone()),
            TRUST_FIXTURE_NOW + 1,
        )
        .expect("append result");
        let entry = log.entries.first().expect("one provenance entry");
        let expected = (
            body.computed_manifest_digest().expect("manifest digest"),
            body.computed_screening_policy_digest()
                .expect("screening-policy digest"),
            policy.body.computed_policy_digest().expect("policy digest"),
            result
                .body
                .computed_evidence_digest()
                .expect("evidence digest"),
            aggregate
                .computed_aggregate_digest()
                .expect("aggregate digest"),
            entry.computed_entry_digest().expect("entry digest"),
        );
        let canonical = norito::encode_canonical(&body).expect("canonical body");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_ne!(
            norito::to_bytes(&body).expect("ambient-layout body"),
            canonical
        );
        assert_eq!(
            (
                body.computed_manifest_digest().expect("manifest digest"),
                body.computed_screening_policy_digest()
                    .expect("screening-policy digest"),
                policy.body.computed_policy_digest().expect("policy digest"),
                result
                    .body
                    .computed_evidence_digest()
                    .expect("evidence digest"),
                aggregate
                    .computed_aggregate_digest()
                    .expect("aggregate digest"),
                entry.computed_entry_digest().expect("entry digest"),
            ),
            expected
        );
    }
    #[test]
    fn authenticated_committee_rejects_subject_split_and_insufficient_quorum() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner_a = checked_random_keypair();
        let runner_b = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner_a, &runner_b], 2);
        let anchors = fixture_trust_anchors(&[&governance]);
        let result_a = sample_signed_result(
            &manifest,
            &policy,
            &runner_a,
            2_000,
            "cid:first",
            TRUST_FIXTURE_NOW,
        );
        let result_b = sample_signed_result(
            &manifest,
            &policy,
            &runner_b,
            8_000,
            "cid:second",
            TRUST_FIXTURE_NOW,
        );
        assert_eq!(
            ModerationCommitteeAggregateV1::aggregate_authenticated(
                &manifest,
                &policy,
                &anchors,
                1,
                std::slice::from_ref(&result_a),
                TRUST_FIXTURE_NOW + 1,
            )
            .expect_err("one result cannot satisfy two-runner quorum"),
            ModerationCommitteeAggregateError::QuorumNotSatisfied {
                found: 1,
                required: 2,
            }
        );
        assert!(matches!(
            ModerationCommitteeAggregateV1::aggregate_authenticated(
                &manifest,
                &policy,
                &anchors,
                1,
                &[result_a, result_b],
                TRUST_FIXTURE_NOW + 1,
            )
            .expect_err("committee cannot mix subjects"),
            ModerationCommitteeAggregateError::SubjectMismatch {
                field: "subject",
                ..
            }
        ));
    }
    #[test]
    fn provenance_log_roundtrips_and_detects_chain_tampering() {
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner_a = checked_random_keypair();
        let runner_b = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner_a, &runner_b], 2);
        let anchors = fixture_trust_anchors(&[&governance]);
        let result_a = sample_signed_result(
            &manifest,
            &policy,
            &runner_a,
            2_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        let result_b = sample_signed_result(
            &manifest,
            &policy,
            &runner_b,
            8_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        let aggregate = ModerationCommitteeAggregateV1::aggregate_authenticated(
            &manifest,
            &policy,
            &anchors,
            1,
            &[result_a.clone(), result_b],
            TRUST_FIXTURE_NOW + 1,
        )
        .expect("aggregate fixture");
        let mut log = ModerationProvenanceLogV1::new([0xA7; 16]).expect("new log");
        log.append(
            ModerationProvenancePayloadV1::SignedScreeningResult(result_a),
            TRUST_FIXTURE_NOW + 1,
        )
        .expect("append runner result");
        log.append(
            ModerationProvenancePayloadV1::CommitteeAggregate(aggregate),
            TRUST_FIXTURE_NOW + 2,
        )
        .expect("append committee aggregate");
        log.validate_chain().expect("valid provenance chain");
        let bytes = norito::encode_canonical(&log).expect("encode provenance");
        let decoded: ModerationProvenanceLogV1 =
            norito::decode_canonical(&bytes).expect("decode provenance");
        assert_eq!(decoded, log);
        let alternate = encode_with_alternate_norito_layout(&log);
        assert!(matches!(
            norito::decode_canonical::<ModerationProvenanceLogV1>(&alternate),
            Err(norito::Error::NonCanonicalEncoding)
        ));
        let mut predecessor_tamper = log.clone();
        predecessor_tamper.entries[1].previous_entry_digest = [0xFF; 32];
        assert_eq!(
            predecessor_tamper
                .validate_chain()
                .expect_err("predecessor tamper must be detected"),
            ModerationProvenanceError::PreviousDigestMismatch { index: 1 }
        );
        let mut payload_tamper = log.clone();
        let ModerationProvenancePayloadV1::SignedScreeningResult(result) =
            &mut payload_tamper.entries[0].payload
        else {
            panic!("first fixture payload is a result")
        };
        result.body.combined_score_bps ^= 1;
        assert_eq!(
            payload_tamper
                .validate_chain()
                .expect_err("embedded evidence digest tamper must be detected"),
            ModerationProvenanceError::PayloadDigestMismatch { index: 0 }
        );
        let mut head_tamper = log;
        head_tamper.head_digest = [0xAB; 32];
        assert_eq!(
            head_tamper
                .validate_chain()
                .expect_err("head tamper must be detected"),
            ModerationProvenanceError::HeadDigestMismatch
        );
    }
    #[test]
    fn provenance_log_rejects_zero_id_time_regression_and_capacity_overflow() {
        assert_eq!(
            ModerationProvenanceLogV1::new([0; 16]).expect_err("zero log id"),
            ModerationProvenanceError::MissingLogId
        );
        let manifest = sign_manifest(sample_body(), &["manifest-governance"]);
        let governance = checked_random_keypair();
        let runner = checked_random_keypair();
        let policy = sample_trust_policy(&manifest, &[&governance], &[&runner], 1);
        let result = sample_signed_result(
            &manifest,
            &policy,
            &runner,
            5_000,
            "cid:subject",
            TRUST_FIXTURE_NOW,
        );
        let mut log = ModerationProvenanceLogV1::new([1; 16]).expect("new log");
        assert!(matches!(
            log.append(
                ModerationProvenancePayloadV1::SignedScreeningResult(result.clone()),
                TRUST_FIXTURE_NOW - 1,
            )
            .expect_err("record cannot predate evidence"),
            ModerationProvenanceError::InvalidTimestamp { index: 0 }
        ));
        let mut oversized = ModerationProvenanceLogV1::new([2; 16]).expect("new log");
        let mut entry = ModerationProvenanceEntryV1 {
            sequence: 0,
            previous_entry_digest: [0; 32],
            entry_digest: [0; 32],
            recorded_at_unix: TRUST_FIXTURE_NOW,
            payload: ModerationProvenancePayloadV1::SignedScreeningResult(result),
        };
        entry.refresh_entry_digest().expect("entry digest");
        oversized.entries = vec![entry; MODERATION_PROVENANCE_MAX_ENTRIES_V1 + 1];
        assert_eq!(
            oversized
                .validate_chain()
                .expect_err("over-capacity log rejected before traversal"),
            ModerationProvenanceError::TooManyEntries {
                found: MODERATION_PROVENANCE_MAX_ENTRIES_V1 + 1,
                maximum: MODERATION_PROVENANCE_MAX_ENTRIES_V1,
            }
        );
    }
}

#[cfg(test)]
mod captured_moderation_schema_tests;
