//! Reusable hidden-function commitment and evaluation plumbing.
//!
//! Naming in this module is split deliberately:
//! - `ram_lfe` covers the outer hidden-function abstraction: commitments,
//!   public policy metadata, evaluation requests, outputs, and receipt-facing
//!   verification metadata.
//! - `BFV` names the Brakerski/Fan-Vercauteren homomorphic encryption backend
//!   used by some evaluators to process encrypted input.
//! - `ram_fhe`-prefixed profile/program names remain on the BFV side because
//!   they describe the encrypted execution machine, not the outer LFE layer.
//!
//! The current evaluators are:
//! - the historical committed `HKDF-SHA3-512` PRF backend,
//! - a BFV-backed secret affine evaluator that consumes BFV-encrypted input,
//! - and a BFV-backed secret programmed evaluator with an instruction-driven
//!   RAM-style encrypted state machine.
//!
//! The canonical V1 contract lives beside them: the three program classes and
//! exact plaintext semantics (`class`), the function identity with its query
//! limit, the policy and the commitment owners (`canonical`), the cleartext
//! reference interpreter (`reference`), the cleartext oracle of the normalizing
//! lowering (`normal_form`) and the heap owner of their fixed-size secrets
//! (`clearing`). `specs/ram_lfe_execution_proof.md` is its specification.
//! The backends above keep their own superseded policy and receipt bindings
//! until the tasks named at each `TODO` retire them.
use crate::{
    BFV_EXACT_EVALUATOR_MAX_MULTIPLICATIVE_DEPTH_U8, BfvAffineCircuit, BfvCiphertext, BfvError,
    BfvEvaluationKeyBundle, BfvIdentifierCiphertext, BfvIdentifierPublicParameters, BfvParameters,
    BfvRnsModulusChain, BfvSecretKey, Hash, RAM_LFE_BFV_IDENTIFIER_MAX_INPUT_BYTES,
    RAM_LFE_BFV_IDENTIFIER_SLOT_COUNT, RAM_LFE_BFV_PLAINTEXT_MODULUS, add_ciphertexts_rns_exact,
    add_plain_scalar, decrypt, decrypt_identifier, derive_identifier_key_material_from_seed,
    evaluate_affine_circuit, multiply_ciphertexts_rns_exact, multiply_plain_scalar,
    registered_bfv_parameter_digest, registered_bfv_rns_modulus_chain,
    subtract_ciphertexts_rns_exact, validate_registered_bfv_parameters,
};
use hex::FromHex as _;
use hkdf::Hkdf;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
#[cfg(feature = "json")]
use norito::derive::{JsonDeserialize, JsonSerialize};
#[cfg(feature = "json")]
use norito::json;
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use sha3::Sha3_512;
use std::{fmt, ops::Deref, str::FromStr, string::String, sync::Arc, vec::Vec};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};
mod affine_secret;
#[cfg(test)]
mod availability_tests;
use affine_secret::SecretAffineCircuit;
mod canonical;
mod class;
mod clearing;
mod initialization;
mod normal_form;
mod phone_control;
mod reference;
#[cfg(test)]
mod specification_tests;
mod trace;
pub use canonical::{
    RAM_LFE_V1_OUTPUT_LEAKAGE_BITS, RAM_LFE_V1_PRIVATE_CONTEXTS, RAM_LFE_V1_PUBLIC_DOMAINS,
    RamLfeAssociatedDataHashV1, RamLfeEncryptionKeyCommitmentV1, RamLfeEvaluationKeyCommitmentV1,
    RamLfeExecutionContextIdV1, RamLfeFunctionCommitmentV1, RamLfeFunctionIdV1,
    RamLfeFunctionIdentityV1, RamLfeInitializedMemoryCommitmentV1, RamLfeInitializerCommitmentV1,
    RamLfeInputCiphertextCommitmentV1, RamLfeOpeningKeyCommitmentV1, RamLfeOutputBlindingV1,
    RamLfeOutputCiphertextCommitmentV1, RamLfeOutputCommitmentV1, RamLfePolicyCommitmentV1,
    RamLfePolicyV1, RamLfePrfKeyCommitmentV1, RamLfeProfileIdV1, RamLfeProgramKeyV1,
    RamLfeQueryLimitV1, RamLfeRelationIdV1,
};
pub use class::{
    RAM_LFE_V1_BOUNDED_MAX_RANK, RAM_LFE_V1_INPUT_SLOTS, RAM_LFE_V1_MAX_INPUT_BYTES,
    RAM_LFE_V1_MAX_INSTRUCTIONS, RAM_LFE_V1_MAX_OUTPUTS, RAM_LFE_V1_PLAINTEXT_MODULUS,
    RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR, RAM_LFE_V1_REFRESH_MAX_RANK_BETWEEN_REFRESHES,
    RAM_LFE_V1_REFRESH_MAX_REFRESHES, RAM_LFE_V1_REGISTERS, RAM_LFE_V1_SELECT_BRANCH_RANK,
    RAM_LFE_V1_SELECT_CONDITION_RANK, RAM_LFE_V1_STATE_LANES, RamLfeClassReportV1, RamLfeClassV1,
    RamLfeOpcodeV1, RamLfeRefreshPointV1, ram_lfe_v1_plaintext_semantics_hash,
};
pub use initialization::{
    BFV_PROGRAM_INITIALIZER_DESCRIPTOR, RAM_LFE_PROGRAM_ASSOCIATED_DATA_MAX_BYTES,
    bfv_program_initializer_descriptor_hash,
};
pub use normal_form::{
    RAM_LFE_V1_NORMAL_BASE_COLUMNS, RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE,
    RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, RAM_LFE_V1_NORMAL_INPUT_COLUMN,
    RAM_LFE_V1_NORMAL_LANE_COLUMN, RamLfeNormalFormV1, RamLfeNormalGateKindV1, RamLfeNormalRoleV1,
    RamLfeNormalShapeV1, ram_lfe_reference_normalize_v1, ram_lfe_v1_centered_scalar,
};
pub use phone_control::{
    PHONE_CONTROL_V1_BLINDING_BYTES, PHONE_CONTROL_V1_CRYPTO_DOMAINS,
    PHONE_CONTROL_V1_NUMBER_BYTES, PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL,
    PHONE_CONTROL_V1_NUMBER_COMMITMENT_ROLE, PhoneControlError, PhoneControlProviderKeyIdV1,
    PhoneNumberBlindingV1, PhoneNumberCommitmentDigestV1, PhoneNumberCommitmentV1,
    PhoneNumberCommitmentValueV1, PhoneNumberV1, phone_control_provider_sign,
    phone_control_provider_verify,
};
pub use reference::{
    RAM_LFE_V1_TRACE_ROW_SCALARS, RamLfeInitialMemoryV1, RamLfeOrderedOutputV1,
    RamLfeReferenceExecutionV1, RamLfeReferenceInputV1, RamLfeReferenceTraceV1,
    ram_lfe_reference_evaluate_v1, ram_lfe_reference_execute_v1,
};
pub use trace::RamLfeProgramExecutionTrace;
use trace::{OwnedCiphertext, OwnedCiphertexts};
mod policy_secret;
mod program;
pub use program::{
    HiddenRamFheProgram, HiddenRamFheProgramBuilder, RAM_LFE_HIDDEN_PROGRAM_MAX_BYTES,
};

const POLICY_DOMAIN: &[u8] = b"iroha.ram_lfe.policy.v1";
const HKDF_SALT_DOMAIN: &[u8] = b"iroha.ram_lfe.hkdf_salt.hkdf_sha3_512_prf.v1";
const HKDF_OPAQUE_INFO_DOMAIN: &[u8] = b"iroha.ram_lfe.opaque_info.hkdf_sha3_512_prf.v1";
const HKDF_RECEIPT_INFO_DOMAIN: &[u8] = b"iroha.ram_lfe.receipt_info.hkdf_sha3_512_prf.v1";
const OPAQUE_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.opaque_hash.hkdf_sha3_512_prf.v1";
const RECEIPT_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.receipt_hash.hkdf_sha3_512_prf.v1";
const BFV_AFFINE_CIRCUIT_DOMAIN: &[u8] = b"iroha.ram_lfe.bfv_affine.circuit.v1";
const BFV_AFFINE_OPAQUE_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.bfv_affine.opaque_hash.v1";
const BFV_AFFINE_RECEIPT_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.bfv_affine.receipt_hash.v1";
const BFV_PROGRAM_OPAQUE_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.bfv_program.opaque_hash.v1";
const BFV_PROGRAM_RECEIPT_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.bfv_program.receipt_hash.v1";
const BFV_PROGRAM_DIGEST_DOMAIN: &[u8] = b"iroha.ram_lfe.bfv_program.digest.v1";
const RAM_FHE_OUTPUT_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.output_hash.v1";
const PHONE_RETAIL_NULLIFIER_DOMAIN: &[u8] = b"iroha.identifier.phone_retail.nullifier.v1";
const IDENTIFIER_OUTPUT_OPAQUE_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.identifier.opaque_hash.v1";
const IDENTIFIER_OUTPUT_RECEIPT_HASH_DOMAIN: &[u8] = b"iroha.ram_lfe.identifier.receipt_hash.v1";
const BFV_AFFINE_OUTPUT_BYTES: usize = Hash::LENGTH;
const BFV_PROGRAM_STATE_WIDTH: usize = initialization::LANES;
const BFV_PROGRAM_REGISTER_COUNT: usize = 4;
const BFV_PROGRAM_MIN_CIPHERTEXT_MODULUS: u64 = 1_u64 << 52;
const BFV_PROGRAM_REGISTER_COUNT_U16: u16 = 4;
const BFV_PROGRAM_STATE_WIDTH_U16: u16 = 32;
const BFV_PROGRAM_IDENTIFIER_SLOT_COUNT: usize = RAM_LFE_BFV_IDENTIFIER_SLOT_COUNT;
const BFV_PROGRAM_IDENTIFIER_SLOT_COUNT_U16: u16 = RAM_LFE_BFV_IDENTIFIER_MAX_INPUT_BYTES + 1;
const BFV_PROGRAM_MAX_INSTRUCTIONS: usize = BFV_PROGRAM_IDENTIFIER_SLOT_COUNT * 4;
const RAM_LFE_PROOF_BACKEND_MAX_BYTES: usize = 128;
const RAM_LFE_PROOF_CIRCUIT_ID_MAX_BYTES: usize = 256;
const RAM_LFE_PROOF_VERIFYING_KEY_MAX_BYTES: usize = 1_048_576;
const MAX_INPUT_BYTES: usize = 1_048_576;
/// Maximum hidden RAM-LFE secret size accepted by evaluators and runtime configuration.
pub const RAM_LFE_SECRET_MAX_BYTES: usize = 4096;
const RAM_LFE_SECRET_REDACTED: &str = "[REDACTED RAM-LFE secret]";
/// Validated, zeroizing hidden RAM-LFE secret material.
///
/// Clones share one allocation so passing configuration into a runtime does not leave additional
/// secret copies in memory. The allocation is zeroized when its final owner is dropped, and debug
/// formatting never exposes its contents.
#[derive(Clone, PartialEq, Eq)]
pub struct RamLfeSecret(Arc<Zeroizing<Vec<u8>>>);
impl RamLfeSecret {
    /// Borrow the validated secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    /// Return the secret length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Return whether this secret is empty.
    ///
    /// Constructed values are always non-empty; this method is provided for slice-like ergonomics.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for RamLfeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RAM_LFE_SECRET_REDACTED)
    }
}
impl AsRef<[u8]> for RamLfeSecret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl Deref for RamLfeSecret {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}
impl TryFrom<Vec<u8>> for RamLfeSecret {
    type Error = RamLfeSecretError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(RamLfeSecretError::Empty);
        }
        if bytes.len() > RAM_LFE_SECRET_MAX_BYTES {
            return Err(RamLfeSecretError::TooLarge {
                actual: bytes.len(),
                maximum: RAM_LFE_SECRET_MAX_BYTES,
            });
        }
        Ok(Self(Arc::new(bytes)))
    }
}
impl FromStr for RamLfeSecret {
    type Err = RamLfeSecretError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        let bytes = Vec::from_hex(value).map_err(RamLfeSecretError::InvalidHex)?;
        Self::try_from(bytes)
    }
}
#[cfg(feature = "json")]
impl json::JsonDeserialize for RamLfeSecret {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value: String = json::JsonDeserialize::json_deserialize(parser)?;
        let value = Zeroizing::new(value);
        value
            .parse()
            .map_err(|error: RamLfeSecretError| json::Error::Message(error.to_string()))
    }
}
/// Errors raised while constructing hidden RAM-LFE secret material.
#[derive(Debug, Clone, Copy, Error)]
pub enum RamLfeSecretError {
    /// The secret is empty.
    #[error("RAM-LFE secret must not be empty")]
    Empty,
    /// The secret exceeds the evaluator limit.
    #[error("RAM-LFE secret is {actual} bytes; maximum is {maximum} bytes")]
    TooLarge {
        /// Supplied secret length.
        actual: usize,
        /// Maximum accepted secret length.
        maximum: usize,
    },
    /// The configured secret is not valid hexadecimal.
    #[error("RAM-LFE secret is not valid hexadecimal: {0}")]
    InvalidHex(#[source] hex::FromHexError),
}
struct ProgramExecutionContext<'a> {
    params: &'a BfvParameters,
    evaluation_keys: &'a BfvEvaluationKeyBundle,
    rns_chain: &'a BfvRnsModulusChain,
}
/// Encrypted input profile applied before the programmed RAM-FHE backend executes.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "mode", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ram_lfe::BfvRamEncryptedInputMode")]
pub enum BfvRamEncryptedInputMode {
    /// Evaluators consume the submitted BFV envelope directly and never
    /// canonicalize it through resolver-side decryption.
    EncryptedEnvelopeV1,
}
// TODO(R.12): superseded by `RamLfeProfileIdV1` in the canonical policy; retire
// with the diagnostic BFV programmed backend.
/// Public RAM-FHE execution profile for the programmed BFV backend.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_crypto::ram_lfe::BfvRamProgramProfile")]
pub struct BfvRamProgramProfile {
    /// Stable profile version understood by the current evaluator.
    pub profile_version: u8,
    /// Number of ciphertext registers in the hidden execution machine.
    pub register_count: u16,
    /// Number of ciphertext memory lanes persisted across program steps.
    pub memory_lane_count: u16,
    /// Maximum ciphertext-ciphertext multiplications performed per step.
    pub ciphertext_mul_per_step: u8,
    /// Canonicalization mode for externally supplied encrypted input.
    pub encrypted_input_mode: BfvRamEncryptedInputMode,
    /// Minimum supported ciphertext modulus for this RAM-FHE profile.
    pub min_ciphertext_modulus: u64,
    /// Exact compiled secret-commitment and initialized-memory derivation contract.
    pub initializer_descriptor_hash: Hash,
}
// TODO(R.6): remove with the obsolete Signed execution mode. The canonical
// `RamLfePolicyV1` has no verification mode.
/// Receipt attestation mode published by a RAM-LFE program policy.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[norito(tag = "mode", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfeVerificationMode")]
pub enum RamLfeVerificationMode {
    /// Canonical payload bytes are signed by the configured resolver key.
    Signed,
    /// Reserved complete-program-execution proof mode, currently unavailable.
    /// Binding payload bytes to a proof alone does not establish execution.
    Proof,
}
// TODO(R.12): superseded by `RamLfeRelationIdV1`. A policy does not publish a
// caller-selected backend, circuit identifier or verifying key.
/// Public proof-verifier metadata published by proof-carrying RAM-LFE policies.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfeProofVerifierMetadata")]
pub struct RamLfeProofVerifierMetadata {
    /// Proof backend identifier understood by higher-layer verifiers.
    pub proof_backend: String,
    /// Stable circuit identifier bound to proof payloads.
    pub circuit_id: String,
    /// Stable hash of the proof public-input schema.
    pub public_inputs_schema_hash: Hash,
    /// Opaque verifying-key bytes published to clients for stateless verification.
    pub verifying_key_bytes: Vec<u8>,
}
/// Canonical branchless instruction for the hidden programmed RAM-FHE backend.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[norito(tag = "op", content = "args", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ram_lfe::HiddenRamFheInstruction")]
pub enum HiddenRamFheInstruction {
    /// Load one encrypted input byte slot into a register.
    LoadInput(u16, u16),
    /// Load a persisted encrypted state lane into a register.
    LoadState(u16, u16),
    /// Store a register back into a persisted encrypted state lane.
    StoreState(u16, u16),
    /// Load a canonical RAM-LFE plaintext-field constant into a register.
    LoadConst(u16, u64),
    /// Add two ciphertext registers.
    Add(u16, u16, u16),
    /// Add a canonical RAM-LFE plaintext-field scalar to a ciphertext register.
    AddPlain(u16, u16, u64),
    /// Subtract a canonical RAM-LFE plaintext-field scalar from a ciphertext register.
    SubPlain(u16, u16, u64),
    /// Multiply a ciphertext register by a canonical RAM-LFE plaintext-field scalar.
    MulPlain(u16, u16, u64),
    /// Multiply two ciphertext registers.
    Mul(u16, u16, u16),
    /// Select between two registers based on whether `condition == 0`.
    SelectEqZero(u16, u16, u16, u16),
    /// Append one ciphertext register to the encrypted output envelope.
    Output(u16),
}
// TODO(R.12): superseded by `RamLfePolicyV1`; retire with the diagnostic BFV
// programmed backend.
/// Public parameter bundle published by programmed BFV policies.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ram_lfe::BfvProgrammedPublicParameters")]
pub struct BfvProgrammedPublicParameters {
    /// BFV envelope parameters used to encrypt identifier bytes.
    pub encryption: BfvIdentifierPublicParameters,
    /// Public evaluation-key bundle used by RAM-FHE evaluators.
    ///
    /// First-release programmed policies consume only the relinearization key.
    /// Rotation and bootstrap refresh keys are governed by Soracloud FHE
    /// execution policies instead of identifier-program public metadata.
    pub evaluation_keys: BfvEvaluationKeyBundle,
    /// Stable digest of the hidden compiled program kept in runtime config.
    pub hidden_program_digest: Hash,
    /// Stable digest of the registered BFV parameter set.
    pub parameter_digest: Hash,
    /// Stable digest of the evaluation-key bundle.
    pub evaluation_key_digest: Hash,
    /// Public RAM-FHE execution profile consumed by clients and verifiers.
    pub ram_fhe_profile: BfvRamProgramProfile,
    /// Receipt verification mode enforced for this program policy.
    pub verification_mode: RamLfeVerificationMode,
    /// Optional verifier metadata published for proof-carrying receipts.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub proof_verifier: Option<RamLfeProofVerifierMetadata>,
}
// TODO(R.6): remove `HkdfSha3_512PrfV1` and its policy, evaluator and tag
// branches. R.12 retires the two diagnostic BFV tags when the canonical
// classes (`RamLfeClassV1`) have a genuine encrypted evaluator.
/// Supported RAM-LFE backends.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfeBackend")]
pub enum RamLfeBackend {
    /// HKDF-SHA3-512 commitment-bound PRF evaluator.
    HkdfSha3_512PrfV1,
    /// BFV-backed secret affine evaluator producing a 32-byte opaque seed.
    BfvAffineV1,
    /// BFV-backed stateful secret program with non-linear per-slot transforms.
    BfvProgrammedV1,
}
impl RamLfeBackend {
    /// Reject diagnostic encryption backends before production use or private work.
    ///
    /// The exact BFV profile uses plaintext-modulus-multiple noise with a
    /// ciphertext modulus divisible by the plaintext modulus. Reducing its
    /// public-key equation removes that noise; it is not private encryption.
    /// Signatures and execution proofs do not repair this algebraic disclosure.
    ///
    /// # Errors
    /// Returns [`RamLfeError::InsecureBfvProfile`] for either diagnostic BFV backend.
    pub fn require_production_support(self) -> Result<(), RamLfeError> {
        match self {
            Self::HkdfSha3_512PrfV1 => Ok(()),
            Self::BfvAffineV1 | Self::BfvProgrammedV1 => Err(RamLfeError::InsecureBfvProfile),
        }
    }
    /// Stable backend identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HkdfSha3_512PrfV1 => "hkdf-sha3-512-prf-v1",
            Self::BfvAffineV1 => "bfv-affine-v1",
            Self::BfvProgrammedV1 => "bfv-programmed-v1",
        }
    }
}
#[cfg(feature = "json")]
impl json::JsonSerialize for RamLfeBackend {
    fn json_serialize(&self, out: &mut String) {
        json::JsonSerialize::json_serialize(self.as_str(), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(self.as_str(), out)
    }
}
#[cfg(feature = "json")]
impl json::JsonDeserialize for RamLfeBackend {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value: String = json::JsonDeserialize::json_deserialize(parser)?;
        match value.as_str() {
            "hkdf-sha3-512-prf-v1" => Ok(Self::HkdfSha3_512PrfV1),
            "bfv-affine-v1" => Ok(Self::BfvAffineV1),
            "bfv-programmed-v1" => Ok(Self::BfvProgrammedV1),
            _ => Err(json::Error::Message(format!(
                "unsupported RAM-LFE backend `{value}`"
            ))),
        }
    }
}
// TODO(R.12): superseded by `RamLfePolicyV1` and `RamLfePolicyCommitmentV1`.
// This record binds opaque public-parameter bytes and one secret commitment.
/// Public commitment to a hidden identifier-derivation policy.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::PolicyCommitment")]
pub struct PolicyCommitment {
    /// Backend used to evaluate the hidden policy.
    pub backend: RamLfeBackend,
    /// Commitment digest tying the hidden evaluator secret to public metadata.
    pub policy_hash: Hash,
    /// Public policy metadata consumed by wallets and verifier code.
    #[norito(default)]
    pub public_parameters: Vec<u8>,
}
/// Client request submitted to a RAM-LFE evaluator.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::ClientRequest")]
pub struct ClientRequest {
    /// Backend-specific request payload.
    pub normalized_input: Vec<u8>,
    /// Public associated data bound into the derivation.
    #[norito(default)]
    pub associated_data: Vec<u8>,
}
// TODO(R.12): replace with a typed ciphertext result and a separate verified
// opening. No encrypted backend returns plaintext.
/// Deterministic RAM-LFE evaluation output.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::EvalResponse")]
pub struct EvalResponse {
    /// Backend output bytes; diagnostic programmed evaluation produces ciphertext.
    pub output: Vec<u8>,
    /// Opaque identifier derived by the hidden policy.
    pub opaque_id: Hash,
    /// Receipt digest that higher layers can sign or attest to.
    pub receipt_hash: Hash,
    /// Backend that produced the output.
    pub backend: RamLfeBackend,
}
/// Errors raised by the RAM-LFE plumbing layer.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RamLfeError {
    /// The diagnostic exact-lift BFV profile cannot protect private plaintext.
    #[error(
        "encrypted RAM-LFE is unavailable: the diagnostic exact-lift BFV profile exposes a noiseless public-key equation and must be replaced"
    )]
    InsecureBfvProfile,
    /// The supplied input must not be empty.
    #[error("normalized input must not be empty")]
    EmptyInput,
    /// The supplied input exceeded the backend limit.
    #[error("normalized input exceeds the maximum supported length")]
    InputTooLarge,
    /// The hidden policy secret must not be empty.
    #[error("policy secret must not be empty")]
    EmptySecret,
    /// The hidden policy secret exceeded the backend limit.
    #[error("policy secret exceeds the maximum supported length")]
    SecretTooLarge,
    /// The hidden secret does not match the published commitment.
    #[error("policy secret does not match the published commitment")]
    CommitmentMismatch,
    /// The hidden compiled program does not match the published program digest.
    #[error("hidden program digest does not match the published commitment")]
    HiddenProgramMismatch,
    /// Norito failed to encode an internal transcript.
    #[error("policy transcript encoding failed: {0}")]
    TranscriptEncoding(String),
    /// HKDF failed to expand the requested output material.
    #[error("HKDF expansion failed")]
    DerivationFailed,
    /// BFV evaluation failed.
    #[error("BFV evaluation failed: {0}")]
    Bfv(String),
    /// The selected backend is not supported by the evaluator.
    #[error("unsupported RAM-LFE backend `{0}`")]
    UnsupportedBackend(String),
    /// A phone nullifier may only be derived from an exact canonical E.164 value.
    #[error("phone nullifier requires canonical E.164 input")]
    NonCanonicalPhone,
    /// The private phone-nullifier key must carry at least 256 bits of entropy.
    #[error("phone nullifier secret must be at least 32 bytes")]
    WeakPhoneNullifierSecret,
    /// The declared class does not admit an instruction of the hidden program.
    #[error("instruction {instruction} ({opcode}) is not admitted by RAM-LFE class {class}")]
    InstructionOutsideClass {
        /// Declared class.
        class: RamLfeClassV1,
        /// Index of the offending instruction in the hidden tape.
        instruction: usize,
        /// Opcode the class does not admit.
        opcode: RamLfeOpcodeV1,
    },
    /// A value of the hidden program exceeds the class's logical rank.
    #[error(
        "instruction {instruction} reaches logical rank {rank}; RAM-LFE class {class} allows {limit}"
    )]
    ClassRankExceeded {
        /// Declared class.
        class: RamLfeClassV1,
        /// Index of the offending instruction in the hidden tape.
        instruction: usize,
        /// Logical rank the instruction's result would reach.
        rank: u16,
        /// Maximum logical rank of the class.
        limit: u16,
    },
    /// The canonical refresh schedule needs more refreshes than the class allows.
    #[error(
        "instruction {instruction} needs another refresh; RAM-LFE class {class} allows {limit} in total"
    )]
    ClassRefreshLimitExceeded {
        /// Declared class.
        class: RamLfeClassV1,
        /// Index of the instruction that required the refresh.
        instruction: usize,
        /// Maximum number of refreshes of the class.
        limit: u16,
    },
    /// A canonical V1 value is malformed.
    #[error("invalid RAM-LFE V1 value: {0}")]
    InvalidCanonicalValue(&'static str),
    /// The operating-system random source failed.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// The function identity has accepted every receipt its query limit allows.
    #[error(
        "RAM-LFE query limit exhausted: the function identity already accepted {limit} receipts"
    )]
    ReceiptLimitExhausted {
        /// Committed lifetime total of the function identity.
        limit: u64,
    },
    /// The beneficiary has had every opening the query limit allows.
    #[error("RAM-LFE query limit exhausted: the beneficiary already had {limit} openings")]
    BeneficiaryOpeningLimitExhausted {
        /// Committed lifetime limit of one beneficiary.
        limit: u32,
    },
    /// An opening was requested by an account other than the receipt's beneficiary.
    #[error("only the beneficiary of a RAM-LFE receipt may request its opening")]
    UnauthorizedOpeningRequester,
}

/// Derive a stable, non-enumerable retail-phone nullifier after canonicalization.
///
/// The attestor must retain the same secret for the lifetime of the pinned policy.
/// The signed canonicality statement is the consensus-visible proof that this
/// private derivation was performed for the encrypted input.
///
/// TODO: Expose this operation through a separately deployed attestor that
/// pins its decryption key and nullifier secret for the policy lifetime.
///
/// # Errors
///
/// Returns [`RamLfeError::NonCanonicalPhone`] unless `canonical_phone` is exact
/// E.164 (`+`, a nonzero leading digit, 2..=15 digits in total),
/// [`RamLfeError::WeakPhoneNullifierSecret`] when `secret` is shorter than 32
/// bytes, and [`RamLfeError::DerivationFailed`] if HKDF expansion fails.
pub fn derive_phone_retail_nullifier_v1(
    secret: &[u8],
    network_id: &[u8; Hash::LENGTH],
    canonical_phone: &str,
) -> Result<Hash, RamLfeError> {
    let bytes = canonical_phone.as_bytes();
    if bytes.len() < 3
        || bytes.len() > 16
        || bytes[0] != b'+'
        || !matches!(bytes[1], b'1'..=b'9')
        || !bytes[2..].iter().all(u8::is_ascii_digit)
    {
        return Err(RamLfeError::NonCanonicalPhone);
    }
    if secret.len() < Hash::LENGTH {
        return Err(RamLfeError::WeakPhoneNullifierSecret);
    }
    let hkdf = Hkdf::<Sha3_512>::new(Some(network_id), secret);
    let mut material = Zeroizing::new([0_u8; Hash::LENGTH]);
    let info = Zeroizing::new([PHONE_RETAIL_NULLIFIER_DOMAIN, canonical_phone.as_bytes()].concat());
    hkdf.expand(&info, material.as_mut())
        .map_err(|_| RamLfeError::DerivationFailed)?;
    Ok(Hash::prehashed(*material))
}

/// Decrypt a BFV input at the trusted attestor boundary and derive its phone
/// nullifier only if the encrypted plaintext itself is exact canonical E.164.
/// The plaintext remains local to the attestor and is never a ledger field.
///
/// # Errors
///
/// Returns [`RamLfeError::Bfv`] when decryption fails,
/// [`RamLfeError::NonCanonicalPhone`] when the plaintext is not UTF-8 canonical
/// E.164, and any error of [`derive_phone_retail_nullifier_v1`].
pub fn derive_phone_retail_nullifier_from_ciphertext_v1(
    public_parameters: &BfvIdentifierPublicParameters,
    secret_key: &BfvSecretKey,
    ciphertext: &BfvIdentifierCiphertext,
    nullifier_secret: &[u8],
    network_id: &[u8; Hash::LENGTH],
) -> Result<Hash, RamLfeError> {
    let plaintext = Zeroizing::new(
        decrypt_identifier(public_parameters, secret_key, ciphertext)
            .map_err(|err| RamLfeError::Bfv(err.to_string()))?,
    );
    let phone = std::str::from_utf8(&plaintext).map_err(|_| RamLfeError::NonCanonicalPhone)?;
    derive_phone_retail_nullifier_v1(nullifier_secret, network_id, phone)
}

#[cfg(test)]
mod phone_retail_nullifier_tests {
    use super::*;
    use crate::{encrypt_identifier_from_seed, ram_lfe_bfv_parameters_v1};

    #[test]
    fn canonical_phone_nullifier_is_stable_and_network_scoped() {
        let secret = [0xA5; 32];
        let first = derive_phone_retail_nullifier_v1(&secret, &[1; 32], "+15551234567")
            .expect("canonical phone");
        assert_eq!(
            first,
            derive_phone_retail_nullifier_v1(&secret, &[1; 32], "+15551234567").unwrap()
        );
        assert_ne!(
            first,
            derive_phone_retail_nullifier_v1(&secret, &[2; 32], "+15551234567").unwrap()
        );
        assert_ne!(
            first,
            derive_phone_retail_nullifier_v1(&secret, &[1; 32], "+15551234568").unwrap()
        );
        for invalid in ["15551234567", "+05551234567", "+1", "+1555 1234567"] {
            assert_eq!(
                derive_phone_retail_nullifier_v1(&secret, &[1; 32], invalid),
                Err(RamLfeError::NonCanonicalPhone)
            );
        }
        assert_eq!(
            derive_phone_retail_nullifier_v1(&[1; 31], &[1; 32], "+15551234567"),
            Err(RamLfeError::WeakPhoneNullifierSecret)
        );
    }
    #[test]
    fn independently_encrypted_same_phone_has_one_nullifier() {
        let (parameters, decryption_key, _) = derive_identifier_key_material_from_seed(
            &ram_lfe_bfv_parameters_v1(),
            63,
            b"phone-program-secret",
            b"phone_retail",
        )
        .expect("derive attestor decryption key");
        let encrypt = |phone: &[u8], seed: &[u8]| {
            encrypt_identifier_from_seed(&parameters, phone, seed).expect("encrypt phone")
        };
        let first = encrypt(b"+15551234567", b"phone-encryption-one");
        let second = encrypt(b"+15551234567", b"phone-encryption-two");
        assert_ne!(first, second, "BFV encryption is randomized");
        let derive = |ciphertext: &BfvIdentifierCiphertext| {
            derive_phone_retail_nullifier_from_ciphertext_v1(
                &parameters,
                &decryption_key,
                ciphertext,
                &[0xC3; 32],
                &[7; 32],
            )
        };
        assert_eq!(derive(&first).unwrap(), derive(&second).unwrap());
        for invalid in [b"15551234567".as_slice(), b"+1", b"+1555 1234567"] {
            assert_eq!(
                derive(&encrypt(invalid, b"invalid-phone-seed")),
                Err(RamLfeError::NonCanonicalPhone)
            );
        }
    }
}
/// Runtime evaluator interface for hidden-function services.
pub trait Evaluator: Send + Sync {
    /// Evaluate a request against the supplied policy commitment.
    ///
    /// # Errors
    /// Returns [`RamLfeError`] when the request, commitment, or backend
    /// evaluation fails validation.
    fn evaluate(
        &self,
        commitment: &PolicyCommitment,
        request: &ClientRequest,
    ) -> Result<EvalResponse, RamLfeError>;
}
/// Construct the commitment record for the built-in HKDF-SHA3-512 backend.
///
/// # Errors
/// Returns [`RamLfeError`] when the secret or public transcript is invalid.
pub fn policy_commitment(
    secret: &[u8],
    public_parameters: Vec<u8>,
) -> Result<PolicyCommitment, RamLfeError> {
    build_policy_commitment(secret, public_parameters, RamLfeBackend::HkdfSha3_512PrfV1)
}
/// Return the default public execution profile for the programmed BFV backend.
#[must_use]
pub fn bfv_program_profile() -> BfvRamProgramProfile {
    BfvRamProgramProfile {
        profile_version: 1,
        register_count: BFV_PROGRAM_REGISTER_COUNT_U16,
        memory_lane_count: BFV_PROGRAM_STATE_WIDTH_U16,
        ciphertext_mul_per_step: BFV_EXACT_EVALUATOR_MAX_MULTIPLICATIVE_DEPTH_U8,
        encrypted_input_mode: BfvRamEncryptedInputMode::EncryptedEnvelopeV1,
        min_ciphertext_modulus: BFV_PROGRAM_MIN_CIPHERTEXT_MODULUS,
        initializer_descriptor_hash: bfv_program_initializer_descriptor_hash(),
    }
}
/// Return the compiled default hidden program for the identifier-programmed backend.
#[must_use]
pub fn default_bfv_programmed_hidden_program() -> HiddenRamFheProgram {
    let mut builder = HiddenRamFheProgram::builder().expect("bounded default program allocation");
    for slot in 0..BFV_PROGRAM_IDENTIFIER_SLOT_COUNT_U16 {
        let lane = slot % BFV_PROGRAM_STATE_WIDTH_U16;
        for instruction in [
            HiddenRamFheInstruction::LoadInput(0, slot),
            HiddenRamFheInstruction::LoadState(1, lane),
            HiddenRamFheInstruction::Add(2, 0, 1),
            HiddenRamFheInstruction::Output(2),
        ] {
            builder
                .push(instruction)
                .expect("fixed default program capacity");
        }
    }
    builder.finish().expect("compiled default program is valid")
}
/// Hash arbitrary RAM-LFE output bytes into a stable digest.
#[must_use]
pub fn ram_lfe_output_hash(output: &[u8]) -> Hash {
    Hash::new_from_chunks(&[RAM_FHE_OUTPUT_HASH_DOMAIN, output])
}
/// Derive the identifier-facing opaque id and receipt hash from engine output bytes.
#[must_use]
pub fn identifier_hashes_from_program_output(program_id: &[u8], output: &[u8]) -> (Hash, Hash) {
    identifier_hashes_from_output_hash(program_id, &ram_lfe_output_hash(output))
}
/// Derive the identifier-facing opaque id and receipt hash from a precomputed output hash.
#[must_use]
pub fn identifier_hashes_from_output_hash(program_id: &[u8], output_hash: &Hash) -> (Hash, Hash) {
    let opaque_id = Hash::new_from_chunks(&[
        IDENTIFIER_OUTPUT_OPAQUE_HASH_DOMAIN,
        program_id,
        output_hash.as_ref(),
    ]);
    let receipt_hash = Hash::new_from_chunks(&[
        IDENTIFIER_OUTPUT_RECEIPT_HASH_DOMAIN,
        program_id,
        output_hash.as_ref(),
        opaque_id.as_ref(),
    ]);
    (opaque_id, receipt_hash)
}
/// Fallibly wrap BFV identifier-encryption parameters into the programmed RAM-FHE public bundle.
///
/// # Errors
/// Returns [`RamLfeError`] when the encryption parameters are not registered
/// production BFV parameters or the evaluation-key metadata is invalid.
pub fn try_bfv_programmed_public_parameters(
    encryption: BfvIdentifierPublicParameters,
    evaluation_keys: BfvEvaluationKeyBundle,
) -> Result<BfvProgrammedPublicParameters, RamLfeError> {
    try_bfv_programmed_public_parameters_with_program(
        encryption,
        evaluation_keys,
        &default_bfv_programmed_hidden_program(),
        RamLfeVerificationMode::Signed,
        None,
    )
}
/// Fallibly wrap BFV identifier-encryption parameters and explicit hidden-program metadata.
///
/// # Errors
/// Returns [`RamLfeError`] when the encryption parameters are not registered
/// production BFV parameters, the evaluation keys are not valid for the
/// programmed backend, or the hidden-program/proof metadata fails admission.
pub fn try_bfv_programmed_public_parameters_with_program(
    encryption: BfvIdentifierPublicParameters,
    evaluation_keys: BfvEvaluationKeyBundle,
    program: &HiddenRamFheProgram,
    verification_mode: RamLfeVerificationMode,
    proof_verifier: Option<RamLfeProofVerifierMetadata>,
) -> Result<BfvProgrammedPublicParameters, RamLfeError> {
    encryption.validate().map_err(|err| map_bfv_error(&err))?;
    validate_programmed_evaluation_keys(&evaluation_keys)?;
    validate_hidden_ram_fhe_program(program)?;
    validate_programmed_encryption_capacity(&encryption)?;
    validate_hidden_program_input_slots(program, encryption.max_input_bytes)?;
    validate_proof_verifier_metadata(verification_mode, proof_verifier.as_ref())?;
    let parameter_digest = registered_bfv_parameter_digest(&encryption.parameters)
        .map_err(|err| map_bfv_error(&err))?;
    let evaluation_key_digest = evaluation_keys
        .digest(&encryption.parameters)
        .map_err(|err| map_bfv_error(&err))?;
    Ok(BfvProgrammedPublicParameters {
        encryption,
        evaluation_keys,
        hidden_program_digest: program
            .digest()
            .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?,
        parameter_digest,
        evaluation_key_digest,
        ram_fhe_profile: bfv_program_profile(),
        verification_mode,
        proof_verifier,
    })
}
/// Decode programmed BFV public parameters.
///
/// # Errors
/// Returns [`RamLfeError`] when the public parameter payload is malformed.
pub fn decode_bfv_programmed_public_parameters(
    public_parameters: &[u8],
) -> Result<BfvProgrammedPublicParameters, RamLfeError> {
    let value: BfvProgrammedPublicParameters = norito::decode_from_bytes(public_parameters)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    value
        .encryption
        .validate()
        .map_err(|err| map_bfv_error(&err))?;
    validate_programmed_profile(&value.ram_fhe_profile)?;
    validate_programmed_public_parameters(&value)?;
    validate_proof_verifier_metadata(value.verification_mode, value.proof_verifier.as_ref())?;
    Ok(value)
}
/// Construct the commitment record for the BFV secret affine backend.
///
/// # Errors
/// Returns [`RamLfeError`] when the secret or public transcript is invalid.
pub fn bfv_affine_policy_commitment(
    secret: &[u8],
    public_parameters: &[u8],
) -> Result<PolicyCommitment, RamLfeError> {
    let decoded = decode_bfv_public_parameters(public_parameters)?;
    let canonical_public_parameters = norito::encode_canonical(&decoded)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    build_policy_commitment(
        secret,
        canonical_public_parameters,
        RamLfeBackend::BfvAffineV1,
    )
}
/// Construct the commitment record for the BFV programmed backend.
///
/// # Errors
/// Returns [`RamLfeError`] when the secret or public transcript is invalid.
pub fn bfv_programmed_policy_commitment(
    secret: &[u8],
    public_parameters: &[u8],
) -> Result<PolicyCommitment, RamLfeError> {
    bfv_programmed_policy_commitment_with_program(
        secret,
        public_parameters,
        &default_bfv_programmed_hidden_program(),
    )
}
/// Construct the commitment record for an explicit hidden BFV program.
///
/// # Errors
/// Returns [`RamLfeError`] when the secret, public transcript, or program is invalid.
pub fn bfv_programmed_policy_commitment_with_program(
    secret: &[u8],
    public_parameters: &[u8],
    program: &HiddenRamFheProgram,
) -> Result<PolicyCommitment, RamLfeError> {
    validate_hidden_program(program)?;
    let expected_digest = program
        .digest()
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    let decoded = decode_bfv_programmed_public_parameters(public_parameters)?;
    if decoded.hidden_program_digest != expected_digest {
        return Err(RamLfeError::CommitmentMismatch);
    }
    validate_hidden_program_input_slots(program, decoded.encryption.max_input_bytes)?;
    let canonical_public_parameters = norito::encode_canonical(&decoded)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    build_policy_commitment(
        secret,
        canonical_public_parameters,
        RamLfeBackend::BfvProgrammedV1,
    )
}
// Each transcript has one explicit first-release frame identity. Slice-backed
// fields borrow their data while keeping encoding independent of Rust references.
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::PolicyCommitmentInputV1",
    frame = "iroha_crypto::ram_lfe::PolicyCommitmentInputV1"
)]
struct PolicyCommitmentInputV1<'a> {
    backend: RamLfeBackend,
    public_parameters: &'a [u8],
    secret_commitment: [u8; 32],
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::HkdfRequestInputV1",
    frame = "iroha_crypto::ram_lfe::HkdfRequestInputV1"
)]
struct HkdfRequestInputV1<'a> {
    policy_hash: Hash,
    public_parameters: &'a [u8],
    associated_data: &'a [u8],
    normalized_input: &'a [u8],
}

fn build_policy_commitment(
    secret: &[u8],
    public_parameters: Vec<u8>,
    backend: RamLfeBackend,
) -> Result<PolicyCommitment, RamLfeError> {
    let secret_commitment = policy_secret::commit(backend, secret)?;
    let transcript = norito::encode_canonical(&PolicyCommitmentInputV1 {
        backend,
        public_parameters: &public_parameters,
        secret_commitment,
    })
    .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    let policy_hash = Hash::new_from_chunks(&[POLICY_DOMAIN, transcript.as_slice()]);
    Ok(PolicyCommitment {
        backend,
        policy_hash,
        public_parameters,
    })
}
/// Evaluate a request using the commitment-bound HKDF-SHA3-512 backend.
///
/// # Errors
/// Rejects both diagnostic BFV backends before inspecting private inputs.
/// Returns [`RamLfeError`] when the secret, commitment, request, or backend
/// transcript fails validation.
pub fn evaluate_commitment(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<EvalResponse, RamLfeError> {
    commitment.backend.require_production_support()?;
    evaluate_diagnostic_commitment_with_hidden_program(secret, commitment, request, None)
}

// Retain exact arithmetic regression coverage without publishing a production
// bypass. This private helper cannot authorize a policy, receipt or opening.
#[cfg(test)]
fn evaluate_diagnostic_commitment(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<EvalResponse, RamLfeError> {
    evaluate_diagnostic_commitment_with_hidden_program(
        secret,
        commitment,
        request,
        Some(&default_bfv_programmed_hidden_program()),
    )
}
/// Evaluate a request using an explicit hidden program for programmed policies.
///
/// For non-programmed backends, `program` is ignored.
///
/// # Errors
/// Rejects both diagnostic BFV backends before inspecting private inputs.
/// Returns [`RamLfeError`] when the secret, commitment, request, or backend
/// transcript fails validation.
pub fn evaluate_commitment_with_hidden_program(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
    program: Option<&HiddenRamFheProgram>,
) -> Result<EvalResponse, RamLfeError> {
    commitment.backend.require_production_support()?;
    evaluate_diagnostic_commitment_with_hidden_program(secret, commitment, request, program)
}

fn evaluate_diagnostic_commitment_with_hidden_program(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
    program: Option<&HiddenRamFheProgram>,
) -> Result<EvalResponse, RamLfeError> {
    validate_secret(secret)?;
    validate_request(request)?;
    match commitment.backend {
        RamLfeBackend::HkdfSha3_512PrfV1 => evaluate_hkdf_prf(secret, commitment, request),
        RamLfeBackend::BfvAffineV1 => evaluate_bfv_affine(secret, commitment, request),
        RamLfeBackend::BfvProgrammedV1 => evaluate_bfv_programmed(
            secret,
            commitment,
            request,
            program.ok_or_else(|| {
                RamLfeError::UnsupportedBackend(
                    "missing hidden program for programmed BFV backend".to_owned(),
                )
            })?,
        ),
    }
}
/// Validate a hidden BFV RAM-FHE program against the first-release profile.
///
/// # Errors
/// Returns [`RamLfeError`] when the program version, shape, register use, memory use, output shape,
/// plaintext immediate encoding, or accumulated multiplicative depth exceeds the published profile.
pub fn validate_hidden_ram_fhe_program(program: &HiddenRamFheProgram) -> Result<(), RamLfeError> {
    validate_hidden_program(program)
}
fn evaluate_hkdf_prf(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<EvalResponse, RamLfeError> {
    let expected = policy_commitment(secret, commitment.public_parameters.clone())?;
    if expected.policy_hash != commitment.policy_hash {
        return Err(RamLfeError::CommitmentMismatch);
    }
    let transcript = hkdf_request_transcript(expected.policy_hash, commitment, request)?;
    let hkdf_salt = [HKDF_SALT_DOMAIN, expected.policy_hash.as_ref()].concat();
    let hkdf = Hkdf::<Sha3_512>::new(Some(&hkdf_salt), secret);
    let mut opaque_material = Zeroizing::new([0_u8; Hash::LENGTH]);
    hkdf.expand_multi_info(
        &[HKDF_OPAQUE_INFO_DOMAIN, transcript.as_slice()],
        opaque_material.as_mut(),
    )
    .map_err(|_| RamLfeError::DerivationFailed)?;
    let opaque_id = Hash::new_from_chunks(&[OPAQUE_HASH_DOMAIN, &opaque_material[..]]);
    let mut receipt_material = Zeroizing::new([0_u8; Hash::LENGTH]);
    hkdf.expand_multi_info(
        &[
            HKDF_RECEIPT_INFO_DOMAIN,
            transcript.as_slice(),
            opaque_id.as_ref(),
        ],
        receipt_material.as_mut(),
    )
    .map_err(|_| RamLfeError::DerivationFailed)?;
    let receipt_hash = Hash::new_from_chunks(&[
        RECEIPT_HASH_DOMAIN,
        &receipt_material[..],
        opaque_id.as_ref(),
    ]);
    Ok(EvalResponse {
        output: request.normalized_input.clone(),
        opaque_id,
        receipt_hash,
        backend: commitment.backend,
    })
}
// Borrow request fields and write directly into one preallocated clearing owner.
// Neither a failed frame write nor HKDF expansion leaves an owned input copy.
// HKDF's internal state and compiler-created copies have separate erasure limits.
fn hkdf_request_transcript(
    policy_hash: Hash,
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<Zeroizing<Vec<u8>>, RamLfeError> {
    let value = HkdfRequestInputV1 {
        policy_hash,
        public_parameters: &commitment.public_parameters,
        associated_data: &request.associated_data,
        normalized_input: &request.normalized_input,
    };
    let length = norito::canonical_frame_len(&value)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    bytes.resize(length, 0);
    let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
    norito::core::write_canonical_to_writer(&value, &mut writer)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    if writer.position() != u64::try_from(length).expect("allocated frame length fits u64") {
        return Err(RamLfeError::TranscriptEncoding(
            "canonical frame length changed".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "ram_lfe/canonical_transcript_tests.rs"]
mod canonical_transcript_tests;

fn evaluate_bfv_affine(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<EvalResponse, RamLfeError> {
    let expected = bfv_affine_policy_commitment(secret, &commitment.public_parameters)?;
    if expected.policy_hash != commitment.policy_hash {
        return Err(RamLfeError::CommitmentMismatch);
    }
    let public_parameters = decode_bfv_public_parameters(&commitment.public_parameters)?;
    let (derived_public_parameters, secret_key, _) = derive_identifier_key_material_from_seed(
        &public_parameters.parameters,
        public_parameters.max_input_bytes,
        secret,
        &request.associated_data,
    )
    .map_err(|err| map_bfv_error(&err))?;
    if derived_public_parameters != public_parameters {
        return Err(RamLfeError::CommitmentMismatch);
    }
    let ciphertext: BfvIdentifierCiphertext = norito::decode_from_bytes(&request.normalized_input)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    let circuit = derive_secret_affine_circuit(secret, &public_parameters, commitment, request)?;
    let outputs =
        evaluate_affine_circuit(&public_parameters.parameters, &circuit, &ciphertext.slots)
            .map_err(|err| map_bfv_error(&err))?;
    let output_bytes = decrypt_affine_outputs(&public_parameters, &secret_key, &outputs)?;
    let opaque_id = Hash::new_from_chunks(&[
        BFV_AFFINE_OPAQUE_HASH_DOMAIN,
        commitment.policy_hash.as_ref(),
        output_bytes.as_slice(),
    ]);
    let receipt_hash = Hash::new_from_chunks(&[
        BFV_AFFINE_RECEIPT_HASH_DOMAIN,
        commitment.policy_hash.as_ref(),
        output_bytes.as_slice(),
        opaque_id.as_ref(),
    ]);
    Ok(EvalResponse {
        output: output_bytes,
        opaque_id,
        receipt_hash,
        backend: commitment.backend,
    })
}
fn evaluate_bfv_programmed(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
    program: &HiddenRamFheProgram,
) -> Result<EvalResponse, RamLfeError> {
    evaluate_bfv_programmed_inner(secret, commitment, request, program, None)
}

/// Evaluate a programmed policy and return clearing private execution snapshots.
///
/// This runs the same interpreter as ordinary evaluation. The trace is sensitive
/// witness material, not an execution proof or a receipt authorization.
///
/// # Errors
/// Rejects the current diagnostic BFV profile before private work. No production
/// programmed trace is available until the encryption profile is replaced.
pub fn evaluate_programmed_with_trace(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
    program: &HiddenRamFheProgram,
) -> Result<(EvalResponse, RamLfeProgramExecutionTrace), RamLfeError> {
    commitment.backend.require_production_support()?;
    evaluate_diagnostic_programmed_with_trace(secret, commitment, request, program)
}

fn evaluate_diagnostic_programmed_with_trace(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
    program: &HiddenRamFheProgram,
) -> Result<(EvalResponse, RamLfeProgramExecutionTrace), RamLfeError> {
    validate_secret(secret)?;
    validate_request(request)?;
    if commitment.backend != RamLfeBackend::BfvProgrammedV1 {
        return Err(RamLfeError::UnsupportedBackend(
            "execution tracing requires a programmed BFV policy".to_owned(),
        ));
    }
    let mut trace = None;
    let response =
        evaluate_bfv_programmed_inner(secret, commitment, request, program, Some(&mut trace))?;
    Ok((
        response,
        trace.expect("successful traced interpreter initializes its trace"),
    ))
}

fn evaluate_bfv_programmed_inner(
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
    program: &HiddenRamFheProgram,
    trace_output: Option<&mut Option<RamLfeProgramExecutionTrace>>,
) -> Result<EvalResponse, RamLfeError> {
    initialization::validate_associated_data(&request.associated_data)?;
    let expected = bfv_programmed_policy_commitment_with_program(
        secret,
        &commitment.public_parameters,
        program,
    )?;
    if expected.policy_hash != commitment.policy_hash {
        return Err(RamLfeError::CommitmentMismatch);
    }
    let public_parameters = decode_bfv_programmed_public_parameters(&commitment.public_parameters)?;
    let encryption = &public_parameters.encryption;
    let ciphertext: BfvIdentifierCiphertext = norito::decode_from_bytes(&request.normalized_input)
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    if ciphertext.slots.is_empty() {
        return Err(RamLfeError::EmptyInput);
    }
    let expected_slots = usize::from(encryption.max_input_bytes).saturating_add(1);
    if ciphertext.slots.len() != expected_slots {
        return Err(RamLfeError::Bfv(format!(
            "identifier ciphertext expected {expected_slots} slots, found {}",
            ciphertext.slots.len()
        )));
    }
    for slot in &ciphertext.slots {
        crate::fhe_bfv::validate_ciphertext(&encryption.parameters, slot)
            .map_err(|error| map_bfv_error(&error))?;
    }
    let inputs = OwnedCiphertexts::from_vec(ciphertext.slots);
    let expected_digest = program
        .digest()
        .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    if expected_digest != public_parameters.hidden_program_digest {
        return Err(RamLfeError::HiddenProgramMismatch);
    }
    let mut state = derive_program_initial_state(
        &encryption.parameters,
        &inputs[0],
        secret,
        commitment,
        request,
    )?;
    let rns_chain = registered_bfv_rns_modulus_chain(&encryption.parameters)
        .map_err(|err| map_bfv_error(&err))?;
    let execution = ProgramExecutionContext {
        params: &encryption.parameters,
        evaluation_keys: &public_parameters.evaluation_keys,
        rns_chain: &rns_chain,
    };
    let mut trace = trace_output
        .as_ref()
        .map(|_| RamLfeProgramExecutionTrace::new())
        .transpose()?;
    let output_bytes =
        execute_hidden_program(&execution, program, &inputs, &mut state, trace.as_mut())?;
    let opaque_id = Hash::new_from_chunks(&[
        BFV_PROGRAM_OPAQUE_HASH_DOMAIN,
        commitment.policy_hash.as_ref(),
        output_bytes.as_slice(),
    ]);
    let receipt_hash = Hash::new_from_chunks(&[
        BFV_PROGRAM_RECEIPT_HASH_DOMAIN,
        commitment.policy_hash.as_ref(),
        output_bytes.as_slice(),
        opaque_id.as_ref(),
    ]);
    if let Some(destination) = trace_output {
        *destination = trace;
    }
    Ok(EvalResponse {
        output: output_bytes,
        opaque_id,
        receipt_hash,
        backend: commitment.backend,
    })
}
fn validate_secret(secret: &[u8]) -> Result<(), RamLfeError> {
    if secret.is_empty() {
        return Err(RamLfeError::EmptySecret);
    }
    if secret.len() > RAM_LFE_SECRET_MAX_BYTES {
        return Err(RamLfeError::SecretTooLarge);
    }
    Ok(())
}
fn decode_bfv_public_parameters(
    public_parameters: &[u8],
) -> Result<BfvIdentifierPublicParameters, RamLfeError> {
    let public_parameters: BfvIdentifierPublicParameters =
        norito::decode_from_bytes(public_parameters)
            .map_err(|err| RamLfeError::TranscriptEncoding(err.to_string()))?;
    public_parameters
        .validate()
        .map_err(|err| map_bfv_error(&err))?;
    Ok(public_parameters)
}
fn validate_programmed_public_parameters(
    public_parameters: &BfvProgrammedPublicParameters,
) -> Result<(), RamLfeError> {
    let encryption = &public_parameters.encryption;
    validate_programmed_encryption_capacity(encryption)?;
    if encryption.parameters.ciphertext_modulus < BFV_PROGRAM_MIN_CIPHERTEXT_MODULUS {
        return Err(RamLfeError::Bfv(format!(
            "programmed BFV backend requires ciphertext_modulus >= {BFV_PROGRAM_MIN_CIPHERTEXT_MODULUS}"
        )));
    }
    validate_registered_bfv_parameters(&encryption.parameters)
        .map_err(|err| map_bfv_error(&err))?;
    if encryption.parameters.plaintext_modulus != RAM_LFE_BFV_PLAINTEXT_MODULUS {
        return Err(RamLfeError::Bfv(format!(
            "programmed BFV backend requires plaintext_modulus={RAM_LFE_BFV_PLAINTEXT_MODULUS}"
        )));
    }
    if public_parameters.hidden_program_digest == Hash::prehashed([0; Hash::LENGTH]) {
        return Err(RamLfeError::Bfv(
            "programmed BFV hidden-program digest must not be zero".to_owned(),
        ));
    }
    let parameter_digest = registered_bfv_parameter_digest(&encryption.parameters)
        .map_err(|err| map_bfv_error(&err))?;
    if public_parameters.parameter_digest != parameter_digest {
        return Err(RamLfeError::Bfv(
            "programmed BFV parameter digest does not match registered parameters".to_owned(),
        ));
    }
    validate_programmed_evaluation_keys(&public_parameters.evaluation_keys)?;
    let evaluation_key_digest = public_parameters
        .evaluation_keys
        .digest(&encryption.parameters)
        .map_err(|err| map_bfv_error(&err))?;
    if public_parameters.evaluation_key_digest != evaluation_key_digest {
        return Err(RamLfeError::Bfv(
            "programmed BFV evaluation-key digest does not match evaluation keys".to_owned(),
        ));
    }
    Ok(())
}
fn validate_programmed_encryption_capacity(
    encryption: &BfvIdentifierPublicParameters,
) -> Result<(), RamLfeError> {
    let slot_count = usize::from(encryption.max_input_bytes).saturating_add(1);
    if slot_count > BFV_PROGRAM_IDENTIFIER_SLOT_COUNT {
        return Err(RamLfeError::Bfv(format!(
            "programmed BFV encrypted envelope supports at most {} input bytes",
            BFV_PROGRAM_IDENTIFIER_SLOT_COUNT - 1
        )));
    }
    Ok(())
}
fn validate_programmed_evaluation_keys(
    evaluation_keys: &BfvEvaluationKeyBundle,
) -> Result<(), RamLfeError> {
    if !evaluation_keys.rotation_keys.is_empty() {
        return Err(RamLfeError::Bfv(
            "programmed BFV public parameters must not publish rotation refresh keys".to_owned(),
        ));
    }
    if !evaluation_keys.galois_keys.is_empty() {
        return Err(RamLfeError::Bfv(
            "programmed BFV public parameters must not publish Galois key-switching keys"
                .to_owned(),
        ));
    }
    if evaluation_keys.bootstrap_key.is_some() {
        return Err(RamLfeError::Bfv(
            "programmed BFV public parameters must not publish bootstrap refresh keys".to_owned(),
        ));
    }
    Ok(())
}
fn validate_programmed_profile(profile: &BfvRamProgramProfile) -> Result<(), RamLfeError> {
    let expected = bfv_program_profile();
    if profile != &expected {
        return Err(RamLfeError::Bfv(
            "unsupported programmed BFV RAM-FHE profile".to_owned(),
        ));
    }
    Ok(())
}
fn validate_proof_verifier_metadata(
    verification_mode: RamLfeVerificationMode,
    proof_verifier: Option<&RamLfeProofVerifierMetadata>,
) -> Result<(), RamLfeError> {
    match (verification_mode, proof_verifier) {
        (RamLfeVerificationMode::Signed, Some(_)) => Err(RamLfeError::Bfv(
            "signed RAM-LFE programs must not publish proof verifier metadata".to_owned(),
        )),
        (RamLfeVerificationMode::Proof, None) => Err(RamLfeError::Bfv(
            "proof-carrying RAM-LFE programs must publish proof verifier metadata".to_owned(),
        )),
        (_, None) => Ok(()),
        (_, Some(metadata)) => {
            validate_proof_metadata_identifier(
                "proof verifier backend",
                &metadata.proof_backend,
                RAM_LFE_PROOF_BACKEND_MAX_BYTES,
            )?;
            if metadata.proof_backend.starts_with("debug/") {
                return Err(RamLfeError::Bfv(
                    "debug proof backends are not supported".to_owned(),
                ));
            }
            validate_proof_metadata_identifier(
                "proof verifier circuit_id",
                &metadata.circuit_id,
                RAM_LFE_PROOF_CIRCUIT_ID_MAX_BYTES,
            )?;
            if metadata.public_inputs_schema_hash == Hash::prehashed([0; Hash::LENGTH]) {
                return Err(RamLfeError::Bfv(
                    "proof verifier public-input schema hash must not be zero".to_owned(),
                ));
            }
            if metadata.verifying_key_bytes.is_empty() {
                return Err(RamLfeError::Bfv(
                    "proof verifier bytes must not be empty".to_owned(),
                ));
            }
            if metadata.verifying_key_bytes.iter().all(|byte| *byte == 0) {
                return Err(RamLfeError::Bfv(
                    "proof verifier bytes must not be all zero".to_owned(),
                ));
            }
            if metadata.verifying_key_bytes.len() > RAM_LFE_PROOF_VERIFYING_KEY_MAX_BYTES {
                return Err(RamLfeError::Bfv(format!(
                    "proof verifier bytes exceed the maximum supported length {RAM_LFE_PROOF_VERIFYING_KEY_MAX_BYTES}"
                )));
            }
            Ok(())
        }
    }
}
fn validate_proof_metadata_identifier(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), RamLfeError> {
    if value.is_empty() {
        return Err(RamLfeError::Bfv(format!("{field} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(RamLfeError::Bfv(format!(
            "{field} exceeds the maximum supported length {max_bytes}"
        )));
    }
    if value.trim() != value {
        return Err(RamLfeError::Bfv(format!(
            "{field} must be canonical without surrounding whitespace"
        )));
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(RamLfeError::Bfv(format!(
            "{field} must contain only printable ASCII bytes"
        )));
    }
    Ok(())
}
fn derive_program_initial_state(
    params: &BfvParameters,
    reference_slot: &BfvCiphertext,
    secret: &[u8],
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<OwnedCiphertexts, RamLfeError> {
    validate_registered_bfv_parameters(params).map_err(|error| map_bfv_error(&error))?;
    let residues =
        initialization::derive_residues(secret, commitment.policy_hash, &request.associated_data)?;
    let zero = OwnedCiphertext(zero_ciphertext_like(params, reference_slot)?);
    let mut state = OwnedCiphertexts::with_capacity(BFV_PROGRAM_STATE_WIDTH)?;
    for &bias in residues.iter() {
        state.push(OwnedCiphertext(
            add_plain_scalar(params, &zero, bias).map_err(|err| map_bfv_error(&err))?,
        ))?;
    }
    Ok(state)
}
fn zero_ciphertext_like(
    params: &BfvParameters,
    reference_slot: &BfvCiphertext,
) -> Result<BfvCiphertext, RamLfeError> {
    multiply_plain_scalar(params, reference_slot, 0).map_err(|err| map_bfv_error(&err))
}
fn execute_hidden_program(
    execution: &ProgramExecutionContext<'_>,
    program: &HiddenRamFheProgram,
    inputs: &[BfvCiphertext],
    state: &mut OwnedCiphertexts,
    mut trace: Option<&mut RamLfeProgramExecutionTrace>,
) -> Result<Vec<u8>, RamLfeError> {
    validate_hidden_program(program)?;
    let mut machine =
        HiddenProgramMachine::new(execution, program.register_count(), inputs, state)?;
    if let Some(trace) = trace.as_mut() {
        trace.record(None, &machine.registers, machine.state, 0)?;
    }
    for instruction in program.instructions() {
        machine.execute_instruction(instruction)?;
        if let Some(trace) = trace.as_mut() {
            trace.record(
                Some(instruction),
                &machine.registers,
                machine.state,
                machine.output_registers.len(),
            )?;
        }
    }
    machine.finish()
}
struct HiddenProgramMachine<'a> {
    execution: &'a ProgramExecutionContext<'a>,
    reference_input: &'a BfvCiphertext,
    state: &'a mut OwnedCiphertexts,
    inputs: &'a [BfvCiphertext],
    registers: OwnedCiphertexts,
    output_registers: OwnedCiphertexts,
}
impl<'a> HiddenProgramMachine<'a> {
    fn new(
        execution: &'a ProgramExecutionContext<'a>,
        register_count: u16,
        inputs: &'a [BfvCiphertext],
        state: &'a mut OwnedCiphertexts,
    ) -> Result<Self, RamLfeError> {
        let reference_input = inputs
            .first()
            .ok_or_else(|| invalid_program_error("program requires at least one input"))?;
        let zero = OwnedCiphertext(zero_ciphertext_like(execution.params, reference_input)?);
        let mut registers = OwnedCiphertexts::with_capacity(usize::from(register_count))?;
        for _ in 0..register_count {
            registers.push(OwnedCiphertext::copy(&zero)?)?;
        }
        Ok(Self {
            execution,
            reference_input,
            state,
            inputs,
            registers,
            output_registers: OwnedCiphertexts::with_capacity(BFV_PROGRAM_IDENTIFIER_SLOT_COUNT)?,
        })
    }
    fn execute_instruction(
        &mut self,
        instruction: HiddenRamFheInstruction,
    ) -> Result<(), RamLfeError> {
        match instruction {
            HiddenRamFheInstruction::LoadInput(dst, input_index) => {
                let value = OwnedCiphertext::copy(
                    self.inputs.get(usize::from(input_index)).ok_or_else(|| {
                        invalid_program_error(&format!("input slot {input_index} out of bounds"))
                    })?,
                )?;
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::LoadState(dst, lane) => {
                let value = OwnedCiphertext::copy(self.program_lane(lane)?)?;
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::StoreState(lane, src) => {
                let value =
                    OwnedCiphertext::copy(program_register(&self.registers, usize::from(src))?)?;
                self.state.replace(usize::from(lane), value)?;
            }
            HiddenRamFheInstruction::LoadConst(dst, value) => {
                let value = OwnedCiphertext(self.load_constant(value)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::Add(dst, lhs, rhs) => {
                let value = OwnedCiphertext(self.add_registers(lhs, rhs)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::AddPlain(dst, src, value) => {
                let value = OwnedCiphertext(self.add_plain(src, value)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::SubPlain(dst, src, value) => {
                let value = OwnedCiphertext(self.sub_plain(src, value)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::MulPlain(dst, src, value) => {
                let value = OwnedCiphertext(self.mul_plain(src, value)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::Mul(dst, lhs, rhs) => {
                let value = OwnedCiphertext(self.mul_registers(lhs, rhs)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::SelectEqZero(dst, condition, if_zero, if_non_zero) => {
                let value =
                    OwnedCiphertext(self.select_eq_zero(condition, if_zero, if_non_zero)?);
                self.registers.replace(usize::from(dst), value)?;
            }
            HiddenRamFheInstruction::Output(src) => {
                self.output_registers
                    .push(OwnedCiphertext::copy(program_register(
                        &self.registers,
                        usize::from(src),
                    )?)?)?;
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<Vec<u8>, RamLfeError> {
        self.output_registers.encode_output()
    }
    fn load_constant(&self, value: u64) -> Result<BfvCiphertext, RamLfeError> {
        let value = value % self.execution.params.plaintext_modulus;
        let constant = OwnedCiphertext(
            add_plain_scalar(self.execution.params, self.reference_input, value)
                .map_err(|err| map_bfv_error(&err))?,
        );
        let zeroed = OwnedCiphertext(
            multiply_plain_scalar(self.execution.params, &constant, 0)
                .map_err(|err| map_bfv_error(&err))?,
        );
        add_plain_scalar(self.execution.params, &zeroed, value).map_err(|err| map_bfv_error(&err))
    }
    fn add_registers(&self, lhs: u16, rhs: u16) -> Result<BfvCiphertext, RamLfeError> {
        add_ciphertexts_rns_exact(
            self.execution.params,
            self.execution.rns_chain,
            program_register(&self.registers, usize::from(lhs))?,
            program_register(&self.registers, usize::from(rhs))?,
        )
        .map_err(|err| map_bfv_error(&err))
    }
    fn add_plain(&self, src: u16, value: u64) -> Result<BfvCiphertext, RamLfeError> {
        add_plain_scalar(
            self.execution.params,
            program_register(&self.registers, usize::from(src))?,
            value,
        )
        .map_err(|err| map_bfv_error(&err))
    }
    fn sub_plain(&self, src: u16, value: u64) -> Result<BfvCiphertext, RamLfeError> {
        let scalar = (self
            .execution
            .params
            .plaintext_modulus
            .saturating_sub(value % self.execution.params.plaintext_modulus))
            % self.execution.params.plaintext_modulus;
        self.add_plain(src, scalar)
    }
    fn mul_plain(&self, src: u16, value: u64) -> Result<BfvCiphertext, RamLfeError> {
        multiply_plain_scalar(
            self.execution.params,
            program_register(&self.registers, usize::from(src))?,
            value,
        )
        .map_err(|err| map_bfv_error(&err))
    }
    fn mul_registers(&self, lhs: u16, rhs: u16) -> Result<BfvCiphertext, RamLfeError> {
        multiply_ciphertexts_rns_exact(
            self.execution.params,
            self.execution.rns_chain,
            &self.execution.evaluation_keys.relinearization_key,
            program_register(&self.registers, usize::from(lhs))?,
            program_register(&self.registers, usize::from(rhs))?,
        )
        .map_err(|err| map_bfv_error(&err))
    }
    fn select_eq_zero(
        &self,
        condition: u16,
        if_zero: u16,
        if_non_zero: u16,
    ) -> Result<BfvCiphertext, RamLfeError> {
        let indicator = OwnedCiphertext(self.eq_zero_indicator(condition)?);
        let zero_value = program_register(&self.registers, usize::from(if_zero))?;
        let non_zero_value = program_register(&self.registers, usize::from(if_non_zero))?;
        let delta = OwnedCiphertext(
            subtract_ciphertexts_rns_exact(
                self.execution.params,
                self.execution.rns_chain,
                zero_value,
                non_zero_value,
            )
            .map_err(|err| map_bfv_error(&err))?,
        );
        let selected_delta = OwnedCiphertext(
            multiply_ciphertexts_rns_exact(
                self.execution.params,
                self.execution.rns_chain,
                &self.execution.evaluation_keys.relinearization_key,
                &indicator,
                &delta,
            )
            .map_err(|err| map_bfv_error(&err))?,
        );
        add_ciphertexts_rns_exact(
            self.execution.params,
            self.execution.rns_chain,
            non_zero_value,
            &selected_delta,
        )
        .map_err(|err| map_bfv_error(&err))
    }
    fn eq_zero_indicator(&self, condition: u16) -> Result<BfvCiphertext, RamLfeError> {
        if self.execution.params.plaintext_modulus != RAM_LFE_BFV_PLAINTEXT_MODULUS {
            return Err(RamLfeError::Bfv(format!(
                "SelectEqZero requires plaintext_modulus={RAM_LFE_BFV_PLAINTEXT_MODULUS}"
            )));
        }
        let condition =
            OwnedCiphertext::copy(program_register(&self.registers, usize::from(condition))?)?;
        let powered = self.pow_ciphertext(condition, 256)?;
        let one = OwnedCiphertext(self.load_constant(1)?);
        subtract_ciphertexts_rns_exact(
            self.execution.params,
            self.execution.rns_chain,
            &one,
            &powered,
        )
        .map_err(|err| map_bfv_error(&err))
    }
    fn pow_ciphertext(
        &self,
        mut base: OwnedCiphertext,
        mut exponent: u16,
    ) -> Result<OwnedCiphertext, RamLfeError> {
        let mut result = OwnedCiphertext(self.load_constant(1)?);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = OwnedCiphertext(
                    multiply_ciphertexts_rns_exact(
                        self.execution.params,
                        self.execution.rns_chain,
                        &self.execution.evaluation_keys.relinearization_key,
                        &result,
                        &base,
                    )
                    .map_err(|err| map_bfv_error(&err))?,
                );
            }
            exponent >>= 1;
            if exponent > 0 {
                base = OwnedCiphertext(
                    multiply_ciphertexts_rns_exact(
                        self.execution.params,
                        self.execution.rns_chain,
                        &self.execution.evaluation_keys.relinearization_key,
                        &base,
                        &base,
                    )
                    .map_err(|err| map_bfv_error(&err))?,
                );
            }
        }
        Ok(result)
    }
    fn program_lane(&self, lane: u16) -> Result<&BfvCiphertext, RamLfeError> {
        self.state
            .get(usize::from(lane))
            .ok_or_else(|| invalid_program_error(&format!("lane {lane} out of bounds")))
    }
}
// The diagnostic BFV evaluator has no refresh, so it admits exactly the
// structurally valid tapes of the canonical `bounded.v1` class.
fn validate_hidden_program(program: &HiddenRamFheProgram) -> Result<(), RamLfeError> {
    match RamLfeClassV1::Bounded.membership(program) {
        Ok(_) => Ok(()),
        Err(RamLfeError::ClassRankExceeded {
            instruction, limit, ..
        }) => Err(invalid_program_error(&format!(
            "instruction {instruction} exceeds the RAM-FHE multiplicative-depth budget {limit}"
        ))),
        Err(error) => Err(error),
    }
}
/// Validate the class-independent shape of a hidden tape.
///
/// Class membership, including every rank and refresh limit, is checked
/// separately by [`RamLfeClassV1::membership`].
fn validate_hidden_program_structure(program: &HiddenRamFheProgram) -> Result<(), RamLfeError> {
    if program.version() != 1 {
        return Err(invalid_program_error("unsupported hidden program version"));
    }
    if usize::from(program.register_count()) != BFV_PROGRAM_REGISTER_COUNT {
        return Err(invalid_program_error(
            "register_count does not match RAM-FHE profile",
        ));
    }
    if usize::from(program.memory_lane_count()) != BFV_PROGRAM_STATE_WIDTH {
        return Err(invalid_program_error(
            "memory_lane_count does not match RAM-FHE profile",
        ));
    }
    if program.instruction_count() == 0 {
        return Err(invalid_program_error(
            "program instruction tape must not be empty",
        ));
    }
    if program.instruction_count() > BFV_PROGRAM_MAX_INSTRUCTIONS {
        return Err(invalid_program_error(&format!(
            "program instruction tape exceeds maximum {BFV_PROGRAM_MAX_INSTRUCTIONS} instructions"
        )));
    }
    if !program
        .instructions()
        .any(|instruction| matches!(instruction, HiddenRamFheInstruction::Output(..)))
    {
        return Err(invalid_program_error(
            "program must emit at least one output",
        ));
    }
    validate_hidden_program_instruction_tape(program)?;
    Ok(())
}
fn validate_hidden_program_instruction_tape(
    program: &HiddenRamFheProgram,
) -> Result<(), RamLfeError> {
    let mut output_count = 0_usize;
    for (pc, instruction) in program.instructions().enumerate() {
        match instruction {
            HiddenRamFheInstruction::LoadInput(dst, input_index) => {
                validate_program_register_index(program, dst, pc)?;
                if usize::from(input_index) >= BFV_PROGRAM_IDENTIFIER_SLOT_COUNT {
                    return Err(invalid_program_error(&format!(
                        "instruction {pc} input slot {input_index} out of bounds"
                    )));
                }
            }
            HiddenRamFheInstruction::LoadState(register, lane)
            | HiddenRamFheInstruction::StoreState(lane, register) => {
                validate_program_register_index(program, register, pc)?;
                if usize::from(lane) >= usize::from(program.memory_lane_count()) {
                    return Err(invalid_program_error(&format!(
                        "instruction {pc} memory lane {lane} out of bounds"
                    )));
                }
            }
            HiddenRamFheInstruction::LoadConst(dst, value) => {
                validate_program_register_index(program, dst, pc)?;
                validate_plaintext_immediate(value, pc)?;
            }
            HiddenRamFheInstruction::Add(dst, lhs, rhs)
            | HiddenRamFheInstruction::Mul(dst, lhs, rhs) => {
                validate_program_register_index(program, dst, pc)?;
                validate_program_register_index(program, lhs, pc)?;
                validate_program_register_index(program, rhs, pc)?;
            }
            HiddenRamFheInstruction::AddPlain(dst, src, value)
            | HiddenRamFheInstruction::SubPlain(dst, src, value)
            | HiddenRamFheInstruction::MulPlain(dst, src, value) => {
                validate_program_register_index(program, dst, pc)?;
                validate_plaintext_immediate(value, pc)?;
                validate_program_register_index(program, src, pc)?;
            }
            HiddenRamFheInstruction::SelectEqZero(dst, condition, if_zero, if_non_zero) => {
                validate_program_register_index(program, dst, pc)?;
                validate_program_register_index(program, condition, pc)?;
                validate_program_register_index(program, if_zero, pc)?;
                validate_program_register_index(program, if_non_zero, pc)?;
            }
            HiddenRamFheInstruction::Output(src) => {
                validate_program_register_index(program, src, pc)?;
                output_count = output_count.saturating_add(1);
                if output_count > BFV_PROGRAM_IDENTIFIER_SLOT_COUNT {
                    return Err(invalid_program_error(&format!(
                        "instruction {pc} emits too many output slots"
                    )));
                }
            }
        }
    }
    Ok(())
}
fn validate_plaintext_immediate(value: u64, pc: usize) -> Result<(), RamLfeError> {
    if value >= RAM_LFE_BFV_PLAINTEXT_MODULUS {
        return Err(invalid_program_error(&format!(
            "instruction {pc} plaintext immediate must be less than {RAM_LFE_BFV_PLAINTEXT_MODULUS}"
        )));
    }
    Ok(())
}
fn validate_hidden_program_input_slots(
    program: &HiddenRamFheProgram,
    max_input_bytes: u16,
) -> Result<(), RamLfeError> {
    let max_slot_index = usize::from(max_input_bytes);
    for (pc, instruction) in program.instructions().enumerate() {
        if let HiddenRamFheInstruction::LoadInput(_, input_index) = instruction
            && usize::from(input_index) > max_slot_index
        {
            return Err(invalid_program_error(&format!(
                "instruction {pc} input slot {input_index} exceeds encrypted envelope max_input_bytes {max_input_bytes}"
            )));
        }
    }
    Ok(())
}
fn validate_program_register_index(
    program: &HiddenRamFheProgram,
    register: u16,
    pc: usize,
) -> Result<(), RamLfeError> {
    if usize::from(register) >= usize::from(program.register_count()) {
        return Err(invalid_program_error(&format!(
            "instruction {pc} register {register} out of bounds"
        )));
    }
    Ok(())
}
fn program_register(
    registers: &[BfvCiphertext],
    index: usize,
) -> Result<&BfvCiphertext, RamLfeError> {
    registers
        .get(index)
        .ok_or_else(|| invalid_program_error(&format!("register {index} out of bounds")))
}
fn invalid_program_error(message: &str) -> RamLfeError {
    RamLfeError::Bfv(format!("invalid BFV RAM program: {message}"))
}
fn derive_secret_affine_circuit(
    secret: &[u8],
    public_parameters: &BfvIdentifierPublicParameters,
    commitment: &PolicyCommitment,
    request: &ClientRequest,
) -> Result<SecretAffineCircuit, RamLfeError> {
    let input_count = usize::from(public_parameters.max_input_bytes).saturating_add(1);
    let mut seed: [u8; Hash::LENGTH] = Hash::new_from_chunks(&[
        BFV_AFFINE_CIRCUIT_DOMAIN,
        secret,
        commitment.policy_hash.as_ref(),
        request.associated_data.as_slice(),
    ])
    .into();
    let mut rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    let mut circuit = SecretAffineCircuit::with_capacity(BFV_AFFINE_OUTPUT_BYTES);
    for _ in 0..BFV_AFFINE_OUTPUT_BYTES {
        let selected_input = rng.random_range(0..input_count);
        let weight = rng.random_range(1..public_parameters.parameters.plaintext_modulus);
        let mut row = vec![0; input_count];
        row[selected_input] = weight;
        circuit.0.weights.push(row);
        circuit.0.bias.push(weight - 1);
    }
    circuit
        .validate(&public_parameters.parameters, input_count)
        .map_err(|err| map_bfv_error(&err))?;
    Ok(circuit)
}
fn decrypt_affine_outputs(
    public_parameters: &BfvIdentifierPublicParameters,
    secret_key: &crate::BfvSecretKey,
    outputs: &[crate::BfvCiphertext],
) -> Result<Vec<u8>, RamLfeError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(outputs.len()));
    for output in outputs {
        let plaintext = Zeroizing::new(
            decrypt(&public_parameters.parameters, secret_key, output)
                .map_err(|err| map_bfv_error(&err))?,
        );
        if plaintext
            .iter()
            .skip(1)
            .any(|&coefficient| coefficient != 0)
        {
            return Err(RamLfeError::Bfv(
                "affine output contains non-zero trailing coefficients".to_owned(),
            ));
        }
        bytes.push(
            u8::try_from(plaintext[0]).map_err(|_| {
                RamLfeError::Bfv("affine output byte does not fit into u8".to_owned())
            })?,
        );
    }
    // Only the complete evaluator output is returned to its caller.
    Ok(std::mem::take(&mut *bytes))
}
fn map_bfv_error(err: &BfvError) -> RamLfeError {
    RamLfeError::Bfv(err.to_string())
}
fn validate_request(request: &ClientRequest) -> Result<(), RamLfeError> {
    if request.normalized_input.is_empty() {
        return Err(RamLfeError::EmptyInput);
    }
    if request.normalized_input.len() > MAX_INPUT_BYTES {
        return Err(RamLfeError::InputTooLarge);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn program_for_test(
        version: u8,
        registers: u16,
        lanes: u16,
        instructions: &[HiddenRamFheInstruction],
    ) -> HiddenRamFheProgram {
        program::from_public_test_parts(version, registers, lanes, instructions)
    }

    use crate::{
        BfvEvaluationKeyBundle, BfvIdentifierCiphertext, BfvIdentifierPublicParameters,
        BfvParameters, bootstrap_key_from_seed, decrypt, derive_identifier_key_material_from_seed,
        encrypt_identifier_from_seed, keygen_from_seed, ram_lfe_bfv_parameters_v1,
        rotation_key_from_seed,
    };
    #[test]
    fn ram_lfe_secret_is_validated_shared_and_redacted() {
        let secret: RamLfeSecret = "0X01020304".parse().expect("valid RAM-LFE secret");
        let clone = secret.clone();
        assert_eq!(secret.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(secret.len(), 4);
        assert!(Arc::ptr_eq(&secret.0, &clone.0));
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("01020304"));
    }
    #[cfg(feature = "json")]
    #[test]
    fn ram_lfe_secret_json_parsing_validates_bounds() {
        let secret: RamLfeSecret =
            norito::json::from_str("\"0x01020304\"").expect("valid RAM-LFE secret JSON");
        assert_eq!(secret.as_bytes(), &[1, 2, 3, 4]);
        assert!("".parse::<RamLfeSecret>().is_err());
        let oversized = vec![0_u8; RAM_LFE_SECRET_MAX_BYTES + 1];
        assert!(RamLfeSecret::try_from(oversized).is_err());
        assert!(norito::json::from_str::<RamLfeSecret>("\"not-hex\"").is_err());
    }
    #[test]
    fn policy_commitment_roundtrip_evaluates() {
        let secret = b"resolver-secret";
        let commitment = policy_commitment(secret, b"phone#retail".to_vec()).expect("commitment");
        let request = ClientRequest {
            normalized_input: b"+15551234567".to_vec(),
            associated_data: b"phone#retail".to_vec(),
        };
        let first = evaluate_commitment(secret, &commitment, &request).expect("evaluation");
        let second = evaluate_commitment(secret, &commitment, &request).expect("evaluation");
        assert_eq!(first, second);
    }
    #[test]
    fn policy_commitment_rejects_wrong_secret() {
        let commitment =
            policy_commitment(b"secret-a", b"phone#retail".to_vec()).expect("commitment");
        let request = ClientRequest {
            normalized_input: b"+15551234567".to_vec(),
            associated_data: b"phone#retail".to_vec(),
        };
        let err = evaluate_commitment(b"secret-b", &commitment, &request)
            .expect_err("wrong secret must fail");
        assert_eq!(err, RamLfeError::CommitmentMismatch);
    }
    #[test]
    fn ram_lfe_public_transcripts_bind_canonical_fields() {
        let program = default_bfv_programmed_hidden_program();
        let program_commitment =
            policy_secret::commit_canonical(policy_secret::PROGRAM_CONTEXT, &program)
                .expect("commit hidden program");
        assert_eq!(
            program.digest().expect("hidden program digest"),
            Hash::new([BFV_PROGRAM_DIGEST_DOMAIN, program_commitment.as_slice()].concat())
        );
        let output = b"ram-lfe-output";
        let output_hash = ram_lfe_output_hash(output);
        assert_eq!(
            output_hash,
            Hash::new([RAM_FHE_OUTPUT_HASH_DOMAIN, &output[..]].concat())
        );
        let program_id = b"phone#retail";
        let (opaque_id, receipt_hash) =
            identifier_hashes_from_output_hash(program_id, &output_hash);
        let legacy_opaque_id = Hash::new(
            [
                IDENTIFIER_OUTPUT_OPAQUE_HASH_DOMAIN,
                &program_id[..],
                output_hash.as_ref(),
            ]
            .concat(),
        );
        let legacy_receipt_hash = Hash::new(
            [
                IDENTIFIER_OUTPUT_RECEIPT_HASH_DOMAIN,
                &program_id[..],
                output_hash.as_ref(),
                legacy_opaque_id.as_ref(),
            ]
            .concat(),
        );
        assert_eq!(opaque_id, legacy_opaque_id);
        assert_eq!(receipt_hash, legacy_receipt_hash);
        let secret = b"resolver-secret";
        let public_parameters = b"phone#retail".to_vec();
        let commitment =
            policy_commitment(secret, public_parameters.clone()).expect("policy commitment");
        let secret_commitment = policy_secret::commit(RamLfeBackend::HkdfSha3_512PrfV1, secret)
            .expect("secret commitment");
        let policy_transcript = norito::encode_canonical(&PolicyCommitmentInputV1 {
            backend: RamLfeBackend::HkdfSha3_512PrfV1,
            public_parameters: &public_parameters,
            secret_commitment,
        })
        .expect("encode policy transcript");
        assert_eq!(
            commitment.policy_hash,
            Hash::new([POLICY_DOMAIN, policy_transcript.as_slice()].concat())
        );
    }
    #[test]
    fn bfv_affine_policy_commitment_roundtrip_evaluates() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let (public_parameters, _, _) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let commitment = bfv_affine_policy_commitment(
            secret,
            &norito::to_bytes(&public_parameters).expect("encode public parameters"),
        )
        .expect("build BFV policy commitment");
        let ciphertext = encrypt_identifier_from_seed(
            &public_parameters,
            b"+15551234567",
            b"bfv-affine-identifier-seed",
        )
        .expect("encrypt identifier");
        let request = ClientRequest {
            normalized_input: norito::to_bytes(&ciphertext).expect("encode BFV ciphertext"),
            associated_data: associated_data.to_vec(),
        };
        let first =
            evaluate_diagnostic_commitment(secret, &commitment, &request).expect("evaluation");
        let second =
            evaluate_diagnostic_commitment(secret, &commitment, &request).expect("evaluation");
        assert_eq!(first, second);
        assert_eq!(first.backend, RamLfeBackend::BfvAffineV1);
        assert_ne!(first.opaque_id, Hash::prehashed([0; Hash::LENGTH]));
    }
    #[test]
    fn secret_affine_circuit_maps_byte_inputs_to_bytes() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let (public_parameters, _, _) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let commitment = bfv_affine_policy_commitment(
            secret,
            &norito::to_bytes(&public_parameters).expect("encode public parameters"),
        )
        .expect("build BFV policy commitment");
        let request = ClientRequest {
            normalized_input: Vec::from(&b"+15551234567"[..]),
            associated_data: associated_data.to_vec(),
        };
        let circuit =
            derive_secret_affine_circuit(secret, &public_parameters, &commitment, &request)
                .expect("derive affine circuit");
        for (row, &bias) in circuit.weights.iter().zip(&circuit.bias) {
            let non_zero_weights = row
                .iter()
                .enumerate()
                .filter(|&(_, &weight)| weight != 0)
                .collect::<Vec<_>>();
            assert_eq!(non_zero_weights.len(), 1);
            let (_, &weight) = non_zero_weights[0];
            assert_eq!(bias, weight - 1);
            for byte in 0_u64..=u64::from(u8::MAX) {
                let output = (u128::from(weight) * u128::from(byte) + u128::from(bias))
                    % u128::from(params.plaintext_modulus);
                assert!(output <= u128::from(u8::MAX));
            }
        }
    }
    #[test]
    fn bfv_programmed_policy_commitment_roundtrip_evaluates() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let evaluation_keys = BfvEvaluationKeyBundle {
            relinearization_key,
            rotation_keys: Vec::new(),
            galois_keys: Vec::new(),
            bootstrap_key: None,
        };
        let programmed =
            try_bfv_programmed_public_parameters(public_parameters.clone(), evaluation_keys)
                .expect("build programmed BFV public parameters");
        let commitment = bfv_programmed_policy_commitment(
            secret,
            &norito::to_bytes(&programmed).expect("encode public parameters"),
        )
        .expect("build BFV policy commitment");
        let ciphertext = encrypt_identifier_from_seed(
            &public_parameters,
            b"+15551234567",
            b"bfv-programmed-identifier-seed",
        )
        .expect("encrypt identifier");
        let request = ClientRequest {
            normalized_input: norito::to_bytes(&ciphertext).expect("encode BFV ciphertext"),
            associated_data: associated_data.to_vec(),
        };
        let first =
            evaluate_diagnostic_commitment(secret, &commitment, &request).expect("evaluation");
        let second =
            evaluate_diagnostic_commitment(secret, &commitment, &request).expect("evaluation");
        assert_eq!(first, second);
        assert_eq!(first.backend, RamLfeBackend::BfvProgrammedV1);
        assert_ne!(first.opaque_id, Hash::prehashed([0; Hash::LENGTH]));
    }
    #[test]
    fn bfv_programmed_runtime_uses_registered_rns_exact_arithmetic() {
        let secret = b"resolver-secret-rns-runtime";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"rns-runtime";
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadInput(0, 1),
                HiddenRamFheInstruction::LoadInput(1, 2),
                HiddenRamFheInstruction::Add(2, 0, 1),
                HiddenRamFheInstruction::Mul(3, 0, 1),
                HiddenRamFheInstruction::LoadInput(0, 3),
                HiddenRamFheInstruction::SelectEqZero(1, 0, 2, 3),
                HiddenRamFheInstruction::Output(2),
                HiddenRamFheInstruction::Output(3),
                HiddenRamFheInstruction::Output(1),
            ],
        );
        validate_hidden_ram_fhe_program(&program).expect("custom RNS program validates");
        let (public_parameters, secret_key, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters.clone(),
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        let commitment = bfv_programmed_policy_commitment_with_program(
            secret,
            &norito::to_bytes(&programmed).expect("encode public parameters"),
            &program,
        )
        .expect("build BFV policy commitment");
        let ciphertext =
            encrypt_identifier_from_seed(&public_parameters, &[2, 3], b"bfv-rns-runtime-input")
                .expect("encrypt identifier");
        let request = ClientRequest {
            normalized_input: norito::to_bytes(&ciphertext).expect("encode BFV ciphertext"),
            associated_data: associated_data.to_vec(),
        };
        let response = evaluate_diagnostic_commitment_with_hidden_program(
            secret,
            &commitment,
            &request,
            Some(&program),
        )
        .expect("RNS-backed programmed evaluation");
        let archived = norito::from_bytes::<BfvIdentifierCiphertext>(&response.output)
            .expect("decode encrypted output");
        let output: BfvIdentifierCiphertext =
            norito::core::DeserializePayload::deserialize(archived);
        let scalars = output
            .slots
            .iter()
            .map(|slot| {
                decrypt(&params, &secret_key, slot)
                    .expect("decrypt output slot")
                    .first()
                    .copied()
                    .expect("slot has coefficient")
            })
            .collect::<Vec<_>>();
        assert_eq!(scalars, vec![5, 6, 5]);
    }
    #[test]
    fn try_bfv_programmed_public_parameters_rejects_unregistered_profile() {
        let params = BfvParameters {
            polynomial_degree: 64,
            ciphertext_modulus: 1_u64 << 40,
            plaintext_modulus: 256,
            decomposition_base_log: 12,
        };
        params
            .validate()
            .expect("sample BFV profile is structurally valid");
        assert_ne!(params, ram_lfe_bfv_parameters_v1());
        let (_, public_key, relinearization_key) =
            keygen_from_seed(&params, b"ram-lfe-unregistered-bfv-keygen").expect("keygen");
        let public_parameters = BfvIdentifierPublicParameters {
            parameters: params,
            public_key,
            max_input_bytes: 63,
        };
        let evaluation_keys = BfvEvaluationKeyBundle {
            relinearization_key,
            rotation_keys: Vec::new(),
            galois_keys: Vec::new(),
            bootstrap_key: None,
        };
        let err = try_bfv_programmed_public_parameters(public_parameters, evaluation_keys)
            .expect_err("programmed BFV constructor must reject unregistered profiles");
        assert!(err.to_string().contains("not registered"));
    }
    #[test]
    fn try_bfv_programmed_public_parameters_rejects_program_inputs_beyond_envelope() {
        let secret = b"resolver-secret-program-input-bounds";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"program-input-bounds";
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadInput(0, 2),
                HiddenRamFheInstruction::Output(0),
            ],
        );
        validate_hidden_ram_fhe_program(&program).expect("profile-wide program shape validates");
        let (mut public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(
                &params,
                RAM_LFE_BFV_IDENTIFIER_MAX_INPUT_BYTES,
                secret,
                associated_data,
            )
            .expect("derive BFV public parameters");
        let input_err = validate_hidden_program_input_slots(&program, 1)
            .expect_err("input slot two must exceed a one-byte envelope");
        assert!(input_err.to_string().contains("max_input_bytes 1"));
        // Smaller envelopes are malformed in V1; construct valid keys before
        // mutating the public metadata to exercise constructor admission.
        public_parameters.max_input_bytes = 1;
        let err = try_bfv_programmed_public_parameters_with_program(
            public_parameters,
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect_err("programmed constructor must reject impossible input slots");
        assert!(err.to_string().contains("max_input_bytes"));
    }
    #[test]
    fn try_bfv_programmed_public_parameters_rejects_noncanonical_plaintext_immediate() {
        let secret = b"resolver-secret-program-immediate";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"program-immediate";
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadConst(0, RAM_LFE_BFV_PLAINTEXT_MODULUS),
                HiddenRamFheInstruction::Output(0),
            ],
        );
        let (public_parameters, _, relinearization_key) = derive_identifier_key_material_from_seed(
            &params,
            RAM_LFE_BFV_IDENTIFIER_MAX_INPUT_BYTES,
            secret,
            associated_data,
        )
        .expect("derive BFV public parameters");
        let err = try_bfv_programmed_public_parameters_with_program(
            public_parameters,
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect_err("programmed constructor must reject noncanonical plaintext immediates");
        assert!(
            err.to_string().contains("plaintext immediate"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn programmed_policy_commitment_rejects_program_inputs_beyond_encoded_envelope() {
        let secret = b"resolver-secret-program-input-policy";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"program-input-policy";
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadInput(0, 2),
                HiddenRamFheInstruction::Output(0),
            ],
        );
        validate_hidden_ram_fhe_program(&program).expect("profile-wide program shape validates");
        let (mut public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(
                &params,
                RAM_LFE_BFV_IDENTIFIER_MAX_INPUT_BYTES,
                secret,
                associated_data,
            )
            .expect("derive BFV public parameters");
        let input_err = validate_hidden_program_input_slots(&program, 1)
            .expect_err("input slot two must exceed a one-byte envelope");
        assert!(input_err.to_string().contains("max_input_bytes 1"));
        // Smaller envelopes are malformed in V1; construct valid keys before
        // mutating the public metadata to exercise constructor admission.
        public_parameters.max_input_bytes = 1;
        let evaluation_keys = BfvEvaluationKeyBundle {
            relinearization_key,
            rotation_keys: Vec::new(),
            galois_keys: Vec::new(),
            bootstrap_key: None,
        };
        let programmed = BfvProgrammedPublicParameters {
            hidden_program_digest: program.digest().expect("program digest"),
            parameter_digest: registered_bfv_parameter_digest(&public_parameters.parameters)
                .expect("registered parameter digest"),
            evaluation_key_digest: evaluation_keys
                .digest(&public_parameters.parameters)
                .expect("evaluation-key digest"),
            encryption: public_parameters,
            evaluation_keys,
            ram_fhe_profile: bfv_program_profile(),
            verification_mode: RamLfeVerificationMode::Signed,
            proof_verifier: None,
        };
        let encoded = norito::to_bytes(&programmed).expect("encode adversarial policy");
        let err = bfv_programmed_policy_commitment_with_program(secret, &encoded, &program)
            .expect_err("policy commitment must reject impossible input slots");
        assert!(err.to_string().contains("max_input_bytes"));
    }
    #[test]
    fn decode_bfv_programmed_public_parameters_rejects_envelope_capacity_above_profile() {
        let secret = b"resolver-secret-program-capacity";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"program-capacity";
        let program = default_bfv_programmed_hidden_program();
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let mut programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters,
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        programmed.encryption.max_input_bytes = BFV_PROGRAM_IDENTIFIER_SLOT_COUNT_U16;
        let encoded = norito::to_bytes(&programmed).expect("encode oversized profile");
        let err = decode_bfv_programmed_public_parameters(&encoded)
            .expect_err("oversized programmed envelope capacity must be rejected");
        assert!(
            err.to_string()
                .contains("max_input_bytes must be exactly 63"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn hidden_program_validation_rejects_chained_multiplicative_depth() {
        let mut instructions = vec![
            HiddenRamFheInstruction::LoadInput(0, 0),
            HiddenRamFheInstruction::LoadInput(1, 1),
        ];
        for _ in 0..=bfv_program_profile().ciphertext_mul_per_step {
            instructions.push(HiddenRamFheInstruction::Mul(0, 0, 1));
        }
        instructions.push(HiddenRamFheInstruction::Output(0));
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &instructions,
        );
        let err = validate_hidden_ram_fhe_program(&program)
            .expect_err("chained multiplications must exceed the profile depth budget");
        assert!(err.to_string().contains("multiplicative-depth budget"));
    }
    #[test]
    fn default_bfv_programmed_hidden_program_uses_profile_indexes() {
        let program = default_bfv_programmed_hidden_program();
        validate_hidden_ram_fhe_program(&program).expect("default program validates");
        assert_eq!(program.register_count(), BFV_PROGRAM_REGISTER_COUNT_U16);
        assert_eq!(program.memory_lane_count(), BFV_PROGRAM_STATE_WIDTH_U16);
        assert_eq!(
            program.instruction_count(),
            BFV_PROGRAM_IDENTIFIER_SLOT_COUNT * 4
        );
        assert_eq!(
            program.instruction(0),
            Some(HiddenRamFheInstruction::LoadInput(0, 0))
        );
        assert_eq!(
            program.instruction(4),
            Some(HiddenRamFheInstruction::LoadInput(0, 1))
        );
        assert_eq!(
            program.instruction(4 * BFV_PROGRAM_STATE_WIDTH),
            Some(HiddenRamFheInstruction::LoadInput(
                0,
                BFV_PROGRAM_STATE_WIDTH_U16
            ))
        );
        assert_eq!(
            program.instructions().last(),
            Some(HiddenRamFheInstruction::Output(2))
        );
    }
    #[test]
    fn hidden_program_validation_rejects_static_index_overflow() {
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadInput(0, BFV_PROGRAM_IDENTIFIER_SLOT_COUNT_U16),
                HiddenRamFheInstruction::Output(0),
            ],
        );
        let err = validate_hidden_ram_fhe_program(&program)
            .expect_err("out-of-range input slot must be rejected before execution");
        assert!(err.to_string().contains("input slot"));
    }
    #[test]
    fn hidden_program_validation_rejects_static_memory_lane_overflow() {
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadState(0, BFV_PROGRAM_STATE_WIDTH_U16),
                HiddenRamFheInstruction::Output(0),
            ],
        );
        let err = validate_hidden_ram_fhe_program(&program)
            .expect_err("out-of-range memory lane must be rejected before execution");
        assert!(err.to_string().contains("memory lane"));
    }
    #[test]
    fn hidden_program_validation_rejects_static_register_overflow() {
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadConst(BFV_PROGRAM_REGISTER_COUNT_U16, 1),
                HiddenRamFheInstruction::Output(0),
            ],
        );
        let err = validate_hidden_ram_fhe_program(&program)
            .expect_err("out-of-range register must be rejected before execution");
        assert!(err.to_string().contains("register"));
    }
    #[test]
    fn hidden_program_validation_rejects_noncanonical_plaintext_immediates() {
        for instruction in [
            HiddenRamFheInstruction::LoadConst(0, RAM_LFE_BFV_PLAINTEXT_MODULUS),
            HiddenRamFheInstruction::AddPlain(0, 0, RAM_LFE_BFV_PLAINTEXT_MODULUS),
            HiddenRamFheInstruction::SubPlain(0, 0, u64::MAX),
            HiddenRamFheInstruction::MulPlain(0, 0, RAM_LFE_BFV_PLAINTEXT_MODULUS + 1),
        ] {
            let program = program_for_test(
                1,
                BFV_PROGRAM_REGISTER_COUNT_U16,
                BFV_PROGRAM_STATE_WIDTH_U16,
                &[instruction, HiddenRamFheInstruction::Output(0)],
            );
            let err = validate_hidden_ram_fhe_program(&program)
                .expect_err("noncanonical plaintext immediate must be rejected before execution");
            assert!(
                err.to_string().contains("plaintext immediate"),
                "unexpected error: {err}"
            );
        }
    }
    #[test]
    fn hidden_program_validation_rejects_output_slot_overflow() {
        let mut instructions = vec![HiddenRamFheInstruction::LoadConst(0, 1)];
        instructions.extend(
            (0..=BFV_PROGRAM_IDENTIFIER_SLOT_COUNT).map(|_| HiddenRamFheInstruction::Output(0)),
        );
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &instructions,
        );
        let err = validate_hidden_ram_fhe_program(&program)
            .expect_err("programs cannot emit more output slots than the profile admits");
        assert!(err.to_string().contains("too many output slots"));
    }
    #[test]
    fn hidden_program_validation_rejects_oversized_instruction_tape() {
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[HiddenRamFheInstruction::LoadConst(0, 1); BFV_PROGRAM_MAX_INSTRUCTIONS + 1],
        );
        let err = validate_hidden_ram_fhe_program(&program)
            .expect_err("oversized instruction tapes must be rejected before execution");
        assert!(err.to_string().contains("maximum"));
    }
    #[test]
    fn hidden_program_validation_rejects_adversarial_program_shapes() {
        let cases = [
            (
                program_for_test(
                    2,
                    BFV_PROGRAM_REGISTER_COUNT_U16,
                    BFV_PROGRAM_STATE_WIDTH_U16,
                    &[
                        HiddenRamFheInstruction::LoadConst(0, 1),
                        HiddenRamFheInstruction::Output(0),
                    ],
                ),
                "version",
            ),
            (
                program_for_test(
                    1,
                    BFV_PROGRAM_REGISTER_COUNT_U16 - 1,
                    BFV_PROGRAM_STATE_WIDTH_U16,
                    &[
                        HiddenRamFheInstruction::LoadConst(0, 1),
                        HiddenRamFheInstruction::Output(0),
                    ],
                ),
                "register_count",
            ),
            (
                program_for_test(
                    1,
                    BFV_PROGRAM_REGISTER_COUNT_U16,
                    BFV_PROGRAM_STATE_WIDTH_U16 - 1,
                    &[
                        HiddenRamFheInstruction::LoadConst(0, 1),
                        HiddenRamFheInstruction::Output(0),
                    ],
                ),
                "memory_lane_count",
            ),
            (
                program_for_test(
                    1,
                    BFV_PROGRAM_REGISTER_COUNT_U16,
                    BFV_PROGRAM_STATE_WIDTH_U16,
                    &[],
                ),
                "instruction tape",
            ),
            (
                program_for_test(
                    1,
                    BFV_PROGRAM_REGISTER_COUNT_U16,
                    BFV_PROGRAM_STATE_WIDTH_U16,
                    &[HiddenRamFheInstruction::LoadConst(0, 1)],
                ),
                "at least one output",
            ),
        ];
        for (program, expected) in cases {
            let err = validate_hidden_ram_fhe_program(&program)
                .expect_err("adversarial hidden-program shape must be rejected");
            assert!(
                err.to_string().contains(expected),
                "expected `{expected}` in {err}"
            );
        }
    }
    #[test]
    fn programmed_public_parameters_reject_tampered_digests() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let program = default_bfv_programmed_hidden_program();
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters,
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        let mut wrong_parameter_digest = programmed.clone();
        wrong_parameter_digest.parameter_digest = Hash::new(b"wrong-parameters");
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&wrong_parameter_digest).expect("encode tampered params"),
        )
        .expect_err("tampered parameter digest must be rejected");
        assert!(err.to_string().contains("parameter digest"));
        let mut zero_program_digest = programmed.clone();
        zero_program_digest.hidden_program_digest = Hash::prehashed([0; Hash::LENGTH]);
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&zero_program_digest).expect("encode zero program digest"),
        )
        .expect_err("zero hidden-program digest must be rejected");
        assert!(err.to_string().contains("hidden-program digest"));
        let mut wrong_evaluation_digest = programmed;
        wrong_evaluation_digest.evaluation_key_digest = Hash::new(b"wrong-evaluation-keys");
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&wrong_evaluation_digest).expect("encode tampered params"),
        )
        .expect_err("tampered evaluation-key digest must be rejected");
        assert!(err.to_string().contains("evaluation-key digest"));
    }
    #[test]
    fn programmed_public_parameters_reject_malformed_archive_without_panicking() {
        let err = decode_bfv_programmed_public_parameters(&[0xFF, 0x00, 0x7F])
            .expect_err("malformed programmed-BFV parameters must fail closed");
        assert!(
            matches!(err, RamLfeError::TranscriptEncoding(_)),
            "unexpected error: {err}"
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn programmed_public_parameters_reject_profile_and_verifier_metadata_abuse() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let program = default_bfv_programmed_hidden_program();
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters,
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        let verifier = RamLfeProofVerifierMetadata {
            proof_backend: "halo2/ram-lfe-v1".to_owned(),
            circuit_id: "ram-lfe-test".to_owned(),
            public_inputs_schema_hash: Hash::new(b"schema"),
            verifying_key_bytes: vec![0xAA],
        };
        let mut wrong_profile = programmed.clone();
        wrong_profile.ram_fhe_profile.register_count = wrong_profile
            .ram_fhe_profile
            .register_count
            .saturating_add(1);
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&wrong_profile).expect("encode wrong profile"),
        )
        .expect_err("tampered RAM-FHE profile must be rejected");
        assert!(err.to_string().contains("profile"));
        let mut signed_with_verifier = programmed.clone();
        signed_with_verifier.proof_verifier = Some(verifier.clone());
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&signed_with_verifier).expect("encode signed verifier abuse"),
        )
        .expect_err("signed policies must not publish proof verifier metadata");
        assert!(err.to_string().contains("signed RAM-LFE"));
        let mut proof_without_verifier = programmed.clone();
        proof_without_verifier.verification_mode = RamLfeVerificationMode::Proof;
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_without_verifier).expect("encode missing verifier"),
        )
        .expect_err("proof policies must publish verifier metadata");
        assert!(err.to_string().contains("proof-carrying"));
        let mut proof_with_blank_backend = programmed.clone();
        proof_with_blank_backend.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_blank_backend.proof_verifier = Some(RamLfeProofVerifierMetadata {
            proof_backend: "   ".to_owned(),
            ..verifier.clone()
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_blank_backend).expect("encode blank backend"),
        )
        .expect_err("blank proof verifier backend must be rejected");
        assert!(err.to_string().contains("backend"));
        let mut proof_with_padded_backend = programmed.clone();
        proof_with_padded_backend.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_padded_backend.proof_verifier = Some(RamLfeProofVerifierMetadata {
            proof_backend: " halo2/ram-lfe-v1".to_owned(),
            ..verifier.clone()
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_padded_backend).expect("encode padded backend"),
        )
        .expect_err("padded proof verifier backend must be rejected");
        assert!(err.to_string().contains("canonical"));
        let mut proof_with_control_circuit = programmed.clone();
        proof_with_control_circuit.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_control_circuit.proof_verifier = Some(RamLfeProofVerifierMetadata {
            circuit_id: "ram-lfe\n-test".to_owned(),
            ..verifier.clone()
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_control_circuit).expect("encode control circuit"),
        )
        .expect_err("control bytes in proof verifier circuit_id must be rejected");
        assert!(err.to_string().contains("printable ASCII"));
        let mut proof_with_zero_schema = programmed.clone();
        proof_with_zero_schema.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_zero_schema.proof_verifier = Some(RamLfeProofVerifierMetadata {
            public_inputs_schema_hash: Hash::prehashed([0; Hash::LENGTH]),
            ..verifier.clone()
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_zero_schema).expect("encode zero schema hash"),
        )
        .expect_err("zero proof verifier schema hash must be rejected");
        assert!(err.to_string().contains("schema hash"));
        let mut proof_with_oversized_vk = programmed.clone();
        proof_with_oversized_vk.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_oversized_vk.proof_verifier = Some(RamLfeProofVerifierMetadata {
            verifying_key_bytes: vec![0xAA; RAM_LFE_PROOF_VERIFYING_KEY_MAX_BYTES + 1],
            ..verifier.clone()
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_oversized_vk).expect("encode oversized verifying key"),
        )
        .expect_err("oversized proof verifier bytes must be rejected");
        assert!(err.to_string().contains("maximum supported length"));
        let mut proof_with_zero_vk = programmed.clone();
        proof_with_zero_vk.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_zero_vk.proof_verifier = Some(RamLfeProofVerifierMetadata {
            verifying_key_bytes: vec![0; 32],
            ..verifier.clone()
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_zero_vk).expect("encode zero verifying key"),
        )
        .expect_err("all-zero proof verifier bytes must be rejected");
        assert!(err.to_string().contains("all zero"));
        let mut proof_with_empty_vk = programmed;
        proof_with_empty_vk.verification_mode = RamLfeVerificationMode::Proof;
        proof_with_empty_vk.proof_verifier = Some(RamLfeProofVerifierMetadata {
            verifying_key_bytes: Vec::new(),
            ..verifier
        });
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&proof_with_empty_vk).expect("encode empty verifying key"),
        )
        .expect_err("empty proof verifier bytes must be rejected");
        assert!(err.to_string().contains("verifier bytes"));
    }
    #[test]
    fn programmed_public_parameters_reject_unused_refresh_keys() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let program = default_bfv_programmed_hidden_program();
        let (public_parameters, secret_key, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters.clone(),
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        let mut with_rotation = programmed.clone();
        with_rotation.evaluation_keys.rotation_keys.push(
            rotation_key_from_seed(
                &params,
                &public_parameters.public_key,
                1,
                b"bfv-programmed-unused-rotation-key",
            )
            .expect("rotation key"),
        );
        with_rotation.evaluation_key_digest = with_rotation
            .evaluation_keys
            .digest(&params)
            .expect("updated evaluation-key digest");
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&with_rotation).expect("encode rotation-key abuse"),
        )
        .expect_err("programmed public parameters must reject unused rotation keys");
        assert!(err.to_string().contains("rotation refresh keys"));
        let mut with_galois = programmed.clone();
        with_galois.evaluation_keys.galois_keys.push(
            crate::galois_key_from_seed(
                &params,
                &secret_key,
                3,
                b"bfv-programmed-unused-galois-key",
            )
            .expect("Galois key"),
        );
        with_galois.evaluation_key_digest = with_galois
            .evaluation_keys
            .digest(&params)
            .expect("updated evaluation-key digest");
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&with_galois).expect("encode Galois-key abuse"),
        )
        .expect_err("programmed public parameters must reject unused Galois keys");
        assert!(err.to_string().contains("Galois key-switching keys"));
        let mut with_bootstrap = programmed;
        with_bootstrap.evaluation_keys.bootstrap_key = Some(
            bootstrap_key_from_seed(
                &params,
                &public_parameters.public_key,
                "programmed-bootstrap-key",
                b"bfv-programmed-unused-bootstrap-key",
            )
            .expect("bootstrap key"),
        );
        with_bootstrap.evaluation_key_digest = with_bootstrap
            .evaluation_keys
            .digest(&params)
            .expect("updated evaluation-key digest");
        let err = decode_bfv_programmed_public_parameters(
            &norito::to_bytes(&with_bootstrap).expect("encode bootstrap-key abuse"),
        )
        .expect_err("programmed public parameters must reject unused bootstrap keys");
        assert!(err.to_string().contains("bootstrap refresh keys"));
    }
    #[test]
    fn programmed_evaluation_rejects_truncated_ciphertext_envelope() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let program = default_bfv_programmed_hidden_program();
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters.clone(),
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        let commitment = bfv_programmed_policy_commitment_with_program(
            secret,
            &norito::to_bytes(&programmed).expect("encode public parameters"),
            &program,
        )
        .expect("build BFV policy commitment");
        let mut ciphertext = encrypt_identifier_from_seed(
            &public_parameters,
            b"+15551234567",
            b"truncated-bfv-programmed-ciphertext",
        )
        .expect("encrypt identifier");
        ciphertext.slots.pop().expect("test ciphertext has slots");
        let request = ClientRequest {
            normalized_input: norito::to_bytes(&ciphertext).expect("encode tampered ciphertext"),
            associated_data: associated_data.to_vec(),
        };
        let err = evaluate_diagnostic_commitment_with_hidden_program(
            secret,
            &commitment,
            &request,
            Some(&program),
        )
        .expect_err("truncated ciphertext envelope must not evaluate");
        assert!(err.to_string().contains("expected"));
    }
    #[test]
    fn select_eq_zero_truth_table_covers_all_byte_values() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let program = program_for_test(
            1,
            BFV_PROGRAM_REGISTER_COUNT_U16,
            BFV_PROGRAM_STATE_WIDTH_U16,
            &[
                HiddenRamFheInstruction::LoadInput(0, 1),
                HiddenRamFheInstruction::LoadConst(1, 42),
                HiddenRamFheInstruction::LoadConst(2, 7),
                HiddenRamFheInstruction::SelectEqZero(3, 0, 1, 2),
                HiddenRamFheInstruction::Output(3),
            ],
        );
        validate_hidden_ram_fhe_program(&program).expect("select program validates");
        let (public_parameters, secret_key, relinearization_key) =
            derive_identifier_key_material_from_seed(
                &params,
                RAM_LFE_BFV_IDENTIFIER_MAX_INPUT_BYTES,
                secret,
                associated_data,
            )
            .expect("derive BFV public parameters");
        let programmed = try_bfv_programmed_public_parameters_with_program(
            public_parameters.clone(),
            BfvEvaluationKeyBundle {
                relinearization_key,
                rotation_keys: Vec::new(),
                galois_keys: Vec::new(),
                bootstrap_key: None,
            },
            &program,
            RamLfeVerificationMode::Signed,
            None,
        )
        .expect("build programmed BFV public parameters");
        let commitment = bfv_programmed_policy_commitment_with_program(
            secret,
            &norito::to_bytes(&programmed).expect("encode public parameters"),
            &program,
        )
        .expect("build BFV policy commitment");
        for byte in 0_u8..=u8::MAX {
            let ciphertext = encrypt_identifier_from_seed(
                &public_parameters,
                &[byte],
                format!("select-eq-zero-byte-{byte}").as_bytes(),
            )
            .expect("encrypt byte");
            let request = ClientRequest {
                normalized_input: norito::to_bytes(&ciphertext).expect("encode BFV ciphertext"),
                associated_data: associated_data.to_vec(),
            };
            let response = evaluate_diagnostic_commitment_with_hidden_program(
                secret,
                &commitment,
                &request,
                Some(&program),
            )
            .expect("evaluate select program");
            let archived = norito::from_bytes::<BfvIdentifierCiphertext>(&response.output)
                .expect("decode output envelope");
            let output: BfvIdentifierCiphertext =
                norito::core::DeserializePayload::deserialize(archived);
            assert_eq!(output.slots.len(), 1);
            let plaintext =
                decrypt(&params, &secret_key, &output.slots[0]).expect("decrypt output");
            assert_eq!(plaintext[0], if byte == 0 { 42 } else { 7 }, "byte {byte}");
        }
    }
    #[test]
    fn bfv_programmed_public_parameters_reject_legacy_payload() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let (public_parameters, _, _) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let legacy_bytes = norito::to_bytes(&public_parameters).expect("encode legacy parameters");
        decode_bfv_programmed_public_parameters(&legacy_bytes)
            .expect_err("legacy raw BFV payloads are not accepted in the first release");
    }
    #[test]
    fn bfv_programmed_public_parameters_reject_debug_proof_backends() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, b"phone#retail")
                .expect("derive BFV public parameters");
        let evaluation_keys = BfvEvaluationKeyBundle {
            relinearization_key,
            rotation_keys: Vec::new(),
            galois_keys: Vec::new(),
            bootstrap_key: None,
        };
        let debug_verifier = RamLfeProofVerifierMetadata {
            proof_backend: "debug/ok".to_owned(),
            circuit_id: "ram-lfe-test".to_owned(),
            public_inputs_schema_hash: Hash::new(b"schema"),
            verifying_key_bytes: vec![0xAA],
        };
        let err = try_bfv_programmed_public_parameters_with_program(
            public_parameters.clone(),
            evaluation_keys.clone(),
            &default_bfv_programmed_hidden_program(),
            RamLfeVerificationMode::Proof,
            Some(debug_verifier.clone()),
        )
        .expect_err("debug proof backend must be rejected");
        assert!(err.to_string().contains("debug proof backends"));
        let mut programmed =
            try_bfv_programmed_public_parameters(public_parameters, evaluation_keys)
                .expect("build programmed BFV public parameters");
        programmed.verification_mode = RamLfeVerificationMode::Proof;
        programmed.proof_verifier = Some(debug_verifier);
        let encoded = norito::to_bytes(&programmed).expect("encode programmed params");
        let err = decode_bfv_programmed_public_parameters(&encoded)
            .expect_err("debug proof backend must be rejected while decoding");
        assert!(err.to_string().contains("debug proof backends"));
    }
    #[test]
    fn bfv_programmed_policy_commitment_changes_with_input() {
        let secret = b"resolver-secret";
        let params = ram_lfe_bfv_parameters_v1();
        let associated_data = b"phone#retail";
        let (public_parameters, _, relinearization_key) =
            derive_identifier_key_material_from_seed(&params, 63, secret, associated_data)
                .expect("derive BFV public parameters");
        let evaluation_keys = BfvEvaluationKeyBundle {
            relinearization_key,
            rotation_keys: Vec::new(),
            galois_keys: Vec::new(),
            bootstrap_key: None,
        };
        let programmed =
            try_bfv_programmed_public_parameters(public_parameters.clone(), evaluation_keys)
                .expect("build programmed BFV public parameters");
        let commitment = bfv_programmed_policy_commitment(
            secret,
            &norito::to_bytes(&programmed).expect("encode public parameters"),
        )
        .expect("build BFV policy commitment");
        let left = ClientRequest {
            normalized_input: norito::to_bytes(
                &encrypt_identifier_from_seed(
                    &public_parameters,
                    b"alice@example.test",
                    b"bfv-programmed-left-seed",
                )
                .expect("encrypt left input"),
            )
            .expect("encode left ciphertext"),
            associated_data: associated_data.to_vec(),
        };
        let right = ClientRequest {
            normalized_input: norito::to_bytes(
                &encrypt_identifier_from_seed(
                    &public_parameters,
                    b"bravo@example.test",
                    b"bfv-programmed-right-seed",
                )
                .expect("encrypt right input"),
            )
            .expect("encode right ciphertext"),
            associated_data: associated_data.to_vec(),
        };
        let left =
            evaluate_diagnostic_commitment(secret, &commitment, &left).expect("left evaluation");
        let right =
            evaluate_diagnostic_commitment(secret, &commitment, &right).expect("right evaluation");
        assert_ne!(left.output, right.output);
        assert_ne!(left.opaque_id, right.opaque_id);
        assert_ne!(left.receipt_hash, right.receipt_hash);
    }
}

#[cfg(test)]
mod captured_schema_tests;

// TODO: qualify an RNS encryption profile and complete relation before adopting
// this structural planner. It cannot authorize encryption or execution.
#[cfg(test)]
mod planning_candidate;
