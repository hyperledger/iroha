//! Iroha Core zero-knowledge verification: compiled proof relations, guarded
//! verification and batch de-duplication.
//!
//! This crate was extracted from `iroha_core` (formerly `iroha_core::zk` and
//! `iroha_core::zk_stark`) so the proof stack compiles as its own unit. The
//! `norito_schema` names inside it (for example `iroha_core::zk_stark::StarkProofV1`)
//! are unchanged protocol declarations, not Rust paths. Log targets now start with
//! `iroha_core_zk`, which `iroha_core=…` `EnvFilter` directives still match by prefix.
//!
//! This crate provides:
//! - [`verify_for_relation`], which requires the application to name the exact
//!   [`ProofRelation`] it needs and returns actionable verification errors.
//! - Stable proof/verifying-key hash helpers (`hash_proof`, `hash_vk`).
//! - Batch-local de-duplication cache (`DedupCache`) and a light pre-verifier.
//! - Closed dispatch for supported native PIPA-R and STARK relations. A backend
//!   label is not a privacy or execution-correctness guarantee. Incomplete IVM
//!   execution relations are not admitted through generic verification.
//! - Canonical Norito proof envelopes for native verification and fixtures.
//!
//! Storage/WSV integration is intentionally limited to proof records and
//! verifying-key registry ISIs; consensus-critical state and policies live in
//! `iroha_core`'s `smartcontracts::isi` and related modules.
#![allow(unexpected_cfgs)]
/// Native STARK/FRI verifier under `zk-stark` (`stark/fri/*`).
#[cfg(feature = "zk-stark")]
pub mod stark;
//
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
/// Wallet-facing confidential proving with canonical relation and key selection.
pub mod confidential;
/// Shared confidential note, tree, and verifier-key primitives.
pub mod confidential_v2;
mod ivm_proof_identity;
mod native_key_carrier;
mod verification;
/// Canonical move-only verification attempt owners and codec classifiers.
pub use iroha_plonk::verification_attempt;
pub use iroha_plonk::verification_attempt::{VerificationAttemptError, VerificationRefusal};
pub use verification::{ProofRelation, ProofVerificationError, VerifiedProof, verify_for_relation};
/// Frame-identity path mapping for the relocated nominal schema names.
#[cfg(test)]
pub(crate) mod frame_test_support;
pub mod kagemusha_wallet_advance_v1;
pub mod kagemusha_wallet_archive_bytes_v1;
/// Complete installed wallet verifier inventory and native artifact identity owner.
pub mod kagemusha_wallet_artifacts_v1;
/// Design §5.3 runtime capacity check: storage and memory bounds from installed relations.
pub mod kagemusha_wallet_capacity_v1;
/// Actual enrolled custody, issuer/account originals and fresh existing-account admission.
pub mod kagemusha_wallet_enrollment_v1;
pub mod kagemusha_wallet_intake_v1;
/// Canonical G1 preparation and typed real native sigma/A/W inputs.
pub mod kagemusha_wallet_preparation_v1;
/// Authenticated native wallet proof artifacts and full sigma/Omega verification.
pub mod kagemusha_wallet_proofs_v1;
/// Immutable arbitrary-asset registration transport verified against installed native genesis.
pub mod kagemusha_wallet_registration_v1;
pub mod kagemusha_wallet_state_v1;
/// Exact native PIPA-R built-in relations and their canonical proof containers.
pub mod native_pipa_r;
// TODO: Qualify the complete private RAM-LFE relation before admitting a circuit.
// These internal experiments have no production verifier entry point.
#[cfg(test)]
mod ram_lfe_byte;
#[cfg(test)]
mod ram_lfe_poseidon;
#[cfg(test)]
mod ram_lfe_test_support;
#[cfg(test)]
mod ram_lfe_word;
/// Core-owned authenticated confidential-spool adapter for MKHE RNS-native sources.
pub mod rns_native_source_v1;
#[cfg(feature = "zk-stark")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroha_data_model::proof::{ProofBox, VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord};
#[cfg(feature = "zk-stark")]
use iroha_data_model::zk::StarkFriOpenProofV1;
#[cfg(test)]
use kaigi_zk::{
    authorization_v1::{
        KAIGI_AUTHORIZATION_BACKEND_V1, KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
        KAIGI_AUTHORIZATION_CIRCUIT_K_V1, KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1,
        KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1,
    },
    usage_v1::{
        KAIGI_USAGE_BACKEND_V1, KAIGI_USAGE_CIRCUIT_ID_V1, KAIGI_USAGE_CIRCUIT_K_V1,
        KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1,
    },
};
use sha2::{Digest, Sha256};
/// Hard caps for TLV sections to preserve bounded parsing and determinism.
/// These are generous relative to current tests and examples.
const MAX_PROOF_LEN: usize = 8 * 1024 * 1024; // 8 MiB
/// Maximum canonical encoding accepted for a STARK/FRI V1 verifying key.
///
/// The payload contains one bounded circuit identifier and a fixed set of
/// scalar parameters, so 4 KiB leaves ample format headroom without allowing
/// registry input to inherit a caller-sized decode budget.
pub const STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES: usize = 4 * 1024;
/// Hard admission cap for an exact compiled native PIPA-R verifying key.
pub const NATIVE_PIPA_R_VERIFYING_KEY_V1_MAX_BYTES: usize = native_pipa_r::MAX_KEY_BYTES;
/// Canonical backend identifier for native PIPA-R verification over Pasta.
pub const ZK_BACKEND_NATIVE_PIPA_R: &str = native_pipa_r::BACKEND;
/// Return whether the exact backend and circuit identify a compiled native relation.
#[must_use]
pub fn pipa_r_open_verify_circuit_id_matches_backend(backend: &str, circuit_id: &str) -> bool {
    native_pipa_r::relation(backend, circuit_id).is_some()
}
/// Sole canonical native STARK/FRI verifier profile for the first release.
pub const ZK_BACKEND_STARK_FRI_V1: &str = iroha_data_model::zk::ZK_BACKEND_STARK_FRI_V1;
/// Reserved suffix for the unavailable complete native IVM execution relation.
///
/// TODO: Admit this identifier only after the full STARK execution relation and
/// finalized State-owned anchor verification are implemented.
pub const IVM_EXECUTION_V1_CIRCUIT_ID: &str = "ivm-execution-v1";
/// Canonical semantic role reserved for governance ballot proofs.
#[doc(hidden)]
pub const GOVERNANCE_BALLOT_CIRCUIT_ID_V1: &str = "vote-ballot";
/// Canonical semantic role reserved for governance tally proofs.
#[doc(hidden)]
pub const GOVERNANCE_TALLY_CIRCUIT_ID_V1: &str = "vote-tally";
fn hash_domain_separated_payload(domain: &[u8], backend: &str, bytes: &[u8]) -> [u8; 32] {
    let backend_len = u64::try_from(backend.len()).expect("backend length must fit into u64");
    let bytes_len = u64::try_from(bytes.len()).expect("payload length must fit into u64");
    let mut h = Sha256::new();
    h.update(domain);
    h.update(backend_len.to_be_bytes());
    h.update(backend.as_bytes());
    h.update(bytes_len.to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}
/// Compute a stable, domain-separated 32-byte hash of the proof payload.
#[inline]
pub fn hash_proof(proof: &ProofBox) -> [u8; 32] {
    hash_domain_separated_payload(b"iroha:zk:v1:proof", &proof.backend, &proof.bytes)
}
/// Compute a stable, domain-separated 32-byte hash of the verifying key payload.
#[inline]
pub fn hash_vk(vk: &VerifyingKeyBox) -> [u8; 32] {
    hash_vk_bytes(&vk.backend, &vk.bytes)
}
#[doc(hidden)]
pub fn hash_vk_bytes(backend: &str, bytes: &[u8]) -> [u8; 32] {
    hash_domain_separated_payload(b"iroha:zk:v1:vk", backend, bytes)
}
/// Returns `true` when `backend` denotes an explicitly admitted native
/// STARK/FRI verifier profile.
#[inline]
#[doc(hidden)]
pub fn is_stark_fri_v1_backend(backend: &str) -> bool {
    iroha_data_model::zk::is_stark_fri_v1_backend_label(backend)
}
/// Returns `true` for backend labels that require a trusted setup and are not
/// admitted into the native verifier registry.
#[inline]
#[must_use]
pub fn is_trusted_setup_backend_label(backend: &str) -> bool {
    let backend = backend.to_ascii_lowercase();
    let backend = backend.as_str();
    has_trusted_setup_backend_segment(backend)
        || has_trusted_setup_backend_compact_label(backend)
        || backend == "groth16"
        || backend.starts_with("groth16/")
        || backend == "kzg"
        || backend.starts_with("kzg/")
        || backend == "bn254"
        || backend == "bn256"
        || backend == "bls12_381"
        || backend == "bls12-381"
        || backend == "halo2/bn254"
        || backend.starts_with("halo2/bn254/")
        || backend.contains("/bn254")
        || backend.contains(":bn254")
        || backend.contains("/bn256")
        || backend.contains(":bn256")
        || backend.contains("/bls12")
        || backend.contains(":bls12")
        || backend == "halo2/kzg"
        || backend.starts_with("halo2/kzg/")
        || backend.contains("/kzg")
        || backend.contains(":kzg")
}
fn has_trusted_setup_backend_segment(backend: &str) -> bool {
    const TRUSTED_SETUP_SEGMENTS: &[&str] = &[
        "groth16",
        "kzg",
        "bn254",
        "bn256",
        "bls12",
        "srs",
        "crs",
        "ptau",
        "ceremony",
        "powersoftau",
    ];
    backend
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|segment| TRUSTED_SETUP_SEGMENTS.contains(&segment))
}
fn has_trusted_setup_backend_compact_label(backend: &str) -> bool {
    let compact = backend
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    [
        "groth16",
        "kzg",
        "bn254",
        "bn256",
        "bls12381",
        "bls12",
        "srs",
        "crs",
        "ptau",
        "ceremony",
        "trustedsetup",
        "structuredreferencestring",
        "universalsrs",
        "powersoftau",
    ]
    .iter()
    .any(|token| compact.contains(token))
}
const DEVELOPER_ONLY_EMBEDDED_BACKEND_TOKENS: &[&str] = &[
    "debug", "mock", "fixture", "dev", "todo", "draft", "pending", "replace",
];
const DEVELOPER_ONLY_EXACT_BACKEND_TOKENS: &[&str] = &[
    "test",
    "dummy",
    "fake",
    "stub",
    "sample",
    "placeholder",
    "todo",
    "draft",
];
const DEVELOPER_ONLY_COMPACT_BACKEND_FRAGMENTS: &[&str] = &[
    "notforproduction",
    "notproduction",
    "notproductionready",
    "notready",
    "replacebeforeproduction",
    "replacebeforemainnet",
    "draftonly",
];
const PRODUCTION_CLAIM_BACKEND_FRAGMENTS: &[&str] = &[
    "productionready",
    "productionhardened",
    "productionenabled",
    "productionapproved",
    "productioncertified",
    "productionclaim",
    "claimedproduction",
    "mainnetready",
    "mainnetcomplete",
    "mainnetclaim",
    "claimedmainnet",
    "mainnetcertified",
    "mainnetapproved",
    "mainnetrelease",
    "auditedproduction",
    "externallyaudited",
    "thirdpartyaudited",
    "boiaudited",
    "auditedmainnet",
    "externalaudit",
    "auditpassed",
    "auditapproved",
    "auditsignoff",
    "auditclaim",
    "claimedaudit",
    "securityreviewpassed",
    "securityauditpassed",
    "securityaudited",
    "externalsecurityreview",
    "certifiedproduction",
    "certifiedmainnet",
    "releaseready",
    "releaseapproved",
    "releasecertified",
];
fn compact_ascii_lowercase_label(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}
#[inline]
fn is_developer_only_direct_backend_token(token: &str) -> bool {
    DEVELOPER_ONLY_EMBEDDED_BACKEND_TOKENS
        .iter()
        .any(|reserved| token.contains(reserved))
        || DEVELOPER_ONLY_EXACT_BACKEND_TOKENS.contains(&token)
}
#[inline]
fn is_developer_only_compact_backend_run(run: &str) -> bool {
    DEVELOPER_ONLY_EMBEDDED_BACKEND_TOKENS
        .iter()
        .any(|reserved| run.contains(reserved))
        || DEVELOPER_ONLY_EXACT_BACKEND_TOKENS.contains(&run)
}
/// Returns `true` for developer-only backend labels that must not enter
/// proof admission, preverification, or native verifier dispatch.
#[inline]
#[must_use]
pub fn is_developer_only_backend_label(backend: &str) -> bool {
    let backend = backend.to_ascii_lowercase();
    let compact = compact_ascii_lowercase_label(&backend);
    if DEVELOPER_ONLY_COMPACT_BACKEND_FRAGMENTS
        .iter()
        .any(|fragment| compact.contains(fragment))
    {
        return true;
    }
    let mut letter_run = String::new();
    for token in backend
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        if is_developer_only_direct_backend_token(token) {
            return true;
        }
        if token.len() == 1 {
            letter_run.push_str(token);
        } else {
            if is_developer_only_compact_backend_run(&letter_run) {
                return true;
            }
            letter_run.clear();
        }
    }
    is_developer_only_compact_backend_run(&letter_run)
}
/// Returns `true` for verifier backend labels that claim production, mainnet,
/// or audit approval instead of matching an explicitly admitted verifier id.
#[inline]
#[must_use]
pub fn is_production_claim_backend_label(backend: &str) -> bool {
    let compact = compact_ascii_lowercase_label(backend);
    PRODUCTION_CLAIM_BACKEND_FRAGMENTS
        .iter()
        .any(|fragment| compact.contains(fragment))
}
/// Return the expected OpenVerify backend tag for labels admitted by native
/// verifier dispatch.
#[inline]
#[must_use]
pub fn verifier_backend_registry_tag_v1(backend: &str) -> Option<iroha_data_model::zk::BackendTag> {
    iroha_data_model::zk::verifier_backend_registry_tag_v1(backend)
}
/// Returns `true` when `backend` names a verifier family that can reach native
/// verifier dispatch.
#[inline]
#[must_use]
pub fn is_verifier_backend_registry_label_v1(backend: &str) -> bool {
    verifier_backend_registry_tag_v1(backend).is_some()
}
fn production_verify_backend_label_is_portable(backend: &str) -> bool {
    if backend.is_empty() || backend.trim() != backend {
        return false;
    }
    let is_lower_ascii_alphanumeric =
        |byte: u8| byte.is_ascii_alphanumeric() && matches!(byte, b'a'..=b'z' | b'0'..=b'9');
    let bytes = backend.as_bytes();
    if !is_lower_ascii_alphanumeric(bytes[0])
        || !is_lower_ascii_alphanumeric(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(|byte| {
            is_lower_ascii_alphanumeric(byte) || matches!(byte, b'/' | b':' | b'.' | b'_' | b'-')
        })
    {
        return false;
    }
    !["//", "::", "..", "/:", ":/", "/.", "./", ":.", ".:"]
        .iter()
        .any(|separator| backend.contains(separator))
}
/// Return the low-level proof engine for an exact production verifier label.
///
/// Textual readiness claims, trusted-setup families, developer-only labels,
/// non-portable spellings, and labels outside the closed registry all fail
/// closed.
#[must_use]
pub fn production_verify_backend_tag(backend: &str) -> Option<iroha_data_model::zk::BackendTag> {
    if !production_verify_backend_label_is_portable(backend)
        || is_production_claim_backend_label(backend)
        || is_trusted_setup_backend_label(backend)
        || is_developer_only_backend_label(backend)
    {
        return None;
    }
    verifier_backend_registry_tag_v1(backend)
}
/// Returns `true` only for an exact production verifier label.
#[inline]
#[must_use]
pub fn is_production_verify_backend_label(backend: &str) -> bool {
    production_verify_backend_tag(backend).is_some()
}
/// Backend material prepared by the strict first-release verifying-key validator.
///
/// This contains only bounded, already-validated parameters. Callers retain the
/// canonical key bytes separately for the native verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PreparedVerifyingKeyMaterialV1 {
    /// Native PIPA-R material authenticated against the exact compiled relation.
    NativePipaRPasta {
        /// Fixed domain exponent of the compiled native relation.
        ipa_k: u32,
    },
    /// Native STARK/FRI material pinned by the canonical registry payload.
    #[cfg_attr(not(feature = "zk-stark"), allow(dead_code))]
    StarkFri {
        /// Canonical circuit identifier embedded in the key payload.
        circuit_id: String,
        /// Evaluation-domain exponent.
        n_log2: u8,
        /// FRI blow-up exponent.
        blowup_log2: u8,
        /// FRI folding arity.
        fold_arity: u8,
        /// Number of verifier queries.
        queries: u16,
        /// Merkle-tree arity.
        merkle_arity: u8,
    },
}
impl PreparedVerifyingKeyMaterialV1 {
    /// Return the authenticated native IPA domain exponent, when applicable.
    #[inline]
    #[must_use]
    #[doc(hidden)]
    pub const fn ipa_k(&self) -> Option<u32> {
        match self {
            Self::NativePipaRPasta { ipa_k } => Some(*ipa_k),
            Self::StarkFri { .. } => None,
        }
    }
}
/// Validate and prepare exact inline verifier material under backend-specific
/// resource limits.
///
/// This is the single material gate shared by registry mutation, state
/// hydration, and native proof dispatch. It rejects a backend/circuit mismatch,
/// oversized or malformed containers, non-canonical STARK encodings, weak
/// STARK parameters, and native keys that differ from the deterministically
/// compiled circuit key.
pub(crate) fn validate_and_prepare_verifying_key_material_v1(
    backend: &str,
    circuit_id: &str,
    backend_tag: iroha_data_model::zk::BackendTag,
    vk: &VerifyingKeyBox,
) -> Result<PreparedVerifyingKeyMaterialV1, VerificationAttemptError<String>> {
    if vk.backend.as_str() != backend {
        return Err(
            ("verifying-key payload backend does not match registry backend".to_owned()).into(),
        );
    }
    if production_verify_backend_tag(backend) != Some(backend_tag) {
        return Err(("verifying-key backend is not an exact production backend".to_owned()).into());
    }
    match backend_tag {
        iroha_data_model::zk::BackendTag::NativePipaRPasta => {
            let kind = native_pipa_r::validate_key(backend, circuit_id, vk)
                .map_err(|error| error.map_rejection(|invalid| invalid.to_string()))?;
            Ok(PreparedVerifyingKeyMaterialV1::NativePipaRPasta { ipa_k: kind.k() })
        }
        iroha_data_model::zk::BackendTag::Stark => {
            #[cfg(not(feature = "zk-stark"))]
            {
                let _ = (circuit_id, vk);
                Err(("verifying-key backend Stark is not enabled".to_owned()).into())
            }
            #[cfg(feature = "zk-stark")]
            {
                // The decoder performs the whole-container check and bounded
                // canonical Norito decode before materializing the typed key.
                let payload =
                    validate_stark_fri_verifying_key_v1(backend, circuit_id, vk.bytes.as_slice())?;
                Ok(PreparedVerifyingKeyMaterialV1::StarkFri {
                    circuit_id: payload.circuit_id,
                    n_log2: payload.n_log2,
                    blowup_log2: payload.blowup_log2,
                    fold_arity: payload.fold_arity,
                    queries: payload.queries,
                    merkle_arity: payload.merkle_arity,
                })
            }
        }
    }
}
/// Validate one verifier registry record and prepare any inline key material.
///
/// Commitment, declared length, registry backend, curve, circuit, and inline
/// key bytes are checked together so mutation and state rehydration cannot
/// disagree about the record that proof dispatch later consumes. Records that
/// publish only an off-ledger commitment have no prepared inline material and
/// remain unusable by native proof dispatch until a validated inline key is
/// installed.
#[doc(hidden)]
pub fn validate_and_prepare_verifying_key_record_v1(
    id: &VerifyingKeyId,
    record: &VerifyingKeyRecord,
) -> Result<Option<PreparedVerifyingKeyMaterialV1>, VerificationAttemptError<String>> {
    if !id.is_portable_registry_id() {
        return Err(("verifying-key registry id is not bounded and portable".to_owned()).into());
    }
    if record.commitment == [0_u8; 32] {
        return Err(("verifying-key commitment must be non-zero".to_owned()).into());
    }
    if record.public_inputs_schema_hash == [0_u8; 32] {
        return Err(("verifying-key public-input schema hash must be non-zero".to_owned()).into());
    }
    let backend = id.backend.as_str();
    if production_verify_backend_tag(backend) != Some(record.backend) {
        return Err(
            ("verifying-key record backend does not match the production registry backend"
                .to_owned())
            .into(),
        );
    }
    match record.backend {
        iroha_data_model::zk::BackendTag::NativePipaRPasta => {
            if record.curve != "vesta" {
                return Err(("native PIPA-R verifying-key curve must be vesta".to_owned()).into());
            }
            let kind = native_pipa_r::relation(backend, &record.circuit_id).ok_or_else(|| {
                "native PIPA-R circuit is not admitted for the registry backend".to_owned()
            })?;
            let schema_hash: [u8; 32] =
                iroha_crypto::Hash::new(native_pipa_r::public_schema(kind)).into();
            if record.public_inputs_schema_hash != schema_hash {
                return Err(
                    ("native PIPA-R public-input schema hash is not canonical".to_owned()).into(),
                );
            }
        }
        iroha_data_model::zk::BackendTag::Stark => {
            if record.curve != "goldilocks" {
                return Err(("STARK/FRI verifying-key curve must be goldilocks".to_owned()).into());
            }
            if !stark_registry_circuit_id_matches_backend(backend, &record.circuit_id) {
                return Err(
                    ("STARK/FRI verifying-key circuit is not admitted for the registry backend"
                        .to_owned())
                    .into(),
                );
            }
        }
    }
    let max_payload_bytes = match record.backend {
        iroha_data_model::zk::BackendTag::NativePipaRPasta => {
            NATIVE_PIPA_R_VERIFYING_KEY_V1_MAX_BYTES
        }
        iroha_data_model::zk::BackendTag::Stark => STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES,
    };
    if u64::from(record.vk_len) > max_payload_bytes as u64 {
        return Err((format!(
            "declared verifying-key length exceeds the {max_payload_bytes}-byte backend limit"
        ))
        .into());
    }
    validate_verifying_key_record_metadata_v1(record)?;
    let Some(vk) = record.key.as_ref() else {
        return Ok(None);
    };
    if vk.bytes.len() > max_payload_bytes {
        return Err((format!(
            "inline verifying-key container exceeds the {max_payload_bytes}-byte backend limit"
        ))
        .into());
    }
    if vk.backend != id.backend {
        return Err(("verifying-key payload backend does not match registry id".to_owned()).into());
    }
    let vk_len = u32::try_from(vk.bytes.len())
        .map_err(|_| "inline verifying-key length exceeds u32".to_owned())?;
    if record.vk_len != vk_len {
        return Err(("verifying-key vk_len does not match inline bytes".to_owned()).into());
    }
    if hash_vk(vk) != record.commitment {
        return Err(("verifying-key commitment does not match inline bytes".to_owned()).into());
    }
    validate_and_prepare_verifying_key_material_v1(backend, &record.circuit_id, record.backend, vk)
        .map(Some)
}

fn validate_verifying_key_record_metadata_v1(record: &VerifyingKeyRecord) -> Result<(), String> {
    if !iroha_data_model::proof::verifying_key_id_field_is_portable(&record.namespace) {
        return Err("verifying-key namespace is not bounded and portable".to_owned());
    }
    if record
        .owner_manifest_id
        .as_ref()
        .is_some_and(|owner| !iroha_data_model::proof::verifying_key_id_field_is_portable(owner))
    {
        return Err("verifying-key owner manifest id is not bounded and portable".to_owned());
    }
    let Some(gas_schedule_id) = record.gas_schedule_id.as_deref() else {
        return Err("verifying-key gas schedule id is required".to_owned());
    };
    if !iroha_data_model::proof::verifying_key_id_field_is_portable(gas_schedule_id) {
        return Err("verifying-key gas schedule id is not bounded and portable".to_owned());
    }
    if record
        .metadata_uri_cid
        .as_deref()
        .is_some_and(|uri| !verifying_key_content_uri_is_portable_v1(uri))
    {
        return Err("verifying-key metadata URI is not bounded and portable".to_owned());
    }
    if record
        .vk_bytes_cid
        .as_deref()
        .is_some_and(|uri| !verifying_key_content_uri_is_portable_v1(uri))
    {
        return Err("verifying-key bytes URI is not bounded and portable".to_owned());
    }
    if matches!(
        (record.activation_height, record.withdraw_height),
        (Some(activation), Some(withdraw)) if withdraw <= activation
    ) {
        return Err(
            "verifying-key withdraw height must be greater than activation height".to_owned(),
        );
    }
    Ok(())
}

fn verifying_key_content_uri_is_portable_v1(uri: &str) -> bool {
    const MAX_URI_BYTES: usize = 512;
    if uri.is_empty()
        || uri.len() > MAX_URI_BYTES
        || uri.trim() != uri
        || uri
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || matches!(*byte, b'\\' | b'?' | b'#' | b'@'))
    {
        return false;
    }
    let body = uri
        .strip_prefix("ipfs://")
        .or_else(|| uri.strip_prefix("cid:"))
        .unwrap_or(uri);
    if body.is_empty()
        || body.starts_with('/')
        || body.ends_with('/')
        || body.contains("..")
        || body.contains("//")
    {
        return false;
    }
    body.split('/').all(|segment| {
        !segment.is_empty()
            && segment
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
    })
}
include!("strict_verifying_key_preparation_tests.rs");
/// Borrow the exact profile-qualified generic OpenVerify circuit identifier.
/// Bare native-protocol identifiers have their own typed consumer and are not
/// alternate spellings of a generic OpenVerify circuit.
pub(crate) fn canonical_stark_fri_circuit_id_for_backend<'a>(
    backend: &str,
    circuit_id: &'a str,
) -> Option<&'a str> {
    if !is_stark_fri_v1_backend(backend)
        || circuit_id.len() > iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES
        || !iroha_data_model::zk::open_verify_circuit_id_is_portable(circuit_id)
    {
        return None;
    }
    let relation = circuit_id.strip_prefix(backend)?.strip_prefix(':')?;
    iroha_data_model::zk::open_verify_circuit_id_is_portable(relation).then_some(circuit_id)
}

// Registry admission for these exact bare native identities retains their own
// typed VK/AIR contract. This list grants no generic OpenVerify dispatch and no
// BFV parameter/security qualification.
fn is_typed_native_stark_circuit_id(circuit_id: &str) -> bool {
    [
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
    ]
    .contains(&circuit_id)
}

fn stark_registry_circuit_id_matches_backend(backend: &str, circuit_id: &str) -> bool {
    if !is_stark_fri_v1_backend(backend) {
        return false;
    }
    if is_typed_native_stark_circuit_id(circuit_id) {
        return true;
    }
    let Some(exact) = canonical_stark_fri_circuit_id_for_backend(backend, circuit_id) else {
        return false;
    };
    let relation = &exact[backend.len() + 1..];
    // Typed keys have one bare registry identity. A matched prefixed record and
    // payload must not preserve an unused second spelling in the registry.
    relation != IVM_EXECUTION_V1_CIRCUIT_ID
        && !is_typed_native_stark_circuit_id(relation)
        && stark_open_verify_circuit_id_matches_backend(backend, exact)
}

/// Check canonical native-STARK identity and reject unavailable IVM relations.
#[must_use]
pub fn stark_open_verify_circuit_id_matches_backend(backend: &str, circuit_id: &str) -> bool {
    canonical_stark_fri_circuit_id_for_backend(backend, circuit_id)
        .and_then(|canonical| canonical.strip_prefix(backend))
        .and_then(|suffix| suffix.strip_prefix(':'))
        .is_some_and(|relation| relation != IVM_EXECUTION_V1_CIRCUIT_ID)
        && !iroha_data_model::zk::open_verify_circuit_id_uses_reserved_privacy_protocol_namespace_v1(
            circuit_id,
        )
        && !stark_open_verify_circuit_id_uses_reserved_proof_family(circuit_id)
}
#[cfg(feature = "zk-stark")]
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct StarkVerifyingKeyCacheKeyV1 {
    backend: String,
    circuit_id: String,
    vk_hash: [u8; 32],
}
#[cfg(feature = "zk-stark")]
type StarkVerifyingKeyCacheMapV1 =
    std::collections::BTreeMap<StarkVerifyingKeyCacheKeyV1, crate::stark::StarkFriVerifyingKeyV1>;
#[cfg(feature = "zk-stark")]
type StarkVerifyingKeyCacheV1 = std::sync::Mutex<StarkVerifyingKeyCacheMapV1>;
#[cfg(feature = "zk-stark")]
const STARK_VERIFYING_KEY_CACHE_CAPACITY_V1: usize = 512;
#[cfg(feature = "zk-stark")]
static STARK_VERIFYING_KEY_CACHE_V1: std::sync::OnceLock<StarkVerifyingKeyCacheV1> =
    std::sync::OnceLock::new();
#[cfg(feature = "zk-stark")]
fn insert_stark_verifying_key_cache_v1(
    cache: &mut StarkVerifyingKeyCacheMapV1,
    key: StarkVerifyingKeyCacheKeyV1,
    payload: crate::stark::StarkFriVerifyingKeyV1,
) -> crate::stark::StarkFriVerifyingKeyV1 {
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    // Validation can run inside a transaction that later rolls back. Bound the
    // process-local accelerator so rejected callbacks cannot grow it without limit.
    while cache.len() >= STARK_VERIFYING_KEY_CACHE_CAPACITY_V1 {
        let Some(evicted) = cache.keys().next().cloned() else {
            break;
        };
        cache.remove(&evicted);
    }
    cache.insert(key, payload.clone());
    payload
}
#[cfg(all(test, feature = "zk-stark"))]
mod stark_verifying_key_cache_tests {
    use super::*;

    fn payload(circuit_id: String) -> crate::stark::StarkFriVerifyingKeyV1 {
        crate::stark::StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id,
            n_log2: crate::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
            blowup_log2: crate::stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: crate::stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        }
    }

    #[test]
    fn rejected_transaction_cache_warming_is_bounded() {
        let mut cache = StarkVerifyingKeyCacheMapV1::new();
        for index in 0..=STARK_VERIFYING_KEY_CACHE_CAPACITY_V1 {
            let circuit_id = format!("circuit-{index:04}");
            let key = StarkVerifyingKeyCacheKeyV1 {
                backend: "stark/fri/poseidon-x7-goldilocks-6x64-v1".to_owned(),
                circuit_id: circuit_id.clone(),
                vk_hash: [u8::try_from(index % 256).expect("bounded byte"); 32],
            };
            insert_stark_verifying_key_cache_v1(&mut cache, key, payload(circuit_id));
        }

        assert_eq!(cache.len(), STARK_VERIFYING_KEY_CACHE_CAPACITY_V1);
        assert!(
            cache.keys().all(|key| key.circuit_id != "circuit-0000"),
            "deterministic eviction must remove the lowest cache key"
        );
        assert!(
            cache.keys().any(|key| key.circuit_id
                == format!("circuit-{STARK_VERIFYING_KEY_CACHE_CAPACITY_V1:04}")),
            "the newest validated key must be cached"
        );
    }
}
#[cfg(all(test, feature = "zk-stark"))]
std::thread_local! {
    // Observe entry, including cache hits, without sharing counters between
    // concurrently executing native tests. No production admission state.
    #[cfg(test)]
    static STARK_VERIFYING_KEY_PREPARATION_ENTRIES_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
/// Decode and validate a canonical STARK/FRI V1 verifier key for one registry binding.
///
/// The returned value is the typed, bounded material that proof verification
/// consumes. Validation binds its circuit and the sole six-lane commitment profile to the exact
/// production backend before a registry record can retain the original bytes.
#[cfg(feature = "zk-stark")]
#[doc(hidden)]
pub fn validate_stark_fri_verifying_key_v1(
    backend: &str,
    circuit_id: &str,
    bytes: &[u8],
) -> Result<crate::stark::StarkFriVerifyingKeyV1, VerificationAttemptError<String>> {
    #[cfg(test)]
    STARK_VERIFYING_KEY_PREPARATION_ENTRIES_V1.with(|entries| entries.set(entries.get() + 1));
    if !stark_registry_circuit_id_matches_backend(backend, circuit_id) {
        return Err(
            ("STARK/FRI circuit id does not match the production backend".to_owned()).into(),
        );
    }
    if bytes.len() > crate::stark::STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES {
        return Err((format!(
            "STARK/FRI verifier key exceeds the {}-byte limit",
            crate::stark::STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES
        ))
        .into());
    }
    let cache_key = StarkVerifyingKeyCacheKeyV1 {
        backend: backend.to_owned(),
        circuit_id: circuit_id.to_owned(),
        vk_hash: hash_vk_bytes(backend, bytes),
    };
    let cache = STARK_VERIFYING_KEY_CACHE_V1
        .get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    if let Some(cached) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached);
    }
    let payload = crate::stark::decode_stark_fri_verifying_key_v1(bytes)?;
    crate::stark::validate_stark_fri_canonical_verifying_key_payload(
        &payload, circuit_id, "registry",
    )?;
    let mut guard = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(insert_stark_verifying_key_cache_v1(
        &mut guard, cache_key, payload,
    ))
}
fn stark_open_verify_circuit_id_uses_reserved_proof_family(circuit_id: &str) -> bool {
    if ivm_proof_identity::circuit_id_uses_reserved_ivm_namespace(circuit_id) {
        return true;
    }
    let trimmed = circuit_id.trim();
    if stark_open_verify_circuit_id_fragment_uses_reserved_proof_family(trimmed) {
        return true;
    }
    let Some(stark_suffix) = trimmed
        .strip_prefix("stark/fri:")
        .or_else(|| trimmed.strip_prefix("stark/fri/"))
    else {
        return false;
    };
    let circuit_fragment = stark_suffix
        .split_once(':')
        .or_else(|| stark_suffix.split_once('/'))
        .map_or(stark_suffix, |(_, fragment)| fragment);
    stark_open_verify_circuit_id_fragment_uses_reserved_proof_family(circuit_fragment)
}
fn stark_open_verify_circuit_id_fragment_uses_reserved_proof_family(fragment: &str) -> bool {
    let lower = fragment.to_ascii_lowercase();
    lower == "halo2"
        || lower
            .strip_prefix("halo2")
            .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with(':'))
        || is_trusted_setup_backend_label(&lower)
}
/// Return whether a canonical generic-STARK circuit id enters the ZK-ACE namespace.
///
/// The complete namespace is reserved from generic `OpenVerify`; ZK-ACE must
/// use typed privacy verification. Deliberately reserving the namespace avoids
/// retaining a dispatch table of retired aliases while making every old
/// spelling fail closed.
fn canonical_circuit_is_zk_ace_relation_for_backend(
    backend: &str,
    canonical_circuit_id: &str,
) -> bool {
    let Some(relation) = canonical_circuit_id
        .strip_prefix(backend)
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return false;
    };
    relation == iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID
        || relation.starts_with("zk_ace_")
        || relation.starts_with("zk-ace-")
}
fn canonical_bfv_full_bootstrap_stark_circuit_id_for_backend(backend: &str) -> Option<String> {
    is_stark_fri_v1_backend(backend).then(|| {
        format!(
            "{backend}:{}",
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1
        )
    })
}
fn canonical_ivm_execution_stark_circuit_id_for_backend(backend: &str) -> Option<String> {
    is_stark_fri_v1_backend(backend).then(|| format!("{backend}:{IVM_EXECUTION_V1_CIRCUIT_ID}"))
}
fn canonical_circuit_is_governance_vote_relation_for_backend(
    backend: &str,
    canonical_circuit_id: &str,
) -> bool {
    [
        GOVERNANCE_BALLOT_CIRCUIT_ID_V1,
        GOVERNANCE_TALLY_CIRCUIT_ID_V1,
    ]
    .into_iter()
    .map(|circuit_id| format!("{backend}:{circuit_id}"))
    .any(|circuit_id| circuit_id == canonical_circuit_id)
}
/// Return whether a canonical circuit id names a typed Soracloud FHE relation.
///
/// These circuit ids must never fall back to the generic binding AIR: that AIR
/// only authenticates public metadata and does not prove any of the private FHE
/// witness relations advertised by the typed Soracloud protocols.
fn canonical_circuit_is_soracloud_fhe_relation_for_backend(
    backend: &str,
    canonical_circuit_id: &str,
) -> bool {
    [
        iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
    ]
    .into_iter()
    .map(|circuit_id| format!("{backend}:{circuit_id}"))
    .any(|circuit_id| circuit_id == canonical_circuit_id)
}
#[cfg(feature = "zk-stark")]
#[doc(hidden)]
pub fn stark_open_verify_domain_tag_current(
    backend: &str,
    circuit_id: &str,
    vk_hash: [u8; 32],
    env_public_inputs: &[u8],
    public_inputs: &[Vec<[u8; 32]>],
) -> String {
    let preimage = stark_binding_air_preimage(
        backend,
        circuit_id,
        vk_hash,
        env_public_inputs,
        public_inputs,
    );
    let digest = crate::stark::stark_open_verify_domain_digest_v1(&preimage)
        .expect("bounded OpenVerify binding preimage hashes into six Goldilocks lanes");
    URL_SAFE_NO_PAD.encode(digest.to_le_bytes())
}
#[cfg(feature = "zk-stark")]
const STARK_BINDING_AIR_CONSTANT: u64 = 17;
#[cfg(feature = "zk-stark")]
const STARK_BINDING_AIR_Z_COEFF: u64 = 19;
#[cfg(feature = "zk-stark")]
const STARK_GOLDILOCKS_MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;
#[cfg(feature = "zk-stark")]
#[doc(hidden)]
pub const STARK_OPEN_VERIFY_AIR_TRANSCRIPT_LABEL_V1: &str = "IROHA-STARK-AIR-V1";
#[cfg(feature = "zk-stark")]
fn stark_binding_air_preimage(
    backend: &str,
    circuit_id: &str,
    vk_hash: [u8; 32],
    env_public_inputs: &[u8],
    public_inputs: &[Vec<[u8; 32]>],
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"iroha:zk:stark-binding-air:v1");
    preimage.extend_from_slice(&(backend.len() as u64).to_le_bytes());
    preimage.extend_from_slice(backend.as_bytes());
    preimage.extend_from_slice(&(circuit_id.len() as u64).to_le_bytes());
    preimage.extend_from_slice(circuit_id.as_bytes());
    preimage.extend_from_slice(&vk_hash);
    preimage.extend_from_slice(&(env_public_inputs.len() as u64).to_le_bytes());
    preimage.extend_from_slice(env_public_inputs);
    preimage.extend_from_slice(&(public_inputs.len() as u64).to_le_bytes());
    let mut cell_count = 0u64;
    for column in public_inputs {
        preimage.extend_from_slice(&(column.len() as u64).to_le_bytes());
        cell_count = cell_count.saturating_add(column.len() as u64);
        for value in column {
            preimage.extend_from_slice(value);
        }
    }
    preimage.extend_from_slice(&cell_count.to_le_bytes());
    preimage
}
#[cfg(feature = "zk-stark")]
fn stark_binding_air_terms(
    backend: &str,
    circuit_id: &str,
    vk_hash: [u8; 32],
    env_public_inputs: &[u8],
    public_inputs: &[Vec<[u8; 32]>],
) -> Vec<crate::stark::StarkCompositionTermV1> {
    let preimage = stark_binding_air_preimage(
        backend,
        circuit_id,
        vk_hash,
        env_public_inputs,
        public_inputs,
    );
    let digest = crate::stark::stark_open_verify_air_terms_digest_v1(&preimage)
        .expect("bounded OpenVerify binding preimage hashes into six Goldilocks lanes");
    let mut terms = Vec::with_capacity(8);
    for (wire_index, value) in (0_u32..).zip(digest.words()) {
        let coeff = u64::from(wire_index) + 3;
        terms.push(crate::stark::StarkCompositionTermV1 {
            wire_index,
            value,
            coeff,
        });
    }
    terms.push(crate::stark::StarkCompositionTermV1 {
        wire_index: 6,
        value: (public_inputs.len() as u128 % STARK_GOLDILOCKS_MODULUS) as u64,
        coeff: 11,
    });
    let cell_count = public_inputs
        .iter()
        .map(Vec::len)
        .fold(0usize, usize::saturating_add);
    terms.push(crate::stark::StarkCompositionTermV1 {
        wire_index: 7,
        value: (cell_count as u128 % STARK_GOLDILOCKS_MODULUS) as u64,
        coeff: 13,
    });
    terms
}
#[cfg(feature = "zk-stark")]
#[doc(hidden)]
pub fn stark_open_verify_air_public_digest_current(
    backend: &str,
    circuit_id: &str,
    vk_hash: [u8; 32],
    env_public_inputs: &[u8],
    public_inputs: &[Vec<[u8; 32]>],
) -> Result<iroha_data_model::privacy::GoldilocksDigest384V1, String> {
    let terms = stark_binding_air_terms(
        backend,
        circuit_id,
        vk_hash,
        env_public_inputs,
        public_inputs,
    );
    crate::stark::stark_air_public_digest_from_composition(
        STARK_BINDING_AIR_CONSTANT,
        STARK_BINDING_AIR_Z_COEFF,
        &terms,
    )
}
#[cfg(any(test, feature = "test-utils"))]
/// Build a STARK/FRI `OpenVerifyEnvelope` from backend-native public inputs.
///
/// The first-release native V1 circuit carries an explicit AIR section whose
/// public statement digest is reconstructed from the outer envelope metadata,
/// verifying-key hash, schema descriptor, and public input columns.
#[cfg(feature = "zk-stark")]
///
/// # Errors
///
/// Returns an input error for an unsupported or mismatched backend, circuit
/// or verifier key, including reserved semantic relations that require their
/// own prover. Native AIR/FRI production and canonical encoding/decoding
/// failures propagate with their original typed causes.
pub fn prove_stark_fri_open_verify_envelope(
    backend: &str,
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
    schema_descriptor: &[u8],
    public_inputs: Vec<Vec<[u8; 32]>>,
) -> Result<ProofBox, crate::stark::StarkProofProductionError> {
    prove_stark_fri_open_verify_envelope_inner(
        backend,
        circuit_id,
        vk_box,
        schema_descriptor,
        public_inputs,
    )
}
#[cfg(all(feature = "zk-stark", any(test, feature = "test-utils")))]
fn prove_stark_fri_open_verify_envelope_inner(
    backend: &str,
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
    schema_descriptor: &[u8],
    public_inputs: Vec<Vec<[u8; 32]>>,
) -> Result<ProofBox, crate::stark::StarkProofProductionError> {
    use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
    if !is_stark_fri_v1_backend(backend) {
        return Err(("backend is not a STARK/FRI V1 backend".to_owned()).into());
    }
    if vk_box.backend != backend {
        return Err(("STARK verifying key backend mismatch".to_owned()).into());
    }
    if !stark_open_verify_circuit_id_matches_backend(backend, circuit_id) {
        return Err(("STARK circuit_id does not match backend family".to_owned()).into());
    }
    let env_circuit_id = canonical_stark_fri_circuit_id_for_backend(backend, circuit_id)
        .ok_or_else(|| "invalid STARK circuit_id".to_owned())?;
    let is_ivm_execution_circuit = canonical_ivm_execution_stark_circuit_id_for_backend(backend)
        .as_deref()
        == Some(env_circuit_id);
    if is_ivm_execution_circuit {
        return Err((
            "IVM execution proof production requires the complete native STARK execution relation"
                .to_owned()).into());
    }
    if canonical_circuit_is_zk_ace_relation_for_backend(backend, env_circuit_id) {
        return Err((
            "generic STARK OpenVerify proof cannot target a ZK-ACE relation; use SubmitPrivacyProofV1"
                .to_owned()).into());
    }
    if canonical_bfv_full_bootstrap_stark_circuit_id_for_backend(backend).as_deref()
        == Some(env_circuit_id)
    {
        return Err((
            "generic STARK OpenVerify proof cannot target the BFV full-bootstrap circuit; use the BFV full-bootstrap STARK prover"
                .to_owned()).into());
    }
    if canonical_circuit_is_governance_vote_relation_for_backend(backend, env_circuit_id) {
        return Err((
            "generic STARK OpenVerify proof cannot target a governance vote role; a dedicated semantic governance circuit is required"
                .to_owned()).into());
    }
    if canonical_circuit_is_soracloud_fhe_relation_for_backend(backend, env_circuit_id) {
        return Err((
            "generic STARK OpenVerify proof cannot target a Soracloud FHE relation; a dedicated typed Soracloud verifier is required"
                .to_owned()).into());
    }
    let vk_payload =
        validate_stark_fri_verifying_key_v1(backend, circuit_id, vk_box.bytes.as_slice())?;
    let vk_circuit_id = canonical_stark_fri_circuit_id_for_backend(backend, &vk_payload.circuit_id)
        .ok_or_else(|| "invalid STARK verifying key circuit_id".to_owned())?;
    if env_circuit_id != vk_circuit_id {
        return Err(("STARK verifying key circuit_id mismatch".to_owned()).into());
    }
    let vk_hash = hash_vk(vk_box);
    let domain_tag = stark_open_verify_domain_tag_current(
        backend,
        circuit_id,
        vk_hash,
        schema_descriptor,
        &public_inputs,
    );
    let params = crate::stark::StarkFriParamsV1 {
        version: 1,
        n_log2: vk_payload.n_log2,
        blowup_log2: vk_payload.blowup_log2,
        fold_arity: vk_payload.fold_arity,
        queries: vk_payload.queries,
        merkle_arity: vk_payload.merkle_arity,
        domain_tag,
    };
    let terms = stark_binding_air_terms(
        backend,
        circuit_id,
        vk_hash,
        schema_descriptor,
        &public_inputs,
    );
    let public_digest = crate::stark::stark_air_public_digest_from_composition(
        STARK_BINDING_AIR_CONSTANT,
        STARK_BINDING_AIR_Z_COEFF,
        &terms,
    )?;
    let envelope_bytes = crate::stark::prove_stark_fri_air_envelope_bytes(
        params,
        STARK_OPEN_VERIFY_AIR_TRANSCRIPT_LABEL_V1.to_owned(),
        env_circuit_id.to_owned(),
        public_digest,
    )?;
    let open = StarkFriOpenProofV1 {
        version: 1,
        public_inputs,
        envelope_bytes,
    };
    let env = OpenVerifyEnvelope {
        backend: BackendTag::Stark,
        circuit_id: circuit_id.to_owned(),
        vk_hash,
        public_inputs: schema_descriptor.to_vec(),
        proof_bytes: norito::core::classify_decode_attempt(|| norito::encode_canonical(&open))?,
        aux: Vec::new(),
    };
    let bytes = norito::core::classify_decode_attempt(|| norito::encode_canonical(&env))?;
    Ok(ProofBox::new(backend.to_owned(), bytes))
}
#[cfg(any(test, feature = "test-utils"))]
/// Test fixtures and helpers for constructing deterministic `OpenVerifyEnvelope` payloads.
pub mod test_utils {
    #[allow(unused_imports)]
    use super::*;
    use iroha_crypto::Hash as CryptoHash;
    use iroha_data_model::{
        proof::{ProofBox, VerifyingKeyBox},
        zk::{BackendTag, OpenVerifyEnvelope},
    };
    /// Deterministic proof envelope fixture used across unit and integration tests.
    #[derive(Clone, Debug)]
    pub struct FixtureEnvelope {
        /// Norito-encoded `OpenVerifyEnvelope` bytes suitable for `ProofBox`.
        pub proof_bytes: Vec<u8>,
        /// Canonical public inputs serialized in the envelope.
        pub public_inputs: Vec<u8>,
        /// Blake2b-32 hash of `public_inputs`, matching verifier registry expectations.
        pub schema_hash: [u8; 32],
        /// Optional backend-specific verifying-key bytes for the fixture circuit.
        pub vk_bytes: Option<Vec<u8>>,
    }
    impl FixtureEnvelope {
        /// Create a `ProofBox` tagged with the provided backend identifier.
        #[must_use]
        pub fn proof_box(&self, backend: impl Into<String>) -> ProofBox {
            ProofBox::new(backend.into(), self.proof_bytes.clone())
        }
        /// Create a verifying-key box for the fixture circuit, if available.
        #[must_use]
        pub fn vk_box(&self, backend: impl Into<String>) -> Option<VerifyingKeyBox> {
            self.vk_bytes
                .as_ref()
                .map(|bytes| VerifyingKeyBox::new(backend.into(), bytes.clone()))
        }
        /// Compute the verifying-key hash for this fixture and backend, if available.
        #[must_use]
        pub fn vk_hash(&self, backend: impl Into<String>) -> Option<[u8; 32]> {
            self.vk_box(backend).map(|vk| super::hash_vk(&vk))
        }
    }
    /// Build a native public-input binding proof for relation-confusion tests.
    #[cfg(feature = "zk-stark")]
    #[must_use]
    pub fn stark_public_binding_fixture_envelope() -> FixtureEnvelope {
        use crate::stark::{
            STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2, STARK_FRI_CONSENSUS_MIN_N_LOG2,
            STARK_FRI_CONSENSUS_MIN_QUERIES, StarkFriVerifyingKeyV1,
        };

        static FIXTURE: std::sync::OnceLock<FixtureEnvelope> = std::sync::OnceLock::new();
        FIXTURE
            .get_or_init(|| {
                let backend = super::ZK_BACKEND_STARK_FRI_V1;
                let circuit_id = format!("{backend}:public-binding-demo");
                let vk = StarkFriVerifyingKeyV1 {
                    version: 1,
                    circuit_id: circuit_id.clone(),
                    n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
                    blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
                    fold_arity: 2,
                    queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
                    merkle_arity: 2,
                };
                let vk_bytes = norito::encode_canonical(&vk).expect("canonical fixture key");
                let key = VerifyingKeyBox::new(backend.to_owned(), vk_bytes.clone());
                let public_inputs = b"public-binding-demo:schema:v1".to_vec();
                let proof = super::prove_stark_fri_open_verify_envelope(
                    backend,
                    &circuit_id,
                    &key,
                    &public_inputs,
                    vec![vec![[0x11; 32]]],
                )
                .expect("native public binding proof");
                FixtureEnvelope {
                    proof_bytes: proof.bytes,
                    schema_hash: CryptoHash::new(&public_inputs).into(),
                    public_inputs,
                    vk_bytes: Some(vk_bytes),
                }
            })
            .clone()
    }
    /// Builds and caches a genuine native confidential transfer fixture.
    ///
    /// Fixed test notes spend seven units into one output. The returned key
    /// and schema are the exact compiled transfer relation. Proof randomness
    /// is fresh on the first call; subsequent calls retain identical bytes.
    /// This relation proves a transfer, never governance authorization.
    #[must_use]
    pub fn native_confidential_fixture_envelope() -> FixtureEnvelope {
        use crate::confidential_v2::{
            CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID, ConfidentialTransferInputV2,
            ConfidentialTransferOutputV2, build_confidential_transfer_proof_v2,
            compute_confidential_root_v2, confidential_transfer_v2_vk_box,
            derive_confidential_diversifier_v2, derive_confidential_note_v2,
            derive_confidential_owner_tag_v2_with_diversifier,
        };

        static FIXTURE: std::sync::OnceLock<FixtureEnvelope> = std::sync::OnceLock::new();
        FIXTURE
            .get_or_init(|| {
                let network =
                    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                        iroha_data_model::block::BlockHeader,
                    >::from_untyped_unchecked(
                        CryptoHash::new(b"native-confidential-integration-fixture"),
                    ));
                let asset = "fixture#universal";
                let spend_key = [0x11; 32];
                let rho = [0x22; 32];
                let diversifier = derive_confidential_diversifier_v2(b"fixture-input");
                let owner =
                    derive_confidential_owner_tag_v2_with_diversifier(&spend_key, diversifier)
                        .expect("fixture input owner");
                let commitment = derive_confidential_note_v2(asset, 7, rho, owner)
                    .expect("fixture input commitment");
                let root = compute_confidential_root_v2(&[commitment]).expect("fixture root");
                let output_owner = derive_confidential_owner_tag_v2_with_diversifier(
                    &[0x33; 32],
                    derive_confidential_diversifier_v2(b"fixture-output"),
                )
                .expect("fixture output owner");
                let key = confidential_transfer_v2_vk_box().expect("compiled transfer key");
                let proof = build_confidential_transfer_proof_v2(
                    &network,
                    asset,
                    &spend_key,
                    &[commitment],
                    &[ConfidentialTransferInputV2 {
                        amount: 7,
                        rho,
                        diversifier,
                        leaf_index: 0,
                    }],
                    &[ConfidentialTransferOutputV2 {
                        amount: 7,
                        rho: [0x44; 32],
                        owner_tag: output_owner,
                    }],
                    root,
                    CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
                    &key,
                )
                .expect("genuine native transfer fixture");
                let envelope: OpenVerifyEnvelope = norito::decode_canonical(&proof.proof.bytes)
                    .expect("canonical transfer envelope");
                FixtureEnvelope {
                    proof_bytes: proof.proof.bytes,
                    schema_hash: CryptoHash::new(&envelope.public_inputs).into(),
                    public_inputs: envelope.public_inputs,
                    vk_bytes: Some(key.bytes),
                }
            })
            .clone()
    }

    /// Build canonical native framing for sizing and pre-verification rejection tests.
    ///
    /// The exact compiled relation selects the schema, public row count and
    /// proof length. The zero transcript is deliberately invalid and no key
    /// is returned. Tests that reach cryptographic verification must build a
    /// genuine proof instead.
    #[must_use]
    pub fn native_framing_fixture_envelope(
        circuit_id: impl Into<String>,
        vk_hash: [u8; 32],
    ) -> FixtureEnvelope {
        let circuit_id = circuit_id.into();
        let kind = super::native_pipa_r::relation(super::ZK_BACKEND_NATIVE_PIPA_R, &circuit_id)
            .expect("native framing fixture must name an exact compiled relation");
        let public_inputs = super::native_pipa_r::public_schema(kind).to_vec();
        let body = iroha_data_model::zk::NativePipaRProofV1 {
            public_inputs: vec![[0; 32]; kind.instance_rows()],
            proof: vec![0; kind.proof_length().expect("compiled native descriptor")],
        };
        let envelope = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id,
            vk_hash,
            public_inputs: public_inputs.clone(),
            proof_bytes: norito::encode_canonical(&body).expect("native framing fixture"),
            aux: Vec::new(),
        };
        FixtureEnvelope {
            proof_bytes: norito::encode_canonical(&envelope).expect("native outer fixture"),
            schema_hash: CryptoHash::new(&public_inputs).into(),
            public_inputs,
            vk_bytes: None,
        }
    }
}
/// Batch-local deduplication cache keyed by proof hash.
#[derive(Clone, Default)]
pub struct DedupCache {
    seen: BTreeSet<[u8; 32]>,
}
impl DedupCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }
}
impl DedupCache {
    #[cfg(any(test, feature = "test-utils"))]
    /// Return true if this proof is new to the cache and insert it; false if duplicate.
    pub fn check_and_insert(&mut self, proof: &ProofBox) -> bool {
        self.seen.insert(hash_proof(proof))
    }
    /// Compute and insert a combined dedup key from the proof and optional vk commitment.
    /// Returns true if not seen before.
    pub fn check_and_insert_with_commitment(
        &mut self,
        proof: &ProofBox,
        vk_commitment: Option<[u8; 32]>,
    ) -> bool {
        let mut h = Sha256::new();
        h.update(b"iroha:zk:v1:preverify-dedup");
        h.update(hash_proof(proof));
        if let Some(c) = vk_commitment {
            h.update(c);
        }
        let key: [u8; 32] = h.finalize().into();
        self.seen.insert(key)
    }
}
fn expected_preverify_envelope_backend_tag(
    backend: &str,
) -> Option<iroha_data_model::zk::BackendTag> {
    production_verify_backend_tag(backend)
}
fn preverify_open_verify_envelope_metadata(
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
    vk_commitment: Option<[u8; 32]>,
    expected_vk_commitment: Option<[u8; 32]>,
) -> Result<(), VerificationAttemptError<PreverifyResult>> {
    let Some(expected_tag) = expected_preverify_envelope_backend_tag(proof.backend.as_str()) else {
        return Ok(());
    };
    let envelope: iroha_data_model::zk::OpenVerifyEnvelope = verification_attempt::codec_attempt(
        || norito::decode_canonical(&proof.bytes),
        |_| PreverifyResult::MalformedProof,
    )?;
    envelope.validate_for_admission().map_err(|err| {
        if err == iroha_data_model::zk::OpenVerifyEnvelopeValidationError::ZeroVerifierKeyHash {
            PreverifyResult::VerifyingKeyMismatch
        } else {
            PreverifyResult::MalformedProof
        }
    })?;
    if envelope.backend != expected_tag {
        return Err((PreverifyResult::MalformedProof).into());
    }
    if expected_tag == iroha_data_model::zk::BackendTag::NativePipaRPasta {
        native_pipa_r::validate_metadata(&proof.backend, &envelope)
            .map_err(|_| PreverifyResult::MalformedProof)?;
    }
    if expected_tag == iroha_data_model::zk::BackendTag::Stark {
        if !stark_open_verify_circuit_id_matches_backend(&proof.backend, &envelope.circuit_id) {
            return Err((PreverifyResult::MalformedProof).into());
        }
        let Some(env_circuit_id) =
            canonical_stark_fri_circuit_id_for_backend(&proof.backend, &envelope.circuit_id)
        else {
            return Err((PreverifyResult::MalformedProof).into());
        };
        if canonical_circuit_is_zk_ace_relation_for_backend(&proof.backend, env_circuit_id) {
            return Err((PreverifyResult::MalformedProof).into());
        }
        if canonical_bfv_full_bootstrap_stark_circuit_id_for_backend(&proof.backend).as_deref()
            == Some(env_circuit_id)
        {
            return Err((PreverifyResult::MalformedProof).into());
        }
        if canonical_circuit_is_governance_vote_relation_for_backend(&proof.backend, env_circuit_id)
        {
            return Err((PreverifyResult::MalformedProof).into());
        }
        if canonical_circuit_is_soracloud_fhe_relation_for_backend(&proof.backend, env_circuit_id) {
            return Err((PreverifyResult::MalformedProof).into());
        }
        if canonical_ivm_execution_stark_circuit_id_for_backend(&proof.backend).as_deref()
            == Some(env_circuit_id)
        {
            return Err((PreverifyResult::MalformedProof).into());
        }
    }
    if let Some(vk_box) = vk
        && hash_vk(vk_box) != envelope.vk_hash
    {
        return Err((PreverifyResult::VerifyingKeyMismatch).into());
    }
    if let Some(commitment) = vk_commitment
        && commitment != envelope.vk_hash
    {
        return Err((PreverifyResult::VerifyingKeyMismatch).into());
    }
    if let Some(expected) = expected_vk_commitment
        && expected != envelope.vk_hash
    {
        return Err((PreverifyResult::VerifyingKeyMismatch).into());
    }
    Ok(())
}
fn preverify_bound_vk_commitment(
    vk_commitment: Option<[u8; 32]>,
    expected_vk_commitment: Option<[u8; 32]>,
) -> Result<[u8; 32], PreverifyResult> {
    let Some(expected) = expected_vk_commitment else {
        return Err(PreverifyResult::VerifyingKeyMissing);
    };
    if expected == [0u8; 32] {
        return Err(PreverifyResult::VerifyingKeyMismatch);
    }
    let Some(commitment) = vk_commitment else {
        return Ok(expected);
    };
    if commitment == [0u8; 32] || commitment != expected {
        return Err(PreverifyResult::VerifyingKeyMismatch);
    }
    Ok(commitment)
}
/// Result of a pre-verification step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreverifyResult {
    /// Proof accepted by lightweight pre-verification and not seen before in this batch.
    Accepted,
    /// Duplicate proof encountered within the same batch.
    Duplicate,
    /// Backend tag is empty or not recognized by the pre-verifier.
    UnsupportedBackend,
    /// Proof payload exceeds the locally accepted maximum size for pre-verify.
    ProofTooBig,
    /// Malformed proof payload (e.g., empty bytes or structurally invalid header for the backend).
    MalformedProof,
    /// Pre-verification exceeded the provided cost budget.
    PreverifyBudgetExceeded,
    /// Proof references a verifying key that is missing or inactive.
    VerifyingKeyMissing,
    /// Proof references a verifying key whose commitment/schema do not match the envelope.
    VerifyingKeyMismatch,
    /// Proof references a verifying key bound to another namespace/manifest.
    NamespaceMismatch,
    /// Proof references a verifying key that is inactive or withdrawn.
    VerifyingKeyInactive,
}
/// Pre-verify a proof under a simple cost budget and deduplication cache.
///
/// This lightweight stage performs backend/tag admission, verifier-key binding
/// checks, bounded envelope parsing where applicable, and batch deduplication.
/// Full cryptographic verification is deferred to lane/overlay execution.
///
/// # Errors
///
/// Returns the original local verification refusal if bounded envelope
/// decoding cannot complete. Completed admission, budget, key-binding and
/// deduplication outcomes are returned as `Ok(PreverifyResult)`.
pub fn preverify_with_budget(
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
    dedup: &mut DedupCache,
    budget: u64,
    vk_commitment: Option<[u8; 32]>,
    expected_vk_commitment: Option<[u8; 32]>,
    vk_active: bool,
) -> Result<PreverifyResult, VerificationRefusal> {
    // Basic sanity: require non-empty backend tag
    if proof.backend.is_empty() {
        return Ok(PreverifyResult::UnsupportedBackend);
    }
    if is_production_claim_backend_label(proof.backend.as_str()) {
        return Ok(PreverifyResult::UnsupportedBackend);
    }
    if is_trusted_setup_backend_label(proof.backend.as_str()) {
        return Ok(PreverifyResult::UnsupportedBackend);
    }
    if is_developer_only_backend_label(proof.backend.as_str()) {
        return Ok(PreverifyResult::UnsupportedBackend);
    }
    if expected_preverify_envelope_backend_tag(proof.backend.as_str()).is_none() {
        return Ok(PreverifyResult::UnsupportedBackend);
    }
    if !vk_active {
        return Ok(PreverifyResult::VerifyingKeyInactive);
    }
    // Extremely lightweight budget model: count raw bytes processed.
    // When budget is 0, treat as unlimited.
    if budget > 0 {
        let limit = usize::try_from(budget).unwrap_or(usize::MAX);
        if limit < proof.bytes.len() {
            return Ok(PreverifyResult::PreverifyBudgetExceeded);
        }
    }
    let bound_vk_commitment =
        match preverify_bound_vk_commitment(vk_commitment, expected_vk_commitment) {
            Ok(commitment) => commitment,
            Err(err) => return Ok(err),
        };
    if let Some(vk_box) = vk
        && vk_box.backend != proof.backend
    {
        return Ok(PreverifyResult::VerifyingKeyMismatch);
    }
    // If we have both VK bytes and expected commitment, enforce the match early.
    if let (Some(expected), Some(vk_box)) = (expected_vk_commitment, vk) {
        let actual = crate::hash_vk(vk_box);
        if actual != expected {
            return Ok(PreverifyResult::VerifyingKeyMismatch);
        }
    }
    if let (Some(expected), Some(commit)) = (expected_vk_commitment, vk_commitment) {
        if expected != commit {
            return Ok(PreverifyResult::VerifyingKeyMismatch);
        }
    }
    if let Err(err) = preverify_open_verify_envelope_metadata(
        proof,
        vk,
        Some(bound_vk_commitment),
        expected_vk_commitment,
    ) {
        return match err {
            VerificationAttemptError::Rejected(verdict) => Ok(verdict),
            VerificationAttemptError::Deferred(original) => Err(original),
        };
    }
    if !dedup.check_and_insert_with_commitment(proof, Some(bound_vk_commitment)) {
        return Ok(PreverifyResult::Duplicate);
    }
    Ok(PreverifyResult::Accepted)
}
#[cfg(feature = "zk-stark")]
fn verify_stark_fri_open_verify_envelope(
    backend: &str,
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
) -> Result<bool, VerificationRefusal> {
    verify_stark_fri_open_verify_envelope_with_limits(
        backend,
        proof,
        vk,
        &crate::stark::StarkVerifierLimits::default(),
    )
}
#[cfg(feature = "zk-stark")]
fn verify_stark_fri_open_verify_envelope_with_limits(
    backend: &str,
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
    limits: &crate::stark::StarkVerifierLimits,
) -> Result<bool, VerificationRefusal> {
    use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
    let reject = |reason: &'static str| {
        tracing::debug!(
            backend,
            reason,
            "stark/fri proof rejected (metadata/integrity check failed)"
        );
        Ok(false)
    };
    let Some(env): Option<OpenVerifyEnvelope> = verification_attempt::completed_result(
        verification_attempt::codec_attempt(|| norito::decode_canonical(&proof.bytes), |_| ()),
    )?
    else {
        return reject("invalid OpenVerifyEnvelope payload");
    };
    if env.backend != BackendTag::Stark {
        return reject("unexpected OpenVerifyEnvelope backend tag");
    }
    if env.validate_for_admission().is_err() {
        return reject("invalid OpenVerifyEnvelope shape");
    }
    if !stark_open_verify_circuit_id_matches_backend(backend, &env.circuit_id) {
        return reject("STARK OpenVerifyEnvelope circuit_id does not match backend family");
    }
    // Refuse dedicated semantic roles before preparing or caching any supplied
    // key. Direct verifier calls have the same early boundary as preverify and
    // the generic prover; a valid key cannot grant generic role authority.
    let env_circuit_id = match canonical_stark_fri_circuit_id_for_backend(backend, &env.circuit_id)
    {
        Some(id) => id,
        None => return reject("invalid STARK envelope circuit_id"),
    };
    if canonical_circuit_is_zk_ace_relation_for_backend(backend, env_circuit_id) {
        return reject("generic ZK-ACE relation requires typed privacy verification");
    }
    if canonical_circuit_is_governance_vote_relation_for_backend(backend, env_circuit_id) {
        return reject("governance vote roles require dedicated semantic verification");
    }
    if canonical_bfv_full_bootstrap_stark_circuit_id_for_backend(backend).as_deref()
        == Some(env_circuit_id)
    {
        return reject("BFV full-bootstrap STARK circuit requires BFV-specific verification");
    }
    if canonical_circuit_is_soracloud_fhe_relation_for_backend(backend, env_circuit_id) {
        return reject("Soracloud FHE relation requires dedicated typed Soracloud verification");
    }
    let is_ivm_execution_circuit = canonical_ivm_execution_stark_circuit_id_for_backend(backend)
        .as_deref()
        == Some(env_circuit_id);
    if is_ivm_execution_circuit {
        return reject("IVM execution proof requires the complete native STARK execution relation");
    }
    let Some(vk_box) = vk else {
        return reject("missing verifying key");
    };
    if vk_box.backend != backend {
        return reject("STARK verifying key backend mismatch");
    }
    let expected_vk_hash = hash_vk(vk_box);
    if env.vk_hash != expected_vk_hash {
        return reject("verifying key commitment mismatch");
    }
    // Reuse the registry/state-hydration material gate at proof dispatch. This
    // pins the parameters before any proof-controlled STARK payload is decoded.
    let (vk_circuit_id_raw, vk_n_log2, vk_blowup_log2, vk_fold_arity, vk_queries, vk_merkle_arity) =
        match validate_and_prepare_verifying_key_material_v1(
            backend,
            &env.circuit_id,
            iroha_data_model::zk::BackendTag::Stark,
            vk_box,
        ) {
            Ok(PreparedVerifyingKeyMaterialV1::StarkFri {
                circuit_id,
                n_log2,
                blowup_log2,
                fold_arity,
                queries,
                merkle_arity,
            }) => (
                circuit_id,
                n_log2,
                blowup_log2,
                fold_arity,
                queries,
                merkle_arity,
            ),
            Ok(PreparedVerifyingKeyMaterialV1::NativePipaRPasta { .. }) => {
                return reject("STARK registry key prepared as a foreign engine");
            }
            Err(VerificationAttemptError::Rejected(_)) => {
                return reject("invalid STARK verifying key payload");
            }
            Err(VerificationAttemptError::Deferred(original)) => return Err(original),
        };
    let vk_circuit_id =
        match canonical_stark_fri_circuit_id_for_backend(backend, &vk_circuit_id_raw) {
            Some(id) => id,
            None => return reject("invalid STARK verifying key circuit_id"),
        };
    if env_circuit_id != vk_circuit_id {
        return reject("STARK verifying key circuit_id mismatch");
    }
    // Decode the STARK wrapper payload.
    let Some(open): Option<StarkFriOpenProofV1> = verification_attempt::completed_result(
        verification_attempt::codec_attempt(|| norito::decode_canonical(&env.proof_bytes), |_| ()),
    )?
    else {
        return reject("invalid STARK wrapper payload");
    };
    if open.version != 1 {
        return reject("unsupported STARK wrapper version");
    }
    if open.envelope_bytes.len() > limits.max_envelope_bytes {
        return reject("inner STARK envelope exceeds verifier limits");
    }
    // Bind the inner STARK envelope to the outer OpenVerifyEnvelope metadata and public inputs by
    // requiring `params.domain_tag` to equal the URL-safe encoding of the typed six-lane digest of
    // `backend || circuit_id || vk_hash || schema/aux public_inputs || wrapper public inputs`.
    //
    // This prevents re-wrapping a valid STARK envelope under a different circuit/vk/public-inputs
    // header without detection.
    let expected_domain_tag = stark_open_verify_domain_tag_current(
        backend,
        &env.circuit_id,
        env.vk_hash,
        &env.public_inputs,
        &open.public_inputs,
    );
    let Some(inner): Option<crate::stark::StarkVerifyEnvelopeV1> =
        verification_attempt::completed_result(verification_attempt::codec_attempt(
            || norito::decode_canonical(&open.envelope_bytes),
            |_| (),
        ))?
    else {
        return reject("invalid inner STARK envelope payload");
    };
    if inner.transcript_label != STARK_OPEN_VERIFY_AIR_TRANSCRIPT_LABEL_V1 {
        return reject("STARK OpenVerifyEnvelope transcript label mismatch");
    }
    if inner.proof.commits.comp_root.is_some() || inner.proof.comp_values.is_some() {
        return reject(
            "STARK OpenVerifyEnvelope inner proof carries auxiliary composition commitments",
        );
    }
    // Verify that the prover is using the parameters pinned by the verifying key.
    if inner.params.n_log2 != vk_n_log2
        || inner.params.blowup_log2 != vk_blowup_log2
        || inner.params.fold_arity != vk_fold_arity
        || inner.params.queries != vk_queries
        || inner.params.merkle_arity != vk_merkle_arity
    {
        return reject("STARK proof parameters do not match verifying key");
    }
    if inner.params.domain_tag != expected_domain_tag {
        return reject("domain tag integrity mismatch");
    }
    let expected_terms = stark_binding_air_terms(
        backend,
        &env.circuit_id,
        env.vk_hash,
        &env.public_inputs,
        &open.public_inputs,
    );
    let expected_public_digest = match crate::stark::stark_air_public_digest_from_composition(
        STARK_BINDING_AIR_CONSTANT,
        STARK_BINDING_AIR_Z_COEFF,
        &expected_terms,
    ) {
        Ok(digest) => digest,
        Err(_) => return reject("STARK AIR public digest reconstruction failed"),
    };
    let Some(air) = inner.proof.air.as_ref() else {
        return reject("missing STARK AIR section");
    };
    let air_circuit_id = match canonical_stark_fri_circuit_id_for_backend(backend, &air.circuit_id)
    {
        Some(id) => id,
        None => return reject("invalid STARK AIR circuit_id"),
    };
    if air_circuit_id != env_circuit_id {
        return reject("STARK AIR circuit_id mismatch");
    }
    if air.public_digest != expected_public_digest {
        return reject("STARK AIR public digest mismatch");
    }
    let stark_ok = crate::stark::verify_decoded_stark_fri_envelope_with_limits(&inner, limits);
    if !stark_ok {
        return reject("inner STARK/FRI verifier rejected proof");
    }
    Ok(true)
}
/// Check the compiled proof relation and envelope integrity for a backend.
///
/// A successful binding proof does not establish execution, witness privacy,
/// ledger authority, or current registry activation. Application callers should
/// use [`verify_for_relation`] to require the exact relation they intend to verify.
///
/// # Errors
///
/// Returns the original local refusal if native verifier initialization,
/// canonical decoding or verification cannot complete. Unsupported backends
/// and completed proof rejection return `Ok(false)`.
pub fn verify_backend(
    backend: &str,
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
) -> Result<bool, VerificationRefusal> {
    if proof.backend.as_str() != backend {
        return Ok(false);
    }
    if !is_production_verify_backend_label(backend) {
        return Ok(false);
    }
    if production_verify_backend_tag(backend)
        == Some(iroha_data_model::zk::BackendTag::NativePipaRPasta)
    {
        return verification_attempt::completed_result(native_pipa_r::verify(backend, proof, vk))
            .map(|completed| completed.is_some());
    }
    // STARK/FRI family: native multi-fold verifier
    if is_stark_fri_v1_backend(backend) {
        #[cfg(feature = "zk-stark")]
        {
            // STARK proofs must use `OpenVerifyEnvelope` so the verifier can bind the
            // backend/circuit metadata and verifying-key hash into the inner STARK envelope.
            return verify_stark_fri_open_verify_envelope(backend, proof, vk);
        }
        #[cfg(not(feature = "zk-stark"))]
        {
            tracing::debug!(
                backend,
                "stark/fri backend requested but binary was built without `zk-stark`"
            );
            return Ok(false);
        }
    }
    // Groth16 family: unsupported in the first release.
    if backend.starts_with("groth16/") {
        return Ok(false);
    }
    // Unknown backend tag
    Ok(false)
}
#[cfg(test)]
mod debug_backend_tests {
    use super::*;
    #[test]
    fn developer_only_backends_are_unsupported() {
        for backend in [
            "debug/ok",
            "debug/reject",
            "debug/sleep",
            "stark/fri/dev-fixture",
            "stark/fri/d-e-v-f-i-x-t-u-r-e",
            "stark/fri/dev",
            "stark/fri/d-e-v",
            "stark/fri/test",
            "stark/fri/t-e-s-t",
            "stark/fri/todo",
            "stark/fri/t-o-d-o",
            "stark/fri/draft-only",
            "stark/fri/d-r-a-f-t",
            "stark/fri/pending-audit",
            "stark/fri/replace-before-mainnet",
            "stark/fri/not-production-ready",
            "stark/fri/placeholder",
            "miden-stark:dev-fixture",
            "halo2/ipa:dev-fixture",
            "halo2/ipa:dev",
            "halo2/ipa:todo-proof",
            "halo2/ipa:t-o-d-o-proof",
            "halo2/ipa:draft-proof",
            "halo2/ipa:d-r-a-f-t-proof",
            "halo2/ipa:pending-audit",
            "halo2/ipa:replace-before-production",
            "halo2/ipa:not-for-production",
            "halo2/ipa:dummy",
            "halo2/ipa:f-a-k-e",
            "halo2/ipa:stub",
            "halo2/ipa:s-a-m-p-l-e",
        ] {
            let proof = ProofBox::new(backend.into(), vec![0x01]);
            let vk = VerifyingKeyBox::new(backend.into(), vec![0x02]);
            assert!(
                !verify_backend(backend, &proof, Some(&vk))
                    .expect("verification attempt must complete for this semantic fixture")
            );
        }
    }
}
#[cfg(test)]
mod stark_backend_tag_tests {
    use super::{
        KAIGI_AUTHORIZATION_BACKEND_V1, KAIGI_USAGE_BACKEND_V1, ZK_BACKEND_NATIVE_PIPA_R,
        ZK_BACKEND_STARK_FRI_V1, is_developer_only_backend_label,
        is_production_claim_backend_label, is_production_verify_backend_label,
        is_stark_fri_v1_backend, is_trusted_setup_backend_label,
        pipa_r_open_verify_circuit_id_matches_backend, production_verify_backend_tag,
        stark_open_verify_circuit_id_matches_backend, verify_backend,
    };
    use iroha_data_model::privacy::PrivacyProtocolIdV1;
    use iroha_data_model::proof::{ProofBox, VerifyingKeyBox};
    use iroha_data_model::zk::BackendTag;
    #[test]
    fn detects_only_the_canonical_stark_backend() {
        assert!(is_stark_fri_v1_backend(
            "stark/fri/poseidon-x7-goldilocks-6x64-v1"
        ));
        assert!(!is_stark_fri_v1_backend("stark/fri"));
        assert!(!is_stark_fri_v1_backend("stark/fri/poseidon2-goldilocks"));
        assert!(!is_stark_fri_v1_backend("stark/fri/sha256_goldilocks.v1"));
        assert!(!is_stark_fri_v1_backend("stark/fri/latest"));
        assert!(!is_stark_fri_v1_backend("stark/fri/attestation"));
        assert!(!is_stark_fri_v1_backend("stark/fri/contest"));
        assert!(!is_stark_fri_v1_backend("stark/fri/random-profile"));
        assert!(!is_stark_fri_v1_backend("stark/fri/sha512-goldilocks"));
        assert!(!is_stark_fri_v1_backend("stark/fri/audit-proof-v1"));
        assert!(!is_stark_fri_v1_backend("stark/fri/"));
        assert!(!is_stark_fri_v1_backend("stark/fri/ "));
        assert!(!is_stark_fri_v1_backend("stark/fri/\t\n"));
        assert!(!is_stark_fri_v1_backend("stark/fri/ sha256-goldilocks"));
        assert!(!is_stark_fri_v1_backend(
            "stark/fri/poseidon-x7-goldilocks-6x64-v1 "
        ));
        assert!(!is_stark_fri_v1_backend("stark/fri/sha256 goldilocks"));
        assert!(!is_stark_fri_v1_backend(
            "stark\u{FF0F}fri/sha256-goldilocks"
        ));
        assert!(!is_stark_fri_v1_backend(
            "stark/fri/\u{200B}sha256-goldilocks"
        ));
        assert!(!is_stark_fri_v1_backend(
            "st\u{0430}rk/fri/sha256-goldilocks"
        ));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod;foo"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod,foo"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod+foo"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod/foo"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod(foo)"));
        assert!(!is_stark_fri_v1_backend("stark/fri/Δ"));
        assert!(!is_stark_fri_v1_backend("stark/fri/kzg"));
        assert!(!is_stark_fri_v1_backend("stark/fri/KZG"));
        assert!(!is_stark_fri_v1_backend("stark/fri/ KZG"));
        assert!(!is_stark_fri_v1_backend("stark/fri:kzg"));
        assert!(!is_stark_fri_v1_backend("stark/fri: KZG"));
        assert!(!is_stark_fri_v1_backend("stark/fri/bn254"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-bn-254"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-groth-16"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-k-z-g"));
        assert!(!is_stark_fri_v1_backend("stark/fri/bls12_381"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-b.l.s.12.381"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-srs"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-s-r-s"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod.crs"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-ptau"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-powers-of-tau"));
        assert!(!is_stark_fri_v1_backend("stark/fri/prod-ceremony"));
        assert!(!is_stark_fri_v1_backend(
            "stark/fri/structured-reference-string"
        ));
        assert!(!is_stark_fri_v1_backend("stark/fri/debug"));
        assert!(!is_stark_fri_v1_backend("stark/fri/Debug"));
        assert!(!is_stark_fri_v1_backend("stark/fri/debug-proof"));
        assert!(!is_stark_fri_v1_backend("stark/fri/d-e-b-u-g"));
        assert!(!is_stark_fri_v1_backend("stark/fri/mock"));
        assert!(!is_stark_fri_v1_backend("stark/fri/Mock"));
        assert!(!is_stark_fri_v1_backend("stark/fri/mock-proof"));
        assert!(!is_stark_fri_v1_backend("stark/fri/m-o-c-k"));
        assert!(!is_stark_fri_v1_backend("stark/fri/dev-fixture"));
        assert!(!is_stark_fri_v1_backend("stark/fri/d-e-v-f-i-x-t-u-r-e"));
        assert!(!is_stark_fri_v1_backend("stark/fri/dev"));
        assert!(!is_stark_fri_v1_backend("stark/fri/d-e-v"));
        assert!(!is_stark_fri_v1_backend("stark/fri/test"));
        assert!(!is_stark_fri_v1_backend("stark/fri/t-e-s-t"));
        assert!(!is_stark_fri_v1_backend("stark/fri/placeholder"));
        assert!(!is_stark_fri_v1_backend("stark/fri/miden"));
        assert!(!is_stark_fri_v1_backend("stark/fri/pq-masp-stark-fri"));
        assert!(!is_stark_fri_v1_backend("stark/fri/post-quantum-masp"));
        assert!(!is_stark_fri_v1_backend("stark/fri-v2"));
        assert!(!is_stark_fri_v1_backend("stark/fri-v10"));
    }
    #[test]
    fn production_claim_classifier_catches_readiness_and_audit_labels() {
        for backend in [
            "halo2/ipa:production-ready",
            "halo2/ipa:claimed-production",
            "halo2/ipa:mainnet-ready",
            "halo2/ipa:mainnet-complete",
            "halo2/ipa:production-certified",
            "stark/fri/audit-signoff",
            "stark/fri/externally-audited",
            "stark/fri/security-review-passed",
            "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
            "stark/fri/a-u-d-i-t-c-l-a-i-m",
            "halo2/ipa:release-ready",
            "halo2/ipa:release-approved",
            "halo2/ipa:certified-mainnet",
            "halo2/ipa:third-party-audited",
            "halo2/ipa/orchard:production-ready",
            "orchard:mainnet-ready",
            "penumbra-masp:external-security-review",
            "jindo-lattice-pcs-zk:release-ready",
            "sis-with-hints:s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        ] {
            assert!(
                is_production_claim_backend_label(backend),
                "production-claim backend {backend} must be classified before allowlists"
            );
            assert!(
                !is_stark_fri_v1_backend(backend),
                "production-claim backend {backend} must not match the STARK family allowlist"
            );
            assert_eq!(
                production_verify_backend_tag(backend),
                None,
                "production-claim backend {backend} must not map to an OpenVerify tag"
            );
            assert!(
                !is_production_verify_backend_label(backend),
                "production-claim backend {backend} must stay fail-closed"
            );
        }
        for backend in [
            "halo2/ipa",
            "halo2/ipa:ivm-replay-binding-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon2-goldilocks",
            "stark/fri/sha256_goldilocks.v1",
            "stark/fri/audit-proof-v1",
        ] {
            assert!(
                !is_production_claim_backend_label(backend),
                "backend {backend} must not be rejected by production-claim text alone"
            );
        }
    }
    #[test]
    fn production_verify_backend_allowlist_is_explicit() {
        for (backend, expected_tag) in [
            (ZK_BACKEND_NATIVE_PIPA_R, BackendTag::NativePipaRPasta),
            (KAIGI_AUTHORIZATION_BACKEND_V1, BackendTag::NativePipaRPasta),
            (KAIGI_USAGE_BACKEND_V1, BackendTag::NativePipaRPasta),
            (
                "pipa-r/pasta/confidential-transfer-v1",
                BackendTag::NativePipaRPasta,
            ),
            (
                "pipa-r/pasta/confidential-unshield-full-v1",
                BackendTag::NativePipaRPasta,
            ),
            (
                "pipa-r/pasta/confidential-unshield-change-v1",
                BackendTag::NativePipaRPasta,
            ),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                BackendTag::Stark,
            ),
        ] {
            assert_eq!(
                production_verify_backend_tag(backend),
                Some(expected_tag),
                "production label {backend} must map to its OpenVerify tag"
            );
            assert!(
                is_production_verify_backend_label(backend),
                "production label {backend} must be admitted"
            );
        }
        for backend in [
            "unknown/privacy/backend",
            "halo2/pasta/ivm-execution-v1",
            "halo2/pasta/kaigi-roster-v1",
            "halo2/pasta/ipa/kaigi-roster-v1",
            "halo2/unknown-native-v1",
            "halo2/ipa:unknown-native-v1",
            "halo2/pasta/ivm-overlay-bind",
            "halo2/pasta/ipa/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
            "halo2/pasta/ipa/confidential-unshield-full-merkle16-axiom-poseidon-v3",
            "halo2/pasta/ipa/confidential-unshield-change-merkle16-axiom-poseidon-v4",
            "halo2/ipa:ivm-replay-binding-v1",
            "HALO2/IPA",
            "stark/FRI",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "halo2/ipa\0",
            "halo2\u{FF0F}ipa",
            "halo2/\u{200B}ipa",
            "h\u{0430}lo2/ipa",
            "../halo2/ipa",
            "halo2/ipa/../tiny-add",
            "halo2/ipa::ivm-replay-binding-v1",
            "halo2//ipa",
            "halo2/ipa:",
            "halo2/ipa.",
            "halo2/ipa/.ivm-replay-binding-v1",
            "halo2/ipa:ivm..execution-v1",
            "stark//fri/sha256-goldilocks",
            "stark/fri//sha256-goldilocks",
            "stark/fri/sha256..goldilocks",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1.",
            "halo2/ipa:ivm-replay-binding-v1 ",
            "halo2/ipa/orchard",
            "halo2/ipa/penumbra",
            "halo2/ipa/masp",
            "halo2/ipa/monero",
            "halo2/ipa/curve-tree",
            "halo2/pasta/tiny-add",
            "halo2/ipa/tiny-add",
            "halo2/ipa:tiny-add",
            "halo2/pasta/tiny-anon-transfer-2x2",
            "halo2/pasta/tiny-commit-open",
            "halo2/pasta/anon-transfer-2x2",
            "halo2/ipa/anon-transfer-2x2",
            "halo2/ipa:anon-transfer-2x2",
            "halo2/pasta/anon-transfer-2x2-merkle2",
            "halo2/ipa/anon-transfer-2x2-merkle8",
            "halo2/ipa:anon-transfer-2x2-merkle16",
            "halo2/pasta/vote-bool-commit",
            "halo2/ipa/vote-bool-commit",
            "halo2/ipa:vote-bool-commit",
            "halo2/pasta/vote-bool-commit-merkle2",
            "halo2/ipa/vote-bool-commit-merkle8",
            "halo2/ipa:vote-bool-commit-merkle16",
            "halo2/ipa:dev-fixture",
            "halo2/ipa:dev",
            "halo2/ipa:d-e-v",
            "halo2/ipa:dummy",
            "halo2/ipa:f-a-k-e",
            "halo2/ipa:stub",
            "halo2/ipa:s-a-m-p-l-e",
            "halo2/ipa:production-ready",
            "halo2/ipa:claimed-production",
            "halo2/ipa:mainnet-ready",
            "halo2/ipa:production-certified",
            "halo2/ipa:release-ready",
            "halo2/ipa:certified-mainnet",
            "halo2/ipa:third-party-audited",
            "stark/fri/miden",
            "stark/fri/latest",
            "stark/fri/attestation",
            "stark/fri/contest",
            "stark/fri/random-profile",
            "stark/fri/sha512-goldilocks",
            "stark/fri/audit-proof-v1",
            "stark/fri/dev-fixture",
            "stark/fri/d-e-v-f-i-x-t-u-r-e",
            "stark/fri/dev",
            "stark/fri/d-e-v",
            "stark/fri/test",
            "stark/fri/t-e-s-t",
            "stark/fri/placeholder",
            "stark/fri/audit-signoff",
            "stark/fri/externally-audited",
            "stark/fri/security-review-passed",
            "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
            "stark/fri/a-u-d-i-t-c-l-a-i-m",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
            " stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1\0",
            "stark\u{FF0F}fri/sha256-goldilocks",
            "stark/fri/\u{200B}sha256-goldilocks",
            "st\u{0430}rk/fri/sha256-goldilocks",
            "../stark/fri",
            "stark/fri/../sha256-goldilocks",
            "halo2/kzg",
            "halo2/mock",
        ] {
            assert_eq!(
                production_verify_backend_tag(backend),
                None,
                "unsupported backend {backend} must not map to an OpenVerify tag"
            );
            assert!(
                !is_production_verify_backend_label(backend),
                "unsupported backend {backend} must stay fail-closed"
            );
        }
    }
    #[test]
    fn verify_backend_rejects_protocol_names_before_dispatch() {
        for backend in [
            "halo2/ipa/orchard",
            "halo2/ipa/penumbra",
            "halo2/ipa/masp",
            "halo2/ipa/monero",
            "halo2/ipa/curve-tree",
            "stark/fri/miden",
            "stark/fri/pq-masp-stark-fri",
        ] {
            let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            let vk = VerifyingKeyBox::new(backend.to_owned(), vec![5, 6, 7, 8]);
            assert!(
                !verify_backend(backend, &proof, Some(&vk))
                    .expect("verification attempt must complete for this semantic fixture"),
                "protocol name {backend} must not reach a native verifier"
            );
        }
    }
    #[test]
    fn verify_backend_rejects_production_claim_labels_before_dispatch() {
        for backend in [
            "halo2/ipa:production-ready",
            "halo2/ipa:claimed-production",
            "halo2/ipa:mainnet-ready",
            "stark/fri/audit-signoff",
            "stark/fri/externally-audited",
            "stark/fri/security-review-passed",
            "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
            "stark/fri/a-u-d-i-t-c-l-a-i-m",
            "halo2/ipa:release-ready",
            "halo2/ipa:certified-mainnet",
            "halo2/ipa:third-party-audited",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        ] {
            let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            let vk = VerifyingKeyBox::new(backend.to_owned(), vec![5, 6, 7, 8]);
            assert!(
                !verify_backend(backend, &proof, Some(&vk))
                    .expect("verification attempt must complete for this semantic fixture"),
                "production-claim backend {backend} must not reach a native verifier"
            );
        }
    }
    #[test]
    fn trusted_setup_classifier_catches_standalone_and_profile_labels() {
        for backend in [
            "kzg",
            "KZG",
            " kzg ",
            "kzg/ceremony-v1",
            "KZG/ceremony-v1",
            "bn254",
            "BN254",
            "\tBN254\n",
            "bn256",
            "bls12_381",
            "BLS12_381",
            "bls12-381",
            "halo2/ipa:kzg",
            "halo2/ipa:KZG",
            "halo2/ipa: KZG",
            "Halo2/IPA:KZG",
            "halo2/pasta/ipa:kzg",
            "stark/fri:kzg",
            "stark/fri:KZG",
            "stark/fri: KZG",
            "stark/fri/prod;kzg",
            "stark/fri/prod,kzg",
            "stark/fri/prod+kzg",
            "stark/fri/prod.kzg",
            "stark/fri/prod-k-z-g",
            "stark/fri/prod(kzg)",
            "halo2/ipa:bn254",
            "halo2/ipa:BN254",
            "halo2/ipa: BN254",
            "stark/fri/prod;bn254",
            "stark/fri/prod-bn-254",
            "stark/fri/prod+bn256",
            "stark/fri/prod-bn-256",
            "stark/fri:bls12_381",
            "stark/fri/prod-bls12-381",
            "stark/fri/prod.bls12_381",
            "stark/fri/prod-b.l.s.12.381",
            "srs",
            "SRS",
            "crs",
            "ptau",
            "powersoftau",
            "powers-of-tau",
            "trusted-setup",
            "structured-reference-string",
            "universal-srs",
            "halo2/ipa:universal-srs",
            "stark/fri/prod-srs",
            "stark/fri/prod-s-r-s",
            "stark/fri/prod.crs",
            "stark/fri/prod-ptau",
            "stark/fri/prod-powers-of-tau",
            "stark/fri/prod-ceremony",
            "stark/fri/structured-reference-string",
            "halo2/ipa;groth16",
            "halo2/ipa:groth-16",
            "halo2/ipa/orchard:kzg",
            "orchard:universal-srs",
            "penumbra-masp:kzg",
            "jindo-lattice-pcs-zk:trusted-setup",
            "miden-stark:ptau",
            "sis-with-hints:groth16",
            "pq-masp-stark-fri:kzg",
        ] {
            assert!(
                is_trusted_setup_backend_label(backend),
                "trusted-setup backend {backend} must be classified before allowlist checks"
            );
        }
        for backend in [
            "halo2/ipa",
            "halo2/pasta/ipa/tiny-add",
            "stark/fri",
            "stark/fri/poseidon2-goldilocks",
        ] {
            assert!(
                !is_trusted_setup_backend_label(backend),
                "transparent backend {backend} must not be classified as trusted setup"
            );
        }
    }
    #[test]
    fn stark_open_verify_circuit_ids_are_bound_to_the_sole_production_profile() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        for circuit_id in [format!("{backend}:binding-air")] {
            assert!(stark_open_verify_circuit_id_matches_backend(
                backend,
                &circuit_id
            ));
        }
        for circuit_id in [
            "stark/fri".to_owned(),
            "stark/fri:binding-air".to_owned(),
            "stark/fri/poseidon2-goldilocks:binding-air".to_owned(),
            backend.to_owned(),
            format!("{backend}:"),
            format!("{backend}-other:binding-air"),
        ] {
            assert!(
                !stark_open_verify_circuit_id_matches_backend(backend, &circuit_id),
                "circuit `{circuit_id}` must not inherit the canonical backend profile"
            );
        }
    }
    #[test]
    fn stark_open_verify_circuit_id_rejects_trusted_setup_family_aliases() {
        assert!(stark_open_verify_circuit_id_matches_backend(
            ZK_BACKEND_STARK_FRI_V1,
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:generic-binding-air"
        ));
        assert!(stark_open_verify_circuit_id_matches_backend(
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1:binding-air"
        ));
        for (backend, circuit_id) in [
            (ZK_BACKEND_STARK_FRI_V1, "bn254"),
            (ZK_BACKEND_STARK_FRI_V1, "BN254"),
            (ZK_BACKEND_STARK_FRI_V1, "b-n-254"),
            (ZK_BACKEND_STARK_FRI_V1, "bls12_381"),
            (ZK_BACKEND_STARK_FRI_V1, "universal-srs"),
            (ZK_BACKEND_STARK_FRI_V1, "structured-reference-string"),
            (ZK_BACKEND_STARK_FRI_V1, "stark/fri:bn254"),
            (ZK_BACKEND_STARK_FRI_V1, "stark/fri/prod-b.l.s.12.381"),
            (
                ZK_BACKEND_STARK_FRI_V1,
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:universal-srs",
            ),
            ("stark/fri/poseidon-x7-goldilocks-6x64-v1", "bn254"),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri:bn254",
            ),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:bn254",
            ),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1/srs",
            ),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:structured-reference-string",
            ),
        ] {
            assert!(
                !stark_open_verify_circuit_id_matches_backend(backend, circuit_id),
                "backend {backend} must reject trusted-setup circuit alias {circuit_id}"
            );
        }
    }
    #[test]
    fn generic_open_verify_matchers_reserve_all_privacy_protocol_labels() {
        fn assert_reserved(label: &str) {
            for circuit_id in [
                label.to_owned(),
                format!("halo2/ipa::{label}"),
                format!("halo2/pasta/{label}"),
                format!("stark/fri:{label}"),
                format!("stark/fri/poseidon-x7-goldilocks-6x64-v1:{label}"),
                format!("generic/namespace/{label}"),
            ] {
                assert!(
                    !pipa_r_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_NATIVE_PIPA_R,
                        &circuit_id
                    ),
                    "Halo2 generic admission must reject privacy circuit id {circuit_id:?}"
                );
                assert!(
                    !pipa_r_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_NATIVE_PIPA_R,
                        &circuit_id,
                    ),
                    "Halo2 backend matching must reject privacy circuit id {circuit_id:?}"
                );
                assert!(
                    !stark_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_STARK_FRI_V1,
                        &circuit_id,
                    ),
                    "base STARK generic admission must reject privacy circuit id {circuit_id:?}"
                );
                assert!(
                    !stark_open_verify_circuit_id_matches_backend(
                        "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                        &circuit_id,
                    ),
                    "profile STARK admission must reject privacy circuit id {circuit_id:?}"
                );
            }
            for malformed_alias in [
                format!(" {label}"),
                format!("{label} "),
                label.to_ascii_uppercase(),
            ] {
                assert!(
                    !pipa_r_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_NATIVE_PIPA_R,
                        &malformed_alias,
                    ),
                    "non-portable Halo2 alias {malformed_alias:?} must fail closed"
                );
                assert!(
                    !stark_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_STARK_FRI_V1,
                        &malformed_alias,
                    ),
                    "non-portable STARK alias {malformed_alias:?} must fail closed"
                );
            }
            for near_miss in [format!("generic-{label}"), format!("{label}-generic")] {
                let halo2_circuit_id = format!("halo2/pasta/ipa/{near_miss}");
                assert!(
                    !pipa_r_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_NATIVE_PIPA_R,
                        &halo2_circuit_id
                    ),
                    "unregistered Halo2 near miss {halo2_circuit_id:?} must fail closed"
                );
                assert!(
                    !stark_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_STARK_FRI_V1,
                        &halo2_circuit_id,
                    ),
                    "unqualified STARK circuit {halo2_circuit_id:?} must fail closed"
                );
                let cross_family_id = format!("{ZK_BACKEND_STARK_FRI_V1}:{halo2_circuit_id}");
                assert!(
                    !stark_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_STARK_FRI_V1,
                        &cross_family_id,
                    ),
                    "STARK generic admission must reject Halo2 circuit id {cross_family_id:?}"
                );
                let circuit_id = format!("{ZK_BACKEND_STARK_FRI_V1}:{near_miss}");
                assert!(
                    stark_open_verify_circuit_id_matches_backend(
                        ZK_BACKEND_STARK_FRI_V1,
                        &circuit_id,
                    ),
                    "canonical STARK near miss {circuit_id:?} must remain available"
                );
            }
        }
        for protocol in PrivacyProtocolIdV1::ALL {
            assert_reserved(protocol.canonical_label());
        }
    }
    #[test]
    fn developer_only_classifier_is_ascii_case_insensitive() {
        for backend in [
            "debug",
            "Debug",
            "DEBUG",
            "mock",
            "Mock",
            "MOCK",
            "halo2/ipa:Debug-Proof",
            "halo2/ipa:D-e-b-u-g-Proof",
            "halo2/ipa:Mock-Proof",
            "halo2/ipa:M-o-c-k-Proof",
            "stark/fri/Debug",
            "stark/fri/D-e-b-u-g",
            "stark/fri/Mock",
            "stark/fri/M-o-c-k",
            "stark/fri/dev-fixture",
            "stark/fri/D-e-v-F-i-x-t-u-r-e",
            "stark/fri/dev",
            "stark/fri/D-e-v",
            "stark/fri/Test",
            "stark/fri/T-e-s-t",
            "stark/fri/Placeholder",
            "miden-stark:DevFixture",
            "halo2/ipa:DevFixture",
            "halo2/ipa:d-e-v-f-i-x-t-u-r-e",
            "halo2/ipa:Dev",
            "halo2/ipa:d-e-v",
            "halo2/ipa:Dummy",
            "halo2/ipa:F-a-k-e",
            "halo2/ipa:Stub",
            "halo2/ipa:S-a-m-p-l-e",
        ] {
            assert!(
                is_developer_only_backend_label(backend),
                "developer-only backend {backend} must be classified before allowlist checks"
            );
        }
    }
    #[test]
    fn developer_only_classifier_does_not_reject_embedded_text_fragments() {
        for backend in [
            "stark/fri/latest",
            "stark/fri/attestation",
            "stark/fri/contest",
            "halo2/ipa:attestation",
        ] {
            assert!(
                !is_developer_only_backend_label(backend),
                "backend {backend} must not be rejected because a normal word contains `test`"
            );
        }
    }
}
#[cfg(all(test, feature = "zk-stark"))]
macro_rules! consensus_stark_vk {
    ($circuit_id:expr $(,)?) => {
        $crate::stark::StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id: $circuit_id,
            n_log2: $crate::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
            blowup_log2: $crate::stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: $crate::stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        }
    };
}
#[cfg(all(test, feature = "zk-stark"))]
mod stark_prover_tests {
    use super::{
        STARK_BINDING_AIR_CONSTANT, STARK_BINDING_AIR_Z_COEFF, STARK_GOLDILOCKS_MODULUS,
        STARK_OPEN_VERIFY_AIR_TRANSCRIPT_LABEL_V1, ZK_BACKEND_STARK_FRI_V1,
        canonical_stark_fri_circuit_id_for_backend, prove_stark_fri_open_verify_envelope,
        stark_binding_air_terms, stark_open_verify_air_public_digest_current,
        stark_open_verify_domain_tag_current, verify_backend_with_timing,
    };
    use crate::stark::{
        STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2, STARK_FRI_CONSENSUS_MIN_N_LOG2,
        STARK_FRI_CONSENSUS_MIN_QUERIES, StarkCompositionValueV1, StarkFriParamsV1,
        StarkFriVerifyingKeyV1, StarkVerifyEnvelopeV1,
    };
    use iroha_data_model::proof::{ProofBox, VerifyingKeyBox};
    use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope, StarkFriOpenProofV1};
    #[test]
    fn stark_exact_circuit_grammar_rejects_retired_wire_spellings() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        let exact = format!("{backend}:binding-air");
        let borrowed = canonical_stark_fri_circuit_id_for_backend(backend, &exact).unwrap();
        assert!(core::ptr::eq(borrowed.as_ptr(), exact.as_ptr()));
        for other in [
            "binding-air".to_owned(),
            format!("{backend}/binding-air"),
            format!(" {exact}"),
            format!("{exact} "),
            format!("{backend}::binding-air"),
            format!("{backend}:"),
            "stark/fri/poseidon2-goldilocks:binding-air".to_owned(),
            format!(
                "{backend}:{}",
                "x".repeat(iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES)
            ),
        ] {
            assert!(
                canonical_stark_fri_circuit_id_for_backend(backend, &other).is_none(),
                "{other}"
            );
        }
        assert!(canonical_stark_fri_circuit_id_for_backend("stark/fri", &exact).is_none());
    }

    #[test]
    fn stark_exact_registry_material_and_cache_do_not_adopt_aliases() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        let exact = format!("{backend}:exact-registry-test");
        let payload = consensus_stark_vk!(exact.clone());
        let bytes = norito::encode_canonical(&payload).unwrap();
        for _ in 0..2 {
            assert_eq!(
                super::validate_stark_fri_verifying_key_v1(backend, &exact, &bytes)
                    .map_err(crate::verification::expect_rejected)
                    .unwrap()
                    .circuit_id,
                exact
            );
        }
        for alias in [
            "exact-registry-test".to_owned(),
            format!("{backend}/exact-registry-test"),
            format!(" {exact} "),
        ] {
            assert!(
                super::validate_stark_fri_verifying_key_v1(backend, &alias, &bytes)
                    .map_err(crate::verification::expect_rejected)
                    .is_err()
            );
            let changed = consensus_stark_vk!(alias.clone());
            let changed_bytes = norito::encode_canonical(&changed).unwrap();
            assert!(
                super::validate_stark_fri_verifying_key_v1(backend, &exact, &changed_bytes)
                    .map_err(crate::verification::expect_rejected)
                    .is_err()
            );
            assert!(
                super::validate_stark_fri_verifying_key_v1(backend, &alias, &changed_bytes)
                    .map_err(crate::verification::expect_rejected)
                    .is_err()
            );
        }
        assert_eq!(
            super::validate_stark_fri_verifying_key_v1(backend, &exact, &bytes)
                .map_err(crate::verification::expect_rejected)
                .unwrap()
                .circuit_id,
            exact
        );
    }

    #[test]
    fn stark_exact_native_key_contract_does_not_grant_generic_dispatch() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        for bare in [
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
        ] {
            assert!(super::is_typed_native_stark_circuit_id(bare));
            assert!(super::stark_registry_circuit_id_matches_backend(
                backend, bare
            ));
            assert!(!super::stark_open_verify_circuit_id_matches_backend(
                backend, bare
            ));
            let payload = consensus_stark_vk!(bare.to_owned());
            let bytes = norito::encode_canonical(&payload).unwrap();
            assert_eq!(
                super::validate_stark_fri_verifying_key_v1(backend, bare, &bytes)
                    .map_err(crate::verification::expect_rejected)
                    .unwrap()
                    .circuit_id,
                bare
            );
            for alias in [
                format!("{backend}:{bare}"),
                format!("{backend}/{bare}"),
                format!(" {bare} "),
            ] {
                assert!(!super::is_typed_native_stark_circuit_id(&alias));
                assert!(!super::stark_registry_circuit_id_matches_backend(
                    backend, &alias
                ));
                assert!(
                    super::validate_stark_fri_verifying_key_v1(backend, &alias, &bytes)
                        .map_err(crate::verification::expect_rejected)
                        .is_err()
                );
                let altered = consensus_stark_vk!(alias.clone());
                assert!(
                    super::validate_stark_fri_verifying_key_v1(
                        backend,
                        &alias,
                        &norito::encode_canonical(&altered).unwrap()
                    )
                    .map_err(crate::verification::expect_rejected)
                    .is_err()
                );
                assert!(
                    super::validate_stark_fri_verifying_key_v1(
                        backend,
                        bare,
                        &norito::encode_canonical(&altered).unwrap()
                    )
                    .map_err(crate::verification::expect_rejected)
                    .is_err()
                );
            }
            assert!(!super::stark_registry_circuit_id_matches_backend(
                "stark/fri",
                bare
            ));
        }
    }

    #[test]
    fn stark_exact_envelope_and_air_reject_aliases_of_a_real_proof() {
        let (backend, exact, vk_box, proof) = sample_stark_open_verify_proof();
        assert!(
            verify_backend_with_timing(backend, &proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture")
                .ok
        );
        let outer: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
        let open: StarkFriOpenProofV1 = norito::decode_canonical(&outer.proof_bytes).unwrap();
        let native: StarkVerifyEnvelopeV1 = norito::decode_canonical(&open.envelope_bytes).unwrap();
        for alias in [
            "tiny-open".to_owned(),
            format!("{backend}/tiny-open"),
            format!(" {exact} "),
        ] {
            let mut altered = outer.clone();
            altered.circuit_id = alias.clone();
            let wire = ProofBox::new(
                backend.to_owned(),
                norito::encode_canonical(&altered).unwrap(),
            );
            assert!(
                !verify_backend_with_timing(backend, &wire, Some(&vk_box))
                    .expect("verification attempt must complete for this semantic fixture")
                    .ok
            );
            let mut changed_native = native.clone();
            changed_native.proof.air.as_mut().unwrap().circuit_id = alias;
            let mut changed_open = open.clone();
            changed_open.envelope_bytes = norito::encode_canonical(&changed_native).unwrap();
            let mut changed_outer = outer.clone();
            changed_outer.proof_bytes = norito::encode_canonical(&changed_open).unwrap();
            let wire = ProofBox::new(
                backend.to_owned(),
                norito::encode_canonical(&changed_outer).unwrap(),
            );
            assert!(
                !verify_backend_with_timing(backend, &wire, Some(&vk_box))
                    .expect("verification attempt must complete for this semantic fixture")
                    .ok
            );
        }
    }
    #[test]
    fn stark_exact_reserved_roles_refuse_before_direct_key_preparation() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        for role in [
            super::GOVERNANCE_BALLOT_CIRCUIT_ID_V1,
            super::GOVERNANCE_TALLY_CIRCUIT_ID_V1,
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
            iroha_data_model::soracloud::SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
        ] {
            let circuit_id = format!("{backend}:{role}");
            assert!(super::stark_open_verify_circuit_id_matches_backend(
                backend,
                &circuit_id
            ));
            let payload = consensus_stark_vk!(circuit_id.clone());
            // A canonical payload and a malformed payload both have authentic
            // outer key hashes. Refusal must precede even the preparation entry,
            // rather than depend on registry grammar, payload decode, or cache.
            for bytes in [norito::encode_canonical(&payload).unwrap(), vec![0x5a]] {
                let vk = VerifyingKeyBox::new(backend.to_owned(), bytes);
                let outer = OpenVerifyEnvelope {
                    backend: BackendTag::Stark,
                    circuit_id: circuit_id.clone(),
                    vk_hash: super::hash_vk(&vk),
                    public_inputs: b"reserved-role:preparation-order:v1".to_vec(),
                    proof_bytes: vec![0x7d],
                    aux: Vec::new(),
                };
                outer.validate_for_admission().unwrap();
                let proof = ProofBox::new(
                    backend.to_owned(),
                    norito::encode_canonical(&outer).unwrap(),
                );
                super::STARK_VERIFYING_KEY_PREPARATION_ENTRIES_V1.with(|entries| entries.set(0));
                assert!(
                    !super::verify_backend(backend, &proof, Some(&vk))
                        .expect("verification attempt must complete for this semantic fixture"),
                    "{role}"
                );
                super::STARK_VERIFYING_KEY_PREPARATION_ENTRIES_V1.with(|entries| {
                    assert_eq!(entries.get(), 0, "reserved role prepared a key: {role}");
                });
            }
        }
        // Exercise an actual generic positive proof twice: the observer sees
        // each native verifier preparation entry even when the key is cached.
        let (backend, _, vk, proof) = sample_stark_open_verify_proof();
        for _ in 0..2 {
            super::STARK_VERIFYING_KEY_PREPARATION_ENTRIES_V1.with(|entries| entries.set(0));
            assert!(
                super::verify_backend(backend, &proof, Some(&vk))
                    .expect("verification attempt must complete for this semantic fixture")
            );
            super::STARK_VERIFYING_KEY_PREPARATION_ENTRIES_V1.with(|entries| {
                assert_eq!(
                    entries.get(),
                    1,
                    "generic verifier preparation observer is live"
                );
            });
        }
    }
    fn sample_stark_open_verify_proof() -> (&'static str, String, VerifyingKeyBox, ProofBox) {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:tiny-open");
        let vk_payload = consensus_stark_vk!(circuit_id.clone());
        let vk_bytes = norito::to_bytes(&vk_payload).expect("encode vk payload");
        let vk_box = VerifyingKeyBox::new(backend.to_owned(), vk_bytes);
        let proof = prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk_box,
            b"tiny:schema:v1",
            vec![vec![[0x11; 32]], vec![[0x22; 32]]],
        )
        .expect("binding AIR STARK proof");
        (backend, circuit_id, vk_box, proof)
    }
    fn weak_stark_vk_payload(circuit_id: String) -> StarkFriVerifyingKeyV1 {
        StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id,
            n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2 - 1,
            blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        }
    }
    fn weak_stark_open_verify_proof(
        backend: &str,
        circuit_id: &str,
        vk_box: &VerifyingKeyBox,
        schema_descriptor: Vec<u8>,
        public_inputs: Vec<Vec<[u8; 32]>>,
    ) -> ProofBox {
        stark_open_verify_proof_with_transcript_label(
            backend,
            circuit_id,
            vk_box,
            schema_descriptor,
            public_inputs,
            STARK_OPEN_VERIFY_AIR_TRANSCRIPT_LABEL_V1,
        )
    }
    fn stark_open_verify_proof_with_transcript_label(
        backend: &str,
        circuit_id: &str,
        vk_box: &VerifyingKeyBox,
        schema_descriptor: Vec<u8>,
        public_inputs: Vec<Vec<[u8; 32]>>,
        transcript_label: &str,
    ) -> ProofBox {
        let vk_payload: StarkFriVerifyingKeyV1 =
            norito::decode_from_bytes(&vk_box.bytes).expect("decode weak STARK VK payload");
        let vk_hash = super::hash_vk(vk_box);
        let domain_tag = stark_open_verify_domain_tag_current(
            backend,
            circuit_id,
            vk_hash,
            &schema_descriptor,
            &public_inputs,
        );
        let params = StarkFriParamsV1 {
            version: 1,
            n_log2: vk_payload.n_log2,
            blowup_log2: vk_payload.blowup_log2,
            fold_arity: vk_payload.fold_arity,
            queries: vk_payload.queries,
            merkle_arity: vk_payload.merkle_arity,
            domain_tag,
        };
        let env_circuit_id = if let Some(relation) = circuit_id
            .strip_prefix(backend)
            .and_then(|suffix| suffix.strip_prefix('/'))
        {
            format!("{backend}:{relation}")
        } else if circuit_id.starts_with(&format!("{backend}:")) {
            circuit_id.to_owned()
        } else {
            format!("{backend}:{circuit_id}")
        };
        let public_digest = stark_open_verify_air_public_digest_current(
            backend,
            circuit_id,
            vk_hash,
            &schema_descriptor,
            &public_inputs,
        )
        .expect("derive weak STARK AIR public digest");
        let envelope_bytes = match crate::stark::prove_stark_fri_air_envelope_bytes(
            params.clone(),
            transcript_label.to_owned(),
            env_circuit_id.to_owned(),
            public_digest,
        ) {
            Ok(envelope_bytes) => envelope_bytes,
            Err(crate::stark::StarkProofProductionError::Input(message))
                if message.contains("BFV full-bootstrap")
                    || message.contains("ZK-ACE")
                    || message.contains("IVM execution")
                    || message.contains("Soracloud") =>
            {
                // Build a real generic fixture before deliberately corrupting
                // its identity. Appending a leaf cannot leave a reserved IVM
                // namespace, even in a rejection-test fixture.
                let fixture_air_circuit_id = format!("{backend}:generic-binding-fixture");
                let envelope_bytes = crate::stark::prove_stark_fri_air_envelope_bytes(
                    params,
                    transcript_label.to_owned(),
                    fixture_air_circuit_id,
                    public_digest,
                )
                .expect("build weak STARK AIR proof with fixture circuit id");
                let mut inner: StarkVerifyEnvelopeV1 = norito::decode_from_bytes(&envelope_bytes)
                    .expect("decode weak STARK AIR proof");
                inner
                    .proof
                    .air
                    .as_mut()
                    .expect("weak STARK AIR proof carries AIR section")
                    .circuit_id = env_circuit_id;
                norito::to_bytes(&inner).expect("encode retargeted weak STARK AIR proof")
            }
            Err(err) => panic!("build weak STARK AIR proof: {err}"),
        };
        let open = StarkFriOpenProofV1 {
            version: 1,
            public_inputs,
            envelope_bytes,
        };
        let outer = OpenVerifyEnvelope {
            backend: BackendTag::Stark,
            circuit_id: circuit_id.to_owned(),
            vk_hash,
            public_inputs: schema_descriptor,
            proof_bytes: norito::to_bytes(&open).expect("encode weak STARK open proof"),
            aux: Vec::new(),
        };
        ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode weak STARK OpenVerifyEnvelope"),
        )
    }
    fn mutate_outer_stark_open_verify_proof(
        backend: &str,
        proof: &ProofBox,
        mutate: impl FnOnce(&mut OpenVerifyEnvelope),
    ) -> ProofBox {
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        mutate(&mut outer);
        ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode tampered outer STARK envelope"),
        )
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_below_floor_verifying_key_payload() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:weak-open");
        let vk_payload = weak_stark_vk_payload(circuit_id.clone());
        let vk_box = VerifyingKeyBox::new(
            backend.to_owned(),
            norito::to_bytes(&vk_payload).expect("encode weak STARK VK payload"),
        );
        let err = prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk_box,
            b"weak:schema:v1",
            vec![vec![[0x11; 32]]],
        )
        .expect_err("generic STARK builder must reject below-floor VK payloads");
        assert!(
            err.to_string().contains("below consensus floor"),
            "unexpected below-floor VK rejection: {err}"
        );
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_below_floor_verifying_key_payload() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:weak-open");
        let vk_payload = weak_stark_vk_payload(circuit_id.clone());
        let vk_box = VerifyingKeyBox::new(
            backend.to_owned(),
            norito::to_bytes(&vk_payload).expect("encode weak STARK VK payload"),
        );
        let proof = weak_stark_open_verify_proof(
            backend,
            &circuit_id,
            &vk_box,
            b"weak:schema:v1".to_vec(),
            vec![vec![[0x11; 32]]],
        );
        let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(
            !report.ok,
            "generic STARK verifier must reject below-floor VK payloads"
        );
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_verifying_key_backend_mismatch() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:backend-mismatch");
        let vk_payload = consensus_stark_vk!(circuit_id.clone());
        let vk_box = VerifyingKeyBox::new(
            "stark/fri".to_owned(),
            norito::to_bytes(&vk_payload).expect("encode backend-mismatched STARK VK payload"),
        );
        let err = prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk_box,
            b"backend-mismatch:schema:v1",
            vec![vec![[0x11; 32]]],
        )
        .expect_err("generic STARK builder must reject verifier-key backend mismatch");
        assert!(
            err.to_string().contains("backend mismatch"),
            "unexpected VK backend mismatch rejection: {err}"
        );
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_verifying_key_backend_mismatch() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:backend-mismatch");
        let vk_payload = consensus_stark_vk!(circuit_id.clone());
        let vk_box = VerifyingKeyBox::new(
            "stark/fri".to_owned(),
            norito::to_bytes(&vk_payload).expect("encode backend-mismatched STARK VK payload"),
        );
        let proof = weak_stark_open_verify_proof(
            backend,
            &circuit_id,
            &vk_box,
            b"backend-mismatch:schema:v1".to_vec(),
            vec![vec![[0x11; 32]]],
        );
        let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(
            !report.ok,
            "generic STARK verifier must reject a verifier key tagged for another backend"
        );
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_circuit_family_mismatch() {
        for (case, backend, circuit_id) in [
            (
                "profile backend with sibling STARK profile",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon2-goldilocks:family-spoof",
            ),
            (
                "profile backend with generic STARK prefix",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri:family-spoof",
            ),
            (
                "profile backend with bare generic STARK family",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri",
            ),
            (
                "generic STARK backend with halo2 circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "halo2/ipa:family-spoof",
            ),
            (
                "generic STARK backend with colon-form halo2 circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "halo2:family-spoof",
            ),
            (
                "generic STARK backend with colon-form kzg circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "kzg:trusted-setup-spoof",
            ),
            (
                "generic STARK backend with bare trusted-setup curve circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "bn254",
            ),
            (
                "generic STARK backend with separated trusted-setup curve circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "b.l.s.12.381",
            ),
            (
                "generic STARK backend with STARK-prefixed trusted-setup circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "stark/fri:universal-srs",
            ),
            (
                "profile backend with bare trusted-setup circuit",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "bn254",
            ),
            (
                "profile backend with profile-prefixed trusted-setup circuit",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:structured-reference-string",
            ),
        ] {
            let vk_payload = consensus_stark_vk!(circuit_id.to_owned());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload)
                    .expect("encode circuit-family-mismatched STARK VK payload"),
            );
            let err = prove_stark_fri_open_verify_envelope(
                backend,
                circuit_id,
                &vk_box,
                b"family-mismatch:schema:v1",
                vec![vec![[0x11; 32]]],
            )
            .expect_err("generic STARK prover must reject circuit ids from another family/profile");
            assert!(
                err.to_string().contains("backend family"),
                "unexpected circuit family rejection for {case}: {err}"
            );
        }
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_circuit_family_mismatch() {
        for (case, backend, circuit_id) in [
            (
                "profile backend with sibling STARK profile",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon2-goldilocks:family-spoof",
            ),
            (
                "profile backend with generic STARK prefix",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri:family-spoof",
            ),
            (
                "profile backend with bare generic STARK family",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri",
            ),
            (
                "generic STARK backend with halo2 circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "halo2/ipa:family-spoof",
            ),
            (
                "generic STARK backend with colon-form halo2 circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "halo2:family-spoof",
            ),
            (
                "generic STARK backend with colon-form kzg circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "kzg:trusted-setup-spoof",
            ),
            (
                "generic STARK backend with bare trusted-setup curve circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "bn254",
            ),
            (
                "generic STARK backend with separated trusted-setup curve circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "b.l.s.12.381",
            ),
            (
                "generic STARK backend with STARK-prefixed trusted-setup circuit",
                super::ZK_BACKEND_STARK_FRI_V1,
                "stark/fri:universal-srs",
            ),
            (
                "profile backend with bare trusted-setup circuit",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "bn254",
            ),
            (
                "profile backend with profile-prefixed trusted-setup circuit",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:structured-reference-string",
            ),
        ] {
            let vk_payload = consensus_stark_vk!(circuit_id.to_owned());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload)
                    .expect("encode circuit-family-mismatched STARK VK payload"),
            );
            let proof = weak_stark_open_verify_proof(
                backend,
                circuit_id,
                &vk_box,
                b"family-mismatch:schema:v1".to_vec(),
                vec![vec![[0x11; 32]]],
            );
            let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture");
            assert!(
                !report.ok,
                "generic STARK verifier must reject circuit id family/profile mismatch for {case}"
            );
        }
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_zk_ace_circuit_aliases() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let canonical = iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID;
        let prefixed_alias = format!("{backend}:{canonical}");
        let slash_alias = format!("{backend}/{canonical}");
        for circuit_id in [canonical.to_owned(), prefixed_alias, slash_alias] {
            let vk_payload = consensus_stark_vk!(circuit_id.clone());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload).expect("encode ZK-ACE alias STARK VK payload"),
            );
            let err = prove_stark_fri_open_verify_envelope(
                backend,
                &circuit_id,
                &vk_box,
                b"zk-ace:generic-schema:v1",
                vec![vec![[0x33; 32]]],
            )
            .expect_err("generic STARK prover must not target ZK-ACE circuit aliases");
            assert!(
                matches!(&err, crate::stark::StarkProofProductionError::Input(message)
                    if message == "STARK circuit_id does not match backend family"),
                "reserved privacy namespaces must reject before verifier-key decoding: {circuit_id}"
            );
        }
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_zk_ace_alias_generic_binding_air() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let canonical = iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID;
        let prefixed_alias = format!("{backend}:{canonical}");
        let slash_alias = format!("{backend}/{canonical}");
        for circuit_id in [prefixed_alias, slash_alias] {
            let vk_payload = consensus_stark_vk!(circuit_id.clone());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload).expect("encode ZK-ACE alias STARK VK payload"),
            );
            let proof = weak_stark_open_verify_proof(
                backend,
                &circuit_id,
                &vk_box,
                b"zk-ace:forged-generic-schema:v1".to_vec(),
                vec![vec![[0x44; 32]]],
            );
            let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture");
            assert!(
                !report.ok,
                "ZK-ACE circuit alias {circuit_id} must not verify as generic binding AIR"
            );
        }
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_ivm_execution_circuit_aliases() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let canonical = super::IVM_EXECUTION_V1_CIRCUIT_ID;
        let prefixed_alias = format!("{backend}:{canonical}");
        let slash_alias = format!("{backend}/{canonical}");
        for circuit_id in [canonical.to_owned(), prefixed_alias, slash_alias] {
            let vk_payload = consensus_stark_vk!(circuit_id.clone());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload).expect("encode IVM alias STARK VK payload"),
            );
            let err = prove_stark_fri_open_verify_envelope(
                backend,
                &circuit_id,
                &vk_box,
                b"ivm:generic-schema:v1",
                vec![vec![[0x66; 32]]],
            )
            .expect_err("generic STARK prover must not target IVM execution circuit aliases");
            assert!(
                matches!(&err, crate::stark::StarkProofProductionError::Input(message)
                    if message == "STARK circuit_id does not match backend family"),
                "unexpected IVM alias rejection for {circuit_id}"
            );
        }
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_ivm_alias_generic_binding_air() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let canonical = super::IVM_EXECUTION_V1_CIRCUIT_ID;
        let prefixed_alias = format!("{backend}:{canonical}");
        let slash_alias = format!("{backend}/{canonical}");
        for circuit_id in [canonical.to_owned(), prefixed_alias, slash_alias] {
            let vk_payload = consensus_stark_vk!(circuit_id.clone());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload).expect("encode IVM alias STARK VK payload"),
            );
            let proof = weak_stark_open_verify_proof(
                backend,
                &circuit_id,
                &vk_box,
                b"ivm:forged-generic-schema:v1".to_vec(),
                vec![vec![[0x77; 32]]],
            );
            let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture");
            assert!(
                !report.ok,
                "IVM execution circuit alias {circuit_id} must not verify with generic schema"
            );
        }
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_namespaced_reserved_aliases() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        for canonical in [
            super::IVM_EXECUTION_V1_CIRCUIT_ID,
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
            iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID,
        ] {
            for circuit_id in [
                format!("tenant:{canonical}"),
                format!("{backend}:tenant:{canonical}"),
            ] {
                let vk_payload = consensus_stark_vk!(circuit_id.clone());
                let vk_box = VerifyingKeyBox::new(
                    backend.to_owned(),
                    norito::to_bytes(&vk_payload)
                        .expect("encode namespaced reserved STARK VK payload"),
                );
                let proof = weak_stark_open_verify_proof(
                    backend,
                    &circuit_id,
                    &vk_box,
                    b"reserved:forged-generic-schema:v1".to_vec(),
                    vec![vec![[0x79; 32]]],
                );
                let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
                    .expect("verification attempt must complete for this semantic fixture");
                assert!(
                    !report.ok,
                    "reserved circuit alias {circuit_id} must not verify as generic binding AIR"
                );
            }
        }
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_bfv_full_bootstrap_circuit_aliases() {
        let canonical = iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1;
        for backend in [
            ZK_BACKEND_STARK_FRI_V1,
            iroha_crypto::BFV_FULL_BOOTSTRAP_PROOF_BACKEND_V1,
        ] {
            let prefixed_alias = format!("{backend}:{canonical}");
            let slash_alias = format!("{backend}/{canonical}");
            for circuit_id in [canonical.to_owned(), prefixed_alias, slash_alias] {
                let vk_payload = consensus_stark_vk!(circuit_id.clone());
                let vk_box = VerifyingKeyBox::new(
                    backend.to_owned(),
                    norito::to_bytes(&vk_payload).expect("encode BFV alias STARK VK payload"),
                );
                let err = prove_stark_fri_open_verify_envelope(
                    backend,
                    &circuit_id,
                    &vk_box,
                    b"bfv:generic-schema:v1",
                    vec![vec![[0x55; 32]]],
                )
                .expect_err("generic STARK prover must not target BFV full-bootstrap aliases");
                assert!(
                    if circuit_id.starts_with(&format!("{backend}:")) {
                        matches!(&err, crate::stark::StarkProofProductionError::Input(message) if message.contains("BFV full-bootstrap"))
                    } else {
                        matches!(&err, crate::stark::StarkProofProductionError::Input(message) if message == "STARK circuit_id does not match backend family")
                    },
                    "unexpected BFV alias rejection for {backend} / {circuit_id}: {err}"
                );
            }
        }
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_bfv_full_bootstrap_alias_generic_binding_air() {
        let canonical = iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1;
        for backend in [
            ZK_BACKEND_STARK_FRI_V1,
            iroha_crypto::BFV_FULL_BOOTSTRAP_PROOF_BACKEND_V1,
            "stark/fri/poseidon2-goldilocks",
        ] {
            let prefixed_alias = format!("{backend}:{canonical}");
            let slash_alias = format!("{backend}/{canonical}");
            for circuit_id in [canonical.to_owned(), prefixed_alias, slash_alias] {
                let vk_payload = consensus_stark_vk!(circuit_id.clone());
                let vk_box = VerifyingKeyBox::new(
                    backend.to_owned(),
                    norito::to_bytes(&vk_payload).expect("encode BFV alias STARK VK payload"),
                );
                let proof = weak_stark_open_verify_proof(
                    backend,
                    &circuit_id,
                    &vk_box,
                    b"bfv:forged-generic-schema:v1".to_vec(),
                    vec![vec![[0x66; 32]]],
                );
                let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
                    .expect("verification attempt must complete for this semantic fixture");
                assert!(
                    !report.ok,
                    "BFV full-bootstrap alias {backend} / {circuit_id} must not verify as generic binding AIR"
                );
            }
        }
    }
    fn soracloud_fhe_proof_relations() -> [(&'static str, &'static [u8]); 4] {
        use iroha_data_model::soracloud::{
            SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
            SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
            SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
            SORACLOUD_FHE_INPUT_ADMISSION_PUBLIC_INPUTS_SCHEMA_V1,
            SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_PUBLIC_KEY_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
        };
        [
            (
                SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
                SORACLOUD_FHE_INPUT_ADMISSION_PUBLIC_INPUTS_SCHEMA_V1,
            ),
            (
                SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
                SORACLOUD_FHE_PUBLIC_KEY_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
            ),
            (
                SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
                SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
            ),
            (
                SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
                SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_PUBLIC_INPUTS_SCHEMA_V1,
            ),
        ]
    }
    #[test]
    fn generic_stark_prover_rejects_every_soracloud_fhe_relation_alias() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        for (canonical, schema) in soracloud_fhe_proof_relations() {
            for circuit_id in [
                canonical.to_owned(),
                format!("{backend}:{canonical}"),
                format!("{backend}/{canonical}"),
            ] {
                let vk_payload = consensus_stark_vk!(circuit_id.clone());
                let vk_box = VerifyingKeyBox::new(
                    backend.to_owned(),
                    norito::to_bytes(&vk_payload).expect("encode Soracloud STARK VK payload"),
                );
                let err = prove_stark_fri_open_verify_envelope(
                    backend,
                    &circuit_id,
                    &vk_box,
                    schema,
                    vec![vec![[0xA7; 32]]],
                )
                .expect_err("generic STARK prover must not target a Soracloud FHE relation");
                assert!(
                    matches!(&err, crate::stark::StarkProofProductionError::Input(message) if message.contains("Soracloud"))
                        || if circuit_id.starts_with(&format!("{backend}:")) {
                            matches!(&err, crate::stark::StarkProofProductionError::Input(message) if message.contains("BFV full-bootstrap"))
                        } else {
                            matches!(&err, crate::stark::StarkProofProductionError::Input(message) if message == "STARK circuit_id does not match backend family")
                        },
                    "unexpected Soracloud relation rejection for {circuit_id}: {err}"
                );
            }
        }
    }
    #[test]
    fn generic_stark_verifier_rejects_public_metadata_only_soracloud_fhe_proofs() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        for (circuit_id, schema) in soracloud_fhe_proof_relations() {
            let vk_payload = consensus_stark_vk!(circuit_id.to_owned());
            let vk_box = VerifyingKeyBox::new(
                backend.to_owned(),
                norito::to_bytes(&vk_payload).expect("encode Soracloud STARK VK payload"),
            );
            // This is exactly the vacuous construction under regression: it
            // carries a claimed public statement hash and the public schema,
            // but no ciphertext, key, refresh, material, or execution witness.
            let proof = weak_stark_open_verify_proof(
                backend,
                circuit_id,
                &vk_box,
                schema.to_vec(),
                vec![vec![[0xA7; 32]]],
            );
            let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture");
            assert!(
                !report.ok,
                "public metadata alone must not prove Soracloud FHE relation {circuit_id}"
            );
        }
    }
    fn stark_field_add_for_test(a: u64, b: u64) -> u64 {
        (((a as u128) + (b as u128)) % STARK_GOLDILOCKS_MODULUS) as u64
    }
    fn stark_field_mul_for_test(a: u64, b: u64) -> u64 {
        (((a as u128) * (b as u128)) % STARK_GOLDILOCKS_MODULUS) as u64
    }
    fn attach_valid_auxiliary_composition_to_open_verify_proof(
        backend: &str,
        outer: &mut OpenVerifyEnvelope,
    ) {
        let mut open: StarkFriOpenProofV1 =
            norito::decode_from_bytes(&outer.proof_bytes).expect("decode STARK open proof");
        let mut inner: StarkVerifyEnvelopeV1 =
            norito::decode_from_bytes(&open.envelope_bytes).expect("decode inner STARK envelope");
        let terms = stark_binding_air_terms(
            backend,
            &outer.circuit_id,
            outer.vk_hash,
            &outer.public_inputs,
            &open.public_inputs,
        );
        let z_final = inner
            .proof
            .queries
            .first()
            .and_then(|chain| chain.last())
            .map(|decommit| decommit.z)
            .expect("generated STARK proof carries a final fold value");
        assert_eq!(
            z_final.coefficients(),
            [0; 4],
            "the V1 terminal Fp4 polynomial must open to zero"
        );
        let mut leaf = stark_field_add_for_test(
            STARK_BINDING_AIR_CONSTANT,
            stark_field_mul_for_test(STARK_BINDING_AIR_Z_COEFF, 0),
        );
        for term in &terms {
            leaf = stark_field_add_for_test(leaf, stark_field_mul_for_test(term.coeff, term.value));
        }
        let (comp_root, path) = crate::stark::stark_merkle_root_and_path_from_field_values_v1(
            &inner.params,
            &[leaf],
            0,
        )
        .expect("derive auxiliary composition commitment");
        let comp_value = StarkCompositionValueV1 {
            leaf,
            constant: STARK_BINDING_AIR_CONSTANT,
            z_coeff: STARK_BINDING_AIR_Z_COEFF,
            aux_terms: terms,
            path,
        };
        inner.proof.commits.comp_root = Some(comp_root);
        inner.proof.comp_values = Some(vec![comp_value; inner.proof.queries.len()]);
        open.envelope_bytes =
            norito::to_bytes(&inner).expect("encode auxiliary inner STARK envelope");
        outer.proof_bytes = norito::to_bytes(&open).expect("encode auxiliary STARK open proof");
    }
    #[test]
    fn prove_stark_open_verify_envelope_emits_binding_air_proof() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(report.ok);
    }
    #[test]
    fn prove_stark_open_verify_envelope_rejects_alternate_layout_verifying_key() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:alternate-layout-vk");
        let vk_payload = consensus_stark_vk!(circuit_id.clone());
        let canonical_vk =
            norito::encode_canonical(&vk_payload).expect("encode canonical STARK VK");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_vk = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&vk_payload).expect("encode alternate-layout STARK VK")
        };
        assert_ne!(alternate_vk, canonical_vk);
        norito::decode_from_bytes::<StarkFriVerifyingKeyV1>(&alternate_vk)
            .expect("ordinary Norito accepts the advertised layout");
        let vk_box = VerifyingKeyBox::new(backend.to_owned(), alternate_vk);
        let err = prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk_box,
            b"alternate-layout-vk:schema:v1",
            vec![vec![[0x11; 32]]],
        )
        .expect_err("alternate-layout STARK VK must be rejected before proving");
        assert!(
            err.to_string()
                .contains("invalid STARK verifying key payload"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_alternate_layout_outer() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let outer: OpenVerifyEnvelope =
            norito::decode_canonical(&proof.bytes).expect("decode canonical outer");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_outer = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&outer).expect("encode alternate-layout outer envelope")
        };
        assert_ne!(alternate_outer, proof.bytes);
        norito::decode_from_bytes::<OpenVerifyEnvelope>(&alternate_outer)
            .expect("ordinary Norito accepts the advertised layout");
        let alternate_proof = ProofBox::new(backend.to_owned(), alternate_outer);
        assert!(
            !verify_backend_with_timing(backend, &alternate_proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture")
                .ok,
            "alternate-layout outer envelope must be rejected"
        );
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_alternate_layout_wrapper() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_canonical(&proof.bytes).expect("decode canonical outer");
        let open: StarkFriOpenProofV1 =
            norito::decode_canonical(&outer.proof_bytes).expect("decode canonical STARK wrapper");
        let canonical_wrapper = outer.proof_bytes.clone();
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_wrapper = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&open).expect("encode alternate-layout STARK wrapper")
        };
        assert_ne!(alternate_wrapper, canonical_wrapper);
        assert_eq!(
            norito::decode_from_bytes::<StarkFriOpenProofV1>(&alternate_wrapper)
                .expect("ordinary Norito accepts the advertised layout"),
            open
        );
        outer.proof_bytes = alternate_wrapper;
        let alternate_proof = ProofBox::new(
            backend.to_owned(),
            norito::encode_canonical(&outer)
                .expect("encode canonical outer around alternate wrapper"),
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert!(
            verify_backend_with_timing(backend, &proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture")
                .ok,
            "canonical STARK proof must verify independently of ambient layout"
        );
        assert!(
            !verify_backend_with_timing(backend, &alternate_proof, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture")
                .ok,
            "alternate-layout STARK wrapper must be rejected inside a canonical outer envelope"
        );
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_bound_public_input_tampering() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        let mut open: StarkFriOpenProofV1 =
            norito::decode_from_bytes(&outer.proof_bytes).expect("decode STARK open proof");
        open.public_inputs[0][0][0] ^= 0x01;
        outer.proof_bytes = norito::to_bytes(&open).expect("encode tampered STARK open proof");
        let tampered = ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode tampered outer STARK envelope"),
        );
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_bound_schema_tampering() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        outer.public_inputs.push(0xAA);
        let tampered = ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode tampered outer STARK envelope"),
        );
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_noncanonical_binding_air_transcript_label() {
        let (backend, circuit_id, vk_box, _proof) = sample_stark_open_verify_proof();
        let proof = stark_open_verify_proof_with_transcript_label(
            backend,
            &circuit_id,
            &vk_box,
            b"tiny:schema:v1".to_vec(),
            vec![vec![[0x11; 32]], vec![[0x22; 32]]],
            "IROHA-STARK-AIR-V1-ALT",
        );
        let report = verify_backend_with_timing(backend, &proof, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(
            !report.ok,
            "generic STARK OpenVerify wrappers must use the canonical binding AIR transcript label"
        );
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_vk_hash_tampering() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        outer.vk_hash[0] ^= 0x01;
        let tampered = ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode tampered outer STARK envelope"),
        );
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_noncanonical_outer_shape() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let cases: [(&str, fn(&mut OpenVerifyEnvelope)); 7] = [
            ("backend tag", |outer| {
                outer.backend = BackendTag::NativePipaRPasta
            }),
            ("empty circuit id", |outer| outer.circuit_id.clear()),
            ("zero verifier-key hash", |outer| outer.vk_hash = [0u8; 32]),
            ("empty public inputs", |outer| outer.public_inputs.clear()),
            ("empty proof bytes", |outer| outer.proof_bytes.clear()),
            ("all-zero proof bytes", |outer| {
                outer.proof_bytes = vec![0u8; 16]
            }),
            ("auxiliary bytes", |outer| {
                outer.aux = b"side-channel".to_vec()
            }),
        ];
        for (case, mutate) in cases {
            let tampered = mutate_outer_stark_open_verify_proof(backend, &proof, mutate);
            let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
                .expect("verification attempt must complete for this semantic fixture");
            assert!(!report.ok, "case {case}");
        }
        let tampered = mutate_outer_stark_open_verify_proof(backend, &proof, |outer| {
            outer.public_inputs =
                vec![0xA5; iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES + 1];
        });
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok, "oversized public inputs");
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_missing_vk() {
        let (backend, _circuit_id, _vk_box, proof) = sample_stark_open_verify_proof();
        let report = verify_backend_with_timing(backend, &proof, None)
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_inner_air_circuit_tampering() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        let mut open: StarkFriOpenProofV1 =
            norito::decode_from_bytes(&outer.proof_bytes).expect("decode STARK open proof");
        let mut inner: StarkVerifyEnvelopeV1 =
            norito::decode_from_bytes(&open.envelope_bytes).expect("decode inner STARK envelope");
        inner
            .proof
            .air
            .as_mut()
            .expect("AIR section")
            .circuit_id
            .push_str(":tampered");
        open.envelope_bytes = norito::to_bytes(&inner).expect("encode tampered inner STARK proof");
        outer.proof_bytes = norito::to_bytes(&open).expect("encode tampered STARK open proof");
        let tampered = ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode tampered outer STARK envelope"),
        );
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_inner_parameter_tampering() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        let mut open: StarkFriOpenProofV1 =
            norito::decode_from_bytes(&outer.proof_bytes).expect("decode STARK open proof");
        let mut inner: StarkVerifyEnvelopeV1 =
            norito::decode_from_bytes(&open.envelope_bytes).expect("decode inner STARK envelope");
        inner.params.queries = inner.params.queries.saturating_add(1);
        open.envelope_bytes = norito::to_bytes(&inner).expect("encode tampered inner STARK proof");
        outer.proof_bytes = norito::to_bytes(&open).expect("encode tampered STARK open proof");
        let tampered = ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode tampered outer STARK envelope"),
        );
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_inner_auxiliary_composition_commitments() {
        let (backend, _circuit_id, vk_box, proof) = sample_stark_open_verify_proof();
        let mut outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        attach_valid_auxiliary_composition_to_open_verify_proof(backend, &mut outer);
        let tampered = ProofBox::new(
            backend.to_owned(),
            norito::to_bytes(&outer).expect("encode auxiliary outer STARK envelope"),
        );
        let report = verify_backend_with_timing(backend, &tampered, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
    #[test]
    fn verify_stark_open_verify_envelope_rejects_malformed_payload_without_panic() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let vk_payload = StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id: format!("{backend}:tiny-open"),
            n_log2: 4,
            blowup_log2: 2,
            fold_arity: 2,
            queries: 2,
            merkle_arity: 2,
        };
        let vk_bytes = norito::to_bytes(&vk_payload).expect("encode vk payload");
        let vk_box = VerifyingKeyBox::new(backend.to_owned(), vk_bytes);
        let malformed = ProofBox::new(backend.to_owned(), vec![0xAA, 0xBB, 0xCC]);
        let report = verify_backend_with_timing(backend, &malformed, Some(&vk_box))
            .expect("verification attempt must complete for this semantic fixture");
        assert!(!report.ok);
    }
}
/// Result produced by [`verify_backend_with_timing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    /// Outcome of the backend verification.
    pub ok: bool,
    /// Time spent verifying.
    pub elapsed: Duration,
}
const REJECTED_VERIFY_REPORT: VerifyReport = VerifyReport {
    ok: false,
    elapsed: Duration::ZERO,
};
/// Configuration guardrails for proof verification (enabled flags + payload size caps).
///
/// This struct is intentionally scalar-only so it can be sourced both from the ZK settings a
/// State froze for a block (`zk_guardrails::guardrails_from_config` in `iroha_core`; the switches
/// and caps there are the committed `zk_validity_policy_v1` parameter or the protocol default)
/// and from host-local verification caps (e.g. IVM host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkVerifyGuardrails {
    /// Whether native PIPA-R verification is enabled.
    pub pipa_r_enabled: bool,
    /// Maximum accepted native PIPA-R outer envelope bytes.
    pub pipa_r_max_envelope_bytes: usize,
    /// Maximum accepted native PIPA-R inner proof container bytes.
    pub pipa_r_max_proof_bytes: usize,
    /// Whether STARK verification is enabled.
    pub stark_enabled: bool,
    /// Maximum accepted outer STARK OpenVerifyEnvelope size (bytes).
    pub stark_max_envelope_bytes: usize,
    /// Maximum accepted backend-native STARK proof payload size (bytes).
    pub stark_max_proof_bytes: usize,
}
/// Verify a backend and report the elapsed time.
///
/// # Errors
///
/// Propagates the original local refusal from [`verify_backend`] when the
/// verification attempt cannot complete; completed rejection is a report
/// whose `ok` field is `false`.
pub fn verify_backend_with_timing(
    backend: &str,
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
) -> Result<VerifyReport, VerificationRefusal> {
    let started = Instant::now();
    let ok = verify_backend(backend, proof, vk)?;
    Ok(VerifyReport {
        ok,
        elapsed: started.elapsed(),
    })
}
/// Verify a backend under explicit configuration guardrails (enabled flags + payload size caps).
///
/// This helper exists to prevent accidentally accepting proofs for a backend that is
/// compiled in but disabled at runtime.
///
/// # Errors
///
/// Returns the original local refusal if canonical decoding, native verifier
/// initialization or verification cannot complete. Disabled backends, payload
/// limit violations and completed rejection are returned as reports with
/// `ok` set to `false`.
pub fn verify_backend_with_timing_guardrails(
    backend: &str,
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
    guardrails: ZkVerifyGuardrails,
) -> Result<VerifyReport, VerificationRefusal> {
    if is_production_claim_backend_label(backend) {
        tracing::debug!(
            backend,
            "production-claim proof backends are not admitted by node verifier guardrails"
        );
        return Ok(REJECTED_VERIFY_REPORT);
    }
    if is_trusted_setup_backend_label(backend) {
        tracing::debug!(
            backend,
            "trusted-setup proof backends are not admitted by node verifier guardrails"
        );
        return Ok(REJECTED_VERIFY_REPORT);
    }
    if is_developer_only_backend_label(backend) {
        tracing::debug!(
            backend,
            "developer-only proof backends are not admitted by node verifier guardrails"
        );
        return Ok(REJECTED_VERIFY_REPORT);
    }
    if !is_production_verify_backend_label(backend) {
        tracing::debug!(
            backend,
            "unsupported proof backends are not admitted by node verifier guardrails"
        );
        return Ok(REJECTED_VERIFY_REPORT);
    }
    if proof.backend.as_str() != backend {
        tracing::debug!(
            backend,
            proof_backend = proof.backend.as_str(),
            "proof backend label does not match requested verifier backend"
        );
        return Ok(REJECTED_VERIFY_REPORT);
    }
    if let Some(vk_box) = vk
        && vk_box.backend.as_str() != backend
    {
        tracing::debug!(
            backend,
            vk_backend = vk_box.backend.as_str(),
            "verifying key backend label does not match requested verifier backend"
        );
        return Ok(REJECTED_VERIFY_REPORT);
    }
    if production_verify_backend_tag(backend)
        == Some(iroha_data_model::zk::BackendTag::NativePipaRPasta)
    {
        if !guardrails.pipa_r_enabled || proof.bytes.len() > guardrails.pipa_r_max_envelope_bytes {
            return Ok(REJECTED_VERIFY_REPORT);
        }
        let Some(envelope) =
            verification_attempt::completed_result(verification_attempt::codec_attempt(
                || {
                    norito::decode_canonical::<iroha_data_model::zk::OpenVerifyEnvelope>(
                        &proof.bytes,
                    )
                },
                |_| (),
            ))?
        else {
            return Ok(REJECTED_VERIFY_REPORT);
        };
        if envelope
            .validate_with_bounds(iroha_data_model::zk::OpenVerifyEnvelopeBounds {
                max_proof_bytes: guardrails.pipa_r_max_proof_bytes,
                ..iroha_data_model::zk::OpenVerifyEnvelopeBounds::default()
            })
            .is_err()
            || native_pipa_r::validate_metadata(backend, &envelope).is_err()
        {
            return Ok(REJECTED_VERIFY_REPORT);
        }
        let Some(key) = vk else {
            return Ok(REJECTED_VERIFY_REPORT);
        };
        let started = Instant::now();
        let completed = verification_attempt::completed_result(native_pipa_r::verify_envelope(
            backend, &envelope, key,
        ))?;
        return Ok(VerifyReport {
            ok: completed.is_some(),
            elapsed: started.elapsed(),
        });
    }
    if is_stark_fri_v1_backend(backend) {
        if !guardrails.stark_enabled {
            tracing::debug!(
                backend,
                "stark verification is disabled by the committed ZK validity policy"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        if proof.bytes.len() > guardrails.stark_max_envelope_bytes {
            tracing::debug!(
                backend,
                "stark payload exceeds the committed max_envelope_bytes"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        let Some(env) =
            verification_attempt::completed_result(verification_attempt::codec_attempt(
                || {
                    norito::decode_canonical::<iroha_data_model::zk::OpenVerifyEnvelope>(
                        &proof.bytes,
                    )
                },
                |_| (),
            ))?
        else {
            return Ok(REJECTED_VERIFY_REPORT);
        };
        if env.backend != iroha_data_model::zk::BackendTag::Stark {
            tracing::debug!(
                backend,
                "stark OpenVerifyEnvelope backend tag does not match verifier backend"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        if let Err(err) = env.validate_with_bounds(iroha_data_model::zk::OpenVerifyEnvelopeBounds {
            max_proof_bytes: guardrails.stark_max_envelope_bytes,
            ..iroha_data_model::zk::OpenVerifyEnvelopeBounds::default()
        }) {
            tracing::debug!(
                backend,
                error = %err,
                "stark OpenVerifyEnvelope failed guardrail validation"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        if !stark_open_verify_circuit_id_matches_backend(backend, &env.circuit_id) {
            tracing::debug!(
                backend,
                circuit_id = env.circuit_id.as_str(),
                "stark OpenVerifyEnvelope circuit id does not match verifier backend"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        let Some(open) =
            verification_attempt::completed_result(verification_attempt::codec_attempt(
                || {
                    norito::decode_canonical::<iroha_data_model::zk::StarkFriOpenProofV1>(
                        &env.proof_bytes,
                    )
                },
                |_| (),
            ))?
        else {
            return Ok(REJECTED_VERIFY_REPORT);
        };
        if open.version != 1 {
            tracing::debug!(
                backend,
                version = open.version,
                "stark OpenVerifyEnvelope wrapper version is unsupported"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        if open.envelope_bytes.is_empty() {
            tracing::debug!(
                backend,
                "stark OpenVerifyEnvelope wrapper has empty native proof bytes"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        if open.envelope_bytes.len() > guardrails.stark_max_proof_bytes {
            tracing::debug!(
                backend,
                "stark envelope proof bytes exceed the committed max_proof_bytes"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
        #[cfg(feature = "zk-stark")]
        {
            let started = Instant::now();
            let limits = crate::stark::StarkVerifierLimits {
                max_envelope_bytes: guardrails.stark_max_proof_bytes,
                ..crate::stark::StarkVerifierLimits::default()
            };
            let ok =
                verify_stark_fri_open_verify_envelope_with_limits(backend, proof, vk, &limits)?;
            return Ok(VerifyReport {
                ok,
                elapsed: started.elapsed(),
            });
        }
        #[cfg(not(feature = "zk-stark"))]
        {
            tracing::debug!(
                backend,
                "stark/fri backend requested but binary was built without `zk-stark`"
            );
            return Ok(REJECTED_VERIFY_REPORT);
        }
    }
    verify_backend_with_timing(backend, proof, vk)
}
#[cfg(test)]
mod guardrails_tests {
    use super::*;
    use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope, StarkFriOpenProofV1};
    const ENABLED_GUARDRAILS: ZkVerifyGuardrails = ZkVerifyGuardrails {
        pipa_r_enabled: true,
        pipa_r_max_envelope_bytes: 1024,
        pipa_r_max_proof_bytes: 1024,
        stark_enabled: true,
        stark_max_envelope_bytes: 1024,
        stark_max_proof_bytes: 1024,
    };
    macro_rules! assert_guardrails_reject {
        ($backend:expr, $proof:expr, $vk:expr, $guardrails:expr $(, $message:literal)? $(,)?) => {{
            let report =
                verify_backend_with_timing_guardrails($backend, $proof, $vk, $guardrails).expect("verification attempt must complete for this semantic fixture");
            assert!(!report.ok $(, $message)?);
            assert_eq!(report.elapsed, Duration::ZERO $(, $message)?);
        }};
    }
    fn native_guardrail_envelope() -> OpenVerifyEnvelope {
        OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID.to_owned(),
            vk_hash: [0x11; 32],
            public_inputs: confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1
                .to_vec(),
            proof_bytes: vec![0xBB; 10],
            aux: Vec::new(),
        }
    }
    #[test]
    fn guardrails_disable_native_returns_zero_duration() {
        let proof = ProofBox::new("pipa-r/pasta".into(), vec![0xAA; 8]);
        assert_guardrails_reject!(
            "pipa-r/pasta",
            &proof,
            None,
            ZkVerifyGuardrails {
                pipa_r_enabled: false,
                ..ENABLED_GUARDRAILS
            },
        );
    }
    #[test]
    fn guardrails_reject_trusted_setup_backends_before_dispatch() {
        for backend in [
            "kzg",
            "KZG",
            " kzg ",
            "bn254",
            "BN254",
            "bls12_381",
            "native/kzg",
            "pipa-r/pasta:kzg",
            "pipa-r/pasta:KZG",
            "pipa-r/pasta: KZG",
            "stark/fri/prod;kzg",
            "stark/fri/prod,kzg",
            "stark/fri/prod+kzg",
            "stark/fri/prod.kzg",
            "stark/fri/prod-k-z-g",
            "stark/fri/prod(kzg)",
            "stark/fri/prod;bn254",
            "stark/fri/prod-bn-254",
            "stark/fri/prod+bn256",
            "stark/fri/prod-bn-256",
            "stark/fri/prod-bls12-381",
            "stark/fri/prod-b.l.s.12.381",
            "srs",
            "SRS",
            "crs",
            "ptau",
            "powersoftau",
            "powers-of-tau",
            "trusted-setup",
            "structured-reference-string",
            "universal-srs",
            "pipa-r/pasta:universal-srs",
            "stark/fri/prod-srs",
            "stark/fri/prod-s-r-s",
            "stark/fri/prod.crs",
            "stark/fri/prod-ptau",
            "stark/fri/prod-powers-of-tau",
            "stark/fri/prod-ceremony",
            "stark/fri/structured-reference-string",
            "pipa-r/pasta;groth16",
            "pipa-r/pasta:groth-16",
            "pipa-r/pasta/orchard:kzg",
            "orchard:universal-srs",
            "penumbra-masp:kzg",
            "jindo-lattice-pcs-zk:trusted-setup",
            "miden-stark:ptau",
            "sis-with-hints:groth16",
            "pq-masp-stark-fri:kzg",
            "native/bn254",
            "groth16/bn254",
        ] {
            let proof = ProofBox::new(backend.into(), vec![1, 2, 3]);
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {backend}",);
        }
    }
    #[test]
    fn guardrails_reject_developer_only_backends_before_dispatch() {
        for backend in [
            "debug",
            "debug-proof",
            "Debug-Proof",
            "debug/ok",
            "native/debug",
            "pipa-r/pasta:debug-proof",
            "pipa-r/pasta:DEBUG-Proof",
            "pipa-r/pasta:d-e-b-u-g-proof",
            "stark/fri/debug",
            "stark/fri/Debug",
            "stark/fri/d-e-b-u-g",
            "mock",
            "mock-proof",
            "Mock-Proof",
            "native/mock",
            "pipa-r/pasta:mock-proof",
            "pipa-r/pasta:Mock-Proof",
            "pipa-r/pasta:m-o-c-k-proof",
            "stark/fri/m-o-c-k",
            "stark/fri/dev-fixture",
            "stark/fri/d-e-v-f-i-x-t-u-r-e",
            "stark/fri/dev",
            "stark/fri/d-e-v",
            "stark/fri/test",
            "stark/fri/t-e-s-t",
            "stark/fri/placeholder",
            "pipa-r/pasta:dev-fixture",
            "pipa-r/pasta:d-e-v-f-i-x-t-u-r-e",
            "pipa-r/pasta:dev",
            "pipa-r/pasta:d-e-v",
            "pipa-r/pasta:dummy",
            "pipa-r/pasta:f-a-k-e",
            "pipa-r/pasta:stub",
            "pipa-r/pasta:s-a-m-p-l-e",
            "zk-trace/mock-proof",
        ] {
            let proof = ProofBox::new(backend.into(), vec![1, 2, 3]);
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {backend}",);
        }
    }
    #[test]
    fn guardrails_reject_protocol_names_before_dispatch() {
        for backend in [
            "pipa-r/pasta/orchard",
            "stark/fri/miden",
            "stark/fri/pq-masp-stark-fri",
            "groth16/bls12-377",
            "anonymous-pgc",
            "verange",
            "zk-ams-recursive-admission-v0",
            "zk-x509-onchain-identity-v0",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
        ] {
            let proof = ProofBox::new(backend.into(), vec![1, 2, 3]);
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {backend}",);
        }
    }
    #[test]
    fn guardrails_reject_production_claim_backends_before_dispatch() {
        for backend in [
            "pipa-r/pasta:production-ready",
            "pipa-r/pasta:claimed-production",
            "pipa-r/pasta:mainnet-ready",
            "pipa-r/pasta:mainnet-complete",
            "stark/fri/audit-signoff",
            "stark/fri/externally-audited",
            "stark/fri/security-review-passed",
            "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
            "stark/fri/a-u-d-i-t-c-l-a-i-m",
            "pipa-r/pasta:release-ready",
            "pipa-r/pasta:release-approved",
            "pipa-r/pasta:certified-mainnet",
            "pipa-r/pasta:third-party-audited",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        ] {
            let proof = ProofBox::new(backend.into(), vec![1, 2, 3]);
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {backend}",);
        }
    }
    #[test]
    fn guardrails_reject_unsupported_backends_before_dispatch() {
        for backend in [
            "unknown/privacy/backend",
            "native/unknown-native-v1",
            "pipa-r/pasta:unknown-native-v1",
            "HALO2/IPA",
            "stark/FRI",
            "pipa-r/pasta::ivm-replay-binding-v1",
            "native//ipa",
            "pipa-r/pasta.",
            "stark//fri/sha256-goldilocks",
            "stark/fri/sha256..goldilocks",
            "h\u{0430}lo2/ipa",
            "native/pasta/tiny-add",
            "pipa-r/pasta/tiny-add",
            "pipa-r/pasta:tiny-add",
            "native/pasta/tiny-commit-open",
            "zk/open-verify-unregistered",
        ] {
            let proof = ProofBox::new(backend.into(), vec![1, 2, 3]);
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {backend}",);
        }
    }
    #[test]
    fn guardrails_reject_proof_and_vk_backend_mismatch_before_dispatch() {
        let envelope_bytes =
            norito::to_bytes(&native_guardrail_envelope()).expect("encode native envelope");
        let wrong_proof_backend =
            ProofBox::new("pipa-r/pasta:ivm-replay-binding-v1".into(), envelope_bytes);
        assert_guardrails_reject!(
            "pipa-r/pasta",
            &wrong_proof_backend,
            None,
            ENABLED_GUARDRAILS,
        );
        let proof = ProofBox::new(
            "pipa-r/pasta".into(),
            norito::to_bytes(&native_guardrail_envelope()).expect("encode native envelope"),
        );
        let wrong_vk_backend =
            VerifyingKeyBox::new("pipa-r/pasta:ivm-replay-binding-v1".into(), vec![0x55]);
        assert_guardrails_reject!(
            "pipa-r/pasta",
            &proof,
            Some(&wrong_vk_backend),
            ENABLED_GUARDRAILS,
        );
    }
    #[test]
    fn guardrails_reject_native_open_verify_circuit_mismatch_before_dispatch() {
        for (case, backend, circuit_id) in [
            (
                "concrete backend with sibling circuit",
                "native/pasta/ivm-replay-binding-v1",
                "native/pasta/tiny-add-public",
            ),
            (
                "concrete backend with aliased sibling circuit",
                "pipa-r/pasta:ivm-replay-binding-v1",
                "pipa-r/pasta:tiny-add-public",
            ),
            (
                "generic native backend with cross-family circuit",
                "pipa-r/pasta",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:spoof",
            ),
            (
                "generic native backend with tiny demo circuit",
                "pipa-r/pasta",
                "pipa-r/pasta:tiny-add",
            ),
            (
                "generic native backend with anonymous-transfer demo circuit",
                "pipa-r/pasta",
                "native/pasta/anon-transfer-2x2",
            ),
            (
                "generic native backend with retired vote circuit",
                "pipa-r/pasta",
                "pipa-r/pasta:vote-bool-commit-merkle8",
            ),
            (
                "generic native backend with historical IVM overlay circuit",
                "pipa-r/pasta",
                "pipa-r/pasta:ivm-overlay-bind",
            ),
            (
                "generic native backend with bare trusted-setup circuit",
                "pipa-r/pasta",
                "kzg",
            ),
            (
                "generic native backend with prefixed trusted-setup circuit",
                "pipa-r/pasta",
                "pipa-r/pasta:kzg",
            ),
            (
                "generic native backend with prefixed STARK circuit",
                "pipa-r/pasta",
                "pipa-r/pasta:stark/fri",
            ),
        ] {
            let mut env = native_guardrail_envelope();
            env.circuit_id = circuit_id.to_owned();
            let proof = ProofBox::new(
                backend.to_owned(),
                norito::to_bytes(&env).expect("encode native envelope"),
            );
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {case}",);
        }
    }
    #[test]
    fn guardrails_enforce_pipa_r_max_envelope_bytes() {
        let proof = ProofBox::new("pipa-r/pasta".into(), vec![0xAA; 9]);
        assert_guardrails_reject!(
            "pipa-r/pasta",
            &proof,
            None,
            ZkVerifyGuardrails {
                pipa_r_max_envelope_bytes: 8,
                ..ENABLED_GUARDRAILS
            },
        );
    }
    #[test]
    fn guardrails_enforce_pipa_r_max_proof_bytes_for_open_verify_envelopes() {
        let env = native_guardrail_envelope();
        let bytes = norito::to_bytes(&env).expect("encode envelope");
        let proof = ProofBox::new("pipa-r/pasta".into(), bytes);
        assert_guardrails_reject!(
            "pipa-r/pasta",
            &proof,
            None,
            ZkVerifyGuardrails {
                pipa_r_max_proof_bytes: 5,
                ..ENABLED_GUARDRAILS
            },
        );
    }
    #[test]
    fn guardrails_reject_open_verify_shape_failures_before_dispatch() {
        let cases: [(&str, fn(&mut OpenVerifyEnvelope)); 6] = [
            ("empty circuit id", |env| env.circuit_id.clear()),
            ("zero verifier-key hash", |env| env.vk_hash = [0u8; 32]),
            ("empty public inputs", |env| env.public_inputs.clear()),
            ("wrong nonzero public-input schema", |env| {
                env.public_inputs = b"noncanonical-but-nonzero-schema".to_vec()
            }),
            ("empty proof bytes", |env| env.proof_bytes.clear()),
            ("auxiliary bytes", |env| env.aux = b"ignored-hint".to_vec()),
        ];
        for (label, mutate) in cases {
            let mut env = native_guardrail_envelope();
            mutate(&mut env);
            let proof = ProofBox::new(
                "pipa-r/pasta".into(),
                norito::to_bytes(&env).expect("encode envelope"),
            );
            assert_guardrails_reject!(
                "pipa-r/pasta",
                &proof,
                None,
                ENABLED_GUARDRAILS,
                "case {label}",
            );
        }
        let mut env = native_guardrail_envelope();
        env.public_inputs =
            vec![0xA5; iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES + 1];
        let proof = ProofBox::new(
            "pipa-r/pasta".into(),
            norito::to_bytes(&env).expect("encode envelope"),
        );
        assert_guardrails_reject!(
            "pipa-r/pasta",
            &proof,
            None,
            ZkVerifyGuardrails {
                pipa_r_max_envelope_bytes: usize::MAX,
                pipa_r_max_proof_bytes: usize::MAX,
                stark_max_envelope_bytes: usize::MAX,
                stark_max_proof_bytes: usize::MAX,
                ..ENABLED_GUARDRAILS
            },
            "oversized public inputs",
        );
    }
    #[test]
    fn guardrails_reject_open_verify_backend_tag_mismatch_before_dispatch() {
        let mut native_env = native_guardrail_envelope();
        native_env.backend = BackendTag::Stark;
        let native_proof = ProofBox::new(
            "pipa-r/pasta".into(),
            norito::to_bytes(&native_env).expect("encode mismatched native envelope"),
        );
        assert_guardrails_reject!("pipa-r/pasta", &native_proof, None, ENABLED_GUARDRAILS,);
        let open = StarkFriOpenProofV1 {
            version: 1,
            public_inputs: Vec::new(),
            envelope_bytes: vec![0xCC; 10],
        };
        let stark_env = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: "stark/fri/poseidon-x7-goldilocks-6x64-v1:dummy".to_owned(),
            vk_hash: [0x11; 32],
            public_inputs: vec![0xAA; 32],
            proof_bytes: norito::to_bytes(&open).expect("encode stark wrapper"),
            aux: Vec::new(),
        };
        let stark_proof = ProofBox::new(
            ZK_BACKEND_STARK_FRI_V1.into(),
            norito::to_bytes(&stark_env).expect("encode mismatched stark envelope"),
        );
        assert_guardrails_reject!(
            ZK_BACKEND_STARK_FRI_V1,
            &stark_proof,
            None,
            ENABLED_GUARDRAILS,
        );
    }
    #[test]
    fn guardrails_disable_stark_returns_zero_duration() {
        let proof = ProofBox::new(ZK_BACKEND_STARK_FRI_V1.into(), vec![0xAA; 8]);
        assert_guardrails_reject!(
            ZK_BACKEND_STARK_FRI_V1,
            &proof,
            None,
            ZkVerifyGuardrails {
                stark_enabled: false,
                ..ENABLED_GUARDRAILS
            },
        );
    }
    #[test]
    fn guardrails_enforce_stark_max_envelope_bytes() {
        let proof = ProofBox::new(ZK_BACKEND_STARK_FRI_V1.into(), vec![0xAA; 9]);
        assert_guardrails_reject!(
            ZK_BACKEND_STARK_FRI_V1,
            &proof,
            None,
            ZkVerifyGuardrails {
                stark_max_envelope_bytes: 8,
                ..ENABLED_GUARDRAILS
            },
        );
    }
    #[test]
    fn guardrails_reject_malformed_stark_outer_envelope_before_dispatch() {
        let proof = ProofBox::new(ZK_BACKEND_STARK_FRI_V1.into(), vec![0xAA, 0xBB, 0xCC]);
        assert_guardrails_reject!(ZK_BACKEND_STARK_FRI_V1, &proof, None, ENABLED_GUARDRAILS,);
    }
    #[test]
    fn guardrails_enforce_stark_max_proof_bytes_inside_open_verify_envelope() {
        let open = StarkFriOpenProofV1 {
            version: 1,
            public_inputs: Vec::new(),
            envelope_bytes: vec![0xCC; 10],
        };
        let env = OpenVerifyEnvelope {
            backend: BackendTag::Stark,
            circuit_id: "stark/fri/poseidon-x7-goldilocks-6x64-v1:dummy".to_owned(),
            vk_hash: [0x11; 32],
            public_inputs: vec![0xAA; 32],
            proof_bytes: norito::to_bytes(&open).expect("encode stark wrapper"),
            aux: Vec::new(),
        };
        let proof = ProofBox::new(
            ZK_BACKEND_STARK_FRI_V1.into(),
            norito::to_bytes(&env).expect("encode envelope"),
        );
        assert_guardrails_reject!(
            ZK_BACKEND_STARK_FRI_V1,
            &proof,
            None,
            ZkVerifyGuardrails {
                stark_max_proof_bytes: 8,
                ..ENABLED_GUARDRAILS
            },
        );
    }
    #[test]
    fn guardrails_reject_malformed_stark_wrapper_before_dispatch() {
        let cases = [
            ("malformed wrapper bytes", vec![0xAA, 0xBB, 0xCC]),
            (
                "unsupported wrapper version",
                norito::to_bytes(&StarkFriOpenProofV1 {
                    version: 2,
                    public_inputs: Vec::new(),
                    envelope_bytes: vec![0xCC; 10],
                })
                .expect("encode unsupported STARK wrapper"),
            ),
            (
                "empty native proof bytes",
                norito::to_bytes(&StarkFriOpenProofV1 {
                    version: 1,
                    public_inputs: Vec::new(),
                    envelope_bytes: Vec::new(),
                })
                .expect("encode empty STARK wrapper"),
            ),
        ];
        for (case, proof_bytes) in cases {
            let env = OpenVerifyEnvelope {
                backend: BackendTag::Stark,
                circuit_id: "stark/fri/poseidon-x7-goldilocks-6x64-v1:dummy".to_owned(),
                vk_hash: [0x11; 32],
                public_inputs: vec![0xAA; 32],
                proof_bytes,
                aux: Vec::new(),
            };
            let proof = ProofBox::new(
                ZK_BACKEND_STARK_FRI_V1.into(),
                norito::to_bytes(&env).expect("encode envelope"),
            );
            assert_guardrails_reject!(
                ZK_BACKEND_STARK_FRI_V1,
                &proof,
                None,
                ENABLED_GUARDRAILS,
                "case {case}",
            );
        }
    }
    #[test]
    fn guardrails_reject_stark_open_verify_circuit_mismatch_before_dispatch() {
        let open = StarkFriOpenProofV1 {
            version: 1,
            public_inputs: Vec::new(),
            envelope_bytes: vec![0xCC; 10],
        };
        for (case, backend, circuit_id) in [
            (
                "profile backend with sibling STARK profile",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon2-goldilocks:dummy",
            ),
            (
                "profile backend with generic STARK prefix",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri:dummy",
            ),
            (
                "generic STARK backend with native circuit",
                ZK_BACKEND_STARK_FRI_V1,
                "pipa-r/pasta:ivm-replay-binding-v1",
            ),
            (
                "generic STARK backend with colon-form native circuit",
                ZK_BACKEND_STARK_FRI_V1,
                "native:ivm-replay-binding-v1",
            ),
            (
                "generic STARK backend with colon-form kzg circuit",
                ZK_BACKEND_STARK_FRI_V1,
                "kzg:trusted-setup-spoof",
            ),
            (
                "generic STARK backend with bare trusted-setup curve circuit",
                ZK_BACKEND_STARK_FRI_V1,
                "bn254",
            ),
            (
                "generic STARK backend with STARK-prefixed trusted-setup circuit",
                ZK_BACKEND_STARK_FRI_V1,
                "stark/fri:universal-srs",
            ),
            (
                "profile backend with profile-prefixed trusted-setup circuit",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:structured-reference-string",
            ),
        ] {
            let env = OpenVerifyEnvelope {
                backend: BackendTag::Stark,
                circuit_id: circuit_id.to_owned(),
                vk_hash: [0x11; 32],
                public_inputs: vec![0xAA; 32],
                proof_bytes: norito::to_bytes(&open).expect("encode stark wrapper"),
                aux: Vec::new(),
            };
            let proof = ProofBox::new(
                backend.to_owned(),
                norito::to_bytes(&env).expect("encode envelope"),
            );
            assert_guardrails_reject!(backend, &proof, None, ENABLED_GUARDRAILS, "case {case}",);
        }
    }
    #[cfg(feature = "zk-stark")]
    #[test]
    fn guardrails_stark_proof_limit_applies_to_inner_envelope_not_outer_wrapper() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:guardrail-split");
        let vk_payload = consensus_stark_vk!(circuit_id.clone());
        let vk_box = VerifyingKeyBox::new(
            backend.to_owned(),
            norito::to_bytes(&vk_payload).expect("encode STARK verifying key"),
        );
        let proof = prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk_box,
            b"guardrail:schema:v1",
            vec![vec![[0x11; 32]], vec![[0x22; 32]]],
        )
        .expect("STARK OpenVerify proof");
        let outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        let open: StarkFriOpenProofV1 =
            norito::decode_from_bytes(&outer.proof_bytes).expect("decode STARK open proof");
        assert!(
            proof.bytes.len() > open.envelope_bytes.len(),
            "outer wrapper should be larger than the native STARK proof bytes"
        );
        let report = verify_backend_with_timing_guardrails(
            backend,
            &proof,
            Some(&vk_box),
            ZkVerifyGuardrails {
                stark_max_envelope_bytes: proof.bytes.len(),
                stark_max_proof_bytes: open.envelope_bytes.len(),
                ..ENABLED_GUARDRAILS
            },
        )
        .expect("verification attempt must complete for this semantic fixture");
        assert!(report.ok);
    }
    #[cfg(feature = "zk-stark")]
    #[test]
    fn guardrails_reject_stark_proof_backend_alias_mismatch_before_dispatch() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = format!("{backend}:guardrail-backend-mismatch");
        let vk_payload = consensus_stark_vk!(circuit_id.clone());
        let vk_box = VerifyingKeyBox::new(
            backend.to_owned(),
            norito::to_bytes(&vk_payload).expect("encode STARK verifying key"),
        );
        let mut proof = prove_stark_fri_open_verify_envelope(
            backend,
            &circuit_id,
            &vk_box,
            b"guardrail:schema:v1",
            vec![vec![[0x11; 32]], vec![[0x22; 32]]],
        )
        .expect("STARK OpenVerify proof");
        let outer: OpenVerifyEnvelope =
            norito::decode_from_bytes(&proof.bytes).expect("decode outer STARK envelope");
        let open: StarkFriOpenProofV1 =
            norito::decode_from_bytes(&outer.proof_bytes).expect("decode STARK open proof");
        proof.backend = "stark/fri".into();
        assert_guardrails_reject!(
            backend,
            &proof,
            Some(&vk_box),
            ZkVerifyGuardrails {
                stark_max_envelope_bytes: proof.bytes.len(),
                stark_max_proof_bytes: open.envelope_bytes.len(),
                ..ENABLED_GUARDRAILS
            },
        );
    }
}
#[cfg(test)]
mod native_parameter_source_tests {
    use super::*;
    #[test]
    fn production_parameter_map_matches_kaigi_circuit_constants() {
        assert_eq!(
            native_pipa_r::relation(ZK_BACKEND_NATIVE_PIPA_R, KAIGI_AUTHORIZATION_CIRCUIT_ID_V1)
                .map(native_pipa_r::NativeRelationV1::k),
            Some(KAIGI_AUTHORIZATION_CIRCUIT_K_V1)
        );
        assert_eq!(KAIGI_AUTHORIZATION_CIRCUIT_K_V1, 13);
        assert_eq!(KAIGI_USAGE_CIRCUIT_K_V1, 12);
        assert_eq!(
            native_pipa_r::relation(ZK_BACKEND_NATIVE_PIPA_R, KAIGI_USAGE_CIRCUIT_ID_V1)
                .map(native_pipa_r::NativeRelationV1::k),
            Some(KAIGI_USAGE_CIRCUIT_K_V1)
        );
        assert_eq!(
            native_pipa_r::relation(ZK_BACKEND_NATIVE_PIPA_R, "halo2/pasta/ipa/kaigi-roster-v1"),
            None
        );
    }
}
#[cfg(test)]
mod kaigi_authorization_v1_tests;
#[cfg(test)]
mod kaigi_usage_v1_tests;

#[cfg(test)]
mod preverify_tests {
    use super::*;
    use PreverifyResult::*;
    use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
    macro_rules! assert_preverify {
        (
            $proof:ident,
            $vk:ident,
            $dedup:ident,
            $vk_hash:ident,
            $result:expr
            $(, $message:expr)?
        ) => {
            assert_eq!(
                preverify_with_budget(
                    &$proof,
                    Some(&$vk),
                    &mut $dedup,
                    0,
                    Some($vk_hash),
                    Some($vk_hash),
                    true,
                ).expect("verification attempt must complete for this semantic fixture"),
                $result
                $(, $message)?
            )
        };
        (
            $proof:ident,
            $vk:ident,
            $dedup:ident,
            $budget:expr,
            $resolved:expr,
            $expected:expr,
            $active:expr,
            $result:expr
            $(, $message:expr)?
        ) => {
            assert_eq!(
                preverify_with_budget(
                    &$proof,
                    Some(&$vk),
                    &mut $dedup,
                    $budget,
                    $resolved,
                    $expected,
                    $active,
                ).expect("verification attempt must complete for this semantic fixture"),
                $result
                $(, $message)?
            )
        };
    }
    fn preverify_enveloped_proof(vk_hash: [u8; 32]) -> ProofBox {
        preverify_enveloped_proof_for_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            BackendTag::NativePipaRPasta,
            "pipa-r/pasta/confidential-transfer-v1",
            vk_hash,
        )
    }
    fn preverify_enveloped_proof_for_backend(
        backend: &str,
        envelope_backend: BackendTag,
        circuit_id: &str,
        vk_hash: [u8; 32],
    ) -> ProofBox {
        let public_inputs = if envelope_backend == BackendTag::NativePipaRPasta {
            native_pipa_r::relation(backend, circuit_id).map_or_else(
                || vec![0x55; 32],
                |kind| native_pipa_r::public_schema(kind).to_vec(),
            )
        } else {
            vec![0x55; 32]
        };
        let envelope = OpenVerifyEnvelope {
            backend: envelope_backend,
            circuit_id: circuit_id.to_owned(),
            vk_hash,
            public_inputs,
            proof_bytes: vec![0xAA, 0xBB, 0xCC],
            aux: Vec::new(),
        };
        ProofBox::new(
            backend.to_owned(),
            norito::encode_canonical(&envelope).expect("encode OpenVerifyEnvelope"),
        )
    }
    fn mutate_preverify_envelope(
        mut proof: ProofBox,
        mutate: impl FnOnce(&mut OpenVerifyEnvelope),
    ) -> ProofBox {
        let mut envelope: OpenVerifyEnvelope =
            norito::decode_canonical(&proof.bytes).expect("decode OpenVerifyEnvelope");
        mutate(&mut envelope);
        proof.bytes = norito::encode_canonical(&envelope).expect("encode OpenVerifyEnvelope");
        proof
    }
    #[test]
    fn proof_hash_length_prefixes_backend_and_payload() {
        let proof_a = ProofBox::new("ab".into(), b"cdef".to_vec());
        let proof_b = ProofBox::new("abc".into(), b"def".to_vec());
        assert_ne!(hash_proof(&proof_a), hash_proof(&proof_b));
    }
    #[test]
    fn verifying_key_hash_length_prefixes_backend_and_payload() {
        let vk_a = VerifyingKeyBox::new("ab".into(), b"cdef".to_vec());
        let vk_b = VerifyingKeyBox::new("abc".into(), b"def".to_vec());
        assert_ne!(hash_vk(&vk_a), hash_vk(&vk_b));
    }
    #[test]
    fn preverify_dedup_key_length_prefixes_backend_and_payload() {
        let mut dedup = DedupCache::new();
        let proof_a = ProofBox::new("ab".into(), b"cdef".to_vec());
        let proof_b = ProofBox::new("abc".into(), b"def".to_vec());
        let commitment = Some([0x42; 32]);
        assert!(dedup.check_and_insert_with_commitment(&proof_a, commitment));
        assert!(
            dedup.check_and_insert_with_commitment(&proof_b, commitment),
            "distinct backend/payload boundaries must not collide in preverify dedup"
        );
    }
    #[test]
    fn preverify_dedup_key_separates_absent_and_present_commitment() {
        let mut dedup = DedupCache::new();
        let proof = ProofBox::new("pipa-r/pasta".into(), b"same-proof".to_vec());
        assert!(dedup.check_and_insert_with_commitment(&proof, None));
        assert!(
            dedup.check_and_insert_with_commitment(&proof, Some([0u8; 32])),
            "missing commitment and all-zero commitment must use distinct preverify dedup keys"
        );
    }
    #[test]
    fn failed_preverify_attempts_do_not_poison_dedup_cache() {
        let vk = VerifyingKeyBox::new("pipa-r/pasta".into(), vec![5, 6, 7, 8]);
        let expected = hash_vk(&vk);
        let proof = preverify_enveloped_proof(expected);
        let mut budget_dedup = DedupCache::new();
        assert_preverify!(
            proof,
            vk,
            budget_dedup,
            1,
            Some(expected),
            Some(expected),
            true,
            PreverifyBudgetExceeded
        );
        assert_preverify!(proof, vk, budget_dedup, expected, Accepted);
        let mut resolved_commitment_dedup = DedupCache::new();
        assert_preverify!(
            proof,
            vk,
            resolved_commitment_dedup,
            0,
            None,
            Some(expected),
            true,
            Accepted
        );
        assert_preverify!(proof, vk, resolved_commitment_dedup, expected, Duplicate);
        let mut missing_expected_dedup = DedupCache::new();
        assert_preverify!(
            proof,
            vk,
            missing_expected_dedup,
            0,
            None,
            None,
            true,
            VerifyingKeyMissing
        );
        assert_preverify!(
            proof,
            vk,
            missing_expected_dedup,
            0,
            Some(expected),
            None,
            true,
            VerifyingKeyMissing
        );
        assert_preverify!(proof, vk, missing_expected_dedup, expected, Accepted);
        let mut zero_commitment_dedup = DedupCache::new();
        assert_preverify!(
            proof,
            vk,
            zero_commitment_dedup,
            0,
            Some([0u8; 32]),
            Some(expected),
            true,
            VerifyingKeyMismatch
        );
        assert_preverify!(
            proof,
            vk,
            zero_commitment_dedup,
            0,
            Some(expected),
            Some([0u8; 32]),
            true,
            VerifyingKeyMismatch
        );
        assert_preverify!(proof, vk, zero_commitment_dedup, expected, Accepted);
        let mut wrong_backend_dedup = DedupCache::new();
        let wrong_backend_vk = VerifyingKeyBox::new("stark/fri".into(), vk.bytes.clone());
        let wrong_backend_expected = hash_vk(&wrong_backend_vk);
        let wrong_backend_proof = preverify_enveloped_proof(wrong_backend_expected);
        assert_preverify!(
            wrong_backend_proof,
            wrong_backend_vk,
            wrong_backend_dedup,
            wrong_backend_expected,
            VerifyingKeyMismatch
        );
        assert_preverify!(proof, vk, wrong_backend_dedup, expected, Accepted);
        let mut mismatch_dedup = DedupCache::new();
        let mut wrong = expected;
        wrong[0] ^= 0x80;
        assert_preverify!(
            proof,
            vk,
            mismatch_dedup,
            0,
            Some(wrong),
            Some(expected),
            true,
            VerifyingKeyMismatch
        );
        assert_preverify!(proof, vk, mismatch_dedup, expected, Accepted);
        let mut wrong_vk_dedup = DedupCache::new();
        let wrong_vk = VerifyingKeyBox::new("pipa-r/pasta".into(), vec![8, 7, 6, 5]);
        assert_preverify!(
            proof,
            wrong_vk,
            wrong_vk_dedup,
            expected,
            VerifyingKeyMismatch
        );
        assert_preverify!(proof, vk, wrong_vk_dedup, expected, Accepted);
        let mut inactive_dedup = DedupCache::new();
        assert_preverify!(
            proof,
            vk,
            inactive_dedup,
            0,
            Some(expected),
            Some(expected),
            false,
            VerifyingKeyInactive
        );
        assert_preverify!(proof, vk, inactive_dedup, expected, Accepted);
    }
    #[test]
    fn preverify_rejects_noncanonical_envelope_metadata_before_dedup() {
        let vk = VerifyingKeyBox::new("pipa-r/pasta".into(), vec![0xA5, 0x5A]);
        let expected = hash_vk(&vk);
        let proof = preverify_enveloped_proof(expected);
        let envelope: OpenVerifyEnvelope =
            norito::decode_canonical(&proof.bytes).expect("decode canonical native envelope");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_layout_proof = {
            let alternate_bytes = {
                let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
                norito::to_bytes(&envelope).expect("encode alternate-layout native envelope")
            };
            assert_ne!(alternate_bytes, proof.bytes);
            norito::decode_from_bytes::<OpenVerifyEnvelope>(&alternate_bytes)
                .expect("ordinary Norito accepts the advertised layout");
            ProofBox::new(ZK_BACKEND_NATIVE_PIPA_R.to_owned(), alternate_bytes)
        };
        for (case, tampered, expected_result) in [
            (
                "raw_payload",
                ProofBox::new(ZK_BACKEND_NATIVE_PIPA_R.to_owned(), vec![1, 2, 3, 4]),
                PreverifyResult::MalformedProof,
            ),
            (
                "alternate_layout",
                alternate_layout_proof,
                PreverifyResult::MalformedProof,
            ),
            (
                "backend_tag",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.backend = BackendTag::Stark;
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "aux",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.aux = b"side-channel".to_vec();
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "empty_circuit_id",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.circuit_id.clear();
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "invalid_circuit_id",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.circuit_id = "halo2/ipa:::preverify-test".to_owned();
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "oversized_circuit_id",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.circuit_id = "a"
                        .repeat(iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_CIRCUIT_ID_BYTES + 1);
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "empty_public_inputs",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.public_inputs.clear();
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "all_zero_public_inputs",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.public_inputs = vec![0; 4];
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "wrong_nonzero_public_input_schema",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.public_inputs = b"noncanonical-but-nonzero-schema".to_vec();
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "oversized_public_inputs",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.public_inputs = vec![
                        0xA5;
                        iroha_data_model::zk::OPEN_VERIFY_DEFAULT_MAX_PUBLIC_INPUT_BYTES
                            + 1
                    ];
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "empty_proof_bytes",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.proof_bytes.clear();
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "all_zero_proof_bytes",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.proof_bytes = vec![0; 16];
                }),
                PreverifyResult::MalformedProof,
            ),
            (
                "zero_vk_hash",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.vk_hash = [0u8; 32];
                }),
                PreverifyResult::VerifyingKeyMismatch,
            ),
            (
                "wrong_vk_hash",
                mutate_preverify_envelope(proof.clone(), |envelope| {
                    envelope.vk_hash[0] ^= 0x80;
                }),
                PreverifyResult::VerifyingKeyMismatch,
            ),
        ] {
            let mut dedup = DedupCache::new();
            assert_preverify!(
                tampered,
                vk,
                dedup,
                expected,
                expected_result,
                "case {case}"
            );
            assert_preverify!(
                proof,
                vk,
                dedup,
                expected,
                Accepted,
                "case {case} should not poison dedup cache"
            );
        }
    }
    #[test]
    fn preverify_rejects_reserved_bfv_stark_open_verify_circuit_before_dedup() {
        let backend = iroha_crypto::BFV_FULL_BOOTSTRAP_PROOF_BACKEND_V1;
        let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xA5, 0x5A, 0xC3]);
        let expected = hash_vk(&vk);
        let canonical = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
            expected,
        );
        let prefixed_circuit_id = format!(
            "{}:{}",
            backend,
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1
        );
        let prefixed = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            &prefixed_circuit_id,
            expected,
        );
        let slash_circuit_id = format!(
            "{}/{}",
            backend,
            iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1
        );
        let slash = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            &slash_circuit_id,
            expected,
        );
        let accepted = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            &format!("{backend}:preverify-test"),
            expected,
        );
        for (case, proof) in [
            ("canonical BFV circuit id", canonical),
            ("backend-prefixed BFV circuit id", prefixed),
            ("slash-form BFV circuit id", slash),
        ] {
            let mut dedup = DedupCache::new();
            assert_preverify!(proof, vk, dedup, expected, MalformedProof, "case {case}");
            assert_preverify!(
                accepted,
                vk,
                dedup,
                expected,
                Accepted,
                "case {case} must not poison dedup"
            );
        }
    }
    #[test]
    fn preverify_rejects_every_generic_soracloud_fhe_relation_alias_before_dedup() {
        use iroha_data_model::soracloud::{
            SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
            SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
        };
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0x3C, 0xA5, 0x5A]);
        let expected = hash_vk(&vk);
        let accepted = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            &format!("{backend}:soracloud-near-miss"),
            expected,
        );
        for canonical in [
            SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
            SORACLOUD_FHE_PUBLIC_KEY_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_BOOTSTRAP_KEY_PROOF_CIRCUIT_ID_V1,
            SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_CIRCUIT_ID_V1,
        ] {
            for circuit_id in [
                canonical.to_owned(),
                format!("{backend}:{canonical}"),
                format!("{backend}/{canonical}"),
            ] {
                let proof = preverify_enveloped_proof_for_backend(
                    backend,
                    BackendTag::Stark,
                    &circuit_id,
                    expected,
                );
                let mut dedup = DedupCache::new();
                assert_preverify!(
                    proof,
                    vk,
                    dedup,
                    expected,
                    MalformedProof,
                    "generic Soracloud relation alias {circuit_id}"
                );
                assert_preverify!(
                    accepted,
                    vk,
                    dedup,
                    expected,
                    Accepted,
                    "rejected alias {circuit_id} must not poison dedup"
                );
            }
        }
    }
    #[test]
    fn preverify_rejects_entire_generic_zk_ace_namespace_before_dedup() {
        let backend = iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_BACKEND;
        let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0x5A, 0xC3, 0xA5]);
        let expected = hash_vk(&vk);
        let accepted = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            &format!("{backend}:generic_zk_binding_near_miss"),
            expected,
        );
        for (spelling, relation) in [
            (
                "typed v1",
                iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID,
            ),
            ("legacy v0", "zk_ace_pq_authorization_v0"),
        ] {
            for (case, circuit_id) in [
                ("bare", relation.to_owned()),
                ("backend-prefixed", format!("{backend}:{relation}")),
                ("slash-prefixed", format!("{backend}/{relation}")),
            ] {
                let proof = preverify_enveloped_proof_for_backend(
                    backend,
                    BackendTag::Stark,
                    &circuit_id,
                    expected,
                );
                let mut dedup = DedupCache::new();
                assert_preverify!(
                    proof,
                    vk,
                    dedup,
                    expected,
                    MalformedProof,
                    "{spelling} {case}"
                );
                assert_preverify!(
                    accepted,
                    vk,
                    dedup,
                    expected,
                    Accepted,
                    "{spelling} {case} must not poison dedup"
                );
            }
        }
    }
    #[test]
    fn preverify_rejects_retired_ivm_stark_relation_before_dedup() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xC3, 0xA5, 0x5A]);
        let expected = hash_vk(&vk);
        let accepted = preverify_enveloped_proof_for_backend(
            backend,
            BackendTag::Stark,
            &format!("{backend}:preverify-test"),
            expected,
        );
        for circuit_id in [
            IVM_EXECUTION_V1_CIRCUIT_ID.to_owned(),
            format!("{backend}:{IVM_EXECUTION_V1_CIRCUIT_ID}"),
            format!("{backend}/{IVM_EXECUTION_V1_CIRCUIT_ID}"),
        ] {
            let retired = preverify_enveloped_proof_for_backend(
                backend,
                BackendTag::Stark,
                &circuit_id,
                expected,
            );
            let mut dedup = DedupCache::new();
            assert_preverify!(retired, vk, dedup, expected, MalformedProof);
            assert_preverify!(accepted, vk, dedup, expected, Accepted);
        }
    }
    #[test]
    fn preverify_rejects_native_open_verify_circuit_mismatch_before_dedup() {
        for (case, backend, accepted_circuit_id, mismatched_circuit_id) in [
            (
                "concrete backend with sibling circuit",
                "pipa-r/pasta/confidential-transfer-v1",
                "pipa-r/pasta/confidential-transfer-v1",
                "pipa-r/pasta/confidential-unshield-full-v1",
            ),
            (
                "generic native backend with cross-family circuit",
                ZK_BACKEND_NATIVE_PIPA_R,
                "pipa-r/pasta/confidential-transfer-v1",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:spoof",
            ),
            (
                "generic native backend with bare trusted-setup circuit",
                ZK_BACKEND_NATIVE_PIPA_R,
                "pipa-r/pasta/confidential-transfer-v1",
                "kzg",
            ),
            (
                "generic native backend with prefixed trusted-setup circuit",
                ZK_BACKEND_NATIVE_PIPA_R,
                "pipa-r/pasta/confidential-transfer-v1",
                "halo2/ipa:kzg",
            ),
            (
                "generic native backend with prefixed STARK circuit",
                ZK_BACKEND_NATIVE_PIPA_R,
                "pipa-r/pasta/confidential-transfer-v1",
                "halo2/ipa:stark/fri",
            ),
        ] {
            let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xA5, 0x5A, 0xC3]);
            let expected = hash_vk(&vk);
            let accepted = preverify_enveloped_proof_for_backend(
                backend,
                BackendTag::NativePipaRPasta,
                accepted_circuit_id,
                expected,
            );
            let mismatched = preverify_enveloped_proof_for_backend(
                backend,
                BackendTag::NativePipaRPasta,
                mismatched_circuit_id,
                expected,
            );
            let mut dedup = DedupCache::new();
            assert_preverify!(
                mismatched,
                vk,
                dedup,
                expected,
                MalformedProof,
                "case {case}"
            );
            assert_preverify!(
                accepted,
                vk,
                dedup,
                expected,
                Accepted,
                "case {case} must not poison dedup"
            );
        }
    }
    #[test]
    fn preverify_rejects_stark_open_verify_circuit_mismatch_before_dedup() {
        let backend = ZK_BACKEND_STARK_FRI_V1;
        let accepted_circuit_id = format!("{backend}:preverify-test");
        for (case, mismatched_circuit_id) in [
            (
                "sibling STARK profile",
                "stark/fri/poseidon2-goldilocks:preverify-test",
            ),
            ("retired generic STARK prefix", "stark/fri:preverify-test"),
            ("bare generic STARK family", "stark/fri"),
            ("halo2 circuit", "halo2/ipa:preverify-test"),
            ("colon-form halo2 circuit", "halo2:preverify-test"),
            ("colon-form kzg circuit", "kzg:trusted-setup-spoof"),
            ("bare trusted-setup curve circuit", "bn254"),
            (
                "STARK-prefixed trusted-setup circuit",
                "stark/fri:universal-srs",
            ),
            (
                "profile-prefixed trusted-setup circuit",
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:structured-reference-string",
            ),
        ] {
            let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xA5, 0x5A, 0xC3]);
            let expected = hash_vk(&vk);
            let accepted = preverify_enveloped_proof_for_backend(
                backend,
                BackendTag::Stark,
                &accepted_circuit_id,
                expected,
            );
            let mismatched = preverify_enveloped_proof_for_backend(
                backend,
                BackendTag::Stark,
                mismatched_circuit_id,
                expected,
            );
            let mut dedup = DedupCache::new();
            assert_preverify!(
                mismatched,
                vk,
                dedup,
                expected,
                MalformedProof,
                "case {case}"
            );
            assert_preverify!(
                accepted,
                vk,
                dedup,
                expected,
                Accepted,
                "case {case} must not poison dedup"
            );
        }
    }
    #[test]
    fn preverify_binds_open_verify_metadata_for_all_production_labels() {
        for (backend, envelope_backend, circuit_id) in [
            (
                ZK_BACKEND_NATIVE_PIPA_R,
                BackendTag::NativePipaRPasta,
                "pipa-r/pasta/confidential-transfer-v1",
            ),
            (
                "pipa-r/pasta/confidential-transfer-v1",
                BackendTag::NativePipaRPasta,
                "pipa-r/pasta/confidential-transfer-v1",
            ),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                BackendTag::Stark,
                "stark/fri/poseidon-x7-goldilocks-6x64-v1:preverify-test",
            ),
        ] {
            let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xA5, 0x5A, 0xC3]);
            let expected = hash_vk(&vk);
            let proof = preverify_enveloped_proof_for_backend(
                backend,
                envelope_backend,
                circuit_id,
                expected,
            );
            let mut dedup = DedupCache::new();
            assert_preverify!(
                proof,
                vk,
                dedup,
                expected,
                Accepted,
                "registry backend {backend} should preverify with a matching envelope"
            );
            let mut raw_dedup = DedupCache::new();
            let raw = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            assert_preverify!(
                raw,
                vk,
                raw_dedup,
                expected,
                MalformedProof,
                "registry backend {backend} must require OpenVerifyEnvelope metadata"
            );
            let wrong_envelope_backend = match envelope_backend {
                BackendTag::NativePipaRPasta => BackendTag::Stark,
                BackendTag::Stark => BackendTag::NativePipaRPasta,
            };
            let wrong_backend_proof = mutate_preverify_envelope(proof.clone(), |envelope| {
                envelope.backend = wrong_envelope_backend;
            });
            let mut wrong_backend_dedup = DedupCache::new();
            assert_preverify!(
                wrong_backend_proof,
                vk,
                wrong_backend_dedup,
                expected,
                MalformedProof,
                "registry backend {backend} must reject mismatched envelope backend tags"
            );
            assert_preverify!(
                proof,
                vk,
                wrong_backend_dedup,
                expected,
                Accepted,
                "mismatched envelope backend for {backend} must not poison dedup"
            );
        }
    }
    #[test]
    fn preverify_rejects_trusted_setup_backends_before_dedup() {
        for backend in [
            "kzg",
            "KZG",
            " kzg ",
            "kzg/ceremony-v1",
            "KZG/ceremony-v1",
            "bn254",
            "BN254",
            "\tBN254\n",
            "bn256",
            "bls12_381",
            "halo2/bn254",
            "halo2/bn254/vote",
            "halo2/kzg",
            "halo2/ipa:kzg",
            "halo2/ipa:KZG",
            "halo2/ipa: KZG",
            "stark/fri/prod;kzg",
            "stark/fri/prod,kzg",
            "stark/fri/prod+kzg",
            "stark/fri/prod.kzg",
            "stark/fri/prod(kzg)",
            "stark/fri/prod;bn254",
            "stark/fri/prod+bn256",
            "stark/fri/prod-bls12-381",
            "halo2/ipa;groth16",
            "halo2/ipa/orchard:kzg",
            "orchard:universal-srs",
            "penumbra-masp:kzg",
            "jindo-lattice-pcs-zk:trusted-setup",
            "miden-stark:ptau",
            "sis-with-hints:groth16",
            "pq-masp-stark-fri:kzg",
            "groth16/bn254",
        ] {
            let mut dedup = DedupCache::new();
            let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend}"
            );
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend} should not poison dedup cache"
            );
        }
    }
    #[test]
    fn preverify_rejects_developer_only_backends_before_dedup() {
        for backend in [
            "debug",
            "debug-proof",
            "Debug-Proof",
            "debug/ok",
            "halo2/debug",
            "halo2/ipa:debug-proof",
            "halo2/ipa:DEBUG-Proof",
            "halo2/ipa:d-e-b-u-g-proof",
            "stark/fri/debug",
            "stark/fri/Debug",
            "stark/fri/d-e-b-u-g",
            "mock",
            "mock-proof",
            "Mock-Proof",
            "halo2/mock",
            "halo2/ipa:mock-proof",
            "halo2/ipa:Mock-Proof",
            "halo2/ipa:m-o-c-k-proof",
            "stark/fri/m-o-c-k",
            "stark/fri/dev-fixture",
            "stark/fri/d-e-v-f-i-x-t-u-r-e",
            "stark/fri/dev",
            "stark/fri/d-e-v",
            "stark/fri/test",
            "stark/fri/t-e-s-t",
            "stark/fri/placeholder",
            "halo2/ipa:dev-fixture",
            "halo2/ipa:d-e-v-f-i-x-t-u-r-e",
            "halo2/ipa:dev",
            "halo2/ipa:d-e-v",
            "halo2/ipa:dummy",
            "halo2/ipa:f-a-k-e",
            "halo2/ipa:stub",
            "halo2/ipa:s-a-m-p-l-e",
            "zk-trace/mock-proof",
        ] {
            let mut dedup = DedupCache::new();
            let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend}"
            );
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend} should not poison dedup cache"
            );
        }
    }
    #[test]
    fn preverify_rejects_production_claim_backends_before_dedup() {
        for backend in [
            "halo2/ipa:production-ready",
            "halo2/ipa:claimed-production",
            "halo2/ipa:mainnet-ready",
            "halo2/ipa:mainnet-complete",
            "stark/fri/audit-signoff",
            "stark/fri/externally-audited",
            "stark/fri/security-review-passed",
            "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
            "stark/fri/a-u-d-i-t-c-l-a-i-m",
            "halo2/ipa:release-ready",
            "halo2/ipa:release-approved",
            "halo2/ipa:certified-mainnet",
            "halo2/ipa:third-party-audited",
            "stark/fri/boi-audited",
            "stark/fri/external-security-review",
            "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        ] {
            let mut dedup = DedupCache::new();
            let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend}"
            );
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend} should not poison dedup cache"
            );
        }
    }
    #[test]
    fn preverify_rejects_unknown_and_protocol_names_before_dedup() {
        for backend in [
            "not-a-production-backend",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "halo2/ipa\0",
            "halo2\u{FF0F}ipa",
            "halo2/\u{200B}ipa",
            "h\u{0430}lo2/ipa",
            "../halo2/ipa",
            "halo2/ipa/../tiny-add",
            "halo2/ipa:ivm-replay-binding-v1 ",
            " stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1\0",
            "stark\u{FF0F}fri/sha256-goldilocks",
            "stark/fri/\u{200B}sha256-goldilocks",
            "st\u{0430}rk/fri/sha256-goldilocks",
            "../stark/fri",
            "stark/fri/../sha256-goldilocks",
            "stark/fri/random-profile",
            "stark/fri/sha512-goldilocks",
            "stark/fri/audit-proof-v1",
            "halo2-ipa-orchard",
            "halo2/ipa/orchard",
            "orchard",
            "groth16-bls12-377",
            "groth16/bls12-377",
            "penumbra-masp",
            "monero-fcmp++",
            "fcmp++",
            "fcmp-plus-plus-curve-tree",
            "lattice-pcs-sis",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
            "miden-stark",
            "stark/fri/miden",
            "aztec-plonkish-private-kernel",
            "pq-masp-stark-fri",
            "stark/fri/pq-masp-stark-fri",
            "post-quantum-masp",
        ] {
            let mut dedup = DedupCache::new();
            let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend}"
            );
            assert_eq!(
                preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                    .expect("verification attempt must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "case {backend} should not poison dedup cache"
            );
        }
    }
    #[test]
    fn unsupported_backend_preverify_attempts_do_not_poison_dedup_cache() {
        let mut dedup = DedupCache::new();
        let proof = ProofBox::new(String::new(), vec![1, 2, 3, 4]);
        assert_eq!(
            preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                .expect("verification attempt must complete for this semantic fixture"),
            PreverifyResult::UnsupportedBackend
        );
        assert_eq!(
            preverify_with_budget(&proof, None, &mut dedup, 0, None, None, true)
                .expect("verification attempt must complete for this semantic fixture"),
            PreverifyResult::UnsupportedBackend,
            "unsupported proofs should keep failing as unsupported, not become dedup duplicates"
        );
    }
}
