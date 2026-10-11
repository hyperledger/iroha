//! Identifier resolution service plumbing for app-facing endpoints.
pub(crate) mod owner_prf;
use iroha_crypto::{
    BfvIdentifierPublicParameters, BfvProgrammedPublicParameters, BfvRamProgramProfile,
    ClientRequest, Hash, HiddenRamFheProgram, KeyPair, RamLfeBackend, RamLfeError, RamLfeSecret,
    RamLfeVerificationMode, Signature, SignatureOf, decode_bfv_programmed_public_parameters,
    evaluate_commitment_with_hidden_program, identifier_hashes_from_output_hash,
    ram_lfe_output_hash,
};
use iroha_data_model::{
    account::OpaqueAccountId,
    identifier::{
        IdentifierClaimRecord, IdentifierNormalization, IdentifierPolicy,
        IdentifierResolutionReceipt, IdentifierResolutionReceiptPayload,
        PhoneRetailCanonicalityAttestationV1,
    },
    nexus::UniversalAccountId,
    prelude::*,
    ram_lfe::{
        RamLfeExecutionReceiptPayload, RamLfeOutputOpening, RamLfeProgramId, RamLfeProgramPolicy,
        RamLfeReceiptAttestation,
    },
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
    vec::Vec,
};
use thiserror::Error;
struct ProgramRuntime {
    secret: RamLfeSecret,
    _hidden_program: HiddenRamFheProgram,
    signer: KeyPair,
    receipt_ttl_ms: Option<u64>,
}
impl fmt::Debug for ProgramRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProgramRuntime")
            .field("secret", &self.secret)
            .field("hidden_program", &"[REDACTED hidden RAM-FHE program]")
            .field("signer", &"[REDACTED RAM-LFE signer]")
            .field("receipt_ttl_ms", &self.receipt_ttl_ms)
            .finish()
    }
}
/// In-process RAM-LFE runtime used by Torii app endpoints.
#[derive(Default)]
pub struct IdentifierResolutionService {
    program_runtimes: RwLock<BTreeMap<RamLfeProgramId, Arc<ProgramRuntime>>>,
}
impl fmt::Debug for IdentifierResolutionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let program_count = self
            .program_runtimes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        formatter
            .debug_struct("IdentifierResolutionService")
            .field("program_count", &program_count)
            .finish()
    }
}
/// Draft returned by RAM-LFE execution before route-specific projection.
#[derive(Debug, Clone)]
pub struct RamLfeExecutionDraft {
    pub output: Vec<u8>,
    pub opaque_hash: Hash,
    pub receipt_hash: Hash,
    pub executed_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub backend: RamLfeBackend,
    pub output_hash: Hash,
    pub input_ciphertext_hash: Hash,
    pub output_ciphertext_hash: Hash,
    pub associated_data_hash: Hash,
    pub program_digest: Hash,
    pub parameter_digest: Hash,
    pub evaluation_key_digest: Hash,
    pub verification_mode: RamLfeVerificationMode,
}
/// Draft returned by hidden-function evaluation before ledger binding lookup.
#[derive(Debug, Clone)]
pub struct IdentifierResolutionDraft {
    /// Network authenticated by the original owner request and native evaluation.
    pub network_id: iroha_data_model::NetworkId,
    pub opaque_id: OpaqueAccountId,
    pub receipt_hash: Hash,
    pub resolved_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub backend: RamLfeBackend,
    pub output_hash: Hash,
    pub input_ciphertext_hash: Hash,
    pub output_ciphertext_hash: Hash,
    pub program_digest: Hash,
    pub parameter_digest: Hash,
    pub evaluation_key_digest: Hash,
    pub verification_mode: RamLfeVerificationMode,
    pub opening: RamLfeOutputOpening,
    pub phone_retail_canonicality: Option<PhoneRetailCanonicalityAttestationV1>,
}
#[derive(Debug, Error)]
pub enum IdentifierResolutionError {
    #[error("RAM-LFE program {0} is not configured in the Torii runtime")]
    UnknownProgram(RamLfeProgramId),
    #[error("resolver signing key does not match the policy public key")]
    SignerMismatch,
    #[error("identifier policy does not publish BFV input-encryption parameters")]
    MissingFheParameters,
    #[error("identifier policy BFV parameters are invalid: {0}")]
    InvalidFheParameters(String),
    #[error("RAM-LFE backend {0:?} does not yet support Torii app execution receipts")]
    UnsupportedBackend(RamLfeBackend),
    #[error("RAM-LFE output opening is invalid: {0}")]
    InvalidOutputOpening(String),
    #[error("RAM-LFE evaluation failed: {0}")]
    Evaluation(#[from] RamLfeError),
    #[error("identifier policy transcript encoding failed: {0}")]
    Encoding(String),
    #[error("RAM-LFE attestation signing failed: {0}")]
    Signing(String),
    #[error("Torii cannot issue proof-mode RAM-LFE receipts without prover runtime support")]
    ProofModeUnsupported,
    #[error("phone#retail canonicality attestation is invalid: {0}")]
    InvalidPhoneCanonicality(String),
}
fn sign_attestation_payload<T: norito::codec::Encode>(
    private_key: &iroha_crypto::PrivateKey,
    payload: &T,
) -> Result<Signature, IdentifierResolutionError> {
    SignatureOf::try_new(private_key, payload)
        .map(Into::into)
        .map_err(|err| IdentifierResolutionError::Signing(err.to_string()))
}
impl IdentifierResolutionService {
    /// Create an empty resolver service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Register in-process program material for RAM-LFE execution.
    pub fn register_program_runtime(
        &self,
        program_id: RamLfeProgramId,
        secret: RamLfeSecret,
        hidden_program: HiddenRamFheProgram,
        signer: KeyPair,
        receipt_ttl_ms: Option<u64>,
    ) {
        self.program_runtimes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                program_id,
                Arc::new(ProgramRuntime {
                    secret,
                    _hidden_program: hidden_program,
                    signer,
                    receipt_ttl_ms,
                }),
            );
    }
    /// Sign a receipt binding a derived opaque identifier to the current ledger target.
    pub fn sign_receipt(
        &self,
        policy: &IdentifierPolicy,
        program_policy: &RamLfeProgramPolicy,
        draft: &IdentifierResolutionDraft,
        claim: &IdentifierClaimRecord,
    ) -> Result<IdentifierResolutionReceipt, IdentifierResolutionError> {
        self.issue_receipt(
            policy,
            program_policy,
            draft,
            claim.uaid,
            claim.account_id.clone(),
        )
    }
    /// Sign a receipt for a prospective claim before the ledger binding exists.
    pub fn issue_claim_receipt(
        &self,
        policy: &IdentifierPolicy,
        program_policy: &RamLfeProgramPolicy,
        draft: &IdentifierResolutionDraft,
        uaid: UniversalAccountId,
        account_id: AccountId,
    ) -> Result<IdentifierResolutionReceipt, IdentifierResolutionError> {
        self.issue_receipt(policy, program_policy, draft, uaid, account_id)
    }
    /// Sign a generic RAM-LFE execution receipt.
    pub fn issue_execution_receipt(
        &self,
        program_policy: &RamLfeProgramPolicy,
        draft: &RamLfeExecutionDraft,
    ) -> Result<iroha_data_model::ram_lfe::RamLfeExecutionReceipt, IdentifierResolutionError> {
        require_supported_program_policy(program_policy)?;
        draft.backend.require_production_support()?;
        let runtime = self.runtime(program_policy)?;
        if runtime.signer.public_key() != &program_policy.resolver_public_key {
            return Err(IdentifierResolutionError::SignerMismatch);
        }
        if draft.verification_mode != RamLfeVerificationMode::Signed {
            return Err(IdentifierResolutionError::ProofModeUnsupported);
        }
        let payload = RamLfeExecutionReceiptPayload {
            program_id: program_policy.program_id.clone(),
            program_digest: draft.program_digest,
            backend: draft.backend,
            verification_mode: draft.verification_mode,
            input_ciphertext_hash: draft.input_ciphertext_hash,
            output_ciphertext_hash: draft.output_ciphertext_hash,
            parameter_digest: draft.parameter_digest,
            evaluation_key_digest: draft.evaluation_key_digest,
            output_hash: draft.output_hash,
            associated_data_hash: draft.associated_data_hash,
            executed_at_ms: draft.executed_at_ms,
            expires_at_ms: draft.expires_at_ms,
        };
        let signature = sign_attestation_payload(runtime.signer.private_key(), &payload)?;
        Ok(iroha_data_model::ram_lfe::RamLfeExecutionReceipt {
            payload,
            attestation: RamLfeReceiptAttestation::Signed(signature),
        })
    }
    fn issue_receipt(
        &self,
        policy: &IdentifierPolicy,
        program_policy: &RamLfeProgramPolicy,
        draft: &IdentifierResolutionDraft,
        uaid: UniversalAccountId,
        account_id: AccountId,
    ) -> Result<IdentifierResolutionReceipt, IdentifierResolutionError> {
        require_supported_program_policy(program_policy)?;
        draft.backend.require_production_support()?;
        if policy.id.is_phone_retail() {
            let statement = &draft
                .phone_retail_canonicality
                .as_ref()
                .ok_or_else(|| {
                    IdentifierResolutionError::InvalidPhoneCanonicality(
                        "attestation is required for phone#retail".to_owned(),
                    )
                })?
                .payload;
            if statement.uaid != uaid || statement.account_id != account_id {
                return Err(IdentifierResolutionError::InvalidPhoneCanonicality(
                    "attestation beneficiary differs from resolved account".to_owned(),
                ));
            }
        } else if draft.phone_retail_canonicality.is_some() {
            return Err(IdentifierResolutionError::InvalidPhoneCanonicality(
                "phone attestation is only valid for phone#retail".to_owned(),
            ));
        }
        let runtime = self.runtime(program_policy)?;
        if runtime.signer.public_key() != &program_policy.resolver_public_key {
            return Err(IdentifierResolutionError::SignerMismatch);
        }
        if draft.verification_mode != RamLfeVerificationMode::Signed {
            return Err(IdentifierResolutionError::ProofModeUnsupported);
        }
        let execution = RamLfeExecutionReceiptPayload {
            program_id: program_policy.program_id.clone(),
            program_digest: draft.program_digest,
            backend: draft.backend,
            verification_mode: draft.verification_mode,
            input_ciphertext_hash: draft.input_ciphertext_hash,
            output_ciphertext_hash: draft.output_ciphertext_hash,
            parameter_digest: draft.parameter_digest,
            evaluation_key_digest: draft.evaluation_key_digest,
            output_hash: draft.output_hash,
            associated_data_hash: Hash::new(program_id_bytes(&program_policy.program_id)),
            executed_at_ms: draft.resolved_at_ms,
            expires_at_ms: draft.expires_at_ms,
        };
        let payload = IdentifierResolutionReceiptPayload {
            network_id: draft.network_id,
            policy_id: policy.id.clone(),
            execution,
            opening: draft.opening.clone(),
            opaque_id: draft.opaque_id,
            receipt_hash: draft.receipt_hash,
            uaid,
            account_id,
        };
        let signature = sign_attestation_payload(runtime.signer.private_key(), &payload)?;
        Ok(IdentifierResolutionReceipt {
            payload,
            attestation: RamLfeReceiptAttestation::Signed(signature),
            phone_retail_canonicality: draft.phone_retail_canonicality.clone(),
        })
    }
    fn runtime(
        &self,
        program_policy: &RamLfeProgramPolicy,
    ) -> Result<Arc<ProgramRuntime>, IdentifierResolutionError> {
        self.program_runtimes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&program_policy.program_id)
            .cloned()
            .ok_or_else(|| {
                IdentifierResolutionError::UnknownProgram(program_policy.program_id.clone())
            })
    }
}
/// Reject unsupported backends before decoding requests, looking up private material, or signing.
pub(crate) fn require_supported_program_policy(
    program_policy: &RamLfeProgramPolicy,
) -> Result<(), IdentifierResolutionError> {
    program_policy.backend.require_production_support()?;
    program_policy
        .commitment
        .backend
        .require_production_support()?;
    Ok(())
}
fn validate_output_opening(
    opening: &RamLfeOutputOpening,
    execution: &RamLfeExecutionDraft,
    program_policy: &RamLfeProgramPolicy,
) -> Result<(), IdentifierResolutionError> {
    let payload = &opening.payload;
    if payload.program_id != program_policy.program_id {
        return Err(IdentifierResolutionError::InvalidOutputOpening(format!(
            "opening program {} does not match policy {}",
            payload.program_id, program_policy.program_id
        )));
    }
    if payload.input_ciphertext_hash != execution.input_ciphertext_hash {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "input ciphertext hash mismatch".to_owned(),
        ));
    }
    if payload.output_ciphertext_hash != execution.output_ciphertext_hash {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "output ciphertext hash mismatch".to_owned(),
        ));
    }
    if payload.parameter_digest != execution.parameter_digest {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "parameter digest mismatch".to_owned(),
        ));
    }
    if payload.evaluation_key_digest != execution.evaluation_key_digest {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "evaluation-key digest mismatch".to_owned(),
        ));
    }
    if payload.opened_output_hash == Hash::prehashed([0; Hash::LENGTH]) {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "opened output hash must not be zero".to_owned(),
        ));
    }
    let now = crate::utils::unix_now_ms();
    if payload.opened_at_ms > now {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "opening timestamp is in the future".to_owned(),
        ));
    }
    if payload
        .expires_at_ms
        .is_some_and(|expires_at_ms| expires_at_ms <= payload.opened_at_ms || expires_at_ms <= now)
    {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "opening is expired or has an invalid expiry".to_owned(),
        ));
    }
    opening
        .verify_signature(&program_policy.output_opening_public_key)
        .map_err(|err| IdentifierResolutionError::InvalidOutputOpening(err.to_string()))
}
pub(crate) fn decode_bfv_public_parameters(
    program_policy: &RamLfeProgramPolicy,
) -> Result<BfvIdentifierPublicParameters, IdentifierResolutionError> {
    if program_policy.commitment.public_parameters.is_empty() {
        return Err(IdentifierResolutionError::MissingFheParameters);
    }
    match program_policy.commitment.backend {
        RamLfeBackend::BfvProgrammedV1 => Ok(decode_bfv_programmed_public_parameters(
            &program_policy.commitment.public_parameters,
        )
        .map_err(|err| IdentifierResolutionError::InvalidFheParameters(err.to_string()))?
        .encryption),
        RamLfeBackend::BfvAffineV1 => {
            let public_parameters: BfvIdentifierPublicParameters =
                norito::decode_from_bytes(&program_policy.commitment.public_parameters)
                    .map_err(|err| IdentifierResolutionError::Encoding(err.to_string()))?;
            public_parameters
                .validate()
                .map_err(|err| IdentifierResolutionError::InvalidFheParameters(err.to_string()))?;
            Ok(public_parameters)
        }
        RamLfeBackend::HkdfSha3_512PrfV1 => Err(IdentifierResolutionError::UnsupportedBackend(
            RamLfeBackend::HkdfSha3_512PrfV1,
        )),
    }
}
pub(crate) fn decode_programmed_public_parameters(
    program_policy: &RamLfeProgramPolicy,
) -> Result<Option<BfvProgrammedPublicParameters>, IdentifierResolutionError> {
    if program_policy.commitment.backend != RamLfeBackend::BfvProgrammedV1 {
        return Ok(None);
    }
    if program_policy.commitment.public_parameters.is_empty() {
        return Err(IdentifierResolutionError::MissingFheParameters);
    }
    decode_bfv_programmed_public_parameters(&program_policy.commitment.public_parameters)
        .map(Some)
        .map_err(|err| IdentifierResolutionError::InvalidFheParameters(err.to_string()))
}
pub(crate) fn decode_ram_fhe_profile(
    program_policy: &RamLfeProgramPolicy,
) -> Result<Option<BfvRamProgramProfile>, IdentifierResolutionError> {
    Ok(decode_programmed_public_parameters(program_policy)?.map(|value| value.ram_fhe_profile))
}
pub(crate) fn program_id_bytes(program_id: &RamLfeProgramId) -> Vec<u8> {
    let mut bytes = Vec::new();
    norito::core::write_canonical_to_writer(program_id, &mut bytes)
        .expect("RAM-LFE program id encoding must succeed");
    bytes
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{
        Algorithm, Hash, PolicyCommitment, RamLfeBackend, RamLfeVerificationMode, Signature,
        SignatureOf, default_bfv_programmed_hidden_program,
    };
    use iroha_data_model::ram_lfe::{
        RamLfeOutputOpening, RamLfeOutputOpeningPayload, RamLfeProgramId, RamLfeProgramPolicy,
        RamLfeReceiptAttestation,
    };
    use sha2::{Digest as _, Sha256};
    use std::str::FromStr;

    #[test]
    fn program_id_associated_data_is_canonical_and_fits_initializer_bound() {
        let max_name = "p".repeat(iroha_model_base::name::MAX_NAME_BYTES);
        let program_id = RamLfeProgramId::from_str(&max_name).expect("maximum program name");
        assert!(RamLfeProgramId::from_str(&(max_name + "p")).is_err());
        let expected = program_id_bytes(&program_id);
        assert!(expected.len() <= iroha_crypto::ram_lfe::RAM_LFE_PROGRAM_ASSOCIATED_DATA_MAX_BYTES);
        let decoded: RamLfeProgramId =
            norito::decode_from_bytes(&expected).expect("canonical program name frame");
        assert_eq!(decoded, program_id);
        for flags in [0, norito::core::default_encode_flags()] {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(program_id_bytes(&program_id), expected);
        }
    }
    fn checked_fixture_keypair(seed: Vec<u8>, algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(seed, algorithm).expect("test fixture key derivation should succeed")
    }
    fn checked_fixture_ed25519_keypair(seed: u8) -> KeyPair {
        checked_fixture_keypair(vec![seed; 32], Algorithm::Ed25519)
    }
    fn checked_fixture_account(seed: u8) -> AccountId {
        AccountId::new(checked_fixture_ed25519_keypair(seed).public_key().clone())
    }
    fn checked_output_opening_signature(
        signer: &KeyPair,
        payload: &RamLfeOutputOpeningPayload,
    ) -> Signature {
        SignatureOf::try_new(signer.private_key(), payload)
            .expect("test output-opening signing should succeed")
            .into()
    }
    fn sample_policy_bundle(
        policy_id: IdentifierPolicyId,
        owner: AccountId,
        signer: &KeyPair,
        secret: &[u8],
    ) -> (IdentifierPolicy, RamLfeProgramPolicy) {
        // Typed public fixture for signing/validation; this does not perform encryption.
        let backend = RamLfeBackend::HkdfSha3_512PrfV1;
        let program_id = sample_program_id(&policy_id);
        let program_policy = RamLfeProgramPolicy::new(
            program_id.clone(),
            owner.clone(),
            backend,
            RamLfeVerificationMode::Signed,
            PolicyCommitment {
                backend,
                policy_hash: Hash::new(secret),
                public_parameters: Vec::new(),
            },
            signer.public_key().clone(),
        );
        let policy = IdentifierPolicy::new(
            policy_id.clone(),
            owner,
            if policy_id.is_phone_retail() {
                IdentifierNormalization::PhoneE164
            } else {
                IdentifierNormalization::EmailAddress
            },
            program_id,
        );
        (policy, program_policy)
    }
    fn sample_program_id(policy_id: &IdentifierPolicyId) -> RamLfeProgramId {
        format!("{}_{}", policy_id.kind, policy_id.business_rule)
            .parse()
            .expect("program id")
    }
    fn execution_fixture(program_policy: &RamLfeProgramPolicy) -> RamLfeExecutionDraft {
        let output = b"typed execution output".to_vec();
        let output_hash = ram_lfe_output_hash(&output);
        RamLfeExecutionDraft {
            output,
            output_hash,
            output_ciphertext_hash: output_hash,
            opaque_hash: Hash::new(b"opaque fixture"),
            receipt_hash: Hash::new(b"receipt fixture"),
            input_ciphertext_hash: Hash::new(b"input ciphertext fixture"),
            associated_data_hash: Hash::new(program_id_bytes(&program_policy.program_id)),
            program_digest: Hash::new(b"program fixture"),
            parameter_digest: Hash::new(b"parameter fixture"),
            evaluation_key_digest: Hash::new(b"evaluation-key fixture"),
            backend: program_policy.backend,
            verification_mode: RamLfeVerificationMode::Signed,
            executed_at_ms: crate::utils::unix_now_ms(),
            expires_at_ms: None,
        }
    }
    fn resolution_fixture(
        program_policy: &RamLfeProgramPolicy,
        signer: &KeyPair,
    ) -> IdentifierResolutionDraft {
        let execution = execution_fixture(program_policy);
        let opening = opening_for_execution(program_policy, signer, &execution);
        let (opaque_id, receipt_hash) = identifier_hashes_from_output_hash(
            &program_id_bytes(&program_policy.program_id),
            &opening.payload.opened_output_hash,
        );
        IdentifierResolutionDraft {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"identifier-component-network",
                )),
            ),
            opaque_id: OpaqueAccountId::from_hash(opaque_id),
            receipt_hash,
            resolved_at_ms: execution.executed_at_ms,
            expires_at_ms: execution.expires_at_ms,
            backend: execution.backend,
            output_hash: execution.output_hash,
            input_ciphertext_hash: execution.input_ciphertext_hash,
            output_ciphertext_hash: execution.output_ciphertext_hash,
            program_digest: execution.program_digest,
            parameter_digest: execution.parameter_digest,
            evaluation_key_digest: execution.evaluation_key_digest,
            verification_mode: execution.verification_mode,
            opening,
            phone_retail_canonicality: None,
        }
    }
    fn opening_for_execution(
        program_policy: &RamLfeProgramPolicy,
        signer: &KeyPair,
        execution: &RamLfeExecutionDraft,
    ) -> RamLfeOutputOpening {
        let payload = RamLfeOutputOpeningPayload {
            program_id: program_policy.program_id.clone(),
            input_ciphertext_hash: execution.input_ciphertext_hash,
            output_ciphertext_hash: execution.output_ciphertext_hash,
            parameter_digest: execution.parameter_digest,
            evaluation_key_digest: execution.evaluation_key_digest,
            opened_output_hash: Hash::new(b"independently authenticated plaintext fixture"),
            opened_at_ms: execution.executed_at_ms,
            expires_at_ms: execution.expires_at_ms,
        };
        RamLfeOutputOpening {
            signature: checked_output_opening_signature(signer, &payload),
            payload,
        }
    }
    fn shared_identifier_receipt_fixture() -> norito::json::Value {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/soracloud/identifier_receipt_vectors_v1.json");
        let fixture = std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixture_path.display()));
        norito::json::from_str(&fixture)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", fixture_path.display()))
    }
    fn fixture_get<'a>(value: &'a norito::json::Value, field: &str) -> &'a norito::json::Value {
        value
            .get(field)
            .unwrap_or_else(|| panic!("fixture field `{field}` is missing"))
    }
    fn fixture_object<'a>(value: &'a norito::json::Value, field: &str) -> &'a norito::json::Value {
        let item = fixture_get(value, field);
        item.as_object()
            .unwrap_or_else(|| panic!("fixture field `{field}` must be an object"));
        item
    }
    fn fixture_array<'a>(value: &'a norito::json::Value, field: &str) -> &'a [norito::json::Value] {
        fixture_get(value, field)
            .as_array()
            .unwrap_or_else(|| panic!("fixture field `{field}` must be an array"))
    }
    fn fixture_str<'a>(value: &'a norito::json::Value, field: &str) -> &'a str {
        fixture_get(value, field)
            .as_str()
            .unwrap_or_else(|| panic!("fixture field `{field}` must be a string"))
    }
    fn fixture_u64(value: &norito::json::Value, field: &str) -> u64 {
        fixture_get(value, field)
            .as_u64()
            .unwrap_or_else(|| panic!("fixture field `{field}` must be an unsigned integer"))
    }
    fn fixture_optional_u64(value: &norito::json::Value, field: &str) -> Option<u64> {
        fixture_get(value, field).as_u64()
    }
    fn receipt_from_fixture(receipt: &norito::json::Value) -> IdentifierResolutionReceipt {
        IdentifierResolutionReceipt {
            payload: payload_from_fixture(fixture_object(receipt, "payload")),
            attestation: attestation_from_fixture(fixture_object(receipt, "attestation")),
            phone_retail_canonicality: None,
        }
    }
    fn payload_from_fixture(payload: &norito::json::Value) -> IdentifierResolutionReceiptPayload {
        let opening = fixture_object(payload, "opening");
        IdentifierResolutionReceiptPayload {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(hash_hex(fixture_str(
                    payload,
                    "network_id",
                ))),
            ),
            policy_id: IdentifierPolicyId::from_str(fixture_str(payload, "policy_id"))
                .expect("valid policy id"),
            execution: RamLfeExecutionReceiptPayload {
                program_id: RamLfeProgramId::from_str(fixture_str(
                    fixture_object(payload, "execution"),
                    "program_id",
                ))
                .expect("valid program id"),
                program_digest: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "program_digest",
                )),
                backend: ram_lfe_backend(fixture_str(
                    fixture_object(payload, "execution"),
                    "backend",
                )),
                verification_mode: verification_mode(fixture_str(
                    fixture_object(payload, "execution"),
                    "verification_mode",
                )),
                input_ciphertext_hash: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "input_ciphertext_hash",
                )),
                output_ciphertext_hash: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "output_ciphertext_hash",
                )),
                parameter_digest: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "parameter_digest",
                )),
                evaluation_key_digest: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "evaluation_key_digest",
                )),
                output_hash: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "output_hash",
                )),
                associated_data_hash: hash_hex(fixture_str(
                    fixture_object(payload, "execution"),
                    "associated_data_hash",
                )),
                executed_at_ms: fixture_u64(fixture_object(payload, "execution"), "executed_at_ms"),
                expires_at_ms: fixture_optional_u64(
                    fixture_object(payload, "execution"),
                    "expires_at_ms",
                ),
            },
            opening: RamLfeOutputOpening {
                payload: opening_payload_from_fixture(fixture_object(opening, "payload")),
                signature: Signature::try_from_hex(fixture_str(opening, "signature"))
                    .expect("valid checked opening signature hex"),
            },
            opaque_id: OpaqueAccountId::from_str(fixture_str(payload, "opaque_id"))
                .expect("valid opaque id"),
            receipt_hash: hash_hex(fixture_str(payload, "receipt_hash")),
            uaid: UniversalAccountId::from_str(fixture_str(payload, "uaid")).expect("valid uaid"),
            account_id: AccountId::parse_encoded(fixture_str(payload, "account_id"))
                .expect("valid account id"),
        }
    }
    fn opening_payload_from_fixture(payload: &norito::json::Value) -> RamLfeOutputOpeningPayload {
        RamLfeOutputOpeningPayload {
            program_id: RamLfeProgramId::from_str(fixture_str(payload, "program_id"))
                .expect("valid program id"),
            input_ciphertext_hash: hash_hex(fixture_str(payload, "input_ciphertext_hash")),
            output_ciphertext_hash: hash_hex(fixture_str(payload, "output_ciphertext_hash")),
            parameter_digest: hash_hex(fixture_str(payload, "parameter_digest")),
            evaluation_key_digest: hash_hex(fixture_str(payload, "evaluation_key_digest")),
            opened_output_hash: hash_hex(fixture_str(payload, "opened_output_hash")),
            opened_at_ms: fixture_u64(payload, "opened_at_ms"),
            expires_at_ms: fixture_optional_u64(payload, "expires_at_ms"),
        }
    }
    fn attestation_from_fixture(attestation: &norito::json::Value) -> RamLfeReceiptAttestation {
        match fixture_str(attestation, "kind") {
            "signed" => RamLfeReceiptAttestation::Signed(
                Signature::try_from_hex(fixture_str(attestation, "signature"))
                    .expect("valid checked receipt signature hex"),
            ),
            other => panic!("unsupported fixture attestation kind `{other}`"),
        }
    }
    fn ram_lfe_backend(raw: &str) -> RamLfeBackend {
        match raw {
            "hkdf-sha3-512-prf-v1" => RamLfeBackend::HkdfSha3_512PrfV1,
            "bfv-affine-v1" => RamLfeBackend::BfvAffineV1,
            "bfv-programmed-v1" => RamLfeBackend::BfvProgrammedV1,
            other => panic!("unsupported RAM-LFE backend `{other}`"),
        }
    }
    fn verification_mode(raw: &str) -> RamLfeVerificationMode {
        match raw {
            "signed" => RamLfeVerificationMode::Signed,
            "proof" => RamLfeVerificationMode::Proof,
            other => panic!("unsupported verification mode `{other}`"),
        }
    }
    fn public_key_literal(raw: &str) -> PublicKey {
        let literal = raw
            .trim()
            .strip_prefix("ed25519:")
            .unwrap_or_else(|| raw.trim());
        PublicKey::from_str(literal).expect("valid public key literal")
    }
    fn hash_hex(value: &str) -> Hash {
        Hash::from_str(value).expect("valid hash")
    }
    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode_upper(Sha256::digest(bytes))
    }
    #[test]
    fn checked_fixture_ed25519_keypair_uses_fallible_seed_derivation() {
        assert_eq!(
            checked_fixture_ed25519_keypair(0x50).algorithm(),
            Algorithm::Ed25519
        );
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
        assert_eq!(
            checked_fixture_account(0x51),
            AccountId::new(checked_fixture_ed25519_keypair(0x51).public_key().clone())
        );
    }
    #[test]
    fn shared_identifier_receipt_signature_matches_fixture() {
        // This vector fixes Norito payload and signature bytes. Its synthetic program
        // and hashes do not satisfy phone#retail admission rules.
        let fixture = shared_identifier_receipt_fixture();
        assert_eq!(
            fixture_str(&fixture, "vector_set"),
            "identifier-receipt-attestation-v1"
        );
        let receipt = receipt_from_fixture(fixture_object(&fixture, "receipt"));
        let signing_seed = hex::decode(fixture_str(&fixture, "signing_seed_hex"))
            .expect("fixture signing seed must be hex");
        let signer = checked_fixture_keypair(signing_seed, Algorithm::Ed25519);
        let signature: Signature = SignatureOf::try_new(signer.private_key(), &receipt.payload)
            .expect("sign shared identifier payload")
            .into();
        let RamLfeReceiptAttestation::Signed(recorded_signature) = &receipt.attestation else {
            panic!("shared fixture receipt must be signed");
        };
        assert_eq!(recorded_signature.payload(), signature.payload());
        assert_eq!(
            fixture_str(&fixture, "canonical_payload_sha256"),
            sha256_hex(&receipt.payload.encode())
        );
        assert_eq!(
            fixture_str(
                fixture_object(fixture_object(&fixture, "receipt"), "attestation"),
                "signature"
            ),
            hex::encode_upper(signature.payload()),
        );
        let signed_attestation_vector = fixture_array(&fixture, "attestation_vectors")
            .iter()
            .find(|vector| fixture_str(vector, "name") == "signed-resolver-attestation")
            .expect("fixture signed attestation vector");
        assert_eq!(
            fixture_str(signed_attestation_vector, "expected_attestation_sha256"),
            sha256_hex(&receipt.attestation.encode()),
        );
        receipt
            .verify(signer.public_key())
            .expect("shared fixture signature must verify");
        let wrong_key = public_key_literal(fixture_str(
            fixture_array(&fixture, "negative_cases")
                .iter()
                .find(|case| fixture_str(case, "name") == "wrong-resolver-key")
                .expect("fixture wrong-resolver-key case"),
            "value",
        ));
        assert!(receipt.verify(&wrong_key).is_err());
    }
    #[test]
    fn runtime_lookup_shares_allocation_and_debug_redacts_runtime_material() {
        let service = IdentifierResolutionService::new();
        let owner = checked_fixture_account(0x41);
        let signer = checked_fixture_ed25519_keypair(0x42);
        let policy_id: IdentifierPolicyId = "phone#retail".parse().expect("policy id");
        let secret = RamLfeSecret::try_from(b"hidden-phone-policy".to_vec())
            .expect("valid RAM-LFE test secret");
        let (_, program_policy) = sample_policy_bundle(policy_id, owner, &signer, secret.as_ref());
        service.register_program_runtime(
            program_policy.program_id.clone(),
            secret,
            default_bfv_programmed_hidden_program(),
            signer,
            Some(30_000),
        );
        let first = service
            .runtime(&program_policy)
            .expect("registered runtime");
        let second = service
            .runtime(&program_policy)
            .expect("registered runtime");
        assert!(Arc::ptr_eq(&first, &second));
        let runtime_debug = format!("{first:?}");
        assert!(runtime_debug.contains("REDACTED RAM-LFE secret"));
        assert!(!runtime_debug.contains("hidden-phone-policy"));
        let service_debug = format!("{service:?}");
        assert!(service_debug.contains("program_count: 1"));
        assert!(!service_debug.contains("hidden-phone-policy"));
    }
    #[test]
    fn receipt_signing_preserves_independently_authenticated_opening() {
        let service = IdentifierResolutionService::new();
        let owner = checked_fixture_account(0x51);
        let signer = checked_fixture_ed25519_keypair(0x52);
        let (policy, program_policy) = sample_policy_bundle(
            "email#retail".parse().expect("policy"),
            owner.clone(),
            &signer,
            b"fixture secret",
        );
        service.register_program_runtime(
            program_policy.program_id.clone(),
            RamLfeSecret::try_from(b"fixture secret".to_vec()).expect("secret"),
            default_bfv_programmed_hidden_program(),
            signer.clone(),
            None,
        );
        let execution = execution_fixture(&program_policy);
        let draft = resolution_fixture(&program_policy, &signer);
        assert_ne!(
            draft.opening.payload.opened_output_hash,
            draft.output_ciphertext_hash
        );
        validate_output_opening(&draft.opening, &execution, &program_policy)
            .expect("authenticated opening");
        let execution_receipt = service
            .issue_execution_receipt(&program_policy, &execution)
            .expect("sign execution");
        execution_receipt
            .verify_signature(signer.public_key())
            .expect("execution signature");
        let claim = IdentifierClaimRecord {
            policy_id: policy.id.clone(),
            opaque_id: draft.opaque_id,
            receipt_hash: draft.receipt_hash,
            phone_retail_nullifier: None,
            uaid: UniversalAccountId::from_hash(Hash::new(b"uaid")),
            account_id: owner.clone(),
            verified_at_ms: draft.resolved_at_ms,
            expires_at_ms: None,
        };
        let receipt = service
            .sign_receipt(&policy, &program_policy, &draft, &claim)
            .expect("sign receipt");
        receipt
            .verify(signer.public_key())
            .expect("identifier signature");
        assert_eq!(receipt.payload.policy_id, policy.id);
        assert_eq!(receipt.payload.opaque_id, draft.opaque_id);
        assert_eq!(receipt.payload.receipt_hash, draft.receipt_hash);
        assert_eq!(receipt.payload.uaid, claim.uaid);
        assert_eq!(receipt.payload.account_id, owner);
        assert_eq!(receipt.payload.opening, draft.opening);
    }

    #[test]
    fn receipt_signing_rejects_wrong_signer_and_proof_mode() {
        let service = IdentifierResolutionService::new();
        let owner = checked_fixture_account(0x61);
        let signer = checked_fixture_ed25519_keypair(0x62);
        let (policy, mut program_policy) = sample_policy_bundle(
            "email#retail".parse().expect("policy"),
            owner.clone(),
            &signer,
            b"fixture secret",
        );
        let mut execution = execution_fixture(&program_policy);
        assert!(matches!(
            service.issue_execution_receipt(&program_policy, &execution),
            Err(IdentifierResolutionError::UnknownProgram(_))
        ));
        service.register_program_runtime(
            program_policy.program_id.clone(),
            RamLfeSecret::try_from(b"fixture secret".to_vec()).expect("secret"),
            default_bfv_programmed_hidden_program(),
            signer.clone(),
            None,
        );
        program_policy.resolver_public_key =
            checked_fixture_ed25519_keypair(0x63).public_key().clone();
        assert!(matches!(
            service.issue_execution_receipt(&program_policy, &execution),
            Err(IdentifierResolutionError::SignerMismatch)
        ));
        program_policy.resolver_public_key = signer.public_key().clone();
        execution.verification_mode = RamLfeVerificationMode::Proof;
        assert!(matches!(
            service.issue_execution_receipt(&program_policy, &execution),
            Err(IdentifierResolutionError::ProofModeUnsupported)
        ));
        let mut draft = resolution_fixture(&program_policy, &signer);
        draft.verification_mode = RamLfeVerificationMode::Proof;
        assert!(matches!(
            service.issue_claim_receipt(
                &policy,
                &program_policy,
                &draft,
                UniversalAccountId::from_hash(Hash::new(b"uaid")),
                owner
            ),
            Err(IdentifierResolutionError::ProofModeUnsupported)
        ));
    }

    #[test]
    fn bfv_backends_are_rejected_before_runtime_lookup_decoding_and_signing() {
        let service = IdentifierResolutionService::new();
        let owner = checked_fixture_account(0x71);
        let signer = checked_fixture_ed25519_keypair(0x72);
        let (policy, supported_policy) = sample_policy_bundle(
            "email#retail".parse().expect("policy"),
            owner.clone(),
            &signer,
            b"fixture secret",
        );
        for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
            for position in 0..2 {
                let mut program_policy = supported_policy.clone();
                if position == 0 {
                    program_policy.backend = backend;
                } else {
                    program_policy.commitment.backend = backend;
                }
                let execution = execution_fixture(&program_policy);
                let draft = resolution_fixture(&program_policy, &signer);
                let claim = IdentifierClaimRecord {
                    policy_id: policy.id.clone(),
                    opaque_id: draft.opaque_id,
                    receipt_hash: draft.receipt_hash,
                    phone_retail_nullifier: None,
                    uaid: UniversalAccountId::from_hash(Hash::new(b"uaid")),
                    account_id: owner.clone(),
                    verified_at_ms: draft.resolved_at_ms,
                    expires_at_ms: None,
                };
                assert_insecure(service.execute_owner_prf(
                    &program_policy,
                    "alice@example.com",
                    &[1; 32],
                    &iroha_data_model::NetworkId::from_genesis_hash(
                        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"test-network")),
                    ),
                ));
                assert_insecure(service.derive_owner_prf(
                    &policy,
                    &program_policy,
                    "alice@example.com",
                    &[1; 32],
                    draft.opening.clone(),
                    None,
                    &iroha_data_model::NetworkId::from_genesis_hash(
                        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"test-network")),
                    ),
                ));
                assert_insecure(service.issue_execution_receipt(&program_policy, &execution));
                assert_insecure(service.sign_receipt(&policy, &program_policy, &draft, &claim));
                assert_insecure(service.issue_claim_receipt(
                    &policy,
                    &program_policy,
                    &draft,
                    claim.uaid,
                    owner.clone(),
                ));
            }
            let mut execution = execution_fixture(&supported_policy);
            execution.backend = backend;
            assert_insecure(service.issue_execution_receipt(&supported_policy, &execution));
            let mut draft = resolution_fixture(&supported_policy, &signer);
            draft.backend = backend;
            assert_insecure(service.issue_claim_receipt(
                &policy,
                &supported_policy,
                &draft,
                UniversalAccountId::from_hash(Hash::new(b"uaid")),
                owner.clone(),
            ));
        }
    }

    fn assert_insecure<T: std::fmt::Debug>(result: Result<T, IdentifierResolutionError>) {
        assert!(
            matches!(
                result,
                Err(IdentifierResolutionError::Evaluation(
                    RamLfeError::InsecureBfvProfile
                ))
            ),
            "expected explicit insecure-profile refusal, got {result:?}"
        );
    }

    #[test]
    fn hkdf_metadata_is_never_decoded_or_executed_as_bfv() {
        let signer = checked_fixture_ed25519_keypair(0x81);
        let (_, mut policy) = sample_policy_bundle(
            "email#retail".parse().expect("policy"),
            checked_fixture_account(0x82),
            &signer,
            b"fixture",
        );
        policy.commitment.public_parameters = vec![0xff, 0, 0x7f];
        assert!(matches!(
            decode_bfv_public_parameters(&policy),
            Err(IdentifierResolutionError::UnsupportedBackend(
                RamLfeBackend::HkdfSha3_512PrfV1
            ))
        ));
        assert!(matches!(
            IdentifierResolutionService::new().execute_owner_prf(
                &policy,
                "alice@example.com",
                &[1; 32],
                &iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"test-network"))
                )
            ),
            Err(IdentifierResolutionError::UnknownProgram(_))
        ));
    }

    #[test]
    fn authenticated_opening_rejects_every_mismatched_context() {
        let signer = checked_fixture_ed25519_keypair(0x91);
        let (_, policy) = sample_policy_bundle(
            "email#retail".parse().expect("policy"),
            checked_fixture_account(0x92),
            &signer,
            b"fixture",
        );
        let execution = execution_fixture(&policy);
        let valid = opening_for_execution(&policy, &signer, &execution);
        validate_output_opening(&valid, &execution, &policy).expect("valid independent opening");
        for field in [
            "program",
            "input",
            "output",
            "parameters",
            "evaluation key",
            "zero",
            "future",
            "expiry",
        ] {
            let mut opening = valid.clone();
            match field {
                "program" => opening.payload.program_id = "other_program".parse().expect("program"),
                "input" => opening.payload.input_ciphertext_hash = Hash::new(b"replayed input"),
                "output" => opening.payload.output_ciphertext_hash = Hash::new(b"other ciphertext"),
                "parameters" => opening.payload.parameter_digest = Hash::new(b"other parameters"),
                "evaluation key" => {
                    opening.payload.evaluation_key_digest = Hash::new(b"other evaluation key")
                }
                "zero" => opening.payload.opened_output_hash = Hash::prehashed([0; Hash::LENGTH]),
                "future" => {
                    opening.payload.opened_at_ms =
                        crate::utils::unix_now_ms().saturating_add(60_000)
                }
                "expiry" => opening.payload.expires_at_ms = Some(opening.payload.opened_at_ms),
                _ => unreachable!(),
            }
            opening.signature = checked_output_opening_signature(&signer, &opening.payload);
            assert!(
                matches!(
                    validate_output_opening(&opening, &execution, &policy),
                    Err(IdentifierResolutionError::InvalidOutputOpening(_))
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn authenticated_opening_rejects_payload_mutation_wrong_key_and_malformed_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let signer = checked_fixture_ed25519_keypair(0xa1);
        let (_, mut policy) = sample_policy_bundle(
            "email#retail".parse().expect("policy"),
            checked_fixture_account(0xa2),
            &signer,
            b"fixture",
        );
        let execution = execution_fixture(&policy);
        let valid = opening_for_execution(&policy, &signer, &execution);
        let mut tampered = valid.clone();
        tampered.payload.opened_output_hash = Hash::new(b"mutated plaintext hash");
        assert!(matches!(
            validate_output_opening(&tampered, &execution, &policy),
            Err(IdentifierResolutionError::InvalidOutputOpening(_))
        ));
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut malformed = valid.clone();
            let mut bytes = malformed.signature.payload().to_vec();
            bytes[..32].copy_from_slice(&replacement_r);
            malformed.signature = Signature::from_bytes(&bytes);
            assert!(
                matches!(
                    validate_output_opening(&malformed, &execution, &policy),
                    Err(IdentifierResolutionError::InvalidOutputOpening(_))
                ),
                "{label}"
            );
        }
        policy.output_opening_public_key =
            checked_fixture_ed25519_keypair(0xa3).public_key().clone();
        assert!(matches!(
            validate_output_opening(&valid, &execution, &policy),
            Err(IdentifierResolutionError::InvalidOutputOpening(_))
        ));
    }
}
