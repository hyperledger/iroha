//! Generic RAM-LFE program-policy instruction handlers.
use super::prelude::*;
use iroha_crypto::{
    BfvIdentifierPublicParameters, Hash, RamLfeBackend, RamLfeVerificationMode,
    decode_bfv_programmed_public_parameters,
};
use iroha_data_model::ram_lfe::{
    RamLfeExecutionReceipt, RamLfeExecutionReceiptPayload, RamLfeProgramPolicy,
    RamLfeReceiptAttestation,
};
use iroha_telemetry::metrics;

// TODO: replace this refusal only with a compiled RAM-LFE program-execution
// relation. A four-limb payload hash binding is not an execution proof.
const PROOF_RELATION_UNAVAILABLE: &str =
    "RAM-LFE proof mode is unavailable: no compiled program-execution proof relation";

/// Execution handlers for RAM-LFE program-policy ISIs.
pub mod isi {
    use super::*;
    use crate::state::StateTransaction;
    impl Execute for iroha_data_model::isi::ram_lfe::RegisterRamLfeProgramPolicy {
        #[metrics(+"register_ram_lfe_program_policy")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let policy = self.policy;
            if authority != &policy.owner {
                return Err(Error::InvariantViolation(
                    "Only the program owner can register a RAM-LFE program policy"
                        .to_owned()
                        .into(),
                ));
            }
            if state_transaction
                .world
                .ram_lfe_program_policies
                .get(&policy.program_id)
                .is_some()
            {
                return Err(Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} is already registered",
                        policy.program_id
                    )
                    .into(),
                ));
            }
            if policy.backend != policy.commitment.backend {
                return Err(Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} backend does not match commitment backend",
                        policy.program_id
                    )
                    .into(),
                ));
            }
            validate_program_policy(&policy)?;
            state_transaction
                .world
                .ram_lfe_program_policies
                .insert(policy.program_id.clone(), policy);
            Ok(())
        }
    }
    impl Execute for iroha_data_model::isi::ram_lfe::ActivateRamLfeProgramPolicy {
        #[metrics(+"activate_ram_lfe_program_policy")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let policy = state_transaction
                .world
                .ram_lfe_program_policies
                .get_mut(&self.program_id)
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        format!(
                            "RAM-LFE program policy {} is not registered",
                            self.program_id
                        )
                        .into(),
                    )
                })?;
            ensure_program_policy_owner(authority, policy)?;
            if policy.active {
                return Err(Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} is already active",
                        policy.program_id
                    )
                    .into(),
                ));
            }
            validate_program_policy(policy)?;
            policy.active = true;
            Ok(())
        }
    }
    impl Execute for iroha_data_model::isi::ram_lfe::DeactivateRamLfeProgramPolicy {
        #[metrics(+"deactivate_ram_lfe_program_policy")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let policy = state_transaction
                .world
                .ram_lfe_program_policies
                .get_mut(&self.program_id)
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        format!(
                            "RAM-LFE program policy {} is not registered",
                            self.program_id
                        )
                        .into(),
                    )
                })?;
            ensure_program_policy_owner(authority, policy)?;
            if !policy.active {
                return Err(Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} is already inactive",
                        policy.program_id
                    )
                    .into(),
                ));
            }
            policy.active = false;
            Ok(())
        }
    }
    fn ensure_program_policy_owner(
        authority: &AccountId,
        policy: &RamLfeProgramPolicy,
    ) -> Result<(), Error> {
        if authority == &policy.owner {
            return Ok(());
        }
        Err(Error::InvariantViolation(
            "Only the program owner can mutate this RAM-LFE program policy"
                .to_owned()
                .into(),
        ))
    }
}
/// Validate a RAM-LFE program policy before storing or restoring it.
pub(crate) fn validate_program_policy(policy: &RamLfeProgramPolicy) -> Result<(), Error> {
    if policy.backend != policy.commitment.backend {
        return Err(Error::InvariantViolation(
            format!(
                "RAM-LFE program policy {} backend does not match commitment backend",
                policy.program_id
            )
            .into(),
        ));
    }
    if policy.verification_mode == RamLfeVerificationMode::Proof {
        return Err(Error::InvariantViolation(PROOF_RELATION_UNAVAILABLE.into()));
    }
    policy
        .backend
        .require_production_support()
        .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
    match policy.backend {
        RamLfeBackend::HkdfSha3_512PrfV1 => {}
        RamLfeBackend::BfvAffineV1 => {
            if policy.commitment.public_parameters.is_empty() {
                return Err(Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} is missing BFV public parameters",
                        policy.program_id
                    )
                    .into(),
                ));
            }
            let public_parameters: BfvIdentifierPublicParameters =
                norito::decode_from_bytes(&policy.commitment.public_parameters).map_err(|err| {
                    Error::InvariantViolation(
                        format!(
                            "RAM-LFE program policy {} has invalid BFV public parameters: {err}",
                            policy.program_id
                        )
                        .into(),
                    )
                })?;
            public_parameters.validate().map_err(|err| {
                Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} has invalid BFV public parameters: {err}",
                        policy.program_id
                    )
                    .into(),
                )
            })?;
        }
        RamLfeBackend::BfvProgrammedV1 => {
            decode_bfv_programmed_public_parameters(&policy.commitment.public_parameters).map_err(
                |err| {
                    Error::InvariantViolation(
                        format!(
                            "RAM-LFE program policy {} has invalid programmed public parameters: {err}",
                            policy.program_id
                        )
                        .into(),
                    )
                },
            )?;
        }
    }
    Ok(())
}
/// Validate a stateless RAM-LFE execution receipt against the published program policy and clock.
///
/// This mirrors the attestation checks used during identifier-claim admission,
/// but without any identifier-specific ledger binding checks. Proof mode is
/// unavailable until a complete program-execution relation is implemented.
pub fn validate_execution_receipt_at(
    receipt: &RamLfeExecutionReceipt,
    program_policy: &RamLfeProgramPolicy,
    now_ms: u64,
    _guardrails: crate::zk::ZkVerifyGuardrails,
) -> Result<(), String> {
    let payload = &receipt.payload;
    if payload.program_id != program_policy.program_id {
        return Err(format!(
            "RAM-LFE receipt program {} does not match program policy {}",
            payload.program_id, program_policy.program_id
        ));
    }
    if payload.backend != program_policy.backend {
        return Err(format!(
            "RAM-LFE receipt backend {} does not match program policy {} backend {}",
            payload.backend.as_str(),
            program_policy.program_id,
            program_policy.backend.as_str()
        ));
    }
    if payload.verification_mode != program_policy.verification_mode {
        return Err(format!(
            "RAM-LFE receipt verification mode does not match program policy {}",
            program_policy.program_id
        ));
    }
    if program_policy.verification_mode == RamLfeVerificationMode::Proof {
        return Err(PROOF_RELATION_UNAVAILABLE.to_owned());
    }
    program_policy
        .backend
        .require_production_support()
        .map_err(|error| error.to_string())?;
    if program_policy.commitment.backend != program_policy.backend {
        return Err(format!(
            "RAM-LFE program policy {} backend does not match its commitment backend",
            program_policy.program_id
        ));
    }
    if let Some(expires_at_ms) = payload.expires_at_ms {
        if expires_at_ms <= payload.executed_at_ms {
            return Err(format!(
                "RAM-LFE receipt for program {} expires at or before execution time",
                program_policy.program_id
            ));
        }
        if expires_at_ms <= now_ms {
            return Err(format!(
                "RAM-LFE receipt for program {} is expired",
                program_policy.program_id
            ));
        }
    }
    if payload.executed_at_ms > now_ms {
        return Err(format!(
            "RAM-LFE receipt for program {} was executed in the future",
            program_policy.program_id
        ));
    }
    let expected = iroha_data_model::identifier::hkdf_identifier_execution_metadata_v1(
        &program_policy.commitment,
    )
    .map_err(|error| error.to_string())?;
    if (
        payload.program_digest,
        payload.parameter_digest,
        payload.evaluation_key_digest,
    ) != expected
    {
        return Err("RAM-LFE receipt metadata differs from the pinned HKDF policy".to_owned());
    }
    let expires = payload
        .expires_at_ms
        .ok_or_else(|| "RAM-LFE owner receipt requires an original bounded expiry".to_owned())?;
    if now_ms == 0 || payload.executed_at_ms == 0 || expires - payload.executed_at_ms > 120_000 {
        return Err(
            "RAM-LFE owner receipt requires a positive original lease of at most 120000ms"
                .to_owned(),
        );
    }
    if payload.output_hash != payload.output_ciphertext_hash
        || payload.output_hash == Hash::prehashed([0; Hash::LENGTH])
        || payload.input_ciphertext_hash == Hash::prehashed([0; Hash::LENGTH])
    {
        return Err(
            "RAM-LFE receipt differs from its opaque output or private input commitment".to_owned(),
        );
    }
    if payload.associated_data_hash != expected_associated_data_hash(program_policy)? {
        return Err("RAM-LFE receipt associated data differs from the current program".to_owned());
    }
    if !matches!(&receipt.attestation, RamLfeReceiptAttestation::Signed(_)) {
        return Err("RAM-LFE owner receipt requires the pinned resolver signature".to_owned());
    }
    receipt
        .verify_signature(&program_policy.resolver_public_key)
        .map_err(|error| format!("RAM-LFE receipt signature is invalid: {error}"))?;
    Ok(())
}
fn expected_associated_data_hash(program_policy: &RamLfeProgramPolicy) -> Result<Hash, String> {
    norito::encode_canonical(&program_policy.program_id)
        .map(Hash::new)
        .map_err(|err| {
            format!(
                "Failed to canonically encode RAM-LFE program id {}: {err}",
                program_policy.program_id
            )
        })
}
/// Reject proof-mode receipts until a complete RAM-LFE relation is compiled.
///
/// This boundary refuses independently of policy registration and caller preflight.
/// A valid proof for another relation, caller-supplied verifier metadata, or four
/// public payload-hash limbs cannot establish hidden program execution. Refusal
/// precedes envelope parsing, key allocation and native verification.
pub(crate) fn verify_execution_proof(
    _proof: &iroha_data_model::proof::ProofBox,
    _execution: &RamLfeExecutionReceiptPayload,
    _verifier: &iroha_crypto::RamLfeProofVerifierMetadata,
    _guardrails: crate::zk::ZkVerifyGuardrails,
) -> Result<(), String> {
    // TODO: replace with the complete policy-bound relation described in
    // specs/ram_lfe_execution_proof.md; never delegate to a generic binding verifier.
    Err(PROOF_RELATION_UNAVAILABLE.to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, PolicyCommitment, RamLfeProofVerifierMetadata};
    use iroha_data_model::{
        account::AccountId,
        proof::{ProofBox, VerifyingKeyBox},
        ram_lfe::{RamLfeProgramId, RamLfeReceiptAttestation},
        zk::{BackendTag, OpenVerifyEnvelope},
    };
    use std::str::FromStr as _;
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("RAM-LFE fixture key generation should succeed")
    }
    fn checked_account_id() -> AccountId {
        AccountId::new(checked_keypair().public_key().clone())
    }
    fn test_guardrails() -> crate::zk::ZkVerifyGuardrails {
        crate::zk::ZkVerifyGuardrails {
            pipa_r_enabled: true,
            pipa_r_max_envelope_bytes: usize::MAX,
            pipa_r_max_proof_bytes: usize::MAX,

            stark_enabled: true,
            stark_max_envelope_bytes: usize::MAX,
            stark_max_proof_bytes: usize::MAX,
        }
    }
    #[test]
    fn checked_keypair_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    #[test]
    fn unavailable_proof_policy_and_receipt_reject_before_parameter_or_proof_work() {
        for backend in [
            RamLfeBackend::HkdfSha3_512PrfV1,
            RamLfeBackend::BfvAffineV1,
            RamLfeBackend::BfvProgrammedV1,
        ] {
            let mut policy = sample_policy();
            policy.backend = backend;
            policy.commitment.backend = backend;
            policy.verification_mode = RamLfeVerificationMode::Proof;
            policy.commitment.public_parameters = vec![0xff];
            let error = validate_program_policy(&policy).expect_err("no compiled relation");
            assert!(error.to_string().contains(PROOF_RELATION_UNAVAILABLE));
            let receipt = sample_receipt(&policy, 100, None);
            assert_eq!(
                validate_execution_receipt_at(&receipt, &policy, 100, test_guardrails()),
                Err(PROOF_RELATION_UNAVAILABLE.to_owned())
            );
        }
        let mut signed = sample_policy();
        signed.backend = RamLfeBackend::HkdfSha3_512PrfV1;
        signed.commitment.backend = signed.backend;
        validate_program_policy(&signed).expect("signed policy remains supported");
    }
    #[test]
    fn signed_diagnostic_bfv_policies_and_receipts_are_unavailable() {
        for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
            let mut policy = sample_policy();
            policy.backend = backend;
            policy.commitment.backend = backend;
            policy.commitment.public_parameters = vec![0xff];
            let error = validate_program_policy(&policy).unwrap_err();
            assert!(error.to_string().contains("noiseless public-key equation"));
            let receipt = sample_receipt(&policy, 100, None);
            assert_eq!(
                validate_execution_receipt_at(&receipt, &policy, 100, test_guardrails()),
                Err(iroha_crypto::RamLfeError::InsecureBfvProfile.to_string())
            );
        }
    }
    #[test]
    fn malformed_bfv_parameters_are_rejected_without_panicking() {
        let resolver = checked_keypair();
        let mut policy = RamLfeProgramPolicy::new(
            RamLfeProgramId::from_str("malformed_bfv").expect("program id"),
            checked_account_id(),
            RamLfeBackend::BfvAffineV1,
            RamLfeVerificationMode::Signed,
            PolicyCommitment {
                backend: RamLfeBackend::BfvAffineV1,
                policy_hash: Hash::new(b"malformed-bfv-policy"),
                public_parameters: vec![0xFF, 0x00, 0x7F],
            },
            resolver.public_key().clone(),
        );
        policy.active = true;
        let error = validate_program_policy(&policy)
            .expect_err("malformed BFV parameters must fail policy admission");
        assert!(
            error.to_string().contains("noiseless public-key equation"),
            "unexpected error: {error}"
        );
    }
    fn sample_policy() -> RamLfeProgramPolicy {
        let owner = checked_account_id();
        let resolver = checked_keypair();
        RamLfeProgramPolicy::new(
            RamLfeProgramId::from_str("test_program").expect("program id"),
            owner,
            RamLfeBackend::HkdfSha3_512PrfV1,
            RamLfeVerificationMode::Signed,
            PolicyCommitment {
                backend: RamLfeBackend::HkdfSha3_512PrfV1,
                policy_hash: Hash::new(b"policy"),
                public_parameters: Vec::new(),
            },
            resolver.public_key().clone(),
        )
    }
    fn sample_receipt(
        policy: &RamLfeProgramPolicy,
        executed_at_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> RamLfeExecutionReceipt {
        RamLfeExecutionReceipt {
            payload: RamLfeExecutionReceiptPayload {
                program_id: policy.program_id.clone(),
                program_digest: Hash::new(b"program"),
                backend: policy.backend,
                verification_mode: policy.verification_mode,
                input_ciphertext_hash: Hash::new(b"input-ciphertext"),
                output_ciphertext_hash: Hash::new(b"output-ciphertext"),
                parameter_digest: Hash::new(b"parameters"),
                evaluation_key_digest: Hash::new(b"evaluation-keys"),
                output_hash: Hash::new(b"output"),
                associated_data_hash: Hash::new(b"associated-data"),
                executed_at_ms,
                expires_at_ms,
            },
            attestation: RamLfeReceiptAttestation::Proof(ProofBox::new(
                "unsupported".into(),
                vec![0xAA],
            )),
        }
    }
    #[test]
    fn validate_execution_receipt_rejects_expired_receipts() {
        let policy = sample_policy();
        let receipt = sample_receipt(&policy, 100, Some(200));
        let err = validate_execution_receipt_at(&receipt, &policy, 200, test_guardrails())
            .expect_err("expired");
        assert!(err.contains("is expired"));
    }
    #[test]
    fn validate_execution_receipt_rejects_malformed_expiry() {
        let policy = sample_policy();
        let receipt = sample_receipt(&policy, 100, Some(100));
        let err = validate_execution_receipt_at(&receipt, &policy, 150, test_guardrails())
            .expect_err("bad expiry");
        assert!(err.contains("expires at or before execution time"));
    }
    #[test]
    fn validate_execution_receipt_rejects_future_execution_time() {
        let policy = sample_policy();
        let receipt = sample_receipt(&policy, 200, None);
        let err = validate_execution_receipt_at(&receipt, &policy, 100, test_guardrails())
            .expect_err("future");
        assert!(err.contains("executed in the future"));
    }
    fn sample_proof_payload() -> RamLfeExecutionReceiptPayload {
        RamLfeExecutionReceiptPayload {
            program_id: RamLfeProgramId::from_str("proof_program").expect("program id"),
            program_digest: Hash::new(b"program"),
            backend: RamLfeBackend::BfvProgrammedV1,
            verification_mode: RamLfeVerificationMode::Proof,
            input_ciphertext_hash: Hash::new(b"input-ciphertext"),
            output_ciphertext_hash: Hash::new(b"output-ciphertext"),
            parameter_digest: Hash::new(b"parameters"),
            evaluation_key_digest: Hash::new(b"evaluation-keys"),
            output_hash: Hash::new(b"output"),
            associated_data_hash: Hash::new(b"associated-data"),
            executed_at_ms: 100,
            expires_at_ms: None,
        }
    }
    fn sample_proof_verifier() -> RamLfeProofVerifierMetadata {
        RamLfeProofVerifierMetadata {
            proof_backend: crate::zk::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
            circuit_id: crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID.to_owned(),
            public_inputs_schema_hash: Hash::new(b"ram-lfe-proof-schema"),
            verifying_key_bytes: b"ram-lfe-proof-vk".to_vec(),
        }
    }
    #[cfg(feature = "zk-stark")]
    #[test]
    fn unavailable_execution_relation_rejects_a_valid_unrelated_native_proof() {
        let fixture = crate::zk::test_utils::stark_public_binding_fixture_envelope();
        let proof = fixture.proof_box(crate::zk::ZK_BACKEND_STARK_FRI_V1);
        let key = fixture
            .vk_box(crate::zk::ZK_BACKEND_STARK_FRI_V1)
            .expect("key");
        crate::zk::verify_for_relation(
            crate::zk::ProofRelation::PublicInputBinding,
            &proof,
            &key,
            test_guardrails(),
        )
        .expect("control is a valid native public-input binding proof");
        let verifier = RamLfeProofVerifierMetadata {
            proof_backend: proof.backend.to_string(),
            circuit_id: format!("{}:public-binding-demo", crate::zk::ZK_BACKEND_STARK_FRI_V1),
            public_inputs_schema_hash: Hash::new(&fixture.public_inputs),
            verifying_key_bytes: key.bytes,
        };
        assert_eq!(
            verify_execution_proof(
                &proof,
                &sample_proof_payload(),
                &verifier,
                test_guardrails()
            ),
            Err(PROOF_RELATION_UNAVAILABLE.to_owned()),
        );
    }

    #[test]
    fn unavailable_execution_relation_rejects_before_reading_proof_or_key() {
        let proof = ProofBox::new(String::new(), vec![0xff]);
        let verifier = RamLfeProofVerifierMetadata {
            proof_backend: String::new(),
            circuit_id: String::new(),
            public_inputs_schema_hash: Hash::prehashed([0; 32]),
            verifying_key_bytes: vec![0xff],
        };
        assert_eq!(
            verify_execution_proof(
                &proof,
                &sample_proof_payload(),
                &verifier,
                test_guardrails()
            ),
            Err(PROOF_RELATION_UNAVAILABLE.to_owned()),
        );
    }
    fn sample_proof_box(
        verifier: &RamLfeProofVerifierMetadata,
        mutate: impl FnOnce(&mut OpenVerifyEnvelope),
    ) -> ProofBox {
        let vk = VerifyingKeyBox::new(
            verifier.proof_backend.clone().into(),
            verifier.verifying_key_bytes.clone(),
        );
        let mut envelope = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: verifier.circuit_id.clone(),
            vk_hash: crate::zk::hash_vk(&vk),
            public_inputs: b"ram-lfe-proof-schema".to_vec(),
            proof_bytes: vec![0xCA, 0xFE],
            aux: Vec::new(),
        };
        mutate(&mut envelope);
        ProofBox::new(
            verifier.proof_backend.clone().into(),
            norito::encode_canonical(&envelope).expect("encode canonical OpenVerifyEnvelope"),
        )
    }
    #[test]
    fn verify_execution_proof_rejects_noncanonical_envelope_metadata_before_proof_decode() {
        let verifier = sample_proof_verifier();
        let execution = sample_proof_payload();
        let bad_backend = sample_proof_box(&verifier, |envelope| {
            envelope.backend = BackendTag::Stark;
        });
        let err = verify_execution_proof(&bad_backend, &execution, &verifier, test_guardrails())
            .expect_err("wrong envelope backend tag must reject before proof parsing");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
        let aux = sample_proof_box(&verifier, |envelope| {
            envelope.aux = b"unbound-ram-lfe-proof-metadata".to_vec();
        });
        let err = verify_execution_proof(&aux, &execution, &verifier, test_guardrails())
            .expect_err("non-empty auxiliary bytes must reject before proof parsing");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
        let zero_vk_hash = sample_proof_box(&verifier, |envelope| {
            envelope.vk_hash = [0u8; Hash::LENGTH];
        });
        let err = verify_execution_proof(&zero_vk_hash, &execution, &verifier, test_guardrails())
            .expect_err("zero verifier-key hash must reject before proof parsing");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
        let schema_drift = sample_proof_box(&verifier, |envelope| {
            envelope.public_inputs.extend_from_slice(b":schema-drift");
        });
        let err = verify_execution_proof(&schema_drift, &execution, &verifier, test_guardrails())
            .expect_err("public-input schema drift must reject before proof parsing");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
        let wrong_vk_hash = sample_proof_box(&verifier, |envelope| {
            envelope.vk_hash = [0xA5; Hash::LENGTH];
        });
        let err = verify_execution_proof(&wrong_vk_hash, &execution, &verifier, test_guardrails())
            .expect_err("wrong verifier-key hash must reject before proof parsing");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_execution_proof_rejects_nonproduction_labels_before_decode() {
        let execution = sample_proof_payload();
        for backend in [
            "halo2/ipa:debug",
            "halo2/ipa:trusted-setup",
            "halo2/ipa:production-ready",
        ] {
            let mut verifier = sample_proof_verifier();
            verifier.proof_backend = backend.to_owned();
            let malformed = ProofBox::new(backend.to_owned().into(), vec![0xFF]);
            let err = verify_execution_proof(&malformed, &execution, &verifier, test_guardrails())
                .expect_err("non-production backend labels must reject before decoding");
            assert!(
                err.contains(PROOF_RELATION_UNAVAILABLE),
                "backend {backend}: unexpected error: {err}"
            );
        }
    }
    #[test]
    fn verify_execution_proof_rejects_alternate_norito_layout_before_proof_decode() {
        let verifier = sample_proof_verifier();
        let execution = sample_proof_payload();
        let canonical = sample_proof_box(&verifier, |_| {});
        let envelope = norito::decode_canonical::<OpenVerifyEnvelope>(&canonical.bytes)
            .expect("decode canonical RAM-LFE proof envelope");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_bytes = {
            let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&envelope).expect("encode alternate-layout RAM-LFE proof envelope")
        };
        assert_ne!(alternate_bytes, canonical.bytes);
        let alternate = ProofBox::new(canonical.backend, alternate_bytes);
        let err = verify_execution_proof(&alternate, &execution, &verifier, test_guardrails())
            .expect_err("alternate-layout RAM-LFE proof envelope must reject");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn associated_data_hash_is_independent_of_ambient_norito_layout() {
        let policy = sample_policy();
        let expected = expected_associated_data_hash(&policy)
            .expect("derive canonical RAM-LFE associated-data hash");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_eq!(
            expected_associated_data_hash(&policy)
                .expect("derive RAM-LFE associated-data hash under alternate ambient layout"),
            expected
        );
    }
    #[test]
    fn verify_execution_proof_refuses_regardless_of_node_guardrails() {
        let verifier = sample_proof_verifier();
        let execution = sample_proof_payload();
        let proof = sample_proof_box(&verifier, |_| {});
        let mut disabled = test_guardrails();
        disabled.pipa_r_enabled = false;
        let err = verify_execution_proof(&proof, &execution, &verifier, disabled)
            .expect_err("disabled native PIPA-R verification must reject");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
        let mut envelope_limited = test_guardrails();
        envelope_limited.pipa_r_max_envelope_bytes = proof.bytes.len().saturating_sub(1);
        let err = verify_execution_proof(&proof, &execution, &verifier, envelope_limited)
            .expect_err("oversized envelope must reject before decode");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
        let mut proof_limited = test_guardrails();
        proof_limited.pipa_r_max_proof_bytes = 1;
        let err = verify_execution_proof(&proof, &execution, &verifier, proof_limited)
            .expect_err("oversized inner proof must reject");
        assert!(
            err.contains(PROOF_RELATION_UNAVAILABLE),
            "unexpected error: {err}"
        );
    }
}

#[cfg(test)]
mod current_hkdf_execution_tests {
    use super::*;
    #[test]
    fn native_hkdf_execution_signature_metadata_and_original_lease_validate() {
        let signer =
            iroha_crypto::KeyPair::try_from_seed(vec![0x73; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap();
        let secret = iroha_crypto::RamLfeSecret::try_from(vec![0x74; 32]).unwrap();
        let commitment = iroha_crypto::policy_commitment(secret.as_ref(), Vec::new()).unwrap();
        let program: iroha_data_model::ram_lfe::RamLfeProgramId = "current_owner".parse().unwrap();
        let policy = RamLfeProgramPolicy::new(
            program.clone(),
            iroha_data_model::account::AccountId::new(signer.public_key().clone()),
            RamLfeBackend::HkdfSha3_512PrfV1,
            RamLfeVerificationMode::Signed,
            commitment,
            signer.public_key().clone(),
        );
        let request = iroha_crypto::ClientRequest {
            normalized_input: b"native-hkdf-component-input".to_vec(),
            associated_data: norito::encode_canonical(&program).unwrap(),
        };
        let evaluated = iroha_crypto::evaluate_commitment_with_hidden_program(
            secret.as_ref(),
            &policy.commitment,
            &request,
            None,
        )
        .unwrap();
        let output = iroha_crypto::ram_lfe_output_hash(evaluated.opaque_id.as_ref());
        let (program_digest, parameter_digest, evaluation_key_digest) =
            iroha_data_model::identifier::hkdf_identifier_execution_metadata_v1(&policy.commitment)
                .unwrap();
        let payload = RamLfeExecutionReceiptPayload {
            program_id: program,
            program_digest,
            backend: policy.backend,
            verification_mode: policy.verification_mode,
            input_ciphertext_hash: Hash::new(b"private-commitment"),
            output_ciphertext_hash: output,
            parameter_digest,
            evaluation_key_digest,
            output_hash: output,
            associated_data_hash: Hash::new(&request.associated_data),
            executed_at_ms: 1_000,
            expires_at_ms: Some(31_000),
        };
        let receipt = RamLfeExecutionReceipt {
            attestation: RamLfeReceiptAttestation::Signed(
                iroha_crypto::SignatureOf::try_new(signer.private_key(), &payload)
                    .unwrap()
                    .into(),
            ),
            payload,
        };
        let guardrails = crate::zk::ZkVerifyGuardrails {
            pipa_r_enabled: true,
            pipa_r_max_envelope_bytes: usize::MAX,
            pipa_r_max_proof_bytes: usize::MAX,
            stark_enabled: true,
            stark_max_envelope_bytes: usize::MAX,
            stark_max_proof_bytes: usize::MAX,
        };
        validate_execution_receipt_at(&receipt, &policy, 1_001, guardrails).unwrap();
        for expiry in [None, Some(1_000), Some(121_001)] {
            let mut changed = receipt.clone();
            changed.payload.expires_at_ms = expiry;
            changed.attestation = RamLfeReceiptAttestation::Signed(
                iroha_crypto::SignatureOf::try_new(signer.private_key(), &changed.payload)
                    .unwrap()
                    .into(),
            );
            assert!(validate_execution_receipt_at(&changed, &policy, 1_001, guardrails).is_err());
        }
        let mut changed = receipt.clone();
        changed.payload.program_digest = Hash::new(b"other-program");
        changed.attestation = RamLfeReceiptAttestation::Signed(
            iroha_crypto::SignatureOf::try_new(signer.private_key(), &changed.payload)
                .unwrap()
                .into(),
        );
        assert!(validate_execution_receipt_at(&changed, &policy, 1_001, guardrails).is_err());
    }
}
