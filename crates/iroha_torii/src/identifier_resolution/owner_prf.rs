//! Current authenticated-owner PRF evaluation and original opening verification.
use super::*;
use iroha_data_model::{
    identifier::{
        hkdf_identifier_execution_metadata_v1, hkdf_identifier_input_commitment_v1,
        hkdf_identifier_request_payload_v1,
    },
    ram_lfe::RamLfeOutputOpeningPayload,
};
use zeroize::Zeroize;

/// Read actual positive OS time without clamping or fabricating a fresh sample.
pub(crate) fn owner_prf_now_ms() -> Result<u64, IdentifierResolutionError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| IdentifierResolutionError::InvalidOutputOpening(error.to_string()))?;
    let now = u64::try_from(now.as_millis()).map_err(|_| {
        IdentifierResolutionError::InvalidOutputOpening("clock overflow".to_owned())
    })?;
    if now == 0 {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "clock must be positive".to_owned(),
        ));
    }
    Ok(now)
}

/// Recheck the exact original bounded opening lease at synchronous delivery.
pub(crate) fn validate_owner_prf_lease(
    opened_at_ms: u64,
    expires_at_ms: Option<u64>,
) -> Result<(), IdentifierResolutionError> {
    validate_owner_prf_lease_at(opened_at_ms, expires_at_ms, owner_prf_now_ms()?)
}

/// Check the original opening against the caller's single genuine delivery-time sample.
pub(crate) fn validate_owner_prf_lease_at(
    opened_at_ms: u64,
    expires_at_ms: Option<u64>,
    now: u64,
) -> Result<(), IdentifierResolutionError> {
    let expires = expires_at_ms.ok_or_else(|| {
        IdentifierResolutionError::InvalidOutputOpening(
            "owner PRF opening requires its original bounded expiry".to_owned(),
        )
    })?;
    if now == 0
        || opened_at_ms == 0
        || opened_at_ms > now
        || expires <= now
        || expires <= opened_at_ms
        || expires - opened_at_ms > 120_000
    {
        return Err(IdentifierResolutionError::InvalidOutputOpening(
            "owner PRF original lease is invalid or expired".to_owned(),
        ));
    }
    Ok(())
}

impl IdentifierResolutionService {
    /// Evaluate the authenticated owner's exact normalized input under the native PRF.
    /// This is not encrypted-input evaluation. Only opaque PRF material is returned;
    /// a private caller nonce blinds the public input commitment without changing identity.
    pub fn execute_owner_prf(
        &self,
        program_policy: &RamLfeProgramPolicy,
        normalized_input: &str,
        input_nonce: &[u8; 32],
        network_id: &iroha_data_model::NetworkId,
    ) -> Result<RamLfeExecutionDraft, IdentifierResolutionError> {
        require_supported_program_policy(program_policy)?;
        if program_policy.backend != RamLfeBackend::HkdfSha3_512PrfV1
            || program_policy.commitment.backend != program_policy.backend
            || program_policy.verification_mode != RamLfeVerificationMode::Signed
            || normalized_input.is_empty()
            || normalized_input.len() > 512
            || input_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(IdentifierResolutionError::UnsupportedBackend(
                program_policy.backend,
            ));
        }
        let runtime = self.runtime(program_policy)?;
        if runtime.signer.public_key() != &program_policy.resolver_public_key
            || runtime.signer.public_key() != &program_policy.output_opening_public_key
        {
            return Err(IdentifierResolutionError::SignerMismatch);
        }
        let mut request = ClientRequest {
            normalized_input: hkdf_identifier_request_payload_v1(
                network_id,
                &program_policy.program_id,
                normalized_input,
            )
            .map_err(|error| IdentifierResolutionError::Encoding(error.to_string()))?,
            associated_data: program_id_bytes(&program_policy.program_id),
        };
        let evaluation = evaluate_commitment_with_hidden_program(
            runtime.secret.as_ref(),
            &program_policy.commitment,
            &request,
            None,
        );
        request.normalized_input.zeroize();
        let mut evaluated = evaluation?;
        evaluated.output.zeroize();
        // The generic HKDF evaluator echoes its input; never expose that output
        // through app receipts. Its independently derived opaque PRF digest is stable.
        let output = evaluated.opaque_id.as_ref().to_vec();
        let output_hash = ram_lfe_output_hash(&output);
        let input_ciphertext_hash = hkdf_identifier_input_commitment_v1(
            network_id,
            &program_policy.program_id,
            normalized_input,
            input_nonce,
        )
        .map_err(|error| IdentifierResolutionError::Encoding(error.to_string()))?;
        let (program_digest, parameter_digest, evaluation_key_digest) =
            hkdf_identifier_execution_metadata_v1(&program_policy.commitment)?;
        let executed_at_ms = owner_prf_now_ms()?;
        let ttl = runtime
            .receipt_ttl_ms
            .filter(|ttl| (1..=120_000).contains(ttl))
            .ok_or_else(|| {
                IdentifierResolutionError::InvalidOutputOpening(
                    "owner PRF requires an explicit positive receipt TTL of at most 120000ms"
                        .to_owned(),
                )
            })?;
        let expires_at_ms = executed_at_ms.checked_add(ttl).ok_or_else(|| {
            IdentifierResolutionError::InvalidOutputOpening("receipt expiry overflow".to_owned())
        })?;
        let (opaque_hash, receipt_hash) =
            identifier_hashes_from_output_hash(&request.associated_data, &output_hash);
        Ok(RamLfeExecutionDraft {
            output,
            opaque_hash,
            receipt_hash,
            executed_at_ms,
            expires_at_ms: Some(expires_at_ms),
            backend: evaluated.backend,
            output_hash,
            input_ciphertext_hash,
            output_ciphertext_hash: output_hash,
            associated_data_hash: Hash::new(&request.associated_data),
            program_digest,
            parameter_digest,
            evaluation_key_digest,
            verification_mode: RamLfeVerificationMode::Signed,
        })
    }

    /// Sign the current native opening only under the key independently pinned by the ledger.
    pub fn owner_prf_opening(
        &self,
        program_policy: &RamLfeProgramPolicy,
        execution: &RamLfeExecutionDraft,
    ) -> Result<RamLfeOutputOpening, IdentifierResolutionError> {
        require_supported_program_policy(program_policy)?;
        let runtime = self.runtime(program_policy)?;
        if runtime.signer.public_key() != &program_policy.output_opening_public_key
            || execution.backend != RamLfeBackend::HkdfSha3_512PrfV1
        {
            return Err(IdentifierResolutionError::SignerMismatch);
        }
        validate_owner_prf_lease(execution.executed_at_ms, execution.expires_at_ms)?;
        let payload = RamLfeOutputOpeningPayload {
            program_id: program_policy.program_id.clone(),
            input_ciphertext_hash: execution.input_ciphertext_hash,
            output_ciphertext_hash: execution.output_ciphertext_hash,
            parameter_digest: execution.parameter_digest,
            evaluation_key_digest: execution.evaluation_key_digest,
            opened_output_hash: execution.output_hash,
            opened_at_ms: execution.executed_at_ms,
            expires_at_ms: execution.expires_at_ms,
        };
        let signature = sign_attestation_payload(runtime.signer.private_key(), &payload)?;
        validate_owner_prf_lease(payload.opened_at_ms, payload.expires_at_ms)?;
        Ok(RamLfeOutputOpening { payload, signature })
    }

    /// Re-evaluate exact owner input and independently authenticate its original opening and phone proof.
    pub fn derive_owner_prf(
        &self,
        policy: &IdentifierPolicy,
        program_policy: &RamLfeProgramPolicy,
        normalized_input: &str,
        input_nonce: &[u8; 32],
        opening: RamLfeOutputOpening,
        canonicality: Option<PhoneRetailCanonicalityAttestationV1>,
        network_id: &iroha_data_model::NetworkId,
    ) -> Result<IdentifierResolutionDraft, IdentifierResolutionError> {
        let normalized = zeroize::Zeroizing::new(
            policy
                .normalization
                .normalize(normalized_input)
                .map_err(|error| IdentifierResolutionError::Encoding(error.to_string()))?,
        );
        if policy.program_id != program_policy.program_id
            || policy.owner != program_policy.owner
            || normalized.as_str() != normalized_input
        {
            return Err(IdentifierResolutionError::InvalidOutputOpening(
                "owner input is not canonically normalized for its exact policy".to_owned(),
            ));
        }
        let execution =
            self.execute_owner_prf(program_policy, normalized_input, input_nonce, network_id)?;
        validate_owner_prf_lease(opening.payload.opened_at_ms, opening.payload.expires_at_ms)?;
        validate_output_opening(&opening, &execution, program_policy)?;
        if opening.payload.opened_output_hash != execution.output_hash {
            return Err(IdentifierResolutionError::InvalidOutputOpening(
                "opening differs from native PRF output".to_owned(),
            ));
        }
        let phone_like = policy.id.kind.as_ref() == "phone"
            || policy.normalization == IdentifierNormalization::PhoneE164
            || policy.program_id.to_string() == "phone_retail";
        if phone_like {
            if !policy.id.is_phone_retail()
                || policy.normalization != IdentifierNormalization::PhoneE164
                || policy.program_id.to_string() != "phone_retail"
            {
                return Err(IdentifierResolutionError::InvalidPhoneCanonicality(
                    "exact phone#retail contract required".to_owned(),
                ));
            }
            let attestation = canonicality.as_ref().ok_or_else(|| {
                IdentifierResolutionError::InvalidPhoneCanonicality(
                    "independent phone attestation required".to_owned(),
                )
            })?;
            let pinned_key = policy
                .phone_retail_attestor_public_key
                .as_ref()
                .ok_or_else(|| {
                    IdentifierResolutionError::InvalidPhoneCanonicality(
                        "attestor key is not pinned".to_owned(),
                    )
                })?;
            if pinned_key == &program_policy.resolver_public_key
                || pinned_key == &program_policy.output_opening_public_key
            {
                return Err(IdentifierResolutionError::InvalidPhoneCanonicality(
                    "attestor must be independent of native resolver and opener".to_owned(),
                ));
            }
            let statement = &attestation.payload;
            let now = owner_prf_now_ms()?;
            if statement.network_id != *network_id
                || statement.policy_id != policy.id
                || statement.program_id != program_policy.program_id
                || statement.input_ciphertext_hash != execution.input_ciphertext_hash
                || statement.output_ciphertext_hash != execution.output_ciphertext_hash
                || statement.opened_output_hash != execution.output_hash
                || statement.canonical_phone_nullifier != execution.output_hash
                || statement.issued_at_ms > now
                || statement.expires_at_ms <= now
                || statement.expires_at_ms <= statement.issued_at_ms
                || statement.expires_at_ms - statement.issued_at_ms > 120_000
                || statement.issued_at_ms != opening.payload.opened_at_ms
                || Some(statement.expires_at_ms) != opening.payload.expires_at_ms
            {
                return Err(IdentifierResolutionError::InvalidPhoneCanonicality(
                    "phone native opening, nullifier or lease changed".to_owned(),
                ));
            }
            attestation.verify(pinned_key).map_err(|error| {
                IdentifierResolutionError::InvalidPhoneCanonicality(error.to_string())
            })?;
        } else if canonicality.is_some() {
            return Err(IdentifierResolutionError::InvalidPhoneCanonicality(
                "phone attestation is only valid for phone#retail".to_owned(),
            ));
        }
        let (opaque_id, receipt_hash) = identifier_hashes_from_output_hash(
            &program_id_bytes(&program_policy.program_id),
            &execution.output_hash,
        );
        Ok(IdentifierResolutionDraft {
            network_id: *network_id,
            opaque_id: OpaqueAccountId::from_hash(opaque_id),
            receipt_hash,
            resolved_at_ms: opening.payload.opened_at_ms,
            expires_at_ms: opening.payload.expires_at_ms,
            backend: execution.backend,
            output_hash: execution.output_hash,
            input_ciphertext_hash: execution.input_ciphertext_hash,
            output_ciphertext_hash: execution.output_ciphertext_hash,
            program_digest: execution.program_digest,
            parameter_digest: execution.parameter_digest,
            evaluation_key_digest: execution.evaluation_key_digest,
            verification_mode: execution.verification_mode,
            opening,
            phone_retail_canonicality: canonicality,
        })
    }
}

#[cfg(test)]
mod owner_prf_current_tests {
    use super::*;
    fn fixture() -> (
        IdentifierResolutionService,
        IdentifierPolicy,
        RamLfeProgramPolicy,
        iroha_data_model::NetworkId,
    ) {
        let signer =
            KeyPair::try_from_seed(vec![71; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        let owner = AccountId::new(signer.public_key().clone());
        let id = "email#retail".parse().unwrap();
        let program: RamLfeProgramId = "email_retail".parse().unwrap();
        let secret = RamLfeSecret::try_from(vec![72; 32]).unwrap();
        let commitment = iroha_crypto::policy_commitment(secret.as_ref(), Vec::new()).unwrap();
        let policy = IdentifierPolicy::new(
            id,
            owner.clone(),
            IdentifierNormalization::EmailAddress,
            program.clone(),
        );
        let native = RamLfeProgramPolicy::new(
            program.clone(),
            owner,
            RamLfeBackend::HkdfSha3_512PrfV1,
            RamLfeVerificationMode::Signed,
            commitment,
            signer.public_key().clone(),
        );
        let service = IdentifierResolutionService::new();
        service.register_program_runtime(
            program,
            secret,
            iroha_crypto::default_bfv_programmed_hidden_program(),
            signer,
            Some(30_000),
        );
        let network = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"owner-prf-test-network")),
        );
        (service, policy, native, network)
    }
    #[test]
    fn stable_native_prf_never_exposes_input_and_nonce_changes_only_private_commitment() {
        let (service, _, program, network) = fixture();
        let first = service
            .execute_owner_prf(&program, "alice@example.test", &[1; 32], &network)
            .unwrap();
        let second = service
            .execute_owner_prf(&program, "alice@example.test", &[2; 32], &network)
            .unwrap();
        assert_eq!(first.output.len(), 32);
        assert_eq!(first.output, second.output);
        assert_eq!(first.receipt_hash, second.receipt_hash);
        assert_eq!(first.opaque_hash, second.opaque_hash);
        assert_ne!(first.input_ciphertext_hash, second.input_ciphertext_hash);
        assert_ne!(first.output, b"alice@example.test");
        let changed = service
            .execute_owner_prf(&program, "bravo@example.test", &[1; 32], &network)
            .unwrap();
        assert_ne!(first.output, changed.output);
        let other = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other-network")),
        );
        assert_ne!(
            first.output,
            service
                .execute_owner_prf(&program, "alice@example.test", &[1; 32], &other)
                .unwrap()
                .output
        );
    }
    #[test]
    fn original_opening_cannot_be_reused_with_substituted_input_nonce_or_ledger_key() {
        let (service, policy, program, network) = fixture();
        let execution = service
            .execute_owner_prf(&program, "alice@example.test", &[1; 32], &network)
            .unwrap();
        let opening = service.owner_prf_opening(&program, &execution).unwrap();
        let draft = service
            .derive_owner_prf(
                &policy,
                &program,
                "alice@example.test",
                &[1; 32],
                opening.clone(),
                None,
                &network,
            )
            .unwrap();
        assert_eq!(draft.resolved_at_ms, opening.payload.opened_at_ms);
        assert_eq!(draft.receipt_hash, execution.receipt_hash);
        for (input, nonce) in [
            ("bravo@example.test", [1; 32]),
            ("alice@example.test", [2; 32]),
        ] {
            assert!(
                service
                    .derive_owner_prf(
                        &policy,
                        &program,
                        input,
                        &nonce,
                        opening.clone(),
                        None,
                        &network
                    )
                    .is_err()
            );
        }
        let mut substituted = program.clone();
        substituted.output_opening_public_key =
            KeyPair::try_from_seed(vec![73; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone();
        assert!(
            service
                .derive_owner_prf(
                    &policy,
                    &substituted,
                    "alice@example.test",
                    &[1; 32],
                    opening,
                    None,
                    &network
                )
                .is_err()
        );
    }
    #[test]
    fn owner_prf_original_opening_lease_is_never_optional_extended_or_renewed() {
        let (service, policy, program, network) = fixture();
        let signer =
            KeyPair::try_from_seed(vec![71; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        let execution = service
            .execute_owner_prf(&program, "alice@example.test", &[1; 32], &network)
            .unwrap();
        let original = service.owner_prf_opening(&program, &execution).unwrap();
        for lease in [
            None,
            Some(original.payload.opened_at_ms),
            Some(original.payload.opened_at_ms + 120_001),
        ] {
            let mut changed = original.clone();
            changed.payload.expires_at_ms = lease;
            changed.signature = SignatureOf::try_new(signer.private_key(), &changed.payload)
                .unwrap()
                .into();
            assert!(
                service
                    .derive_owner_prf(
                        &policy,
                        &program,
                        "alice@example.test",
                        &[1; 32],
                        changed,
                        None,
                        &network
                    )
                    .is_err()
            );
        }
        let draft = service
            .derive_owner_prf(
                &policy,
                &program,
                "alice@example.test",
                &[1; 32],
                original.clone(),
                None,
                &network,
            )
            .unwrap();
        assert_eq!(draft.opening, original);
        assert_eq!(draft.resolved_at_ms, original.payload.opened_at_ms);
        assert_eq!(draft.expires_at_ms, original.payload.expires_at_ms);
    }

    #[test]
    fn independent_phone_signature_covers_original_scope_nullifier_beneficiary_and_lease() {
        let (_, _, mut program, network) = fixture();
        let resolver_key =
            KeyPair::try_from_seed(vec![71; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        let attestor =
            KeyPair::try_from_seed(vec![74; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
        program.program_id = "phone_retail".parse().unwrap();
        let service = IdentifierResolutionService::new();
        service.register_program_runtime(
            program.program_id.clone(),
            RamLfeSecret::try_from(vec![72; 32]).unwrap(),
            iroha_crypto::default_bfv_programmed_hidden_program(),
            resolver_key.clone(),
            Some(30_000),
        );
        let policy = IdentifierPolicy::new(
            "phone#retail".parse().unwrap(),
            program.owner.clone(),
            IdentifierNormalization::PhoneE164,
            program.program_id.clone(),
        )
        .with_phone_retail_attestor_public_key(attestor.public_key().clone());
        let execution = service
            .execute_owner_prf(&program, "+6771234567", &[1; 32], &network)
            .unwrap();
        let opening = service.owner_prf_opening(&program, &execution).unwrap();
        let beneficiary = AccountId::new(
            KeyPair::try_from_seed(vec![75; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let uaid = UniversalAccountId::from_hash(Hash::new(b"phone beneficiary"));
        let statement = iroha_data_model::identifier::PhoneRetailCanonicalityPayloadV1 {
            network_id: network.clone(),
            policy_id: policy.id.clone(),
            program_id: program.program_id.clone(),
            input_ciphertext_hash: execution.input_ciphertext_hash,
            output_ciphertext_hash: execution.output_ciphertext_hash,
            opened_output_hash: execution.output_hash,
            canonical_phone_nullifier: execution.output_hash,
            uaid,
            account_id: beneficiary.clone(),
            issued_at_ms: opening.payload.opened_at_ms,
            expires_at_ms: opening.payload.expires_at_ms.unwrap(),
        };
        let proof = PhoneRetailCanonicalityAttestationV1 {
            signature: SignatureOf::try_new(attestor.private_key(), &statement)
                .unwrap()
                .into(),
            payload: statement.clone(),
        };
        let draft = service
            .derive_owner_prf(
                &policy,
                &program,
                "+6771234567",
                &[1; 32],
                opening.clone(),
                Some(proof.clone()),
                &network,
            )
            .unwrap();
        let receipt = service
            .issue_claim_receipt(&policy, &program, &draft, uaid, beneficiary.clone())
            .unwrap();
        receipt.verify(resolver_key.public_key()).unwrap();
        assert_eq!(receipt.phone_retail_canonicality, Some(proof.clone()));
        assert!(
            service
                .issue_claim_receipt(&policy, &program, &draft, uaid, program.owner.clone())
                .is_err()
        );
        assert!(
            service
                .derive_owner_prf(
                    &policy,
                    &program,
                    "+6771234567",
                    &[1; 32],
                    opening.clone(),
                    None,
                    &network
                )
                .is_err()
        );
        for field in [
            "network",
            "program",
            "policy",
            "input",
            "output",
            "opened",
            "nullifier",
            "issued",
            "expiry",
        ] {
            let mut altered = statement.clone();
            match field {
                "network" => {
                    altered.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other")),
                    )
                }
                "program" => altered.program_id = "other_program".parse().unwrap(),
                "policy" => altered.policy_id = "phone#other".parse().unwrap(),
                "input" => altered.input_ciphertext_hash = Hash::new(b"other"),
                "output" => altered.output_ciphertext_hash = Hash::new(b"other"),
                "opened" => altered.opened_output_hash = Hash::new(b"other"),
                "nullifier" => altered.canonical_phone_nullifier = Hash::new(b"other"),
                "issued" => altered.issued_at_ms -= 1,
                "expiry" => altered.expires_at_ms += 1,
                _ => unreachable!(),
            }
            let changed = PhoneRetailCanonicalityAttestationV1 {
                signature: SignatureOf::try_new(attestor.private_key(), &altered)
                    .unwrap()
                    .into(),
                payload: altered,
            };
            assert!(
                service
                    .derive_owner_prf(
                        &policy,
                        &program,
                        "+6771234567",
                        &[1; 32],
                        opening.clone(),
                        Some(changed),
                        &network
                    )
                    .is_err(),
                "{field}"
            );
        }
        let mut shared_key_policy = policy.clone();
        shared_key_policy.phone_retail_attestor_public_key =
            Some(resolver_key.public_key().clone());
        assert!(
            service
                .derive_owner_prf(
                    &shared_key_policy,
                    &program,
                    "+6771234567",
                    &[1; 32],
                    opening,
                    Some(proof),
                    &network
                )
                .is_err()
        );
    }

    #[test]
    fn one_delivery_sample_checks_original_opening_rollback_and_expiry() {
        assert!(validate_owner_prf_lease_at(150, Some(200), 199).is_ok());
        for now in [0, 100, 200, 250] {
            assert!(validate_owner_prf_lease_at(150, Some(200), now).is_err());
        }
        assert!(validate_owner_prf_lease_at(150, None, 199).is_err());
    }
}
