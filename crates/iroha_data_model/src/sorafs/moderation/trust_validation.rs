//! Signed moderation trust-policy and screening-result verification.

use super::*;

impl ModerationTrustPolicyV1 {
    /// Validate structure, manifest binding, signatures, external trust roots,
    /// quorum downgrade resistance, and current policy activity.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationTrustPolicyError`] when the manifest binding, policy
    /// structure, signer set, signatures, quorum, or validity window is invalid.
    pub fn validate_with_trust_anchors(
        &self,
        manifest: &ModerationReproManifestV1,
        trust_anchors: &BTreeSet<PublicKey>,
        minimum_governance_quorum: u16,
        now_unix: u64,
    ) -> Result<ModerationTrustPolicySummaryV1, ModerationTrustPolicyError> {
        manifest
            .validate()
            .map_err(|error| ModerationTrustPolicyError::InvalidManifest(error.to_string()))?;
        self.validate_structure(manifest, now_unix)?;
        if minimum_governance_quorum == 0 {
            return Err(ModerationTrustPolicyError::InvalidQuorum {
                field: "minimum_governance_quorum",
                found: 0,
            });
        }
        if self.body.governance_quorum < minimum_governance_quorum {
            return Err(ModerationTrustPolicyError::GovernanceQuorumDowngrade {
                policy: self.body.governance_quorum,
                minimum: minimum_governance_quorum,
            });
        }
        let trusted_count = self
            .signatures
            .iter()
            .filter(|signature| trust_anchors.contains(&signature.public_key))
            .count();
        let trusted_count = u16::try_from(trusted_count).map_err(|_| {
            ModerationTrustPolicyError::InvalidSignatureCount {
                found: self.signatures.len(),
                maximum: MODERATION_TRUST_MAX_SIGNATURES_V1,
            }
        })?;
        let required = self.body.governance_quorum.max(minimum_governance_quorum);
        if trusted_count < required {
            return Err(ModerationTrustPolicyError::InsufficientTrustedGovernance {
                found: trusted_count,
                required,
            });
        }
        Ok(ModerationTrustPolicySummaryV1 {
            trusted_signer_count: u16::try_from(self.body.trusted_signers.len())
                .expect("validated signer count fits u16"),
            trusted_governance_signature_count: trusted_count,
            result_quorum: self.body.result_quorum,
        })
    }
    fn validate_structure(
        &self,
        manifest: &ModerationReproManifestV1,
        now_unix: u64,
    ) -> Result<(), ModerationTrustPolicyError> {
        if self.body.schema_version != MODERATION_TRUST_POLICY_VERSION_V1 {
            return Err(ModerationTrustPolicyError::UnsupportedVersion {
                expected: MODERATION_TRUST_POLICY_VERSION_V1,
                found: self.body.schema_version,
            });
        }
        for (field, missing) in [
            ("policy_id", self.body.policy_id == [0; 16]),
            ("policy_digest", self.body.policy_digest == [0; 32]),
            ("manifest_id", self.body.manifest_id == [0; 16]),
            ("manifest_digest", self.body.manifest_digest == [0; 32]),
            ("runner_hash", self.body.runner_hash == [0; 32]),
        ] {
            if missing {
                return Err(ModerationTrustPolicyError::MissingIdentity { field });
            }
        }
        let computed = self
            .body
            .computed_policy_digest()
            .map_err(|error| ModerationTrustPolicyError::Encoding(error.to_string()))?;
        if computed != self.body.policy_digest {
            return Err(ModerationTrustPolicyError::DigestMismatch);
        }
        if self.body.manifest_id != manifest.body.manifest_id
            || self.body.manifest_digest != manifest.body.manifest_digest
            || self.body.runner_hash != manifest.body.runner_hash
        {
            return Err(ModerationTrustPolicyError::ManifestBindingMismatch);
        }
        if self.body.issued_at_unix == 0
            || self.body.valid_from_unix == 0
            || self.body.valid_until_unix <= self.body.valid_from_unix
            || self.body.issued_at_unix > self.body.valid_from_unix
        {
            return Err(ModerationTrustPolicyError::InvalidTimeWindow { field: "policy" });
        }
        let policy_skew_end = self
            .body
            .valid_until_unix
            .checked_add(self.body.max_clock_skew_secs)
            .ok_or(ModerationTrustPolicyError::InvalidTimeWindow {
                field: "policy_expiry",
            })?;
        if now_unix
            < self
                .body
                .valid_from_unix
                .saturating_sub(self.body.max_clock_skew_secs)
            || now_unix >= policy_skew_end
        {
            return Err(ModerationTrustPolicyError::InvalidTimeWindow {
                field: "policy_inactive",
            });
        }
        for (field, found, maximum) in [
            (
                "max_result_age_secs",
                self.body.max_result_age_secs,
                MODERATION_TRUST_MAX_RESULT_AGE_SECS_V1,
            ),
            (
                "max_result_ttl_secs",
                self.body.max_result_ttl_secs,
                MODERATION_TRUST_MAX_RESULT_TTL_SECS_V1,
            ),
            (
                "max_clock_skew_secs",
                self.body.max_clock_skew_secs,
                MODERATION_TRUST_MAX_CLOCK_SKEW_SECS_V1,
            ),
        ] {
            if found == 0 || found > maximum {
                return Err(ModerationTrustPolicyError::InvalidBound {
                    field,
                    found,
                    maximum,
                });
            }
        }
        if self.body.trusted_signers.is_empty()
            || self.body.trusted_signers.len() > MODERATION_TRUST_MAX_SIGNERS_V1
        {
            return Err(ModerationTrustPolicyError::InvalidSignerCount {
                found: self.body.trusted_signers.len(),
                maximum: MODERATION_TRUST_MAX_SIGNERS_V1,
            });
        }
        if self.body.result_quorum == 0
            || usize::from(self.body.result_quorum) > self.body.trusted_signers.len()
        {
            return Err(ModerationTrustPolicyError::InvalidQuorum {
                field: "result_quorum",
                found: self.body.result_quorum,
            });
        }
        if self.body.governance_quorum == 0
            || usize::from(self.body.governance_quorum) > self.signatures.len()
        {
            return Err(ModerationTrustPolicyError::InvalidQuorum {
                field: "governance_quorum",
                found: self.body.governance_quorum,
            });
        }
        if let Some(notes) = &self.body.notes {
            validate_repro_text(
                notes,
                MODERATION_REPRO_MAX_NOTES_BYTES_V1,
                "trust_policy.notes",
            )
            .map_err(|_| ModerationTrustPolicyError::InvalidText {
                field: "trust_policy.notes",
            })?;
        }
        let mut previous_runner_key: Option<&PublicKey> = None;
        for signer in &self.body.trusted_signers {
            validate_repro_text(
                &signer.role,
                MODERATION_REPRO_MAX_SIGNATURE_ROLE_BYTES_V1,
                "trust_policy.trusted_signers.role",
            )
            .map_err(|_| ModerationTrustPolicyError::InvalidText {
                field: "trust_policy.trusted_signers.role",
            })?;
            if previous_runner_key.is_some_and(|previous| previous >= &signer.public_key) {
                return Err(ModerationTrustPolicyError::NonCanonicalKeyOrder {
                    field: "trusted_signers",
                });
            }
            previous_runner_key = Some(&signer.public_key);
            if signer.valid_from_unix < self.body.valid_from_unix
                || signer.valid_until_unix > self.body.valid_until_unix
                || signer.valid_until_unix <= signer.valid_from_unix
                || signer.revoked_at_unix.is_some_and(|revoked| {
                    revoked <= signer.valid_from_unix || revoked > signer.valid_until_unix
                })
            {
                return Err(ModerationTrustPolicyError::InvalidTimeWindow {
                    field: "trusted_signer",
                });
            }
        }
        if self.signatures.is_empty() || self.signatures.len() > MODERATION_TRUST_MAX_SIGNATURES_V1
        {
            return Err(ModerationTrustPolicyError::InvalidSignatureCount {
                found: self.signatures.len(),
                maximum: MODERATION_TRUST_MAX_SIGNATURES_V1,
            });
        }
        let mut previous_governance_key: Option<&PublicKey> = None;
        for signature in &self.signatures {
            validate_repro_text(
                &signature.role,
                MODERATION_REPRO_MAX_SIGNATURE_ROLE_BYTES_V1,
                "trust_policy.signatures.role",
            )
            .map_err(|_| ModerationTrustPolicyError::InvalidText {
                field: "trust_policy.signatures.role",
            })?;
            if previous_governance_key.is_some_and(|previous| previous >= &signature.public_key) {
                return Err(ModerationTrustPolicyError::NonCanonicalKeyOrder {
                    field: "signatures",
                });
            }
            previous_governance_key = Some(&signature.public_key);
            verify_trust_policy_signature(&signature.signature, &signature.public_key, &self.body)
                .map_err(|source| ModerationTrustPolicyError::BadSignature {
                    role: signature.role.clone(),
                    source,
                })?;
        }
        Ok(())
    }
}

impl ModerationSignedScreeningResultV1 {
    /// Verify manifest/policy bindings, signer authorization and revocation,
    /// deterministic score derivation, signature validity, and freshness.
    ///
    /// # Errors
    ///
    /// Returns [`ModerationSignedResultError`] when any binding, score, signer,
    /// signature, digest, or time invariant is invalid.
    pub fn validate(
        &self,
        manifest: &ModerationReproManifestV1,
        policy: &ModerationTrustPolicyV1,
        now_unix: u64,
    ) -> Result<(), ModerationSignedResultError> {
        let body = &self.body;
        if body.schema_version != MODERATION_SIGNED_RESULT_VERSION_V1 {
            return Err(ModerationSignedResultError::UnsupportedVersion {
                expected: MODERATION_SIGNED_RESULT_VERSION_V1,
                found: body.schema_version,
            });
        }
        for (field, mismatch) in [
            ("manifest_id", body.manifest_id != manifest.body.manifest_id),
            (
                "manifest_digest",
                body.manifest_digest != manifest.body.manifest_digest,
            ),
            ("runner_hash", body.runner_hash != manifest.body.runner_hash),
            (
                "trust_policy_id",
                body.trust_policy_id != policy.body.policy_id,
            ),
            (
                "trust_policy_digest",
                body.trust_policy_digest != policy.body.policy_digest,
            ),
        ] {
            if mismatch {
                return Err(ModerationSignedResultError::BindingMismatch { field });
            }
        }
        for (field, missing) in [
            ("subject_digest", body.subject_digest == [0; 32]),
            ("policy_digest", body.policy_digest == [0; 32]),
            ("evidence_digest", body.evidence_digest == [0; 32]),
        ] {
            if missing {
                return Err(ModerationSignedResultError::MissingDigest { field });
            }
        }
        let expected_policy_digest = manifest
            .body
            .computed_screening_policy_digest()
            .map_err(|error| ModerationSignedResultError::Encoding(error.to_string()))?;
        if body.policy_digest != expected_policy_digest {
            return Err(ModerationSignedResultError::BindingMismatch {
                field: "policy_digest",
            });
        }
        validate_repro_text(
            &body.subject,
            MODERATION_SIGNED_RESULT_MAX_SUBJECT_BYTES_V1,
            "signed_result.subject",
        )
        .map_err(|_| ModerationSignedResultError::InvalidText { field: "subject" })?;
        if let Some(notes) = &body.notes {
            validate_repro_text(
                notes,
                MODERATION_REPRO_MAX_NOTES_BYTES_V1,
                "signed_result.notes",
            )
            .map_err(|_| ModerationSignedResultError::InvalidText { field: "notes" })?;
        }
        if body.screened_at_unix == 0 || body.expires_at_unix <= body.screened_at_unix {
            return Err(ModerationSignedResultError::InvalidTime {
                field: "result_lifetime",
            });
        }
        let ttl = body.expires_at_unix - body.screened_at_unix;
        if ttl > policy.body.max_result_ttl_secs {
            return Err(ModerationSignedResultError::InvalidTime {
                field: "expires_at_unix",
            });
        }
        let future_limit = now_unix
            .checked_add(policy.body.max_clock_skew_secs)
            .ok_or(ModerationSignedResultError::InvalidTime { field: "now_unix" })?;
        if body.screened_at_unix > future_limit {
            return Err(ModerationSignedResultError::Freshness {
                reason: "screened_at_unix is too far in the future",
            });
        }
        let expiry_with_skew = body
            .expires_at_unix
            .checked_add(policy.body.max_clock_skew_secs)
            .ok_or(ModerationSignedResultError::InvalidTime {
                field: "expires_at_unix",
            })?;
        if now_unix >= expiry_with_skew {
            return Err(ModerationSignedResultError::Freshness {
                reason: "result expired",
            });
        }
        let maximum_age = policy
            .body
            .max_result_age_secs
            .checked_add(policy.body.max_clock_skew_secs)
            .ok_or(ModerationSignedResultError::InvalidTime {
                field: "max_result_age_secs",
            })?;
        if now_unix.saturating_sub(body.screened_at_unix) > maximum_age {
            return Err(ModerationSignedResultError::Freshness {
                reason: "result is too old",
            });
        }
        if body.model_scores.len() != manifest.body.models.len() {
            return Err(ModerationSignedResultError::ModelScoreMismatch {
                index: body.model_scores.len(),
                field: "count",
            });
        }
        let mut weighted = 0_u64;
        let mut total_weight = 0_u64;
        for (index, (score, model)) in body
            .model_scores
            .iter()
            .zip(&manifest.body.models)
            .enumerate()
        {
            if score.model_id != model.model_id {
                return Err(ModerationSignedResultError::ModelScoreMismatch {
                    index,
                    field: "model_id",
                });
            }
            if score.artifact_digest != model.artifact_digest {
                return Err(ModerationSignedResultError::ModelScoreMismatch {
                    index,
                    field: "artifact_digest",
                });
            }
            if score.score_bps > MODERATION_REPRO_MAX_BPS {
                return Err(ModerationSignedResultError::ModelScoreMismatch {
                    index,
                    field: "score_bps",
                });
            }
            let weight = model.weight.unwrap_or(MODERATION_REPRO_MAX_BPS);
            weighted = weighted
                .checked_add(u64::from(score.score_bps) * u64::from(weight))
                .ok_or(ModerationSignedResultError::CombinedScoreMismatch)?;
            total_weight = total_weight
                .checked_add(u64::from(weight))
                .ok_or(ModerationSignedResultError::CombinedScoreMismatch)?;
        }
        if total_weight == 0 {
            return Err(ModerationSignedResultError::CombinedScoreMismatch);
        }
        let combined = weighted
            .checked_add(total_weight / 2)
            .ok_or(ModerationSignedResultError::CombinedScoreMismatch)?
            / total_weight;
        if u64::from(body.combined_score_bps) != combined {
            return Err(ModerationSignedResultError::CombinedScoreMismatch);
        }
        let expected_verdict = if body.combined_score_bps >= manifest.body.thresholds.escalate {
            "escalate"
        } else if body.combined_score_bps >= manifest.body.thresholds.quarantine {
            "quarantine"
        } else {
            "pass"
        };
        if body.verdict != expected_verdict {
            return Err(ModerationSignedResultError::VerdictMismatch {
                found: body.verdict.clone(),
                expected: expected_verdict,
            });
        }
        let signer = policy
            .body
            .trusted_signers
            .iter()
            .find(|signer| signer.public_key == self.signer_public_key)
            .ok_or(ModerationSignedResultError::UnauthorizedSigner {
                reason: "signer key is absent from policy",
            })?;
        if body.screened_at_unix < signer.valid_from_unix
            || body.screened_at_unix >= signer.valid_until_unix
        {
            return Err(ModerationSignedResultError::UnauthorizedSigner {
                reason: "result is outside signer validity window",
            });
        }
        if body.expires_at_unix > signer.valid_until_unix
            || body.expires_at_unix > policy.body.valid_until_unix
        {
            return Err(ModerationSignedResultError::UnauthorizedSigner {
                reason: "result outlives signer or policy authorization",
            });
        }
        if let Some(revoked) = signer.revoked_at_unix {
            // Signed runner timestamps are not trusted time sources. Once the
            // externally signed policy marks a key revoked, fail closed even
            // for a compromised key that backdates a newly forged result.
            if body.screened_at_unix >= revoked || now_unix >= revoked {
                return Err(ModerationSignedResultError::UnauthorizedSigner {
                    reason: "signer was revoked",
                });
            }
            if body.expires_at_unix > revoked {
                return Err(ModerationSignedResultError::UnauthorizedSigner {
                    reason: "result outlives signer revocation",
                });
            }
        }
        let computed = body
            .computed_evidence_digest()
            .map_err(|error| ModerationSignedResultError::Encoding(error.to_string()))?;
        if computed != body.evidence_digest {
            return Err(ModerationSignedResultError::EvidenceDigestMismatch);
        }
        verify_signed_result_signature(&self.signature, &self.signer_public_key, body)
            .map_err(ModerationSignedResultError::BadSignature)
    }
}

fn verify_trust_policy_signature(
    signature: &SignatureOf<ModerationTrustPolicyBodyV1>,
    public_key: &PublicKey,
    body: &ModerationTrustPolicyBodyV1,
) -> Result<(), iroha_crypto::Error> {
    validate_typed_signature_payload(signature.payload(), public_key)?;
    signature.verify(public_key, body)
}

fn verify_signed_result_signature(
    signature: &SignatureOf<ModerationSignedScreeningBodyV1>,
    public_key: &PublicKey,
    body: &ModerationSignedScreeningBodyV1,
) -> Result<(), iroha_crypto::Error> {
    validate_typed_signature_payload(signature.payload(), public_key)?;
    signature.verify(public_key, body)
}

fn validate_typed_signature_payload(
    payload: &[u8],
    public_key: &PublicKey,
) -> Result<(), iroha_crypto::Error> {
    match public_key.try_algorithm() {
        Ok(Algorithm::Ed25519) => iroha_crypto::ed25519_validate_signature_encoding(payload)
            .map_err(iroha_crypto::SignatureEncodingError::into_error),
        Ok(Algorithm::MlDsa) => iroha_crypto::mldsa65_validate_signature_encoding(payload)
            .map_err(iroha_crypto::SignatureEncodingError::into_error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod borrowed_signature_validation_tests {
    use super::*;

    #[test]
    fn trust_shape_validation_borrows_preexisting_signature_under_zero_copy_budget() {
        let pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519).unwrap();
        let signature =
            iroha_crypto::Signature::try_new(pair.private_key(), b"trust shape").unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        norito::with_decode_limits_scope(limits, || {
            validate_typed_signature_payload(signature.payload(), pair.public_key()).unwrap();
            assert_eq!(
                validate_typed_signature_payload(&[1; 63], pair.public_key()),
                Err(iroha_crypto::Error::BadSignature)
            );
        });
    }
}
