//! Public settlement manifest, proof statement, and state delta validation.

use super::*;

impl AtomicPrivateSettlementV1 {
    /// Supported manifest version.
    pub const VERSION: u8 = ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1;

    pub(super) fn bundle_id_material(&self) -> PrivateSettlementBundleIdMaterialV1 {
        PrivateSettlementBundleIdMaterialV1 {
            network_id: self.network_id,
            authority_context_height: self.authority_context_height,
            expiry_height: self.expiry_height,
            sponsor: self.sponsor.clone(),
            fee_intent_digest: self.fee_intent_digest,
            reimbursement_terms_commitment: self.reimbursement_terms_commitment,
            reimbursement_leg_ordinal: self.reimbursement_leg_ordinal,
            legs: self
                .legs
                .iter()
                .map(|leg| PrivateSettlementBundleLegMaterialV1 {
                    ordinal: leg.ordinal,
                    route: leg.route,
                    pool_id: leg.pool_id,
                    asset_binding_commitment: leg.asset_binding_commitment,
                    audit_policy_digest: leg.audit_policy_digest,
                })
                .collect(),
        }
    }

    /// Compute the stable bundle identifier from public intent material.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if canonical material cannot be encoded.
    pub fn computed_bundle_id(&self) -> Result<Hash, norito::Error> {
        canonical_hash(BUNDLE_ID_DOMAIN_V1, &self.bundle_id_material())
    }

    /// Compute the proof transcript's canonical public-intent digest.
    ///
    /// This projection binds every settlement intent field and every ordered
    /// participant route, pool, asset binding, and audit policy. It
    /// deliberately excludes the payload, restricted-availability, and delta
    /// digests because those artifacts are produced after the proof. The final
    /// manifest, committee certificates, carrier, and receipt continue to bind
    /// those exact post-proof digests through [`Self::manifest_digest`].
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if canonical material cannot be encoded.
    pub fn proof_binding_digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(
            PROOF_BINDING_DIGEST_DOMAIN_V1,
            &PrivateSettlementProofBindingMaterialV1 {
                version: self.version,
                bundle_id: self.bundle_id,
                intent: self.bundle_id_material(),
            },
        )
    }

    /// Compute the digest of the exact public fee intent.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the fee intent cannot be encoded.
    pub fn computed_fee_intent_digest(&self) -> Result<Hash, norito::Error> {
        PrivateSettlementProofIntentV1::fee_intent_digest(&self.public_fee_intent)
    }

    /// Compute the digest of the exact manifest, including sidecar and delta commitments.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the manifest cannot be encoded.
    pub fn manifest_digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(MANIFEST_DIGEST_DOMAIN_V1, self)
    }

    /// Validate participant bounds, canonical ordering, expiry, and all commitments.
    ///
    /// # Errors
    ///
    /// Returns a typed fail-closed structural error.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        self.validate_with_availability_v1(true)
    }

    /// Validate a pre-certification manifest whose availability digests are reserved zeroes.
    ///
    /// All settlement intent, payload, and delta commitments are final at this
    /// boundary. Only the per-leg availability-certificate digests remain
    /// unset so every committee signs the same immutable sidecar material.
    ///
    /// # Errors
    ///
    /// Returns a typed fail-closed structural error.
    pub fn validate_provisional(&self) -> Result<(), PrivateSettlementValidationError> {
        self.validate_with_availability_v1(false)
    }

    fn validate_with_availability_v1(
        &self,
        certificates_are_final: bool,
    ) -> Result<(), PrivateSettlementValidationError> {
        if !(ATOMIC_PRIVATE_SETTLEMENT_MIN_LEGS_V1..=ATOMIC_PRIVATE_SETTLEMENT_MAX_LEGS_V1)
            .contains(&self.legs.len())
        {
            return Err(PrivateSettlementValidationError::ParticipantCount {
                count: self.legs.len(),
            });
        }
        self.proof_intent().validate()?;
        for leg in &self.legs {
            if hash_is_zero(&leg.payload_digest)
                || hash_is_zero(&leg.delta_digest)
                || (certificates_are_final && hash_is_zero(&leg.availability_certificate_digest))
                || (!certificates_are_final && !hash_is_zero(&leg.availability_certificate_digest))
            {
                return Err(PrivateSettlementValidationError::ZeroCommitment);
            }
        }
        Ok(())
    }
}

impl PrivateSettlementProofProfileV1 {
    /// Compute the pinned digest of this proof relation and wire profile.
    #[must_use]
    pub fn digest(self) -> Hash {
        match self {
            Self::IvmPrivateNoteFixed2In3Out => Hash::prehashed(
                Sha256::digest(PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1).into(),
            ),
        }
    }
}

impl PrivateSettlementProofStatementV1 {
    /// Compute the domain-separated statement digest.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the statement cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(STATEMENT_DIGEST_DOMAIN_V1, self)
    }

    /// Validate the complete fixed-shape public relation boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed structural error before any expensive proof verification.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.proof_profile_digest != self.profile.digest()
            || hash_is_zero(&self.bundle_id)
            || hash_is_zero(&self.route.lane_incarnation)
            || self.pool_id.is_zero()
            || hash_is_zero(&self.asset_binding_commitment)
            || self.old_root.is_zero()
            || self.new_root.is_zero()
            || hash_is_zero(&self.audit_plaintext_commitment)
            || self.audit_input_commitment == [0; 32]
            || hash_is_zero(&self.audit_capsule_digest)
            || hash_is_zero(&self.audit_policy_digest)
            || hash_is_zero(&self.fee_intent_digest)
            || hash_is_zero(&self.reimbursement_terms_commitment)
        {
            return Err(PrivateSettlementValidationError::ZeroCommitment);
        }
        if self.old_root == self.new_root
            || self.authority_context_height == 0
            || self.old_epoch == 0
            || self.old_epoch.checked_add(1) != Some(self.new_epoch)
            || self.audit_key_epoch == 0
            || self.expiry_height <= self.authority_context_height
        {
            return Err(PrivateSettlementValidationError::InvalidEpoch);
        }
        if self.nullifiers.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
            || self.output_commitments.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
            || self.encrypted_outputs.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::InvalidFixedSlotCount {
                nullifiers: self.nullifiers.len(),
                outputs: self.output_commitments.len(),
            });
        }
        if self.nullifiers.iter().any(PrivacyNullifierV1::is_zero)
            || self
                .output_commitments
                .iter()
                .any(PrivacyCommitmentV1::is_zero)
        {
            return Err(PrivateSettlementValidationError::ZeroCommitment);
        }
        if self.nullifiers[0] == self.nullifiers[1]
            || self
                .output_commitments
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::DuplicateStateItem);
        }
        if self
            .encrypted_outputs
            .iter()
            .map(|output| output.recipient)
            .collect::<BTreeSet<_>>()
            .len()
            != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::DuplicateStateItem);
        }
        for (index, output) in self.encrypted_outputs.iter().enumerate() {
            if output.recipient.is_zero()
                || output.ephemeral_public_key.is_zero()
                || output.commitment != self.output_commitments[index]
                || output.ciphertext.len() != PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1
                || output.ciphertext.get(..4) != Some(b"IPNE".as_slice())
                || output.ciphertext[4..4 + PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1]
                    .iter()
                    .all(|byte| *byte == 0)
                || output.ciphertext[4 + PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1..]
                    .iter()
                    .all(|byte| *byte == 0)
            {
                return Err(PrivateSettlementValidationError::InvalidEncryptedOutput { index });
            }
        }
        Ok(())
    }
}

impl PrivateSettlementDeltaV1 {
    /// Compute the domain-separated canonical delta digest.
    ///
    /// # Errors
    ///
    /// Returns a Norito encoding error if the delta cannot be encoded.
    pub fn digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(DELTA_DIGEST_DOMAIN_V1, self)
    }

    /// Validate the complete public delta without requiring restricted proof material.
    ///
    /// This is the validation boundary used by global receipt admission. It
    /// deliberately repeats the fixed-shape checks from the proof statement so
    /// a committee certificate can never make malformed public state data
    /// admissible by itself.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a reserved digest, malformed route, invalid
    /// epoch transition, duplicate state item, or malformed encrypted output.
    pub fn validate_public_shape(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if hash_is_zero(&self.bundle_id)
            || hash_is_zero(&self.route.lane_incarnation)
            || self.pool_id.is_zero()
            || hash_is_zero(&self.asset_binding_commitment)
            || self.old_root.is_zero()
            || self.new_root.is_zero()
            || hash_is_zero(&self.statement_digest)
            || hash_is_zero(&self.proof_digest)
            || hash_is_zero(&self.capsule_digest)
            || hash_is_zero(&self.audit_policy_digest)
        {
            return Err(PrivateSettlementValidationError::ZeroCommitment);
        }
        if self.old_root == self.new_root
            || self.old_epoch == 0
            || self.audit_key_epoch == 0
            || self.old_epoch.checked_add(1) != Some(self.new_epoch)
        {
            return Err(PrivateSettlementValidationError::InvalidEpoch);
        }
        if self.nullifiers.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
            || self.output_commitments.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
            || self.encrypted_outputs.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::InvalidFixedSlotCount {
                nullifiers: self.nullifiers.len(),
                outputs: self.output_commitments.len(),
            });
        }
        if self.nullifiers.iter().any(PrivacyNullifierV1::is_zero)
            || self
                .output_commitments
                .iter()
                .any(PrivacyCommitmentV1::is_zero)
        {
            return Err(PrivateSettlementValidationError::ZeroCommitment);
        }
        if self
            .nullifiers
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
            || self
                .output_commitments
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::DuplicateStateItem);
        }
        if self
            .encrypted_outputs
            .iter()
            .map(|output| output.recipient)
            .collect::<BTreeSet<_>>()
            .len()
            != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
        {
            return Err(PrivateSettlementValidationError::DuplicateStateItem);
        }
        for (index, output) in self.encrypted_outputs.iter().enumerate() {
            if output.recipient.is_zero()
                || output.ephemeral_public_key.is_zero()
                || output.commitment != self.output_commitments[index]
                || output.ciphertext.len() != PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1
                || output.ciphertext.get(..4) != Some(b"IPNE".as_slice())
                || output.ciphertext[4..4 + PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1]
                    .iter()
                    .all(|byte| *byte == 0)
                || output.ciphertext[4 + PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1..]
                    .iter()
                    .all(|byte| *byte == 0)
            {
                return Err(PrivateSettlementValidationError::InvalidEncryptedOutput { index });
            }
        }
        Ok(())
    }

    /// Validate fixed slot shape and alignment with its proof statement.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed or substituted state material.
    pub fn validate_against(
        &self,
        statement: &PrivateSettlementProofStatementV1,
    ) -> Result<(), PrivateSettlementValidationError> {
        statement.validate()?;
        self.validate_public_shape()?;
        let expected_statement_digest = statement
            .digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if self.statement_digest != expected_statement_digest
            || self.bundle_id != statement.bundle_id
            || self.leg_ordinal != statement.leg_ordinal
            || self.route != statement.route
            || self.pool_id != statement.pool_id
            || self.asset_binding_commitment != statement.asset_binding_commitment
            || self.old_root != statement.old_root
            || self.new_root != statement.new_root
            || self.old_epoch != statement.old_epoch
            || self.new_epoch != statement.new_epoch
            || self.nullifiers != statement.nullifiers
            || self.output_commitments != statement.output_commitments
            || self.encrypted_outputs != statement.encrypted_outputs
            || self.capsule_digest != statement.audit_capsule_digest
            || self.audit_policy_digest != statement.audit_policy_digest
            || self.audit_key_epoch != statement.audit_key_epoch
        {
            return Err(PrivateSettlementValidationError::DeltaStatementMismatch);
        }
        Ok(())
    }
}
