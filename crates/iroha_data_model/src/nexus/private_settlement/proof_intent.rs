//! Distinct pre-proof intent and consuming post-proof artifact binding.
use super::*;

/// Public terms that exist before generating a proof, ciphertext or availability certificate.
///
/// This is not a settlement manifest and cannot be submitted to Register or Finalize. The
/// exact existing bundle-ID projection owns all shared terms; artifact digests have no fields
/// in this type. Its codec is data-only and validation grants no authority over wallet secrets.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::nexus::PrivateSettlementProofIntentV1")]
pub struct PrivateSettlementProofIntentV1 {
    /// First-release public intent version.
    pub version: u8,
    /// Derived stable identifier; validated against the exact material.
    pub bundle_id: Hash,
    /// Exact public fee payer, assets and limits.
    pub public_fee_intent: FeePaymentIntent,
    /// Sole shared projection of the signed public business intent.
    pub material: PrivateSettlementBundleIdMaterialV1,
}
impl std::ops::Deref for PrivateSettlementProofIntentV1 {
    type Target = PrivateSettlementBundleIdMaterialV1;
    fn deref(&self) -> &Self::Target {
        &self.material
    }
}
impl AtomicPrivateSettlementV1 {
    /// Project public proof terms only; callers still validate complete artifacts separately.
    #[must_use]
    pub fn proof_intent(&self) -> PrivateSettlementProofIntentV1 {
        PrivateSettlementProofIntentV1 {
            version: self.version,
            bundle_id: self.bundle_id,
            public_fee_intent: self.public_fee_intent.clone(),
            material: self.bundle_id_material(),
        }
    }
}
impl PrivateSettlementProofIntentV1 {
    /// Compute the canonical public fee commitment before any proof artifact exists.
    /// # Errors
    /// Canonical encoding failure.
    pub fn fee_intent_digest(public_fee_intent: &FeePaymentIntent) -> Result<Hash, norito::Error> {
        canonical_hash(FEE_INTENT_DIGEST_DOMAIN_V1, public_fee_intent)
    }

    /// Construct the public pre-proof intent from actual caller terms, deriving both commitments.
    /// No complete manifest or placeholder artifact/hash is needed by a one-call wallet.
    /// # Errors
    /// Invalid public terms, participant shape, fee intent or canonical encoding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: NetworkId,
        authority_context_height: u64,
        expiry_height: u64,
        sponsor: AccountId,
        public_fee_intent: FeePaymentIntent,
        reimbursement_terms_commitment: Hash,
        reimbursement_leg_ordinal: u8,
        legs: Vec<PrivateSettlementBundleLegMaterialV1>,
    ) -> Result<Self, PrivateSettlementValidationError> {
        let fee_intent_digest = Self::fee_intent_digest(&public_fee_intent)
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let material = PrivateSettlementBundleIdMaterialV1 {
            network_id,
            authority_context_height,
            expiry_height,
            sponsor,
            fee_intent_digest,
            reimbursement_terms_commitment,
            reimbursement_leg_ordinal,
            legs,
        };
        let bundle_id = canonical_hash(BUNDLE_ID_DOMAIN_V1, &material)
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        let intent = Self {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            bundle_id,
            public_fee_intent,
            material,
        };
        intent.validate()?;
        Ok(intent)
    }
    /// Compute the exact existing bundle-ID commitment, without artifact sentinels.
    /// # Errors
    /// Canonical encoding failure.
    pub fn computed_bundle_id(&self) -> Result<Hash, norito::Error> {
        canonical_hash(BUNDLE_ID_DOMAIN_V1, &self.material)
    }
    /// Compute the existing public fee commitment.
    /// # Errors
    /// Canonical encoding failure.
    pub fn computed_fee_intent_digest(&self) -> Result<Hash, norito::Error> {
        Self::fee_intent_digest(&self.public_fee_intent)
    }
    /// Compute the same proof binding used by complete manifests.
    /// # Errors
    /// Canonical encoding failure.
    pub fn proof_binding_digest(&self) -> Result<Hash, norito::Error> {
        canonical_hash(
            PROOF_BINDING_DIGEST_DOMAIN_V1,
            &PrivateSettlementProofBindingMaterialV1 {
                version: self.version,
                bundle_id: self.bundle_id,
                intent: self.material.clone(),
            },
        )
    }
    /// Validate all public intent terms, with no post-proof fields to guess or bypass.
    /// # Errors
    /// Malformed, unordered, cross-dataspace duplicate, expired or mismatched intent.
    pub fn validate(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1 {
            return Err(PrivateSettlementValidationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.authority_context_height == 0 || self.expiry_height <= self.authority_context_height
        {
            return Err(PrivateSettlementValidationError::InvalidExpiry);
        }
        if !(ATOMIC_PRIVATE_SETTLEMENT_MIN_LEGS_V1..=ATOMIC_PRIVATE_SETTLEMENT_MAX_LEGS_V1)
            .contains(&self.legs.len())
        {
            return Err(PrivateSettlementValidationError::ParticipantCount {
                count: self.legs.len(),
            });
        }
        if usize::from(self.reimbursement_leg_ordinal) >= self.legs.len() {
            return Err(PrivateSettlementValidationError::InvalidReimbursementLeg);
        }
        if self.public_fee_intent.validate().is_err() {
            return Err(PrivateSettlementValidationError::InvalidFeeIntent);
        }
        if hash_is_zero(&self.fee_intent_digest)
            || hash_is_zero(&self.reimbursement_terms_commitment)
        {
            return Err(PrivateSettlementValidationError::ZeroCommitment);
        }
        let computed_fee_intent_digest = self
            .computed_fee_intent_digest()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if self.fee_intent_digest != computed_fee_intent_digest {
            return Err(PrivateSettlementValidationError::FeeIntentDigestMismatch);
        }
        let mut previous_route = None;
        let mut participant_dataspaces = BTreeSet::new();
        for (index, leg) in self.legs.iter().enumerate() {
            let expected =
                u8::try_from(index).expect("private settlement has at most 255 participant legs");
            if leg.ordinal != expected {
                return Err(PrivateSettlementValidationError::NonCanonicalOrdinal {
                    index,
                    actual: leg.ordinal,
                });
            }
            if previous_route.is_some_and(|previous| previous >= leg.route) {
                return Err(PrivateSettlementValidationError::NonCanonicalRouteOrder);
            }
            previous_route = Some(leg.route);
            if !participant_dataspaces.insert(leg.route.dataspace_id) {
                return Err(PrivateSettlementValidationError::DuplicateDataspace);
            }
            if hash_is_zero(&leg.route.lane_incarnation)
                || leg.pool_id.is_zero()
                || hash_is_zero(&leg.asset_binding_commitment)
                || hash_is_zero(&leg.audit_policy_digest)
            {
                return Err(PrivateSettlementValidationError::ZeroCommitment);
            }
        }
        let computed = self
            .computed_bundle_id()
            .map_err(|_| PrivateSettlementValidationError::CanonicalEncoding)?;
        if self.bundle_id != computed {
            return Err(PrivateSettlementValidationError::BundleIdMismatch);
        }
        Ok(())
    }
    /// Consume the intent with exact produced sidecar/delta commitments.
    ///
    /// Availability certification follows this boundary. Every artifact-bearing leg must
    /// agree with its original intent and have actual nonzero payload and delta digests;
    /// an unproved intent cannot become a provisional manifest by itself.
    /// # Errors
    /// Missing/substituted legs, zero artifact commitments or prefilled availability data.
    pub fn bind_provisional_artifacts(
        self,
        legs: Vec<PrivateSettlementLegCommitmentV1>,
    ) -> Result<AtomicPrivateSettlementV1, PrivateSettlementValidationError> {
        self.validate()?;
        if legs.len() != self.legs.len()
            || legs.iter().zip(&self.legs).any(|(actual, expected)| {
                actual.ordinal != expected.ordinal
                    || actual.route != expected.route
                    || actual.pool_id != expected.pool_id
                    || actual.asset_binding_commitment != expected.asset_binding_commitment
                    || actual.audit_policy_digest != expected.audit_policy_digest
            })
        {
            return Err(PrivateSettlementValidationError::BundleIdMismatch);
        }
        let Self {
            version,
            bundle_id,
            public_fee_intent,
            material,
        } = self;
        let manifest = AtomicPrivateSettlementV1 {
            version,
            network_id: material.network_id,
            bundle_id,
            authority_context_height: material.authority_context_height,
            expiry_height: material.expiry_height,
            sponsor: material.sponsor,
            public_fee_intent,
            fee_intent_digest: material.fee_intent_digest,
            reimbursement_terms_commitment: material.reimbursement_terms_commitment,
            reimbursement_leg_ordinal: material.reimbursement_leg_ordinal,
            legs,
        };
        manifest.validate_provisional()?;
        Ok(manifest)
    }
}
