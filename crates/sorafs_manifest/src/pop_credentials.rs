#![allow(unexpected_cfgs)]
//! SoraFS proof-of-personhood credential payloads and deterministic validators.
mod zk;
use blake3::Hasher;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signer, SigningKey};
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
use std::collections::BTreeSet;
use thiserror::Error;
/// Schema version for [`PopCredentialV1`].
pub const POP_CREDENTIAL_VERSION_V1: u8 = 1;
/// Schema version for [`PopCommitmentRootV1`].
pub const POP_COMMITMENT_ROOT_VERSION_V1: u8 = 1;
/// Schema version for [`PopRevocationListV1`].
pub const POP_REVOCATION_LIST_VERSION_V1: u8 = 1;
/// Schema version for [`PopIssuedCredentialBundleV1`].
pub const POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1: u8 = 1;
/// Schema version for [`PopEnrollmentRequestV1`].
pub const POP_ENROLLMENT_REQUEST_VERSION_V1: u8 = 1;
/// Schema version for [`PopRenewalRequestV1`].
pub const POP_RENEWAL_REQUEST_VERSION_V1: u8 = 1;
/// Schema version for [`PopMembershipProofV1`].
pub const POP_MEMBERSHIP_PROOF_VERSION_V1: u8 = 1;
const POP_CREDENTIAL_SIGNATURE_DOMAIN_V1: &[u8] = b"sorafs.pop.credential.signature.v1";
const POP_ROOT_SIGNATURE_DOMAIN_V1: &[u8] = b"sorafs.pop.commitment-root.signature.v1";
const POP_REVOCATION_SIGNATURE_DOMAIN_V1: &[u8] = b"sorafs.pop.revocation-list.signature.v1";
/// Fixed depth of the first-release credential commitment tree.
pub const POP_CREDENTIAL_TREE_DEPTH_V1: u8 = 32;
/// Fixed depth of the first-release sparse revocation tree.
///
/// Revocation nonces are uniformly random 128-bit values and every bit selects
/// one path level, giving 128-bit collision resistance for sparse-tree keys.
pub const POP_REVOCATION_TREE_DEPTH_V1: u8 = 128;
/// Maximum accepted verifier-context length in UTF-8 bytes.
pub const POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1: usize = 256;
/// Maximum number of replay-cache nullifiers accepted by the slice API.
pub const POP_MEMBERSHIP_SEEN_NULLIFIERS_MAX_V1: usize = 65_536;
/// Maximum serialized PIPA-R transcript accepted by the verifier.
pub const POP_MEMBERSHIP_PROOF_MAX_BYTES_V1: usize = 128 * 1024;
/// Maximum number of explicit revocations in one signed V1 snapshot.
pub const POP_REVOCATION_ENTRIES_MAX_V1: usize = 4_096;
/// Maximum number of committed attributes carried by one credential.
pub const POP_CREDENTIAL_ATTRIBUTES_MAX_V1: usize = 64;
/// Maximum number of attribute keys requested during enrollment.
pub const POP_REQUESTED_ATTRIBUTES_MAX_V1: usize = 64;
/// Maximum UTF-8 byte length of issuer and applicant identifiers.
pub const POP_IDENTITY_TEXT_MAX_BYTES_V1: usize = 256;
/// Maximum UTF-8 byte length of an attribute key.
pub const POP_ATTRIBUTE_KEY_MAX_BYTES_V1: usize = 128;
/// Proof-of-personhood credential class used for juror eligibility routing.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopEligibilityClassV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[norito(tag = "class", content = "value", rename_all = "snake_case")]
pub enum PopEligibilityClassV1 {
    /// General juror pool.
    General,
    /// Region-scoped juror pool.
    Regional,
    /// Domain-expert juror pool.
    Expert,
    /// Emergency juror pool.
    Emergency,
    /// Observer-only credential that cannot vote.
    Observer,
}
/// Signature algorithm used by SFM-4b1 payload publishers.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopSignatureAlgorithmV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
)]
#[norito(tag = "algorithm", content = "value", rename_all = "snake_case")]
pub enum PopSignatureAlgorithmV1 {
    /// Ed25519 signatures over canonical Norito payload digests.
    Ed25519,
}
/// Membership proof system.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopMembershipProofSystemV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
)]
#[norito(tag = "proof_system", content = "value", rename_all = "snake_case")]
pub enum PopMembershipProofSystemV1 {
    /// Native PIPA-R over the Pasta cycle with transparent IPA commitments.
    NativePipaRV1,
}
/// Credential attribute commitment.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopCredentialAttributeV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopCredentialAttributeV1 {
    /// Stable attribute name.
    pub key: String,
    /// BLAKE3-256 commitment to the attribute value and salt.
    pub value_commitment: [u8; 32],
}
impl PopCredentialAttributeV1 {
    /// Validate the committed attribute shape.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        validate_bounded_text("attribute key", &self.key, POP_ATTRIBUTE_KEY_MAX_BYTES_V1)?;
        validate_digest("attribute value commitment", self.value_commitment)?;
        Ok(())
    }
}
/// Detached signature attached to PoP credential payloads.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopSignatureV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopSignatureV1 {
    /// Signature algorithm.
    pub algorithm: PopSignatureAlgorithmV1,
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}
impl PopSignatureV1 {
    /// Validate signature material for the advertised algorithm.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        match self.algorithm {
            PopSignatureAlgorithmV1::Ed25519 => {
                if self.public_key.len() != PUBLIC_KEY_LENGTH {
                    return Err(PopCredentialValidationError::InvalidPublicKeyLength {
                        length: self.public_key.len(),
                    });
                }
                if crate::inert_bytes(&self.public_key) {
                    return Err(PopCredentialValidationError::InvalidPublicKey {
                        reason: "public key material must not be all zero".to_owned(),
                    });
                }
                if self.signature.len() != SIGNATURE_LENGTH {
                    return Err(PopCredentialValidationError::InvalidSignatureLength {
                        length: self.signature.len(),
                    });
                }
                let mut signature = [0u8; SIGNATURE_LENGTH];
                signature.copy_from_slice(&self.signature);
                crate::checked_ed25519_signature_from_bytes(&signature).map_err(|reason| {
                    PopCredentialValidationError::SignatureVerification { reason }
                })?;
            }
        }
        Ok(())
    }
}
/// Proof-of-personhood credential issued to a juror wallet.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopCredentialV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopCredentialV1 {
    /// Schema version (`POP_CREDENTIAL_VERSION_V1`).
    pub version: u8,
    /// Unique credential identifier.
    pub credential_id: [u8; 32],
    /// Holder commitment; the canonical account identity is not embedded.
    pub holder_commitment: [u8; 32],
    /// Juror eligibility class granted by the credential.
    pub eligibility_class: PopEligibilityClassV1,
    /// Committed attributes used by future policy checks.
    pub attributes: Vec<PopCredentialAttributeV1>,
    /// Issuer identifier.
    pub issuer_id: String,
    /// Unix epoch seconds when the credential was issued.
    pub issued_at_epoch: u64,
    /// Unix epoch seconds when the credential expires.
    pub expires_at_epoch: u64,
    /// Earliest Unix epoch seconds when renewal can be requested.
    pub renewal_at_epoch: u64,
    /// Revocation nonce listed by governance if the credential is revoked.
    pub revocation_nonce: [u8; 32],
    /// Commitment root containing this credential.
    pub commitment_root: [u8; 32],
    /// Commitment tree version containing this credential.
    pub commitment_tree_version: u64,
    /// Revocation list version observed at issuance.
    pub revocation_list_version: u64,
    /// Issuer signature over the canonical credential payload.
    pub issuer_signature: PopSignatureV1,
}
impl PopCredentialV1 {
    /// Validate structural invariants that do not depend on wall-clock time.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_CREDENTIAL_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "credential",
                found: self.version,
            });
        }
        validate_digest("credential id", self.credential_id)?;
        validate_canonical_scalar("credential id", self.credential_id)?;
        validate_digest("holder commitment", self.holder_commitment)?;
        validate_canonical_scalar("holder commitment", self.holder_commitment)?;
        if self.attributes.len() > POP_CREDENTIAL_ATTRIBUTES_MAX_V1 {
            return Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "credential attributes",
                maximum: POP_CREDENTIAL_ATTRIBUTES_MAX_V1,
                actual: self.attributes.len(),
            });
        }
        validate_attributes(&self.attributes)?;
        validate_bounded_text("issuer id", &self.issuer_id, POP_IDENTITY_TEXT_MAX_BYTES_V1)?;
        if self.issued_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "issued_at_epoch",
            });
        }
        if self.issued_at_epoch >= self.expires_at_epoch {
            return Err(PopCredentialValidationError::InvalidValidityWindow {
                starts_at_epoch: self.issued_at_epoch,
                ends_at_epoch: self.expires_at_epoch,
            });
        }
        if self.renewal_at_epoch < self.issued_at_epoch
            || self.renewal_at_epoch > self.expires_at_epoch
        {
            return Err(PopCredentialValidationError::InvalidRenewalEpoch {
                renewal_at_epoch: self.renewal_at_epoch,
                issued_at_epoch: self.issued_at_epoch,
                expires_at_epoch: self.expires_at_epoch,
            });
        }
        validate_digest("revocation nonce", self.revocation_nonce)?;
        validate_revocation_nonce(self.revocation_nonce)?;
        validate_digest("commitment root", self.commitment_root)?;
        validate_canonical_scalar("commitment root", self.commitment_root)?;
        if self.commitment_tree_version == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter {
                field: "commitment_tree_version",
            });
        }
        if self.revocation_list_version == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter {
                field: "revocation_list_version",
            });
        }
        self.issuer_signature.validate()
    }
    /// Validate structural invariants and expiry at `now_epoch`.
    pub fn validate_at(&self, now_epoch: u64) -> Result<(), PopCredentialValidationError> {
        self.validate()?;
        if now_epoch >= self.expires_at_epoch {
            return Err(PopCredentialValidationError::ExpiredCredential {
                now_epoch,
                expires_at_epoch: self.expires_at_epoch,
            });
        }
        Ok(())
    }
}
/// Published commitment root for the active PoP credential set.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopCommitmentRootV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopCommitmentRootV1 {
    /// Schema version (`POP_COMMITMENT_ROOT_VERSION_V1`).
    pub version: u8,
    /// Root digest of the credential commitment tree.
    pub root_digest: [u8; 32],
    /// Number of leaves included in the root.
    pub tree_size: u64,
    /// Fixed depth of the credential commitment tree.
    pub tree_depth: u8,
    /// Monotonic commitment tree version.
    pub tree_version: u64,
    /// Issuer identifier.
    pub issuer_id: String,
    /// Unix epoch seconds when the root was published.
    pub published_at_epoch: u64,
    /// Previous root digest, if this is not the initial root.
    pub previous_root_digest: Option<[u8; 32]>,
    /// Governance event digest that authorised this root.
    pub governance_event_digest: [u8; 32],
    /// Publisher signature over the canonical root payload.
    pub publisher_signature: PopSignatureV1,
}
impl PopCommitmentRootV1 {
    /// Validate root publication invariants.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_COMMITMENT_ROOT_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "commitment root",
                found: self.version,
            });
        }
        validate_digest("commitment root", self.root_digest)?;
        validate_canonical_scalar("commitment root", self.root_digest)?;
        if self.tree_size == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter { field: "tree_size" });
        }
        if self.tree_depth != POP_CREDENTIAL_TREE_DEPTH_V1 {
            return Err(PopCredentialValidationError::InvalidTreeDepth {
                tree: "credential",
                expected: POP_CREDENTIAL_TREE_DEPTH_V1,
                actual: self.tree_depth,
            });
        }
        if self.tree_size > (1u64 << POP_CREDENTIAL_TREE_DEPTH_V1) {
            return Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "credential tree leaves",
                maximum: usize::try_from(1u64 << POP_CREDENTIAL_TREE_DEPTH_V1)
                    .unwrap_or(usize::MAX),
                actual: usize::try_from(self.tree_size).unwrap_or(usize::MAX),
            });
        }
        if self.tree_version == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter {
                field: "tree_version",
            });
        }
        validate_bounded_text("issuer id", &self.issuer_id, POP_IDENTITY_TEXT_MAX_BYTES_V1)?;
        if self.published_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "published_at_epoch",
            });
        }
        if let Some(previous) = self.previous_root_digest {
            validate_digest("previous commitment root", previous)?;
            if previous == self.root_digest {
                return Err(PopCredentialValidationError::DuplicateDigest {
                    field: "previous_root_digest",
                });
            }
        }
        validate_digest("governance event digest", self.governance_event_digest)?;
        self.publisher_signature.validate()
    }
}
/// Governance reason attached to a revocation entry.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopRevocationReasonV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
)]
#[norito(tag = "reason", content = "value", rename_all = "snake_case")]
pub enum PopRevocationReasonV1 {
    /// Credential was rotated to a newer nonce.
    Rotated,
    /// Holder requested withdrawal.
    HolderRequested,
    /// Issuer found enrollment evidence invalid.
    EnrollmentInvalid,
    /// Governance suspended the credential.
    GovernanceSuspension,
    /// Credential expired and was removed from active proof sets.
    Expired,
}
/// Single PoP credential revocation entry.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopRevocationEntryV1")]
#[derive(
    Debug,
    Clone,
    Copy,
    NoritoSerialize,
    NoritoDeserialize,
    JsonSerialize,
    JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct PopRevocationEntryV1 {
    /// Revocation nonce from the credential.
    pub nonce: [u8; 32],
    /// Unix epoch seconds when the nonce was revoked.
    pub revoked_at_epoch: u64,
    /// Governance reason code.
    pub reason: PopRevocationReasonV1,
}
impl PopRevocationEntryV1 {
    /// Validate a revocation entry.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        validate_digest("revocation nonce", self.nonce)?;
        validate_revocation_nonce(self.nonce)?;
        if self.revoked_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "revoked_at_epoch",
            });
        }
        Ok(())
    }
}
/// Published revocation list for PoP credential nonces.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopRevocationListV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopRevocationListV1 {
    /// Schema version (`POP_REVOCATION_LIST_VERSION_V1`).
    pub version: u8,
    /// Monotonic revocation list version.
    pub list_version: u64,
    /// Commitment root this list applies to.
    pub commitment_root: [u8; 32],
    /// Root of the sparse revoked-nonce tree.
    pub revocation_root: [u8; 32],
    /// Fixed depth of the sparse revoked-nonce tree.
    pub revocation_tree_depth: u8,
    /// Issuer identifier.
    pub issuer_id: String,
    /// Unix epoch seconds when the list was published.
    pub published_at_epoch: u64,
    /// Sorted revocation entries.
    pub entries: Vec<PopRevocationEntryV1>,
    /// Publisher signature over the canonical revocation-list payload.
    pub publisher_signature: PopSignatureV1,
}
impl PopRevocationListV1 {
    /// Validate revocation-list invariants.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_REVOCATION_LIST_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "revocation list",
                found: self.version,
            });
        }
        if self.list_version == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter {
                field: "list_version",
            });
        }
        validate_digest("commitment root", self.commitment_root)?;
        validate_canonical_scalar("commitment root", self.commitment_root)?;
        validate_digest("revocation root", self.revocation_root)?;
        validate_canonical_scalar("revocation root", self.revocation_root)?;
        if self.revocation_tree_depth != POP_REVOCATION_TREE_DEPTH_V1 {
            return Err(PopCredentialValidationError::InvalidTreeDepth {
                tree: "revocation",
                expected: POP_REVOCATION_TREE_DEPTH_V1,
                actual: self.revocation_tree_depth,
            });
        }
        validate_bounded_text("issuer id", &self.issuer_id, POP_IDENTITY_TEXT_MAX_BYTES_V1)?;
        if self.published_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "published_at_epoch",
            });
        }
        if self.entries.len() > POP_REVOCATION_ENTRIES_MAX_V1 {
            return Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "revocation entries",
                maximum: POP_REVOCATION_ENTRIES_MAX_V1,
                actual: self.entries.len(),
            });
        }
        let mut previous_nonce = None;
        for entry in &self.entries {
            entry.validate()?;
            if let Some(previous) = previous_nonce {
                if previous == entry.nonce {
                    return Err(PopCredentialValidationError::DuplicateRevocationNonce);
                }
                if previous > entry.nonce {
                    return Err(PopCredentialValidationError::UnsortedRevocationList);
                }
            }
            previous_nonce = Some(entry.nonce);
        }
        let expected_root = zk::revocation_root_from_entries_v1(&self.entries)?;
        if self.revocation_root != expected_root {
            return Err(PopCredentialValidationError::RevocationRootMismatch);
        }
        self.publisher_signature.validate()
    }
    /// Returns true if the nonce appears in the revocation list.
    #[must_use]
    pub fn contains_nonce(&self, nonce: [u8; 32]) -> bool {
        self.entries
            .binary_search_by_key(&nonce, |entry| entry.nonce)
            .is_ok()
    }
}
/// Cohesive issuer publication emitted when a PoP credential is issued.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopIssuedCredentialBundleV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopIssuedCredentialBundleV1 {
    /// Schema version (`POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1`).
    pub version: u8,
    /// Signed credential issued to the juror wallet.
    pub credential: PopCredentialV1,
    /// Signed commitment-root publication that includes the credential.
    pub commitment_root: PopCommitmentRootV1,
    /// Signed revocation-list snapshot observed at issuance.
    pub revocation_list: PopRevocationListV1,
}
impl PopIssuedCredentialBundleV1 {
    /// Validate issuer signatures and cross-publication consistency.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "issued credential bundle",
                found: self.version,
            });
        }
        verify_pop_credential_signature_v1(&self.credential)?;
        verify_pop_commitment_root_signature_v1(&self.commitment_root)?;
        verify_pop_revocation_list_signature_v1(&self.revocation_list)?;
        validate_pop_issuer_publications_v1(
            &self.credential,
            &self.commitment_root,
            &self.revocation_list,
        )
    }
}
/// Enrollment request submitted before credential issuance.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopEnrollmentRequestV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopEnrollmentRequestV1 {
    /// Schema version (`POP_ENROLLMENT_REQUEST_VERSION_V1`).
    pub version: u8,
    /// Unique enrollment request identifier.
    pub request_id: [u8; 32],
    /// Canonical applicant identifier or account alias supplied to the issuer.
    pub applicant_id: String,
    /// Requested eligibility class.
    pub requested_class: PopEligibilityClassV1,
    /// Requested attribute keys.
    pub requested_attributes: Vec<String>,
    /// Digest of off-chain enrollment attestations.
    pub attestation_digest: [u8; 32],
    /// Unix epoch seconds when the request was submitted.
    pub submitted_at_epoch: u64,
    /// Unix epoch seconds after which the request is stale.
    pub expires_at_epoch: u64,
}
impl PopEnrollmentRequestV1 {
    /// Validate enrollment request invariants.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_ENROLLMENT_REQUEST_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "enrollment request",
                found: self.version,
            });
        }
        validate_digest("enrollment request id", self.request_id)?;
        validate_bounded_text(
            "applicant id",
            &self.applicant_id,
            POP_IDENTITY_TEXT_MAX_BYTES_V1,
        )?;
        if self.requested_attributes.len() > POP_REQUESTED_ATTRIBUTES_MAX_V1 {
            return Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "requested attributes",
                maximum: POP_REQUESTED_ATTRIBUTES_MAX_V1,
                actual: self.requested_attributes.len(),
            });
        }
        validate_text_list("requested attribute", &self.requested_attributes)?;
        validate_digest("attestation digest", self.attestation_digest)?;
        if self.submitted_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "submitted_at_epoch",
            });
        }
        if self.submitted_at_epoch >= self.expires_at_epoch {
            return Err(PopCredentialValidationError::InvalidValidityWindow {
                starts_at_epoch: self.submitted_at_epoch,
                ends_at_epoch: self.expires_at_epoch,
            });
        }
        Ok(())
    }
}
/// Renewal request submitted before credential rotation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopRenewalRequestV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopRenewalRequestV1 {
    /// Schema version (`POP_RENEWAL_REQUEST_VERSION_V1`).
    pub version: u8,
    /// Unique renewal request identifier.
    pub request_id: [u8; 32],
    /// Credential being renewed.
    pub previous_credential_id: [u8; 32],
    /// Current holder commitment.
    pub holder_commitment: [u8; 32],
    /// New holder commitment to use after rotation.
    pub rotation_commitment: [u8; 32],
    /// Requested new expiry.
    pub requested_expires_at_epoch: u64,
    /// Unix epoch seconds when the request was submitted.
    pub submitted_at_epoch: u64,
    /// Digest of renewal attestation evidence.
    pub attestation_digest: [u8; 32],
}
impl PopRenewalRequestV1 {
    /// Validate renewal request invariants.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_RENEWAL_REQUEST_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "renewal request",
                found: self.version,
            });
        }
        validate_digest("renewal request id", self.request_id)?;
        validate_digest("previous credential id", self.previous_credential_id)?;
        validate_digest("holder commitment", self.holder_commitment)?;
        validate_digest("rotation commitment", self.rotation_commitment)?;
        if self.rotation_commitment == self.holder_commitment {
            return Err(PopCredentialValidationError::DuplicateDigest {
                field: "rotation_commitment",
            });
        }
        if self.submitted_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "submitted_at_epoch",
            });
        }
        if self.submitted_at_epoch >= self.requested_expires_at_epoch {
            return Err(PopCredentialValidationError::InvalidValidityWindow {
                starts_at_epoch: self.submitted_at_epoch,
                ends_at_epoch: self.requested_expires_at_epoch,
            });
        }
        validate_digest("attestation digest", self.attestation_digest)?;
        Ok(())
    }
}
/// Pinned verifier metadata for the first-release PoP circuit.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopMembershipVerifierMaterialV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopMembershipVerifierMaterialV1 {
    /// Stable circuit identifier.
    pub circuit_id: String,
    /// PIPA-R domain exponent.
    pub circuit_k: u32,
    /// Credential membership-tree depth compiled into the circuit.
    pub credential_tree_depth: u8,
    /// Sparse revocation-tree depth compiled into the circuit.
    pub revocation_tree_depth: u8,
    /// BLAKE3 digest of the deterministic transparent IPA parameters.
    pub parameter_digest: [u8; 32],
    /// BLAKE3 digest of the processed verifying key.
    pub verifying_key_digest: [u8; 32],
}
impl PopMembershipVerifierMaterialV1 {
    /// Validate the fixed circuit shape and non-inert key fingerprints.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        validate_text("membership circuit id", &self.circuit_id)?;
        if self.circuit_id != zk::POP_MEMBERSHIP_CIRCUIT_ID_V1 {
            return Err(PopCredentialValidationError::InvalidVerifierMaterial {
                reason: "unexpected membership circuit id".to_owned(),
            });
        }
        if self.circuit_k != zk::POP_MEMBERSHIP_CIRCUIT_K_V1 {
            return Err(PopCredentialValidationError::InvalidVerifierMaterial {
                reason: "unexpected PIPA-R circuit exponent".to_owned(),
            });
        }
        if self.credential_tree_depth != POP_CREDENTIAL_TREE_DEPTH_V1
            || self.revocation_tree_depth != POP_REVOCATION_TREE_DEPTH_V1
        {
            return Err(PopCredentialValidationError::InvalidVerifierMaterial {
                reason: "unexpected membership circuit tree depth".to_owned(),
            });
        }
        validate_digest("membership parameter digest", self.parameter_digest)?;
        validate_digest("membership verifying-key digest", self.verifying_key_digest)
    }
}
/// Membership proof presented by a juror client for a verifier challenge.
///
/// Credential identifiers, holder commitments, revocation nonces, and Merkle
/// paths are deliberately absent. They exist only as PIPA-R private witnesses.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::pop_credentials::PopMembershipProofV1")]
#[derive(
    Debug, Clone, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize, PartialEq, Eq,
)]
pub struct PopMembershipProofV1 {
    /// Schema version (`POP_MEMBERSHIP_PROOF_VERSION_V1`).
    pub version: u8,
    /// Eligibility class proven by the hidden credential leaf.
    pub eligibility_class: PopEligibilityClassV1,
    /// Signed active credential commitment root used by the proof.
    pub commitment_root: [u8; 32],
    /// Commitment tree version used by the proof.
    pub commitment_tree_version: u64,
    /// Signed sparse revocation root used by the non-membership proof.
    pub revocation_root: [u8; 32],
    /// Revocation list version used by the proof.
    pub revocation_list_version: u64,
    /// Per-holder, per-challenge/context nullifier for replay prevention.
    pub nullifier: [u8; 32],
    /// Verifier challenge digest.
    pub challenge_digest: [u8; 32],
    /// Domain/context string supplied by the verifier.
    pub verifier_context: String,
    /// Required verifier-selected recipient or action binding, committed by the
    /// proof independently of the shared challenge/context nullifier domain.
    pub presentation_binding_digest: [u8; 32],
    /// Membership proof system.
    pub proof_system: PopMembershipProofSystemV1,
    /// Pinned transparent parameters and verifying-key fingerprints.
    pub verifier_material: PopMembershipVerifierMaterialV1,
    /// Raw native PIPA-R proof transcript.
    pub proof_bytes: Vec<u8>,
    /// Credential expiry proven by the hidden leaf.
    pub expires_at_epoch: u64,
}
impl PopMembershipProofV1 {
    /// Validate bounded proof metadata before any expensive cryptography.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        if self.version != POP_MEMBERSHIP_PROOF_VERSION_V1 {
            return Err(PopCredentialValidationError::UnsupportedVersion {
                payload: "membership proof",
                found: self.version,
            });
        }
        validate_digest("commitment root", self.commitment_root)?;
        validate_canonical_scalar("commitment root", self.commitment_root)?;
        if self.commitment_tree_version == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter {
                field: "commitment_tree_version",
            });
        }
        validate_digest("revocation root", self.revocation_root)?;
        validate_canonical_scalar("revocation root", self.revocation_root)?;
        if self.revocation_list_version == 0 {
            return Err(PopCredentialValidationError::InvalidVersionCounter {
                field: "revocation_list_version",
            });
        }
        validate_digest("nullifier", self.nullifier)?;
        validate_canonical_scalar("nullifier", self.nullifier)?;
        validate_digest("challenge digest", self.challenge_digest)?;
        validate_verifier_context(&self.verifier_context)?;
        validate_digest(
            "presentation binding digest",
            self.presentation_binding_digest,
        )?;
        self.verifier_material.validate()?;
        if self.proof_bytes.is_empty() || self.proof_bytes.len() > POP_MEMBERSHIP_PROOF_MAX_BYTES_V1
        {
            return Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "membership proof bytes",
                maximum: POP_MEMBERSHIP_PROOF_MAX_BYTES_V1,
                actual: self.proof_bytes.len(),
            });
        }
        if self.expires_at_epoch == 0 {
            return Err(PopCredentialValidationError::InvalidTimestamp {
                field: "expires_at_epoch",
            });
        }
        Ok(())
    }
    /// Validate proof shape and expiry at `now_epoch`.
    pub fn validate_at(&self, now_epoch: u64) -> Result<(), PopCredentialValidationError> {
        self.validate()?;
        if now_epoch >= self.expires_at_epoch {
            return Err(PopCredentialValidationError::ExpiredProof {
                now_epoch,
                expires_at_epoch: self.expires_at_epoch,
            });
        }
        Ok(())
    }
}
/// Private credential-tree authentication path held by the juror wallet.
#[derive(Clone)]
pub struct PopCredentialMerklePathV1 {
    /// One canonical Pasta scalar sibling per credential-tree level.
    pub siblings: Vec<[u8; 32]>,
    /// `false` when the current node is left, `true` when it is right.
    pub directions: Vec<bool>,
}
impl core::fmt::Debug for PopCredentialMerklePathV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PopCredentialMerklePathV1")
            .field("depth", &self.siblings.len())
            .field("path", &"[REDACTED]")
            .finish()
    }
}
/// Private sparse-tree non-membership path held by the juror wallet.
#[derive(Clone)]
pub struct PopRevocationNonMembershipPathV1 {
    /// One canonical Pasta scalar sibling per sparse-tree level.
    pub siblings: Vec<[u8; 32]>,
}
impl core::fmt::Debug for PopRevocationNonMembershipPathV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PopRevocationNonMembershipPathV1")
            .field("depth", &self.siblings.len())
            .field("path", &"[REDACTED]")
            .finish()
    }
}
/// Private witness consumed by the PoP prover and never serialized into a proof.
pub struct PopMembershipWitnessV1 {
    /// Canonical non-zero Pasta scalar known only to the holder.
    pub holder_secret: [u8; 32],
    /// Authentication path for the hidden credential leaf.
    pub credential_path: PopCredentialMerklePathV1,
    /// Empty-leaf path at the credential's hidden revocation nonce.
    pub revocation_path: PopRevocationNonMembershipPathV1,
}
impl core::fmt::Debug for PopMembershipWitnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PopMembershipWitnessV1")
            .field("holder_secret", &"[REDACTED]")
            .field(
                "credential_path_depth",
                &self.credential_path.siblings.len(),
            )
            .field(
                "revocation_path_depth",
                &self.revocation_path.siblings.len(),
            )
            .finish()
    }
}
impl Drop for PopMembershipWitnessV1 {
    fn drop(&mut self) {
        self.holder_secret.fill(0);
        for sibling in &mut self.credential_path.siblings {
            sibling.fill(0);
        }
        self.credential_path.directions.fill(false);
        for sibling in &mut self.revocation_path.siblings {
            sibling.fill(0);
        }
    }
}
impl PopMembershipWitnessV1 {
    /// Validate private witness dimensions and canonical field encodings.
    pub fn validate(&self) -> Result<(), PopCredentialValidationError> {
        validate_digest("holder secret", self.holder_secret)?;
        validate_canonical_scalar("holder secret", self.holder_secret)?;
        if self.credential_path.siblings.len() != usize::from(POP_CREDENTIAL_TREE_DEPTH_V1)
            || self.credential_path.directions.len() != usize::from(POP_CREDENTIAL_TREE_DEPTH_V1)
        {
            return Err(PopCredentialValidationError::InvalidMerklePathDepth {
                tree: "credential",
                expected: usize::from(POP_CREDENTIAL_TREE_DEPTH_V1),
                siblings: self.credential_path.siblings.len(),
                directions: self.credential_path.directions.len(),
            });
        }
        if self.revocation_path.siblings.len() != usize::from(POP_REVOCATION_TREE_DEPTH_V1) {
            return Err(PopCredentialValidationError::InvalidMerklePathDepth {
                tree: "revocation",
                expected: usize::from(POP_REVOCATION_TREE_DEPTH_V1),
                siblings: self.revocation_path.siblings.len(),
                directions: usize::from(POP_REVOCATION_TREE_DEPTH_V1),
            });
        }
        for sibling in self
            .credential_path
            .siblings
            .iter()
            .chain(self.revocation_path.siblings.iter())
        {
            validate_canonical_scalar("membership path sibling", *sibling)?;
        }
        Ok(())
    }
}
mod borrowed_norito {
    use norito::core::SerializePayload;
    pub(super) struct Vec<'a, T>(Option<&'a std::vec::Vec<T>>);
    impl<'a, T> Vec<'a, T> {
        pub(super) fn borrowed(value: &'a std::vec::Vec<T>) -> Self {
            Self(Some(value))
        }
        pub(super) fn empty() -> Self {
            Self(None)
        }
    }
    impl<T: SerializePayload> SerializePayload for Vec<'_, T> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            match self.0 {
                Some(value) => value.serialize(writer),
                None => std::vec::Vec::<T>::new().serialize(writer),
            }
        }
        fn encoded_len_hint(&self) -> Option<usize> {
            match self.0 {
                Some(value) => value.encoded_len_hint(),
                None => std::vec::Vec::<T>::new().encoded_len_hint(),
            }
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            match self.0 {
                Some(value) => value.encoded_len_exact(),
                None => std::vec::Vec::<T>::new().encoded_len_exact(),
            }
        }
    }
}
#[derive(norito::derive::SerializePayload)]
struct PopSignatureSigningViewWireV1<'a> {
    algorithm: PopSignatureAlgorithmV1,
    public_key: borrowed_norito::Vec<'a, u8>,
    signature: borrowed_norito::Vec<'a, u8>,
}
struct PopSignatureSigningViewV1<'a>(PopSignatureSigningViewWireV1<'a>);
impl<'a> PopSignatureSigningViewV1<'a> {
    fn from_signature(signature: &'a PopSignatureV1) -> Self {
        Self(PopSignatureSigningViewWireV1 {
            algorithm: signature.algorithm,
            public_key: borrowed_norito::Vec::borrowed(&signature.public_key),
            signature: borrowed_norito::Vec::empty(),
        })
    }
}
impl norito::core::SerializePayload for PopSignatureSigningViewV1<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
#[derive(norito::derive::SerializePayload)]
struct PopCredentialSigningViewWireV1<'a> {
    version: u8,
    credential_id: [u8; 32],
    holder_commitment: [u8; 32],
    eligibility_class: PopEligibilityClassV1,
    attributes: borrowed_norito::Vec<'a, PopCredentialAttributeV1>,
    // Cow preserves String's self-delimiting packed-field layout without copying.
    issuer_id: std::borrow::Cow<'a, str>,
    issued_at_epoch: u64,
    expires_at_epoch: u64,
    renewal_at_epoch: u64,
    revocation_nonce: [u8; 32],
    commitment_root: [u8; 32],
    commitment_tree_version: u64,
    revocation_list_version: u64,
    issuer_signature: PopSignatureSigningViewV1<'a>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_manifest::pop_credentials::PopCredentialSigningViewV1",
    frame = "sorafs_manifest::pop_credentials::PopCredentialV1"
)]
struct PopCredentialSigningViewV1<'a>(PopCredentialSigningViewWireV1<'a>);
impl<'a> PopCredentialSigningViewV1<'a> {
    fn from_credential(credential: &'a PopCredentialV1) -> Self {
        Self(PopCredentialSigningViewWireV1 {
            version: credential.version,
            credential_id: credential.credential_id,
            holder_commitment: credential.holder_commitment,
            eligibility_class: credential.eligibility_class,
            attributes: borrowed_norito::Vec::borrowed(&credential.attributes),
            issuer_id: std::borrow::Cow::Borrowed(&credential.issuer_id),
            issued_at_epoch: credential.issued_at_epoch,
            expires_at_epoch: credential.expires_at_epoch,
            renewal_at_epoch: credential.renewal_at_epoch,
            revocation_nonce: credential.revocation_nonce,
            commitment_root: credential.commitment_root,
            commitment_tree_version: credential.commitment_tree_version,
            revocation_list_version: credential.revocation_list_version,
            issuer_signature: PopSignatureSigningViewV1::from_signature(
                &credential.issuer_signature,
            ),
        })
    }
}

impl norito::core::SerializePayload for PopCredentialSigningViewV1<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
#[derive(norito::derive::SerializePayload)]
struct PopCommitmentRootSigningViewWireV1<'a> {
    version: u8,
    root_digest: [u8; 32],
    tree_size: u64,
    tree_depth: u8,
    tree_version: u64,
    issuer_id: std::borrow::Cow<'a, str>,
    published_at_epoch: u64,
    previous_root_digest: Option<[u8; 32]>,
    governance_event_digest: [u8; 32],
    publisher_signature: PopSignatureSigningViewV1<'a>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_manifest::pop_credentials::PopCommitmentRootSigningViewV1",
    frame = "sorafs_manifest::pop_credentials::PopCommitmentRootV1"
)]
struct PopCommitmentRootSigningViewV1<'a>(PopCommitmentRootSigningViewWireV1<'a>);
impl<'a> PopCommitmentRootSigningViewV1<'a> {
    fn from_root(root: &'a PopCommitmentRootV1) -> Self {
        Self(PopCommitmentRootSigningViewWireV1 {
            version: root.version,
            root_digest: root.root_digest,
            tree_size: root.tree_size,
            tree_depth: root.tree_depth,
            tree_version: root.tree_version,
            issuer_id: std::borrow::Cow::Borrowed(&root.issuer_id),
            published_at_epoch: root.published_at_epoch,
            previous_root_digest: root.previous_root_digest,
            governance_event_digest: root.governance_event_digest,
            publisher_signature: PopSignatureSigningViewV1::from_signature(
                &root.publisher_signature,
            ),
        })
    }
}

impl norito::core::SerializePayload for PopCommitmentRootSigningViewV1<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
#[derive(norito::derive::SerializePayload)]
struct PopRevocationListSigningViewWireV1<'a> {
    version: u8,
    list_version: u64,
    commitment_root: [u8; 32],
    revocation_root: [u8; 32],
    revocation_tree_depth: u8,
    issuer_id: std::borrow::Cow<'a, str>,
    published_at_epoch: u64,
    entries: borrowed_norito::Vec<'a, PopRevocationEntryV1>,
    publisher_signature: PopSignatureSigningViewV1<'a>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_manifest::pop_credentials::PopRevocationListSigningViewV1",
    frame = "sorafs_manifest::pop_credentials::PopRevocationListV1"
)]
struct PopRevocationListSigningViewV1<'a>(PopRevocationListSigningViewWireV1<'a>);
impl<'a> PopRevocationListSigningViewV1<'a> {
    fn from_revocations(revocations: &'a PopRevocationListV1) -> Self {
        Self(PopRevocationListSigningViewWireV1 {
            version: revocations.version,
            list_version: revocations.list_version,
            commitment_root: revocations.commitment_root,
            revocation_root: revocations.revocation_root,
            revocation_tree_depth: revocations.revocation_tree_depth,
            issuer_id: std::borrow::Cow::Borrowed(&revocations.issuer_id),
            published_at_epoch: revocations.published_at_epoch,
            entries: borrowed_norito::Vec::borrowed(&revocations.entries),
            publisher_signature: PopSignatureSigningViewV1::from_signature(
                &revocations.publisher_signature,
            ),
        })
    }
}

impl norito::core::SerializePayload for PopRevocationListSigningViewV1<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
/// Derive the canonical Ed25519 digest for a PoP credential signature.
pub fn pop_credential_signature_digest_v1(
    credential: &PopCredentialV1,
) -> Result<[u8; 32], PopCredentialValidationError> {
    preflight_credential_signature_source(credential)?;
    let signable = PopCredentialSigningViewV1::from_credential(credential);
    pop_signature_digest(POP_CREDENTIAL_SIGNATURE_DOMAIN_V1, &signable)
}
/// Verify the issuer signature attached to a PoP credential.
pub fn verify_pop_credential_signature_v1(
    credential: &PopCredentialV1,
) -> Result<(), PopCredentialValidationError> {
    credential.validate()?;
    let digest = pop_credential_signature_digest_v1(credential)?;
    verify_pop_signature_v1(&credential.issuer_signature, &digest)
}
/// Sign a PoP credential with the canonical SFM-4b1 Ed25519 digest.
pub fn sign_pop_credential_ed25519_v1(
    mut credential: PopCredentialV1,
    signing_key: &SigningKey,
) -> Result<PopCredentialV1, PopCredentialValidationError> {
    credential.issuer_signature = empty_ed25519_pop_signature(signing_key);
    let digest = pop_credential_signature_digest_v1(&credential)?;
    credential.issuer_signature.signature = signing_key.sign(&digest).to_bytes().to_vec();
    verify_pop_credential_signature_v1(&credential)?;
    Ok(credential)
}
/// Derive the canonical Ed25519 digest for a commitment-root signature.
pub fn pop_commitment_root_signature_digest_v1(
    root: &PopCommitmentRootV1,
) -> Result<[u8; 32], PopCredentialValidationError> {
    preflight_root_signature_source(root)?;
    let signable = PopCommitmentRootSigningViewV1::from_root(root);
    pop_signature_digest(POP_ROOT_SIGNATURE_DOMAIN_V1, &signable)
}
/// Verify the publisher signature attached to a commitment root.
pub fn verify_pop_commitment_root_signature_v1(
    root: &PopCommitmentRootV1,
) -> Result<(), PopCredentialValidationError> {
    root.validate()?;
    let digest = pop_commitment_root_signature_digest_v1(root)?;
    verify_pop_signature_v1(&root.publisher_signature, &digest)
}
/// Sign a commitment root with the canonical SFM-4b1 Ed25519 digest.
pub fn sign_pop_commitment_root_ed25519_v1(
    mut root: PopCommitmentRootV1,
    signing_key: &SigningKey,
) -> Result<PopCommitmentRootV1, PopCredentialValidationError> {
    root.publisher_signature = empty_ed25519_pop_signature(signing_key);
    let digest = pop_commitment_root_signature_digest_v1(&root)?;
    root.publisher_signature.signature = signing_key.sign(&digest).to_bytes().to_vec();
    verify_pop_commitment_root_signature_v1(&root)?;
    Ok(root)
}
/// Derive the canonical Ed25519 digest for a revocation-list signature.
pub fn pop_revocation_list_signature_digest_v1(
    revocations: &PopRevocationListV1,
) -> Result<[u8; 32], PopCredentialValidationError> {
    preflight_revocation_signature_source(revocations)?;
    let signable = PopRevocationListSigningViewV1::from_revocations(revocations);
    pop_signature_digest(POP_REVOCATION_SIGNATURE_DOMAIN_V1, &signable)
}
/// Verify the publisher signature attached to a revocation list.
pub fn verify_pop_revocation_list_signature_v1(
    revocations: &PopRevocationListV1,
) -> Result<(), PopCredentialValidationError> {
    revocations.validate()?;
    let digest = pop_revocation_list_signature_digest_v1(revocations)?;
    verify_pop_signature_v1(&revocations.publisher_signature, &digest)
}
/// Sign a revocation list with the canonical SFM-4b1 Ed25519 digest.
pub fn sign_pop_revocation_list_ed25519_v1(
    mut revocations: PopRevocationListV1,
    signing_key: &SigningKey,
) -> Result<PopRevocationListV1, PopCredentialValidationError> {
    revocations.publisher_signature = empty_ed25519_pop_signature(signing_key);
    let digest = pop_revocation_list_signature_digest_v1(&revocations)?;
    revocations.publisher_signature.signature = signing_key.sign(&digest).to_bytes().to_vec();
    verify_pop_revocation_list_signature_v1(&revocations)?;
    Ok(revocations)
}
/// Sign and validate the canonical issuer bundle for a newly issued credential.
pub fn issue_pop_credential_bundle_ed25519_v1(
    credential: PopCredentialV1,
    commitment_root: PopCommitmentRootV1,
    revocation_list: PopRevocationListV1,
    signing_key: &SigningKey,
) -> Result<PopIssuedCredentialBundleV1, PopCredentialValidationError> {
    let bundle = PopIssuedCredentialBundleV1 {
        version: POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1,
        credential: sign_pop_credential_ed25519_v1(credential, signing_key)?,
        commitment_root: sign_pop_commitment_root_ed25519_v1(commitment_root, signing_key)?,
        revocation_list: sign_pop_revocation_list_ed25519_v1(revocation_list, signing_key)?,
    };
    bundle.validate()?;
    Ok(bundle)
}
/// Derive a holder commitment from a private holder secret and credential id.
///
/// Both inputs must be canonical non-zero Pasta scalars. The returned
/// commitment is suitable for [`PopCredentialV1::holder_commitment`].
pub fn derive_pop_holder_commitment_v1(
    holder_secret: [u8; 32],
    credential_id: [u8; 32],
) -> Result<[u8; 32], PopCredentialValidationError> {
    zk::holder_commitment_v1(holder_secret, credential_id)
}
/// Derive the canonical hidden credential leaf committed by the issuer tree.
pub fn pop_credential_leaf_v1(
    credential: &PopCredentialV1,
) -> Result<[u8; 32], PopCredentialValidationError> {
    credential.validate()?;
    zk::credential_leaf_v1(credential)
}
/// Fold one fixed-depth credential authentication path into its root.
pub fn pop_credential_root_from_path_v1(
    leaf: [u8; 32],
    path: &PopCredentialMerklePathV1,
) -> Result<[u8; 32], PopCredentialValidationError> {
    zk::credential_root_from_path_v1(leaf, &path.siblings, &path.directions)
}
/// Compute the canonical sparse revocation root for a signed snapshot.
pub fn pop_revocation_root_v1(
    entries: &[PopRevocationEntryV1],
) -> Result<[u8; 32], PopCredentialValidationError> {
    if entries.len() > POP_REVOCATION_ENTRIES_MAX_V1 {
        return Err(PopCredentialValidationError::ResourceLimitExceeded {
            resource: "revocation entries",
            maximum: POP_REVOCATION_ENTRIES_MAX_V1,
            actual: entries.len(),
        });
    }
    zk::revocation_root_from_entries_v1(entries)
}
/// Build the private sparse-tree path proving that `nonce` is not revoked.
pub fn build_pop_revocation_non_membership_path_v1(
    entries: &[PopRevocationEntryV1],
    nonce: [u8; 32],
) -> Result<PopRevocationNonMembershipPathV1, PopCredentialValidationError> {
    if entries.len() > POP_REVOCATION_ENTRIES_MAX_V1 {
        return Err(PopCredentialValidationError::ResourceLimitExceeded {
            resource: "revocation entries",
            maximum: POP_REVOCATION_ENTRIES_MAX_V1,
            actual: entries.len(),
        });
    }
    zk::build_revocation_non_membership_path_v1(entries, nonce)
}
/// Return the deterministic, pinned V1 parameter and verifying-key fingerprints.
pub fn pop_membership_verifier_material_v1()
-> Result<PopMembershipVerifierMaterialV1, PopCredentialValidationError> {
    zk::verifier_material_v1()
}
/// Independently prepared challenge and relying-party binding for a PoP presentation.
///
/// Verification compares every coordinate with the proof's committed statement.
/// Callers must retain their own expected values rather than deriving them from
/// an untrusted proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PopMembershipPresentationV1<'a> {
    /// Verifier's fresh challenge commitment.
    pub challenge_digest: [u8; 32],
    /// Exact relying-party context for this presentation.
    pub verifier_context: &'a str,
    /// Commitment to the authoritative action and its recipient.
    pub presentation_binding_digest: [u8; 32],
}

/// Create a privacy-preserving PoP membership proof for a verifier challenge.
pub fn prove_pop_membership_v1(
    credential: &PopCredentialV1,
    commitment_root: &PopCommitmentRootV1,
    revocations: &PopRevocationListV1,
    witness: &PopMembershipWitnessV1,
    presentation: PopMembershipPresentationV1<'_>,
    now_epoch: u64,
) -> Result<PopMembershipProofV1, PopCredentialValidationError> {
    let PopMembershipPresentationV1 {
        challenge_digest,
        verifier_context,
        presentation_binding_digest,
    } = presentation;
    validate_digest("challenge digest", challenge_digest)?;
    validate_verifier_context(verifier_context)?;
    validate_digest("presentation binding digest", presentation_binding_digest)?;
    witness.validate()?;
    credential.validate_at(now_epoch)?;
    verify_pop_credential_signature_v1(credential)?;
    verify_pop_commitment_root_signature_v1(commitment_root)?;
    verify_pop_revocation_list_signature_v1(revocations)?;
    validate_pop_active_publications_v1(credential, commitment_root, revocations)?;
    if revocations.contains_nonce(credential.revocation_nonce) {
        return Err(PopCredentialValidationError::RevokedCredential);
    }
    zk::validate_prover_paths(
        credential,
        witness,
        commitment_root.root_digest,
        revocations.revocation_root,
    )?;
    let proof = zk::prove_v1(
        credential,
        witness,
        commitment_root.root_digest,
        revocations.revocation_root,
        revocations.list_version,
        PopMembershipPresentationV1 {
            challenge_digest,
            verifier_context,
            presentation_binding_digest,
        },
    )?;
    verify_pop_membership_proof_v1(
        &proof,
        commitment_root,
        revocations,
        PopMembershipPresentationV1 {
            challenge_digest,
            verifier_context,
            presentation_binding_digest,
        },
        now_epoch,
        &[],
    )?;
    Ok(proof)
}
/// Verify a PoP membership proof against signed active root and revocation state.
pub fn verify_pop_membership_proof_v1(
    proof: &PopMembershipProofV1,
    commitment_root: &PopCommitmentRootV1,
    revocations: &PopRevocationListV1,
    presentation: PopMembershipPresentationV1<'_>,
    now_epoch: u64,
    seen_nullifiers: &[[u8; 32]],
) -> Result<(), PopCredentialValidationError> {
    let PopMembershipPresentationV1 {
        challenge_digest: expected_challenge_digest,
        verifier_context: expected_verifier_context,
        presentation_binding_digest: expected_presentation_binding_digest,
    } = presentation;
    if seen_nullifiers.len() > POP_MEMBERSHIP_SEEN_NULLIFIERS_MAX_V1 {
        return Err(PopCredentialValidationError::ReplayCacheLimitExceeded);
    }
    proof.validate_at(now_epoch)?;
    verify_pop_commitment_root_signature_v1(commitment_root)?;
    verify_pop_revocation_list_signature_v1(revocations)?;
    validate_pop_verifier_publications_v1(commitment_root, revocations)?;
    if proof.commitment_root != commitment_root.root_digest {
        return Err(PopCredentialValidationError::WrongCommitmentRoot);
    }
    if proof.commitment_tree_version != commitment_root.tree_version {
        return Err(PopCredentialValidationError::CommitmentTreeVersionMismatch);
    }
    if proof.revocation_root != revocations.revocation_root {
        return Err(PopCredentialValidationError::RevocationRootMismatch);
    }
    if proof.revocation_list_version < revocations.list_version {
        return Err(PopCredentialValidationError::StaleRevocationList {
            proof_version: proof.revocation_list_version,
            current_version: revocations.list_version,
        });
    }
    if proof.revocation_list_version > revocations.list_version {
        return Err(
            PopCredentialValidationError::RevocationListVersionMismatch {
                proof_version: proof.revocation_list_version,
                current_version: revocations.list_version,
            },
        );
    }
    if proof.challenge_digest != expected_challenge_digest {
        return Err(PopCredentialValidationError::ChallengeMismatch);
    }
    if proof.verifier_context != expected_verifier_context {
        return Err(PopCredentialValidationError::VerifierContextMismatch);
    }
    if proof.presentation_binding_digest != expected_presentation_binding_digest {
        return Err(PopCredentialValidationError::PresentationBindingMismatch);
    }
    if seen_nullifiers.contains(&proof.nullifier) {
        return Err(PopCredentialValidationError::ReplayedProof);
    }
    zk::verify_v1(proof)
}
/// Errors returned by SFM-4b1 PoP credential validators.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PopCredentialValidationError {
    /// Payload version is not supported.
    #[error("unsupported {payload} version {found}")]
    UnsupportedVersion { payload: &'static str, found: u8 },
    /// Required digest-like field is all zeroes.
    #[error("{field} must be non-zero")]
    InvalidDigest { field: &'static str },
    /// Text field is empty after trimming.
    #[error("{field} must not be empty")]
    EmptyText { field: &'static str },
    /// Text field contains control characters or surrounding whitespace.
    #[error("{field} contains invalid text")]
    InvalidText { field: &'static str },
    /// Duplicate committed attribute key.
    #[error("duplicate credential attribute key {key}")]
    DuplicateAttribute { key: String },
    /// Duplicate requested attribute key.
    #[error("duplicate requested attribute key {key}")]
    DuplicateRequestedAttribute { key: String },
    /// Timestamp field is invalid.
    #[error("{field} timestamp must be greater than zero")]
    InvalidTimestamp { field: &'static str },
    /// Monotonic counter field is invalid.
    #[error("{field} must be greater than zero")]
    InvalidVersionCounter { field: &'static str },
    /// A fixed Merkle-tree depth does not match the compiled V1 circuit.
    #[error("{tree} tree depth must be {expected}, got {actual}")]
    InvalidTreeDepth {
        tree: &'static str,
        expected: u8,
        actual: u8,
    },
    /// A private Merkle authentication path has the wrong dimensions.
    #[error(
        "{tree} Merkle path requires {expected} levels, got {siblings} siblings and {directions} directions"
    )]
    InvalidMerklePathDepth {
        tree: &'static str,
        expected: usize,
        siblings: usize,
        directions: usize,
    },
    /// A bounded collection or byte payload exceeded its hard limit.
    #[error("{resource} exceeds maximum {maximum}: got {actual}")]
    ResourceLimitExceeded {
        resource: &'static str,
        maximum: usize,
        actual: usize,
    },
    /// A field element is not canonically encoded for the Pasta scalar field.
    #[error("{field} is not a canonical Pasta scalar")]
    InvalidScalarEncoding { field: &'static str },
    /// Revocation nonces must be canonical non-zero 128-bit little-endian keys.
    #[error("revocation nonce must be a non-zero 128-bit little-endian value")]
    InvalidRevocationNonceEncoding,
    /// Validity window is empty or inverted.
    #[error("validity window {starts_at_epoch}..{ends_at_epoch} is invalid")]
    InvalidValidityWindow {
        starts_at_epoch: u64,
        ends_at_epoch: u64,
    },
    /// Renewal epoch falls outside the credential validity window.
    #[error("renewal epoch {renewal_at_epoch} is outside {issued_at_epoch}..{expires_at_epoch}")]
    InvalidRenewalEpoch {
        renewal_at_epoch: u64,
        issued_at_epoch: u64,
        expires_at_epoch: u64,
    },
    /// A digest field duplicates a field that must rotate.
    #[error("{field} duplicates an incompatible digest")]
    DuplicateDigest { field: &'static str },
    /// Ed25519 public key length is invalid.
    #[error("ed25519 public key must be 32 bytes, got {length}")]
    InvalidPublicKeyLength { length: usize },
    /// Ed25519 signature length is invalid.
    #[error("ed25519 signature must be 64 bytes, got {length}")]
    InvalidSignatureLength { length: usize },
    /// Ed25519 public key bytes are invalid.
    #[error("invalid ed25519 public key: {reason}")]
    InvalidPublicKey { reason: String },
    /// Signature payload could not be encoded.
    #[error("failed to encode signature payload: {reason}")]
    SignaturePayloadEncoding { reason: String },
    /// Signature verification failed.
    #[error("signature verification failed: {reason}")]
    SignatureVerification { reason: String },
    /// Credential is expired.
    #[error("credential expired at {expires_at_epoch}, now {now_epoch}")]
    ExpiredCredential {
        now_epoch: u64,
        expires_at_epoch: u64,
    },
    /// Proof is expired.
    #[error("membership proof expired at {expires_at_epoch}, now {now_epoch}")]
    ExpiredProof {
        now_epoch: u64,
        expires_at_epoch: u64,
    },
    /// Revocation list entries are not sorted by nonce.
    #[error("revocation list entries must be sorted by nonce")]
    UnsortedRevocationList,
    /// Revocation list has duplicate nonces.
    #[error("revocation list has duplicate nonces")]
    DuplicateRevocationNonce,
    /// Signed sparse revocation root does not match the supplied state or witness.
    #[error("sparse revocation root mismatch")]
    RevocationRootMismatch,
    /// Proof holder commitment does not match the supplied credential.
    #[error("membership proof holder commitment mismatch")]
    ProofHolderCommitmentMismatch,
    /// Commitment root does not match credential, proof, or revocation material.
    #[error("membership proof uses the wrong commitment root")]
    WrongCommitmentRoot,
    /// Commitment tree version does not match the published root.
    #[error("commitment tree version mismatch")]
    CommitmentTreeVersionMismatch,
    /// Credential, commitment root, and revocation list issuer ids do not match.
    #[error("credential, commitment root, and revocation list issuer ids must match")]
    IssuerMismatch,
    /// Credential, commitment root, and revocation list issuer public keys do not match.
    #[error("credential, commitment root, and revocation list issuer public keys must match")]
    IssuerKeyMismatch,
    /// Proof used a stale revocation list version.
    #[error(
        "membership proof revocation list version {proof_version} is stale; current {current_version}"
    )]
    StaleRevocationList {
        proof_version: u64,
        current_version: u64,
    },
    /// Proof used a revocation list version newer than the supplied list.
    #[error(
        "membership proof revocation list version {proof_version} does not match supplied {current_version}"
    )]
    RevocationListVersionMismatch {
        proof_version: u64,
        current_version: u64,
    },
    /// Credential was issued against a revocation list version that does not match supplied state.
    #[error("credential revocation list version does not match supplied revocation list")]
    CredentialRevocationListMismatch,
    /// Credential nonce is revoked.
    #[error("credential revocation nonce is revoked")]
    RevokedCredential,
    /// Proof nullifier has already been consumed.
    #[error("membership proof nullifier has already been consumed")]
    ReplayedProof,
    /// Caller supplied too many replay-cache entries to the slice verifier.
    #[error("membership proof replay-cache input exceeds the bounded slice API")]
    ReplayCacheLimitExceeded,
    /// Pinned PIPA-R parameters or verifying-key material is invalid.
    #[error("invalid PoP membership verifier material: {reason}")]
    InvalidVerifierMaterial { reason: String },
    /// PIPA-R proving or deterministic material construction failed.
    #[error("PoP membership proof backend failed: {reason}")]
    ProofBackend { reason: String },
    /// native PIPA-R cryptographic verification failed.
    #[error("invalid PoP membership proof: {reason}")]
    InvalidMembershipProof { reason: String },
    /// Expected challenge does not match the proof statement.
    #[error("membership proof challenge does not match verifier challenge")]
    ChallengeMismatch,
    /// Expected verifier domain/context does not match the proof statement.
    #[error("membership proof context does not match verifier context")]
    VerifierContextMismatch,
    /// Proof was prepared for a different verifier-selected recipient or action.
    #[error("membership proof presentation binding does not match the verifier request")]
    PresentationBindingMismatch,
}
const POP_SIGNATURE_PREIMAGE_MAX_BYTES_V1: usize = 512 * 1024;
fn preflight_signature_public_key(
    signature: &PopSignatureV1,
) -> Result<(), PopCredentialValidationError> {
    if signature.public_key.len() != PUBLIC_KEY_LENGTH {
        return Err(PopCredentialValidationError::InvalidPublicKeyLength {
            length: signature.public_key.len(),
        });
    }
    Ok(())
}
fn preflight_bounded_source(
    resource: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), PopCredentialValidationError> {
    if actual > maximum {
        return Err(PopCredentialValidationError::ResourceLimitExceeded {
            resource,
            maximum,
            actual,
        });
    }
    Ok(())
}
fn preflight_credential_signature_source(
    credential: &PopCredentialV1,
) -> Result<(), PopCredentialValidationError> {
    preflight_bounded_source(
        "credential attributes",
        credential.attributes.len(),
        POP_CREDENTIAL_ATTRIBUTES_MAX_V1,
    )?;
    preflight_bounded_source(
        "issuer id bytes",
        credential.issuer_id.len(),
        POP_IDENTITY_TEXT_MAX_BYTES_V1,
    )?;
    for attribute in &credential.attributes {
        preflight_bounded_source(
            "credential attribute key bytes",
            attribute.key.len(),
            POP_ATTRIBUTE_KEY_MAX_BYTES_V1,
        )?;
    }
    preflight_signature_public_key(&credential.issuer_signature)
}
fn preflight_root_signature_source(
    root: &PopCommitmentRootV1,
) -> Result<(), PopCredentialValidationError> {
    preflight_bounded_source(
        "issuer id bytes",
        root.issuer_id.len(),
        POP_IDENTITY_TEXT_MAX_BYTES_V1,
    )?;
    preflight_signature_public_key(&root.publisher_signature)
}
fn preflight_revocation_signature_source(
    revocations: &PopRevocationListV1,
) -> Result<(), PopCredentialValidationError> {
    preflight_bounded_source(
        "revocation entries",
        revocations.entries.len(),
        POP_REVOCATION_ENTRIES_MAX_V1,
    )?;
    preflight_bounded_source(
        "issuer id bytes",
        revocations.issuer_id.len(),
        POP_IDENTITY_TEXT_MAX_BYTES_V1,
    )?;
    preflight_signature_public_key(&revocations.publisher_signature)
}
fn pop_signature_digest<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    payload: &T,
) -> Result<[u8; 32], PopCredentialValidationError> {
    // Signature preimages use one V1 layout, including their size admission.
    // An enclosing decoded envelope must not select different signing bytes.
    let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let encoded_len = norito::core::encoded_frame_len(payload).map_err(|err| {
        PopCredentialValidationError::SignaturePayloadEncoding {
            reason: err.to_string(),
        }
    })?;
    preflight_bounded_source(
        "signature preimage bytes",
        encoded_len,
        POP_SIGNATURE_PREIMAGE_MAX_BYTES_V1,
    )?;
    struct Blake3Writer<'a>(&'a mut Hasher);
    impl std::io::Write for Blake3Writer<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hasher = Hasher::new();
    hasher.update(domain);
    norito::core::write_canonical_to_writer(payload, &mut Blake3Writer(&mut hasher)).map_err(
        |err| PopCredentialValidationError::SignaturePayloadEncoding {
            reason: err.to_string(),
        },
    )?;
    Ok(*hasher.finalize().as_bytes())
}
fn empty_ed25519_pop_signature(signing_key: &SigningKey) -> PopSignatureV1 {
    PopSignatureV1 {
        algorithm: PopSignatureAlgorithmV1::Ed25519,
        public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature: Vec::new(),
    }
}
fn verify_pop_signature_v1(
    signature: &PopSignatureV1,
    digest: &[u8; 32],
) -> Result<(), PopCredentialValidationError> {
    signature.validate()?;
    match signature.algorithm {
        PopSignatureAlgorithmV1::Ed25519 => verify_ed25519_pop_signature(signature, digest),
    }
}
fn verify_ed25519_pop_signature(
    signature: &PopSignatureV1,
    digest: &[u8; 32],
) -> Result<(), PopCredentialValidationError> {
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&signature.public_key);
    let verifying_key = crate::checked_ed25519_verifying_key_from_bytes(&public_key)
        .map_err(|err| PopCredentialValidationError::InvalidPublicKey { reason: err })?;
    let mut signature_bytes = [0u8; SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(&signature.signature);
    let signature = crate::checked_ed25519_signature_from_bytes(&signature_bytes)
        .map_err(|reason| PopCredentialValidationError::SignatureVerification { reason })?;
    verifying_key
        .verify_strict(digest, &signature)
        .map_err(|err| PopCredentialValidationError::SignatureVerification {
            reason: err.to_string(),
        })
}
fn validate_digest(
    field: &'static str,
    digest: [u8; 32],
) -> Result<(), PopCredentialValidationError> {
    if digest.iter().all(|byte| *byte == 0) {
        return Err(PopCredentialValidationError::InvalidDigest { field });
    }
    Ok(())
}
fn validate_canonical_scalar(
    field: &'static str,
    bytes: [u8; 32],
) -> Result<(), PopCredentialValidationError> {
    zk::canonical_scalar(bytes)
        .map(|_| ())
        .map_err(|_| PopCredentialValidationError::InvalidScalarEncoding { field })
}
fn validate_revocation_nonce(nonce: [u8; 32]) -> Result<(), PopCredentialValidationError> {
    zk::revocation_nonce_u128(nonce).map(|_| ())
}
fn validate_verifier_context(context: &str) -> Result<(), PopCredentialValidationError> {
    validate_text("verifier context", context)?;
    if context.len() > POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1 {
        return Err(PopCredentialValidationError::ResourceLimitExceeded {
            resource: "verifier context bytes",
            maximum: POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1,
            actual: context.len(),
        });
    }
    Ok(())
}
fn validate_text(field: &'static str, value: &str) -> Result<(), PopCredentialValidationError> {
    if value.trim().is_empty() {
        return Err(PopCredentialValidationError::EmptyText { field });
    }
    if value != value.trim() || value.chars().any(char::is_control) {
        return Err(PopCredentialValidationError::InvalidText { field });
    }
    Ok(())
}
fn validate_bounded_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), PopCredentialValidationError> {
    validate_text(field, value)?;
    if value.len() > maximum {
        return Err(PopCredentialValidationError::ResourceLimitExceeded {
            resource: field,
            maximum,
            actual: value.len(),
        });
    }
    Ok(())
}
fn validate_attributes(
    attributes: &[PopCredentialAttributeV1],
) -> Result<(), PopCredentialValidationError> {
    let mut keys = BTreeSet::new();
    for attribute in attributes {
        attribute.validate()?;
        if !keys.insert(attribute.key.clone()) {
            return Err(PopCredentialValidationError::DuplicateAttribute {
                key: attribute.key.clone(),
            });
        }
    }
    Ok(())
}
fn validate_pop_issuer_publications_v1(
    credential: &PopCredentialV1,
    commitment_root: &PopCommitmentRootV1,
    revocation_list: &PopRevocationListV1,
) -> Result<(), PopCredentialValidationError> {
    if credential.commitment_root != commitment_root.root_digest
        || revocation_list.commitment_root != commitment_root.root_digest
    {
        return Err(PopCredentialValidationError::WrongCommitmentRoot);
    }
    if credential.commitment_tree_version != commitment_root.tree_version {
        return Err(PopCredentialValidationError::CommitmentTreeVersionMismatch);
    }
    if credential.issuer_id.as_str() != commitment_root.issuer_id.as_str()
        || credential.issuer_id.as_str() != revocation_list.issuer_id.as_str()
    {
        return Err(PopCredentialValidationError::IssuerMismatch);
    }
    if credential.issuer_signature.public_key.as_slice()
        != commitment_root.publisher_signature.public_key.as_slice()
        || credential.issuer_signature.public_key.as_slice()
            != revocation_list.publisher_signature.public_key.as_slice()
    {
        return Err(PopCredentialValidationError::IssuerKeyMismatch);
    }
    if credential.revocation_list_version != revocation_list.list_version {
        return Err(PopCredentialValidationError::CredentialRevocationListMismatch);
    }
    if revocation_list.contains_nonce(credential.revocation_nonce) {
        return Err(PopCredentialValidationError::RevokedCredential);
    }
    Ok(())
}
fn validate_pop_verifier_publications_v1(
    commitment_root: &PopCommitmentRootV1,
    revocation_list: &PopRevocationListV1,
) -> Result<(), PopCredentialValidationError> {
    if revocation_list.commitment_root != commitment_root.root_digest {
        return Err(PopCredentialValidationError::WrongCommitmentRoot);
    }
    if commitment_root.issuer_id != revocation_list.issuer_id {
        return Err(PopCredentialValidationError::IssuerMismatch);
    }
    if commitment_root.publisher_signature.public_key
        != revocation_list.publisher_signature.public_key
    {
        return Err(PopCredentialValidationError::IssuerKeyMismatch);
    }
    Ok(())
}
fn validate_pop_active_publications_v1(
    credential: &PopCredentialV1,
    commitment_root: &PopCommitmentRootV1,
    revocation_list: &PopRevocationListV1,
) -> Result<(), PopCredentialValidationError> {
    validate_pop_verifier_publications_v1(commitment_root, revocation_list)?;
    if credential.commitment_root != commitment_root.root_digest {
        return Err(PopCredentialValidationError::WrongCommitmentRoot);
    }
    if credential.commitment_tree_version != commitment_root.tree_version {
        return Err(PopCredentialValidationError::CommitmentTreeVersionMismatch);
    }
    if credential.issuer_id != commitment_root.issuer_id {
        return Err(PopCredentialValidationError::IssuerMismatch);
    }
    if credential.issuer_signature.public_key != commitment_root.publisher_signature.public_key {
        return Err(PopCredentialValidationError::IssuerKeyMismatch);
    }
    if credential.revocation_list_version > revocation_list.list_version {
        return Err(PopCredentialValidationError::CredentialRevocationListMismatch);
    }
    Ok(())
}
fn validate_text_list(
    field: &'static str,
    values: &[String],
) -> Result<(), PopCredentialValidationError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_bounded_text(field, value, POP_ATTRIBUTE_KEY_MAX_BYTES_V1)?;
        if !seen.insert(value.clone()) {
            return Err(PopCredentialValidationError::DuplicateRequestedAttribute {
                key: value.clone(),
            });
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    const SMALL_ORDER_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    fn scalar(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }
    pub(super) fn nonce(value: u128) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&value.to_le_bytes());
        bytes
    }
    pub(super) fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn empty_signature(key: &SigningKey) -> PopSignatureV1 {
        PopSignatureV1 {
            algorithm: PopSignatureAlgorithmV1::Ed25519,
            public_key: key.verifying_key().to_bytes().to_vec(),
            signature: vec![2; 64],
        }
    }
    fn encode_frame_with_flags<T: norito::core::NoritoSerialize>(value: &T, flags: u8) -> Vec<u8> {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        norito::to_bytes(value).expect("encode explicit-layout PoP frame")
    }
    fn supported_layouts() -> [u8; 2] {
        [0, norito::core::header_flags::COMPACT_LEN]
    }
    fn canonical_owned_signature_digest<T: norito::core::NoritoSerialize>(
        domain: &[u8],
        value: &T,
    ) -> [u8; 32] {
        let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let bytes = norito::to_bytes(value).expect("encode canonical owned PoP signature preimage");
        let mut hasher = Hasher::new();
        hasher.update(domain);
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }
    #[derive(Clone)]
    pub(super) struct Fixture {
        pub(super) credential: PopCredentialV1,
        pub(super) root: PopCommitmentRootV1,
        pub(super) revocations: PopRevocationListV1,
        proof: PopMembershipProofV1,
        holder_secret: [u8; 32],
        credential_path: PopCredentialMerklePathV1,
        revocation_path: PopRevocationNonMembershipPathV1,
    }
    fn build_fixture() -> Fixture {
        let key = signing_key(0x55);
        let holder_secret = scalar(0x1234_5678);
        let credential_id = scalar(0x8765_4321);
        let holder_commitment =
            derive_pop_holder_commitment_v1(holder_secret, credential_id).expect("commitment");
        let mut credential = PopCredentialV1 {
            version: POP_CREDENTIAL_VERSION_V1,
            credential_id,
            holder_commitment,
            eligibility_class: PopEligibilityClassV1::General,
            attributes: vec![PopCredentialAttributeV1 {
                key: "residency".to_owned(),
                value_commitment: digest(0x13),
            }],
            issuer_id: "issuer.sorafs".to_owned(),
            issued_at_epoch: 100,
            expires_at_epoch: 1_000,
            renewal_at_epoch: 800,
            revocation_nonce: nonce(0xfeed_beef_dead_cafe_1234_5678_9abc_def0),
            commitment_root: scalar(1),
            commitment_tree_version: 7,
            revocation_list_version: 3,
            issuer_signature: empty_signature(&key),
        };
        credential =
            sign_pop_credential_ed25519_v1(credential, &key).expect("placeholder signature");
        let credential_path = PopCredentialMerklePathV1 {
            siblings: vec![scalar(0); usize::from(POP_CREDENTIAL_TREE_DEPTH_V1)],
            directions: (0..usize::from(POP_CREDENTIAL_TREE_DEPTH_V1))
                .map(|level| level % 3 == 1)
                .collect(),
        };
        let leaf = pop_credential_leaf_v1(&credential).expect("credential leaf");
        let root_digest =
            pop_credential_root_from_path_v1(leaf, &credential_path).expect("credential root");
        credential.commitment_root = root_digest;
        credential =
            sign_pop_credential_ed25519_v1(credential, &key).expect("credential signature");
        let root = sign_pop_commitment_root_ed25519_v1(
            PopCommitmentRootV1 {
                version: POP_COMMITMENT_ROOT_VERSION_V1,
                root_digest,
                tree_size: 1,
                tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
                tree_version: 7,
                issuer_id: "issuer.sorafs".to_owned(),
                published_at_epoch: 120,
                previous_root_digest: Some(scalar(99)),
                governance_event_digest: digest(0x17),
                publisher_signature: empty_signature(&key),
            },
            &key,
        )
        .expect("root signature");
        let revocation_entries = Vec::new();
        let revocation_root =
            pop_revocation_root_v1(&revocation_entries).expect("empty revocation root");
        let revocations = sign_pop_revocation_list_ed25519_v1(
            PopRevocationListV1 {
                version: POP_REVOCATION_LIST_VERSION_V1,
                list_version: 3,
                commitment_root: root_digest,
                revocation_root,
                revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
                issuer_id: "issuer.sorafs".to_owned(),
                published_at_epoch: 130,
                entries: revocation_entries,
                publisher_signature: empty_signature(&key),
            },
            &key,
        )
        .expect("revocation signature");
        let revocation_path = build_pop_revocation_non_membership_path_v1(
            &revocations.entries,
            credential.revocation_nonce,
        )
        .expect("non-membership path");
        let witness = PopMembershipWitnessV1 {
            holder_secret,
            credential_path: credential_path.clone(),
            revocation_path: revocation_path.clone(),
        };
        let proof = prove_pop_membership_v1(
            &credential,
            &root,
            &revocations,
            &witness,
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: digest(0x44),
            },
            500,
        )
        .expect("membership proof");
        Fixture {
            credential,
            root,
            revocations,
            proof,
            holder_secret,
            credential_path,
            revocation_path,
        }
    }
    pub(super) fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(build_fixture)
    }
    fn witness_from(fixture: &Fixture) -> PopMembershipWitnessV1 {
        PopMembershipWitnessV1 {
            holder_secret: fixture.holder_secret,
            credential_path: fixture.credential_path.clone(),
            revocation_path: fixture.revocation_path.clone(),
        }
    }
    fn enrollment() -> PopEnrollmentRequestV1 {
        PopEnrollmentRequestV1 {
            version: POP_ENROLLMENT_REQUEST_VERSION_V1,
            request_id: digest(0x21),
            applicant_id: "alice@sora".to_string(),
            requested_class: PopEligibilityClassV1::General,
            requested_attributes: vec!["residency".to_string()],
            attestation_digest: digest(0x22),
            submitted_at_epoch: 100,
            expires_at_epoch: 200,
        }
    }
    fn renewal() -> PopRenewalRequestV1 {
        PopRenewalRequestV1 {
            version: POP_RENEWAL_REQUEST_VERSION_V1,
            request_id: digest(0x31),
            previous_credential_id: scalar(11),
            holder_commitment: scalar(12),
            rotation_commitment: scalar(32),
            requested_expires_at_epoch: 2_000,
            submitted_at_epoch: 900,
            attestation_digest: digest(0x33),
        }
    }
    fn norito_roundtrip<T>(value: &T) -> T
    where
        T: norito::core::NoritoSerialize
            + for<'decode> norito::NoritoDeserialize<'decode>
            + PartialEq
            + std::fmt::Debug,
    {
        let bytes = norito::to_bytes(value).expect("encode");
        let decoded = norito::decode_from_bytes(&bytes).expect("decode");
        assert_eq!(value, &decoded);
        decoded
    }
    #[test]
    fn payloads_roundtrip_through_norito() {
        let fixture = fixture();
        norito_roundtrip(&fixture.credential);
        norito_roundtrip(&fixture.root);
        norito_roundtrip(&fixture.revocations);
        norito_roundtrip(&PopIssuedCredentialBundleV1 {
            version: POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1,
            credential: fixture.credential.clone(),
            commitment_root: fixture.root.clone(),
            revocation_list: fixture.revocations.clone(),
        });
        norito_roundtrip(&enrollment());
        norito_roundtrip(&renewal());
        norito_roundtrip(&fixture.proof);
    }
    #[test]
    fn borrowed_signature_preimages_match_owned_frames_and_canonical_digests() {
        let fixture = fixture();
        let mut owned_credential = fixture.credential.clone();
        owned_credential.issuer_signature.signature.clear();
        let borrowed_credential = PopCredentialSigningViewV1::from_credential(&fixture.credential);
        let mut owned_root = fixture.root.clone();
        owned_root.publisher_signature.signature.clear();
        let borrowed_root = PopCommitmentRootSigningViewV1::from_root(&fixture.root);
        let mut owned_revocations = fixture.revocations.clone();
        owned_revocations.publisher_signature.signature.clear();
        let borrowed_revocations =
            PopRevocationListSigningViewV1::from_revocations(&fixture.revocations);
        for flags in supported_layouts() {
            assert_eq!(
                encode_frame_with_flags(&borrowed_credential, flags),
                encode_frame_with_flags(&owned_credential, flags),
                "borrowed credential signing frame changed for flags 0x{flags:02x}"
            );
            assert_eq!(
                encode_frame_with_flags(&borrowed_root, flags),
                encode_frame_with_flags(&owned_root, flags),
                "borrowed root signing frame changed for flags 0x{flags:02x}"
            );
            assert_eq!(
                encode_frame_with_flags(&borrowed_revocations, flags),
                encode_frame_with_flags(&owned_revocations, flags),
                "borrowed revocation signing frame changed for flags 0x{flags:02x}"
            );
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                pop_credential_signature_digest_v1(&fixture.credential)
                    .expect("stream credential digest"),
                canonical_owned_signature_digest(
                    POP_CREDENTIAL_SIGNATURE_DOMAIN_V1,
                    &owned_credential,
                ),
                "streamed credential digest changed for flags 0x{flags:02x}"
            );
            assert_eq!(
                pop_commitment_root_signature_digest_v1(&fixture.root).expect("stream root digest"),
                canonical_owned_signature_digest(POP_ROOT_SIGNATURE_DOMAIN_V1, &owned_root),
                "streamed root digest changed for flags 0x{flags:02x}"
            );
            assert_eq!(
                pop_revocation_list_signature_digest_v1(&fixture.revocations)
                    .expect("stream revocation digest"),
                canonical_owned_signature_digest(
                    POP_REVOCATION_SIGNATURE_DOMAIN_V1,
                    &owned_revocations,
                ),
                "streamed revocation digest changed for flags 0x{flags:02x}"
            );
        }
    }
    #[test]
    fn credential_publication_signatures_and_leaf_ignore_enclosing_norito_layout() {
        let fixture = fixture();
        let expected_leaf = pop_credential_leaf_v1(&fixture.credential).expect("canonical leaf");
        for flags in supported_layouts() {
            let _layout = norito::core::DecodeFlagsGuard::enter(flags);
            verify_pop_credential_signature_v1(&fixture.credential)
                .expect("credential signature must not depend on enclosing layout");
            verify_pop_commitment_root_signature_v1(&fixture.root)
                .expect("root signature must not depend on enclosing layout");
            verify_pop_revocation_list_signature_v1(&fixture.revocations)
                .expect("revocation signature must not depend on enclosing layout");
            assert_eq!(
                pop_credential_leaf_v1(&fixture.credential).expect("canonical credential leaf"),
                expected_leaf,
                "credential tree membership must not depend on enclosing layout"
            );
            assert_eq!(
                norito::core::get_decode_flags(),
                flags,
                "signature verification must restore the enclosing decoder's flags"
            );
        }
    }
    #[test]
    fn credential_publications_reject_valid_signatures_over_noncanonical_layouts() {
        fn alternate_signature<T: norito::core::NoritoSerialize>(
            domain: &[u8],
            unsigned: &T,
        ) -> Vec<u8> {
            let alternate = encode_frame_with_flags(unsigned, 0);
            assert_ne!(
                alternate,
                norito::encode_canonical(unsigned).expect("canonical frame")
            );
            let mut hasher = Hasher::new();
            hasher.update(domain);
            hasher.update(&alternate);
            signing_key(0x55)
                .sign(hasher.finalize().as_bytes())
                .to_bytes()
                .to_vec()
        }
        let fixture = fixture();
        let mut credential = fixture.credential.clone();
        credential.issuer_signature.signature.clear();
        credential.issuer_signature.signature =
            alternate_signature(POP_CREDENTIAL_SIGNATURE_DOMAIN_V1, &credential);
        let mut root = fixture.root.clone();
        root.publisher_signature.signature.clear();
        root.publisher_signature.signature =
            alternate_signature(POP_ROOT_SIGNATURE_DOMAIN_V1, &root);
        let mut revocations = fixture.revocations.clone();
        revocations.publisher_signature.signature.clear();
        revocations.publisher_signature.signature =
            alternate_signature(POP_REVOCATION_SIGNATURE_DOMAIN_V1, &revocations);
        for flags in supported_layouts() {
            let _layout = norito::core::DecodeFlagsGuard::enter(flags);
            for result in [
                verify_pop_credential_signature_v1(&credential),
                verify_pop_commitment_root_signature_v1(&root),
                verify_pop_revocation_list_signature_v1(&revocations),
            ] {
                assert!(
                    matches!(
                        result,
                        Err(PopCredentialValidationError::SignatureVerification { .. })
                    ),
                    "a valid signature over a noncanonical preimage must not get an alternate verification path"
                );
            }
        }
    }
    #[test]
    fn signature_preimages_reject_unadmitted_source_cardinality() {
        let mut credential = fixture().credential.clone();
        credential.attributes.resize(
            POP_CREDENTIAL_ATTRIBUTES_MAX_V1 + 1,
            credential.attributes[0].clone(),
        );
        assert!(matches!(
            pop_credential_signature_digest_v1(&credential),
            Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "credential attributes",
                maximum: POP_CREDENTIAL_ATTRIBUTES_MAX_V1,
                ..
            })
        ));
        let mut revocations = fixture().revocations.clone();
        revocations.entries.resize(
            POP_REVOCATION_ENTRIES_MAX_V1 + 1,
            PopRevocationEntryV1 {
                nonce: nonce(1),
                revoked_at_epoch: 1,
                reason: PopRevocationReasonV1::Expired,
            },
        );
        assert!(matches!(
            pop_revocation_list_signature_digest_v1(&revocations),
            Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "revocation entries",
                maximum: POP_REVOCATION_ENTRIES_MAX_V1,
                ..
            })
        ));
    }
    #[test]
    fn signatures_verify_and_reject_forgery() {
        let fixture = fixture();
        verify_pop_credential_signature_v1(&fixture.credential).expect("credential verifies");
        verify_pop_commitment_root_signature_v1(&fixture.root).expect("root verifies");
        verify_pop_revocation_list_signature_v1(&fixture.revocations).expect("revocations verify");
        let mut forged = fixture.credential.clone();
        forged.credential_id = scalar(0x99);
        let err = verify_pop_credential_signature_v1(&forged).expect_err("forgery rejected");
        assert!(matches!(
            err,
            PopCredentialValidationError::SignatureVerification { .. }
        ));
    }
    #[test]
    fn signatures_reject_all_zero_signature_material() {
        let fixture = fixture();
        let mut credential = fixture.credential.clone();
        let mut root = fixture.root.clone();
        let mut revocations = fixture.revocations.clone();
        credential.issuer_signature.signature.fill(0);
        root.publisher_signature.signature.fill(0);
        revocations.publisher_signature.signature.fill(0);
        let err = verify_pop_credential_signature_v1(&credential)
            .expect_err("all-zero POP credential signature must be rejected");
        assert!(matches!(
            err,
            PopCredentialValidationError::SignatureVerification { reason }
                if reason.contains("all zero")
        ));
        let err = verify_pop_commitment_root_signature_v1(&root)
            .expect_err("all-zero POP root signature must be rejected");
        assert!(matches!(
            err,
            PopCredentialValidationError::SignatureVerification { reason }
                if reason.contains("all zero")
        ));
        let err = verify_pop_revocation_list_signature_v1(&revocations)
            .expect_err("all-zero POP revocation signature must be rejected");
        assert!(matches!(
            err,
            PopCredentialValidationError::SignatureVerification { reason }
                if reason.contains("all zero")
        ));
    }
    #[test]
    fn credential_signature_rejects_malformed_ed25519_signature_r() {
        for (label, replacement_r, expected_reason) in [
            ("small-order", SMALL_ORDER_R, "small-order"),
            ("noncanonical", NONCANONICAL_R, "not a canonical"),
        ] {
            let mut credential = fixture().credential.clone();
            credential.issuer_signature.signature[..PUBLIC_KEY_LENGTH]
                .copy_from_slice(&replacement_r);
            let err = verify_pop_credential_signature_v1(&credential)
                .expect_err("malformed POP credential signature R must be rejected");
            assert!(
                matches!(
                    &err,
                    PopCredentialValidationError::SignatureVerification { reason }
                        if reason.contains(expected_reason)
                ),
                "{label} signature R produced unexpected error: {err}"
            );
        }
    }
    #[test]
    fn issued_credential_bundle_signs_and_validates_publications() {
        let fixture = fixture();
        let bundle = PopIssuedCredentialBundleV1 {
            version: POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1,
            credential: fixture.credential.clone(),
            commitment_root: fixture.root.clone(),
            revocation_list: fixture.revocations.clone(),
        };
        bundle.validate().expect("issued bundle validates");
        verify_pop_membership_proof_v1(
            &fixture.proof,
            &bundle.commitment_root,
            &bundle.revocation_list,
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: digest(0x44),
            },
            500,
            &[],
        )
        .expect("bundle verifies private membership proof");
    }
    #[test]
    fn issued_credential_bundle_rejects_inconsistent_revocation_version() {
        let fixture = fixture();
        let mut bundle = PopIssuedCredentialBundleV1 {
            version: POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1,
            credential: fixture.credential.clone(),
            commitment_root: fixture.root.clone(),
            revocation_list: fixture.revocations.clone(),
        };
        bundle.revocation_list.list_version += 1;
        bundle.revocation_list =
            sign_pop_revocation_list_ed25519_v1(bundle.revocation_list, &signing_key(0x55))
                .expect("resign revocations");
        let err = bundle.validate().expect_err("revocation version mismatch");
        assert_eq!(
            err,
            PopCredentialValidationError::CredentialRevocationListMismatch
        );
    }
    #[test]
    fn issued_credential_bundle_rejects_issuer_key_drift() {
        let fixture = fixture();
        let mut bundle = PopIssuedCredentialBundleV1 {
            version: POP_ISSUED_CREDENTIAL_BUNDLE_VERSION_V1,
            credential: fixture.credential.clone(),
            commitment_root: fixture.root.clone(),
            revocation_list: fixture.revocations.clone(),
        };
        bundle.commitment_root.publisher_signature = empty_signature(&signing_key(0x66));
        bundle.commitment_root =
            sign_pop_commitment_root_ed25519_v1(bundle.commitment_root, &signing_key(0x66))
                .expect("resign root");
        let err = bundle.validate().expect_err("issuer key drift");
        assert_eq!(err, PopCredentialValidationError::IssuerKeyMismatch);
    }
    #[test]
    fn membership_proof_verifies_without_public_identity_material() {
        let fixture = fixture();
        verify_pop_membership_proof_v1(
            &fixture.proof,
            &fixture.root,
            &fixture.revocations,
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: digest(0x44),
            },
            500,
            &[],
        )
        .expect("membership proof verifies");
        let encoded = norito::to_bytes(&fixture.proof).expect("encode proof");
        assert!(
            !encoded
                .windows(fixture.credential.credential_id.len())
                .any(|window| window == &fixture.credential.credential_id[..])
        );
        assert!(
            !encoded
                .windows(fixture.credential.holder_commitment.len())
                .any(|window| window == &fixture.credential.holder_commitment[..])
        );
        assert!(
            !encoded
                .windows(fixture.credential.revocation_nonce.len())
                .any(|window| window == &fixture.credential.revocation_nonce[..])
        );
    }
    #[test]
    fn membership_proof_presentation_binding_cannot_be_retargeted() {
        let fixture = fixture();
        let other_binding = digest(0x45);
        assert_eq!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: other_binding
                },
                500,
                &[],
            )
            .expect_err("a copied proof cannot authorize another recipient"),
            PopCredentialValidationError::PresentationBindingMismatch,
        );
        let mut retargeted = fixture.proof.clone();
        retargeted.presentation_binding_digest = other_binding;
        assert!(
            matches!(
                verify_pop_membership_proof_v1(
                    &retargeted,
                    &fixture.root,
                    &fixture.revocations,
                    PopMembershipPresentationV1 {
                        challenge_digest: digest(0x43),
                        verifier_context: "jury-case-1",
                        presentation_binding_digest: other_binding
                    },
                    500,
                    &[],
                ),
                Err(PopCredentialValidationError::InvalidMembershipProof { .. })
            ),
            "the PIPA-R statement must bind the recipient even after envelope substitution"
        );
        retargeted.presentation_binding_digest = [0; 32];
        assert!(matches!(
            retargeted.validate(),
            Err(PopCredentialValidationError::InvalidDigest {
                field: "presentation binding digest"
            })
        ));
        let encoded =
            norito::encode_canonical(&fixture.proof).expect("encode recipient-bound proof");
        let decoded: PopMembershipProofV1 =
            norito::decode_canonical(&encoded).expect("decode recipient-bound proof");
        assert_eq!(decoded, fixture.proof);
    }
    #[test]
    fn membership_proof_wire_requires_presentation_binding() {
        // Encode the exact former field order only to demonstrate that an
        // unbound proof cannot decode through the sole current V1 schema.
        #[derive(NoritoSerialize)]
        struct UnboundProof {
            version: u8,
            eligibility_class: PopEligibilityClassV1,
            commitment_root: [u8; 32],
            commitment_tree_version: u64,
            revocation_root: [u8; 32],
            revocation_list_version: u64,
            nullifier: [u8; 32],
            challenge_digest: [u8; 32],
            verifier_context: String,
            proof_system: PopMembershipProofSystemV1,
            verifier_material: PopMembershipVerifierMaterialV1,
            proof_bytes: Vec<u8>,
            expires_at_epoch: u64,
        }
        let proof = &fixture().proof;
        let unbound = UnboundProof {
            version: proof.version,
            eligibility_class: proof.eligibility_class,
            commitment_root: proof.commitment_root,
            commitment_tree_version: proof.commitment_tree_version,
            revocation_root: proof.revocation_root,
            revocation_list_version: proof.revocation_list_version,
            nullifier: proof.nullifier,
            challenge_digest: proof.challenge_digest,
            verifier_context: proof.verifier_context.clone(),
            proof_system: proof.proof_system,
            verifier_material: proof.verifier_material.clone(),
            proof_bytes: proof.proof_bytes.clone(),
            expires_at_epoch: proof.expires_at_epoch,
        };
        // Advertise the real proof schema with its proper alignment/checksum,
        // so rejection exercises the missing field rather than a test type's
        // unrelated schema name.
        let unbound_wire = {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let (payload, flags) = norito::codec::encode_with_header_flags(&unbound);
            norito::core::frame_bare_with_header_flags::<PopMembershipProofV1>(&payload, flags)
                .expect("frame unbound layout as the actual V1 proof schema")
        };
        let error = norito::decode_from_bytes::<PopMembershipProofV1>(&unbound_wire)
            .expect_err("ordinary current-schema decoding must reject an absent proof binding");
        assert!(!matches!(error, norito::Error::SchemaMismatch));
        assert!(norito::decode_canonical::<PopMembershipProofV1>(&unbound_wire).is_err());
        let current_wire = norito::encode_canonical(proof).expect("encode recipient-bound proof");
        assert_eq!(
            norito::decode_canonical::<PopMembershipProofV1>(&current_wire).unwrap(),
            *proof
        );
    }
    #[test]
    fn membership_proof_recipient_changes_preserve_shared_nullifier_scope() {
        let fixture = fixture();
        let other_binding = digest(0x45);
        let proof = prove_pop_membership_v1(
            &fixture.credential,
            &fixture.root,
            &fixture.revocations,
            &PopMembershipWitnessV1 {
                holder_secret: fixture.holder_secret,
                credential_path: fixture.credential_path.clone(),
                revocation_path: fixture.revocation_path.clone(),
            },
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: other_binding,
            },
            500,
        )
        .expect("holder can prove the same credential for a different explicit recipient");
        assert_ne!(
            proof.presentation_binding_digest,
            fixture.proof.presentation_binding_digest
        );
        assert_eq!(
            proof.nullifier, fixture.proof.nullifier,
            "recipient binding must not permit one credential to occupy multiple panel slots"
        );
        assert_eq!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: other_binding
                },
                500,
                &[fixture.proof.nullifier],
            )
            .expect_err("second recipient must hit the shared consumed-nullifier set"),
            PopCredentialValidationError::ReplayedProof,
        );
    }
    #[test]
    fn expired_proofs_are_rejected() {
        let fixture = fixture();
        let err = verify_pop_membership_proof_v1(
            &fixture.proof,
            &fixture.root,
            &fixture.revocations,
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: digest(0x44),
            },
            1_000,
            &[],
        )
        .expect_err("expired proof");
        assert!(matches!(
            err,
            PopCredentialValidationError::ExpiredProof { .. }
        ));
    }
    #[test]
    fn revoked_witnesses_are_rejected_before_proving() {
        let fixture = fixture();
        let mut revocations = fixture.revocations.clone();
        revocations.entries.push(PopRevocationEntryV1 {
            nonce: fixture.credential.revocation_nonce,
            revoked_at_epoch: 200,
            reason: PopRevocationReasonV1::GovernanceSuspension,
        });
        revocations.revocation_root =
            pop_revocation_root_v1(&revocations.entries).expect("revoked root");
        revocations = sign_pop_revocation_list_ed25519_v1(revocations, &signing_key(0x55))
            .expect("resign revocations");
        let err = prove_pop_membership_v1(
            &fixture.credential,
            &fixture.root,
            &revocations,
            &witness_from(fixture),
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: digest(0x44),
            },
            500,
        )
        .expect_err("revoked witness");
        assert_eq!(err, PopCredentialValidationError::RevokedCredential);
        assert_eq!(
            build_pop_revocation_non_membership_path_v1(
                &revocations.entries,
                fixture.credential.revocation_nonce,
            )
            .expect_err("revoked key has no empty-leaf path"),
            PopCredentialValidationError::RevokedCredential
        );
    }
    #[test]
    fn wrong_root_tree_version_class_and_revocation_state_are_rejected() {
        let fixture = fixture();
        let mut proof = fixture.proof.clone();
        proof.commitment_root = scalar(66);
        assert_eq!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .expect_err("wrong root"),
            PopCredentialValidationError::WrongCommitmentRoot
        );
        let mut proof = fixture.proof.clone();
        proof.commitment_tree_version += 1;
        assert_eq!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .expect_err("wrong tree version"),
            PopCredentialValidationError::CommitmentTreeVersionMismatch
        );
        let mut proof = fixture.proof.clone();
        proof.eligibility_class = PopEligibilityClassV1::Expert;
        assert!(matches!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            ),
            Err(PopCredentialValidationError::InvalidMembershipProof { .. })
        ));
        let mut proof = fixture.proof.clone();
        proof.revocation_root = scalar(77);
        assert_eq!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .expect_err("wrong revocation root"),
            PopCredentialValidationError::RevocationRootMismatch
        );
    }
    #[test]
    fn wrong_challenge_and_context_are_rejected_before_crypto() {
        let fixture = fixture();
        assert_eq!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x44),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .expect_err("wrong challenge"),
            PopCredentialValidationError::ChallengeMismatch
        );
        assert_eq!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-2",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .expect_err("wrong context"),
            PopCredentialValidationError::VerifierContextMismatch
        );
    }
    #[test]
    fn wrong_revocation_list_versions_are_rejected() {
        let fixture = fixture();
        let mut proof = fixture.proof.clone();
        proof.revocation_list_version -= 1;
        assert!(matches!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            ),
            Err(PopCredentialValidationError::StaleRevocationList { .. })
        ));
        proof.revocation_list_version += 2;
        assert!(matches!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            ),
            Err(PopCredentialValidationError::RevocationListVersionMismatch { .. })
        ));
    }
    #[test]
    fn replayed_and_tampered_nullifiers_are_rejected() {
        let fixture = fixture();
        assert_eq!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[fixture.proof.nullifier],
            )
            .expect_err("replayed nullifier"),
            PopCredentialValidationError::ReplayedProof
        );
        let mut proof = fixture.proof.clone();
        proof.nullifier = scalar(987_654);
        assert!(matches!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            ),
            Err(PopCredentialValidationError::InvalidMembershipProof { .. })
        ));
    }
    #[test]
    fn malformed_truncated_oversized_and_mutated_proofs_are_rejected() {
        let fixture = fixture();
        let mut proof = fixture.proof.clone();
        proof.proof_bytes.clear();
        assert!(matches!(
            proof.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded { .. })
        ));
        let mut proof = fixture.proof.clone();
        proof.proof_bytes.truncate(proof.proof_bytes.len() / 2);
        assert!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .is_err()
        );
        let mut proof = fixture.proof.clone();
        proof.proof_bytes = vec![0xAA; POP_MEMBERSHIP_PROOF_MAX_BYTES_V1 + 1];
        assert!(matches!(
            proof.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded { .. })
        ));
        let mut proof = fixture.proof.clone();
        let midpoint = proof.proof_bytes.len() / 2;
        proof.proof_bytes[midpoint] ^= 0x80;
        assert!(matches!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            ),
            Err(PopCredentialValidationError::InvalidMembershipProof { .. })
        ));
        let mut proof = fixture.proof.clone();
        proof.proof_bytes.push(0);
        assert!(matches!(
            verify_pop_membership_proof_v1(
                &proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            ),
            Err(PopCredentialValidationError::InvalidMembershipProof { .. })
        ));
    }
    #[test]
    fn pinned_key_and_parameter_material_rejects_tampering() {
        let fixture = fixture();
        for mutation in 0..3 {
            let mut proof = fixture.proof.clone();
            match mutation {
                0 => proof.verifier_material.circuit_k += 1,
                1 => proof.verifier_material.parameter_digest[0] ^= 1,
                _ => proof.verifier_material.verifying_key_digest[0] ^= 1,
            }
            assert!(
                verify_pop_membership_proof_v1(
                    &proof,
                    &fixture.root,
                    &fixture.revocations,
                    PopMembershipPresentationV1 {
                        challenge_digest: digest(0x43),
                        verifier_context: "jury-case-1",
                        presentation_binding_digest: digest(0x44)
                    },
                    500,
                    &[],
                )
                .is_err()
            );
        }
    }
    #[test]
    fn public_input_reordering_is_rejected_by_pipa_r_transcript() {
        let fixture = fixture();
        assert!(matches!(
            zk::verify_with_reordered_public_inputs_for_test(&fixture.proof),
            Err(PopCredentialValidationError::InvalidMembershipProof { .. })
        ));
    }
    #[test]
    fn invalid_holder_secret_and_paths_fail_before_proving() {
        let fixture = fixture();
        let mut witness = witness_from(fixture);
        witness.holder_secret = scalar(999);
        assert_eq!(
            prove_pop_membership_v1(
                &fixture.credential,
                &fixture.root,
                &fixture.revocations,
                &witness,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
            )
            .expect_err("wrong holder secret"),
            PopCredentialValidationError::ProofHolderCommitmentMismatch
        );
        let mut witness = witness_from(fixture);
        witness.credential_path.siblings.pop();
        assert!(matches!(
            witness.validate(),
            Err(PopCredentialValidationError::InvalidMerklePathDepth { .. })
        ));
        let mut witness = witness_from(fixture);
        witness.revocation_path.siblings[0] = scalar(123);
        assert_eq!(
            prove_pop_membership_v1(
                &fixture.credential,
                &fixture.root,
                &fixture.revocations,
                &witness,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
            )
            .expect_err("tampered revocation path"),
            PopCredentialValidationError::RevocationRootMismatch
        );
    }
    #[test]
    fn invalid_tree_depth_nonce_encoding_and_revocation_root_fail_closed() {
        let fixture = fixture();
        let mut root = fixture.root.clone();
        root.tree_depth -= 1;
        assert!(matches!(
            root.validate(),
            Err(PopCredentialValidationError::InvalidTreeDepth { .. })
        ));
        let mut credential = fixture.credential.clone();
        credential.revocation_nonce[31] = 1;
        assert_eq!(
            credential.validate().expect_err("wide nonce"),
            PopCredentialValidationError::InvalidRevocationNonceEncoding
        );
        let mut revocations = fixture.revocations.clone();
        revocations.revocation_root = scalar(1);
        assert_eq!(
            revocations.validate().expect_err("wrong sparse root"),
            PopCredentialValidationError::RevocationRootMismatch
        );
    }
    #[test]
    fn replay_cache_and_context_are_strictly_bounded() {
        let fixture = fixture();
        let seen = vec![[1u8; 32]; POP_MEMBERSHIP_SEEN_NULLIFIERS_MAX_V1 + 1];
        assert_eq!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &fixture.root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &seen,
            )
            .expect_err("oversized replay slice"),
            PopCredentialValidationError::ReplayCacheLimitExceeded
        );
        let mut proof = fixture.proof.clone();
        proof.verifier_context = "x".repeat(POP_MEMBERSHIP_CONTEXT_MAX_BYTES_V1 + 1);
        assert!(matches!(
            proof.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded { .. })
        ));
    }
    #[test]
    fn signed_publication_tampering_is_rejected() {
        let fixture = fixture();
        let mut root = fixture.root.clone();
        root.publisher_signature.signature[10] ^= 1;
        assert!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &root,
                &fixture.revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .is_err()
        );
        let mut revocations = fixture.revocations.clone();
        revocations.publisher_signature.signature[10] ^= 1;
        assert!(
            verify_pop_membership_proof_v1(
                &fixture.proof,
                &fixture.root,
                &revocations,
                PopMembershipPresentationV1 {
                    challenge_digest: digest(0x43),
                    verifier_context: "jury-case-1",
                    presentation_binding_digest: digest(0x44)
                },
                500,
                &[],
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_roots_are_rejected_before_crypto() {
        let fixture = fixture();
        let mut proof = fixture.proof.clone();
        proof.commitment_root = scalar(66);
        let err = verify_pop_membership_proof_v1(
            &proof,
            &fixture.root,
            &fixture.revocations,
            PopMembershipPresentationV1 {
                challenge_digest: digest(0x43),
                verifier_context: "jury-case-1",
                presentation_binding_digest: digest(0x44),
            },
            500,
            &[],
        )
        .expect_err("wrong root");
        assert_eq!(err, PopCredentialValidationError::WrongCommitmentRoot);
    }
    #[test]
    fn revocation_entries_must_be_sorted_and_unique() {
        let mut list = fixture().revocations.clone();
        list.entries = vec![
            PopRevocationEntryV1 {
                nonce: nonce(0x20),
                revoked_at_epoch: 200,
                reason: PopRevocationReasonV1::Rotated,
            },
            PopRevocationEntryV1 {
                nonce: nonce(0x10),
                revoked_at_epoch: 201,
                reason: PopRevocationReasonV1::Rotated,
            },
        ];
        let err = list.validate().expect_err("unsorted list");
        assert_eq!(err, PopCredentialValidationError::UnsortedRevocationList);
        list.entries[1].nonce = nonce(0x20);
        let err = list.validate().expect_err("duplicate nonce");
        assert_eq!(err, PopCredentialValidationError::DuplicateRevocationNonce);
    }
    #[test]
    fn identity_text_and_attribute_collections_are_strictly_bounded() {
        let mut credential = fixture().credential.clone();
        credential.issuer_id = "i".repeat(POP_IDENTITY_TEXT_MAX_BYTES_V1 + 1);
        assert!(matches!(
            credential.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "issuer id",
                ..
            })
        ));
        let mut credential = fixture().credential.clone();
        credential.attributes = (0..=POP_CREDENTIAL_ATTRIBUTES_MAX_V1)
            .map(|index| PopCredentialAttributeV1 {
                key: format!("attribute-{index}"),
                value_commitment: digest(0xA1),
            })
            .collect();
        assert!(matches!(
            credential.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "credential attributes",
                ..
            })
        ));
        let mut credential = fixture().credential.clone();
        credential.attributes[0].key = "k".repeat(POP_ATTRIBUTE_KEY_MAX_BYTES_V1 + 1);
        assert!(matches!(
            credential.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "attribute key",
                ..
            })
        ));
        let request = PopEnrollmentRequestV1 {
            version: POP_ENROLLMENT_REQUEST_VERSION_V1,
            request_id: digest(0xA2),
            applicant_id: "applicant".to_owned(),
            requested_class: PopEligibilityClassV1::General,
            requested_attributes: (0..=POP_REQUESTED_ATTRIBUTES_MAX_V1)
                .map(|index| format!("attribute-{index}"))
                .collect(),
            attestation_digest: digest(0xA3),
            submitted_at_epoch: 1,
            expires_at_epoch: 2,
        };
        assert!(matches!(
            request.validate(),
            Err(PopCredentialValidationError::ResourceLimitExceeded {
                resource: "requested attributes",
                ..
            })
        ));
    }
}

#[cfg(test)]
include!("pop_credentials/captured_owner_identity_tests.rs");

#[cfg(test)]
#[path = "pop_credentials/borrowed_payload_tests.rs"]
mod borrowed_payload_tests;

#[cfg(test)]
#[path = "pop_credentials/signing_identity_tests.rs"]
pub(crate) mod signing_identity_tests;
