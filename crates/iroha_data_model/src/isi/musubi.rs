//! First-release Musubi registry instructions.
//!
//! These instructions intentionally have no pre-release compatibility aliases.
//! Every mutable operation carries an explicit compare-and-set or policy
//! revision, and Parliament recovery carries an exact action-bound decision.
use super::*;
use crate::musubi::{
    ArchiveId, MUSUBI_MAX_PACKAGE_OWNERS_V1, MusubiAliasNameV1, MusubiArchiveCommitmentV1,
    MusubiArchiveLocationIdV1, MusubiGovernanceDecisionV1, MusubiNamespaceBindingV1,
    MusubiNamespaceDelegationV1, MusubiNamespaceV1, MusubiPackageIdV1, MusubiPackageRoleV1,
    MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1, MusubiPinOutboxHighWaterV1,
    MusubiProviderBundleAttestationSetDigestV1, MusubiProviderBundleVerificationAttestationV1,
    MusubiPublicationV1, MusubiReasonV1, MusubiRegistryPolicyV1, MusubiReleaseDigestV1,
    MusubiReleaseIdV1, MusubiReleaseMetadataV1, MusubiSeedIngressReceiptV1,
    validate_musubi_account_id_v1,
};
use crate::sorafs::pin_registry::{ManifestDigest, ReplicationOrderId};
use iroha_model_base::error::ParseError;

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
isi! {
    /// Register one immutable namespace-to-home-dataspace binding.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RegisterMusubiNamespaceBindingV1")]
    pub struct RegisterMusubiNamespaceBindingV1 {
        /// Immutable namespace binding.
        pub binding: MusubiNamespaceBindingV1,
        /// Exact registry-policy revision observed by the submitter.
        pub expected_policy_revision: u64,
    }
}
impl RegisterMusubiNamespaceBindingV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.namespace_binding.register";
    /// Construct an immutable namespace-binding registration.
    #[must_use]
    pub const fn new(binding: MusubiNamespaceBindingV1, expected_policy_revision: u64) -> Self {
        Self {
            binding,
            expected_policy_revision,
        }
    }
}
impl crate::seal::Instruction for RegisterMusubiNamespaceBindingV1 {}
isi! {
    /// Register an immutable source archive commitment.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RegisterMusubiArchiveV1")]
    pub struct RegisterMusubiArchiveV1 {
        /// Complete commitment whose domain-separated hash is the archive id.
        pub commitment: MusubiArchiveCommitmentV1,
        /// Signed, unexpired receipt for the exact CAR accepted by authenticated seed ingress.
        pub staging_receipt: MusubiSeedIngressReceiptV1,
        /// Exact registry-policy revision observed by the submitter.
        pub expected_policy_revision: u64,
    }
}
impl RegisterMusubiArchiveV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.archive.register";
    /// Construct an archive registration.
    #[must_use]
    pub const fn new(
        commitment: MusubiArchiveCommitmentV1,
        staging_receipt: MusubiSeedIngressReceiptV1,
        expected_policy_revision: u64,
    ) -> Self {
        Self {
            commitment,
            staging_receipt,
            expected_policy_revision,
        }
    }
}
impl crate::seal::Instruction for RegisterMusubiArchiveV1 {}
isi! {
    /// Advance one publisher's complete immutable signed pin-intent inventory high-water.
    ///
    /// The signer submits this instruction and waits for finality before any represented pin
    /// transaction can enter Queue. The instruction carries no private signed wire.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::AdvanceMusubiPinOutboxV1")]
    pub struct AdvanceMusubiPinOutboxV1 {
        /// Exact deployment identity.
        pub network_id: crate::NetworkId,
        /// Signed transaction authority that owns this monotonic lineage.
        pub pin_authority: AccountId,
        /// Immutable signing-session identity.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub session_id: [u8; 32],
        /// Exact current revision, or zero only before initialization.
        pub expected_revision: u64,
        /// Exact current complete inventory digest, or zero only before initialization.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub expected_inventory_digest: [u8; 32],
        /// Digest of the complete next inventory, including every retained signed wire.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub inventory_digest: [u8; 32],
    }
}
impl AdvanceMusubiPinOutboxV1 {
    /// First-release wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.pin_outbox.advance";

    /// Validate the self-contained signed instruction fields.
    ///
    /// # Errors
    /// Rejects malformed identity, lineage, predecessor, or next digest.
    pub fn validate(&self) -> Result<(), ParseError> {
        validate_musubi_account_id_v1(&self.pin_authority)?;
        self.validate_fields()
    }

    /// Validate lineage fields after the native owner has bounded the signed authority.
    ///
    /// # Errors
    /// Rejects malformed network, session, predecessor, or next inventory bindings.
    pub fn validate_fields(&self) -> Result<(), ParseError> {
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.session_id == [0; 32]
            || self.inventory_digest == [0; 32]
            || self.inventory_digest == self.expected_inventory_digest
            || (self.expected_revision == 0) != (self.expected_inventory_digest == [0; 32])
        {
            return Err(ParseError::new("Musubi pin-outbox advance is invalid"));
        }
        Ok(())
    }

    /// Build the exact value committed by a successful signed transaction.
    ///
    /// # Errors
    /// Rejects malformed fields, revision overflow, or an invalid finality context.
    pub fn recorded_high_water(
        &self,
        recorded_at_height: u64,
        transaction_hash: [u8; 32],
    ) -> Result<MusubiPinOutboxHighWaterV1, ParseError> {
        self.validate()?;
        let revision = self
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| ParseError::new("Musubi pin-outbox revision overflow"))?;
        let record = MusubiPinOutboxHighWaterV1 {
            version: crate::musubi::MUSUBI_PIN_OUTBOX_HIGH_WATER_VERSION_V1,
            network_id: self.network_id,
            pin_authority: self.pin_authority.clone(),
            session_id: self.session_id,
            revision,
            inventory_digest: self.inventory_digest,
            recorded_at_height,
            transaction_hash,
        };
        record.validate()?;
        Ok(record)
    }
}
impl crate::seal::Instruction for AdvanceMusubiPinOutboxV1 {}
/// Maximum canonical Check instruction frame, before any native history read.
pub const MUSUBI_PIN_OUTBOX_CHECK_MAX_BYTES_V1: usize = 4 * 1024;
/// Maximum original signed External envelope for either native pin-outbox operation.
pub const MUSUBI_PIN_OUTBOX_EXTERNAL_MAX_BYTES_V1: usize = 64 * 1024;
isi! {
    /// Read one authority's exact high-water under a fresh signed challenge and native floor.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::CheckMusubiPinOutboxV1")]
    pub struct CheckMusubiPinOutboxV1 {
        /// Exact deployment identity.
        pub network_id: crate::NetworkId,
        /// Sole signed authority whose entire high-water row is checked.
        pub pin_authority: AccountId,
        /// Independently retained local session, including when expecting absence.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub session_id: [u8; 32],
        /// Independently retained complete local inventory, including when expecting absence.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub inventory_digest: [u8; 32],
        /// Fresh one-round challenge generated by the native reader.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub challenge: [u8; 32],
        /// Original committed native execution below this Check.
        pub floor: MusubiPinOutboxCheckFloorV1,
        /// Authority-wide absence or complete current row equality.
        pub expected: MusubiPinOutboxCheckExpectationV1,
    }
}
impl CheckMusubiPinOutboxV1 {
    /// First-release wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.pin_outbox.check";

    /// Validate the complete bounded signed assertion without authenticating its floor.
    ///
    /// # Errors
    /// Rejects inert bindings, inconsistent expected rows, or oversized canonical frames.
    pub fn validate(&self) -> Result<(), ParseError> {
        validate_musubi_account_id_v1(&self.pin_authority)?;
        self.validate_fields()?;
        if norito::canonical_frame_len(self)
            .map_err(|_| ParseError::new("Musubi pin-outbox Check frame is invalid"))?
            > MUSUBI_PIN_OUTBOX_CHECK_MAX_BYTES_V1
        {
            return Err(ParseError::new(
                "Musubi pin-outbox Check frame exceeds its bound",
            ));
        }
        Ok(())
    }

    /// Validate signed bindings after the native owner has fallibly bounded the complete frame.
    /// This pure field check performs no encoding, cloning, or local history reads.
    ///
    /// # Errors
    /// Rejects inert coordinates or a complete expected row inconsistent with the outer binding.
    pub fn validate_fields(&self) -> Result<(), ParseError> {
        self.floor.validate()?;
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.session_id == [0; 32]
            || self.inventory_digest == [0; 32]
            || self.challenge == [0; 32]
        {
            return Err(ParseError::new(
                "Musubi pin-outbox Check binding is invalid",
            ));
        }
        if let MusubiPinOutboxCheckExpectationV1::Present(row) = &self.expected {
            row.validate_fields()?;
            if row.network_id != self.network_id
                || row.pin_authority != self.pin_authority
                || row.session_id != self.session_id
                || row.inventory_digest != self.inventory_digest
            {
                return Err(ParseError::new(
                    "Musubi pin-outbox Check expected row binding differs",
                ));
            }
        }
        Ok(())
    }
}
impl crate::seal::Instruction for CheckMusubiPinOutboxV1 {}
isi! {
    /// Register one immutable provider attestation for later compact location-set commitments.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RegisterMusubiProviderBundleAttestationV1")]
    pub struct RegisterMusubiProviderBundleAttestationV1 {
        /// Exactly one complete signed provider bundle-verification attestation.
        pub attestation: MusubiProviderBundleVerificationAttestationV1,
        /// Compare-and-set archive location revision authorizing this staged attestation.
        pub expected_location_revision: u64,
    }
}
impl RegisterMusubiProviderBundleAttestationV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.provider_bundle_attestation.register";
    /// Construct a manager-relayable immutable provider-attestation registration.
    #[must_use]
    pub const fn new(
        attestation: MusubiProviderBundleVerificationAttestationV1,
        expected_location_revision: u64,
    ) -> Self {
        Self {
            attestation,
            expected_location_revision,
        }
    }
    /// Validate the complete attestation and location revision before immutable registration.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the attestation is invalid or the expected
    /// location revision is zero.
    pub fn validate(&self) -> Result<(), ParseError> {
        self.attestation.validate()?;
        if self.expected_location_revision == 0 {
            return Err(ParseError::new(
                "Musubi provider attestation location revision must be nonzero",
            ));
        }
        Ok(())
    }
}
impl crate::seal::Instruction for RegisterMusubiProviderBundleAttestationV1 {}
isi! {
    /// Add or renew one `SoraFS` location for a registered archive.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::AddMusubiArchiveLocationV1")]
    pub struct AddMusubiArchiveLocationV1 {
        /// Registered archive identity.
        pub archive_id: ArchiveId,
        /// Stable location identity.
        pub location_id: MusubiArchiveLocationIdV1,
        /// Registry-grade `SoraFS` pin manifest.
        pub pin_manifest: ManifestDigest,
        /// Replication order whose finalized completions prove availability.
        pub replication_order: ReplicationOrderId,
        /// Digest of the sorted independently registered provider-attestation set.
        pub provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
        /// Earliest epoch at which renewal should occur.
        pub renew_after_epoch: u64,
        /// Epoch after which the location is invalid.
        pub expires_at_epoch: u64,
        /// Compare-and-set archive location revision.
        pub expected_location_revision: u64,
    }
}
impl AddMusubiArchiveLocationV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.archive_location.add";
    /// Validate exact archive/location identities, attestation-set commitment, and renewal bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when an identity or digest is zero, the renewal
    /// bounds are invalid, or the expected location revision is zero.
    pub fn validate(&self) -> Result<(), ParseError> {
        if self.archive_id.is_zero()
            || self.location_id.is_zero()
            || self.pin_manifest.as_bytes().iter().all(|byte| *byte == 0)
            || self
                .replication_order
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.provider_attestation_set_digest.is_zero()
            || self.renew_after_epoch >= self.expires_at_epoch
            || self.expected_location_revision == 0
        {
            return Err(ParseError::new(
                "Musubi archive location request is invalid or noncanonical",
            ));
        }
        Ok(())
    }
}
impl crate::seal::Instruction for AddMusubiArchiveLocationV1 {}
isi! {
    /// Retire one archive location without changing archive or release identity.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RetireMusubiArchiveLocationV1")]
    pub struct RetireMusubiArchiveLocationV1 {
        /// Registered archive identity.
        pub archive_id: ArchiveId,
        /// Exact location to retire.
        pub location_id: MusubiArchiveLocationIdV1,
        /// Compare-and-set archive location revision.
        pub expected_location_revision: u64,
        /// Bounded public retirement reason.
        pub reason: MusubiReasonV1,
    }
}
impl RetireMusubiArchiveLocationV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.archive_location.retire";
}
impl crate::seal::Instruction for RetireMusubiArchiveLocationV1 {}
isi! {
    /// Claim an absent package if authorized and publish one immutable release.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::PublishMusubiReleaseV1")]
    pub struct PublishMusubiReleaseV1 {
        /// Exact canonical namespace whose immutable binding authorizes the package claim.
        pub namespace: MusubiNamespaceV1,
        /// Immutable release plus bounded exact publication proof.
        pub publication: MusubiPublicationV1,
        /// Optional generation-bound namespace delegation for the first claim.
        pub namespace_delegation: Option<MusubiNamespaceDelegationV1>,
        /// Exact registry-policy revision observed by the publisher.
        pub expected_policy_revision: u64,
        /// Existing-package governance revision; absent only for the first claim.
        pub expected_governance_revision: Option<u64>,
    }
}
impl PublishMusubiReleaseV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.release.publish";
    /// Construct a publication request.
    #[must_use]
    pub const fn new(
        namespace: MusubiNamespaceV1,
        publication: MusubiPublicationV1,
        namespace_delegation: Option<MusubiNamespaceDelegationV1>,
        expected_policy_revision: u64,
        expected_governance_revision: Option<u64>,
    ) -> Self {
        Self {
            namespace,
            publication,
            namespace_delegation,
            expected_policy_revision,
            expected_governance_revision,
        }
    }
}
impl crate::seal::Instruction for PublishMusubiReleaseV1 {}
isi! {
    /// Yank or unyank an immutable release.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::SetMusubiReleaseYankV1")]
    pub struct SetMusubiReleaseYankV1 {
        /// Exact immutable release.
        pub release: MusubiReleaseIdV1,
        /// `true` yanks; `false` unyanks.
        pub yanked: bool,
        /// Bounded public transition reason.
        pub reason: MusubiReasonV1,
        /// Compare-and-set yank revision.
        pub expected_yank_revision: u64,
    }
}
impl SetMusubiReleaseYankV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.release_yank.set";
    /// Construct a reversible yank transition.
    #[must_use]
    pub const fn new(
        release: MusubiReleaseIdV1,
        yanked: bool,
        reason: MusubiReasonV1,
        expected_yank_revision: u64,
    ) -> Self {
        Self {
            release,
            yanked,
            reason,
            expected_yank_revision,
        }
    }
}
impl crate::seal::Instruction for SetMusubiReleaseYankV1 {}
isi! {
    /// Replace the mutable package metadata projection.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::SetMusubiPackageMetadataV1")]
    pub struct SetMusubiPackageMetadataV1 {
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Complete replacement metadata.
        pub metadata: MusubiReleaseMetadataV1,
        /// Compare-and-set metadata revision.
        pub expected_metadata_revision: u64,
    }
}
impl SetMusubiPackageMetadataV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.package_metadata.set";
}
impl crate::seal::Instruction for SetMusubiPackageMetadataV1 {}
isi! {
    /// Invite an account to an owner or maintainer role.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::InviteMusubiPackageMaintainerV1")]
    pub struct InviteMusubiPackageMaintainerV1 {
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Stable invitation identity.
        pub invite_id: crate::musubi::MusubiInviteIdV1,
        /// Account that alone may accept.
        pub invited_account: AccountId,
        /// Offered role.
        pub role: MusubiPackageRoleV1,
        /// Last height at which the invite may be accepted.
        pub expires_at_height: u64,
        /// Compare-and-set governance revision.
        pub expected_governance_revision: u64,
    }
}
impl InviteMusubiPackageMaintainerV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.package_member.invite";
    /// Validate the structural invitation and bounded invited account identity.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the package, account, invitation identity,
    /// expiry, role, or expected governance revision is invalid.
    pub fn validate(&self) -> Result<(), ParseError> {
        self.package.validate()?;
        validate_musubi_account_id_v1(&self.invited_account)?;
        if self.invite_id.is_zero()
            || self.expires_at_height == 0
            || self.expected_governance_revision == 0
            || matches!(self.role, MusubiPackageRoleV1::Maintainer(role) if role.is_empty())
        {
            return Err(ParseError::new("Musubi package invitation is invalid"));
        }
        Ok(())
    }
}
impl crate::seal::Instruction for InviteMusubiPackageMaintainerV1 {}
isi! {
    /// Accept a pending package role invitation as its invited account.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::AcceptMusubiPackageMaintainerV1")]
    pub struct AcceptMusubiPackageMaintainerV1 {
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Exact invitation identity.
        pub invite_id: crate::musubi::MusubiInviteIdV1,
        /// Compare-and-set governance revision.
        pub expected_governance_revision: u64,
    }
}
impl AcceptMusubiPackageMaintainerV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.package_member.accept";
}
impl crate::seal::Instruction for AcceptMusubiPackageMaintainerV1 {}
isi! {
    /// Revoke a pending package role invitation as a current package owner.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RevokeMusubiPackageMaintainerInvitationV1")]
    pub struct RevokeMusubiPackageMaintainerInvitationV1 {
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Exact pending invitation identity.
        pub invite_id: crate::musubi::MusubiInviteIdV1,
        /// Compare-and-set governance revision.
        pub expected_governance_revision: u64,
    }
}
impl RevokeMusubiPackageMaintainerInvitationV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.package_member.invitation.revoke";
}
impl crate::seal::Instruction for RevokeMusubiPackageMaintainerInvitationV1 {}
isi! {
    /// Change an accepted package member's role.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::SetMusubiPackageMaintainerRoleV1")]
    pub struct SetMusubiPackageMaintainerRoleV1 {
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Accepted member account.
        pub account: AccountId,
        /// Complete replacement role.
        pub role: MusubiPackageRoleV1,
        /// Compare-and-set governance revision.
        pub expected_governance_revision: u64,
    }
}
impl SetMusubiPackageMaintainerRoleV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.package_member.set_role";
    /// Validate the package, bounded member account, role, and revision.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the package or account is invalid, the role
    /// label is empty, or the expected governance revision is zero.
    pub fn validate(&self) -> Result<(), ParseError> {
        self.package.validate()?;
        validate_musubi_account_id_v1(&self.account)?;
        if self.expected_governance_revision == 0
            || matches!(self.role, MusubiPackageRoleV1::Maintainer(role) if role.is_empty())
        {
            return Err(ParseError::new(
                "Musubi package maintainer role request is invalid",
            ));
        }
        Ok(())
    }
}
impl crate::seal::Instruction for SetMusubiPackageMaintainerRoleV1 {}
isi! {
    /// Remove an accepted package member while preserving the last owner.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RemoveMusubiPackageMaintainerV1")]
    pub struct RemoveMusubiPackageMaintainerV1 {
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Accepted member account to remove.
        pub account: AccountId,
        /// Compare-and-set governance revision.
        pub expected_governance_revision: u64,
    }
}
impl RemoveMusubiPackageMaintainerV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.package_member.remove";
    /// Validate the package, bounded member account, and revision.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the package or account is invalid or the
    /// expected governance revision is zero.
    pub fn validate(&self) -> Result<(), ParseError> {
        self.package.validate()?;
        validate_musubi_account_id_v1(&self.account)?;
        if self.expected_governance_revision == 0 {
            return Err(ParseError::new(
                "Musubi package maintainer removal request is invalid",
            ));
        }
        Ok(())
    }
}
impl crate::seal::Instruction for RemoveMusubiPackageMaintainerV1 {}
isi! {
    /// Register a paid permanent global package alias.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RegisterMusubiAliasV1")]
    pub struct RegisterMusubiAliasV1 {
        /// Permanent lowercase ASCII kebab alias.
        pub alias: MusubiAliasNameV1,
        /// Package target normalized before submission.
        pub target: MusubiPackageIdV1,
        /// Exact prospective pricing-policy revision.
        pub expected_pricing_revision: u64,
    }
}
impl RegisterMusubiAliasV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.alias.register";
    /// Construct a permanent alias registration.
    #[must_use]
    pub const fn new(
        alias: MusubiAliasNameV1,
        target: MusubiPackageIdV1,
        expected_pricing_revision: u64,
    ) -> Self {
        Self {
            alias,
            target,
            expected_pricing_revision,
        }
    }
}
impl crate::seal::Instruction for RegisterMusubiAliasV1 {}
isi! {
    /// Apply an enacted Parliament package-owner recovery.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RecoverMusubiPackageV1")]
    pub struct RecoverMusubiPackageV1 {
        /// Enacted, action-digest-bound decision.
        pub decision: MusubiGovernanceDecisionV1,
        /// Stable package identity.
        pub package: MusubiPackageIdV1,
        /// Sorted replacement owner set.
        pub owners: Vec<AccountId>,
        /// Compare-and-set governance revision.
        pub expected_governance_revision: u64,
    }
}
impl RecoverMusubiPackageV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.parliament.package_recover";
    /// Validate the enacted decision shape and bounded replacement-owner set.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the decision, package, owner set, account
    /// identity, or expected governance revision is invalid.
    pub fn validate(&self) -> Result<(), ParseError> {
        self.decision.validate()?;
        self.package.validate()?;
        if self.owners.is_empty()
            || self.owners.len() > MUSUBI_MAX_PACKAGE_OWNERS_V1
            || self.owners.windows(2).any(|pair| pair[0] >= pair[1])
            || self.expected_governance_revision == 0
        {
            return Err(ParseError::new(
                "Musubi Parliament package recovery request is invalid",
            ));
        }
        self.owners
            .iter()
            .try_for_each(validate_musubi_account_id_v1)
    }
}
impl crate::seal::Instruction for RecoverMusubiPackageV1 {}
isi! {
    /// Apply an enacted Parliament retarget of a permanent alias.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::RetargetMusubiAliasV1")]
    pub struct RetargetMusubiAliasV1 {
        /// Enacted, action-digest-bound decision.
        pub decision: MusubiGovernanceDecisionV1,
        /// Permanent alias.
        pub alias: MusubiAliasNameV1,
        /// New structural target.
        pub target: MusubiPackageIdV1,
        /// Compare-and-set alias-history revision.
        pub expected_history_revision: u64,
    }
}
impl RetargetMusubiAliasV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.parliament.alias_retarget";
}
impl crate::seal::Instruction for RetargetMusubiAliasV1 {}
isi! {
    /// Apply an enacted Parliament artifact takedown.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::SetMusubiArtifactTakedownV1")]
    pub struct SetMusubiArtifactTakedownV1 {
        /// Enacted, action-digest-bound decision.
        pub decision: MusubiGovernanceDecisionV1,
        /// Exact immutable release.
        pub release: MusubiReleaseIdV1,
        /// Bounded public takedown reason.
        pub reason: MusubiReasonV1,
        /// Compare-and-set artifact-governance revision.
        pub expected_artifact_governance_revision: u64,
    }
}
impl SetMusubiArtifactTakedownV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.parliament.artifact_takedown";
}
impl crate::seal::Instruction for SetMusubiArtifactTakedownV1 {}
isi! {
    /// Replace the prospective registry admission and alias pricing policy.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::SetMusubiRegistryPolicyV1")]
    pub struct SetMusubiRegistryPolicyV1 {
        /// Enacted, action-digest-bound decision.
        pub decision: MusubiGovernanceDecisionV1,
        /// Complete replacement policy.
        pub policy: MusubiRegistryPolicyV1,
        /// Compare-and-set current policy revision.
        pub expected_policy_revision: u64,
    }
}
impl SetMusubiRegistryPolicyV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.parliament.registry_policy.set";
}
impl crate::seal::Instruction for SetMusubiRegistryPolicyV1 {}
isi! {
    /// Assert an exact immutable release digest.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::musubi::AssertMusubiReleaseDigestV1")]
    pub struct AssertMusubiReleaseDigestV1 {
        /// Exact release identity.
        pub release: MusubiReleaseIdV1,
        /// Required immutable digest.
        pub expected_digest: MusubiReleaseDigestV1,
    }
}
impl AssertMusubiReleaseDigestV1 {
    /// First-release stable wire identifier.
    pub const WIRE_ID: &'static str = "iroha.musubi.v1.release_digest.assert";
    /// Construct an exact release digest assertion.
    #[must_use]
    pub const fn new(release: MusubiReleaseIdV1, expected_digest: MusubiReleaseDigestV1) -> Self {
        Self {
            release,
            expected_digest,
        }
    }
}
impl crate::seal::Instruction for AssertMusubiReleaseDigestV1 {}

impl_aos_decode_from_slice!(RegisterMusubiNamespaceBindingV1 {
    binding: MusubiNamespaceBindingV1,
    expected_policy_revision: u64,
});
impl_aos_decode_from_slice!(RegisterMusubiArchiveV1 {
    commitment: MusubiArchiveCommitmentV1,
    staging_receipt: MusubiSeedIngressReceiptV1,
    expected_policy_revision: u64,
});
impl_aos_decode_from_slice!(AdvanceMusubiPinOutboxV1 {
    network_id: crate::NetworkId,
    pin_authority: AccountId,
    session_id: [u8; 32],
    expected_revision: u64,
    expected_inventory_digest: [u8; 32],
    inventory_digest: [u8; 32],
});
impl_aos_decode_from_slice!(CheckMusubiPinOutboxV1 {
    network_id: crate::NetworkId,
    pin_authority: AccountId,
    session_id: [u8; 32],
    inventory_digest: [u8; 32],
    challenge: [u8; 32],
    floor: MusubiPinOutboxCheckFloorV1,
    expected: MusubiPinOutboxCheckExpectationV1,
});
impl_aos_decode_from_slice!(RegisterMusubiProviderBundleAttestationV1 {
    attestation: MusubiProviderBundleVerificationAttestationV1,
    expected_location_revision: u64,
});
impl_aos_decode_from_slice!(AddMusubiArchiveLocationV1 {
    archive_id: ArchiveId,
    location_id: MusubiArchiveLocationIdV1,
    pin_manifest: ManifestDigest,
    replication_order: ReplicationOrderId,
    provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
    renew_after_epoch: u64,
    expires_at_epoch: u64,
    expected_location_revision: u64,
});
impl_aos_decode_from_slice!(RetireMusubiArchiveLocationV1 {
    archive_id: ArchiveId,
    location_id: MusubiArchiveLocationIdV1,
    expected_location_revision: u64,
    reason: MusubiReasonV1,
});
impl_aos_decode_from_slice!(PublishMusubiReleaseV1 {
    namespace: MusubiNamespaceV1,
    publication: MusubiPublicationV1,
    namespace_delegation: Option<MusubiNamespaceDelegationV1>,
    expected_policy_revision: u64,
    expected_governance_revision: Option<u64>,
});
impl_aos_decode_from_slice!(SetMusubiReleaseYankV1 {
    release: MusubiReleaseIdV1,
    yanked: bool,
    reason: MusubiReasonV1,
    expected_yank_revision: u64,
});
impl_aos_decode_from_slice!(SetMusubiPackageMetadataV1 {
    package: MusubiPackageIdV1,
    metadata: MusubiReleaseMetadataV1,
    expected_metadata_revision: u64,
});
impl_aos_decode_from_slice!(InviteMusubiPackageMaintainerV1 {
    package: MusubiPackageIdV1,
    invite_id: crate::musubi::MusubiInviteIdV1,
    invited_account: AccountId,
    role: MusubiPackageRoleV1,
    expires_at_height: u64,
    expected_governance_revision: u64,
});
impl_aos_decode_from_slice!(AcceptMusubiPackageMaintainerV1 {
    package: MusubiPackageIdV1,
    invite_id: crate::musubi::MusubiInviteIdV1,
    expected_governance_revision: u64,
});
impl_aos_decode_from_slice!(RevokeMusubiPackageMaintainerInvitationV1 {
    package: MusubiPackageIdV1,
    invite_id: crate::musubi::MusubiInviteIdV1,
    expected_governance_revision: u64,
});
impl_aos_decode_from_slice!(SetMusubiPackageMaintainerRoleV1 {
    package: MusubiPackageIdV1,
    account: AccountId,
    role: MusubiPackageRoleV1,
    expected_governance_revision: u64,
});
impl_aos_decode_from_slice!(RemoveMusubiPackageMaintainerV1 {
    package: MusubiPackageIdV1,
    account: AccountId,
    expected_governance_revision: u64,
});
impl_aos_decode_from_slice!(RegisterMusubiAliasV1 {
    alias: MusubiAliasNameV1,
    target: MusubiPackageIdV1,
    expected_pricing_revision: u64,
});
impl_aos_decode_from_slice!(RecoverMusubiPackageV1 {
    decision: MusubiGovernanceDecisionV1,
    package: MusubiPackageIdV1,
    owners: Vec<AccountId>,
    expected_governance_revision: u64,
});
impl_aos_decode_from_slice!(RetargetMusubiAliasV1 {
    decision: MusubiGovernanceDecisionV1,
    alias: MusubiAliasNameV1,
    target: MusubiPackageIdV1,
    expected_history_revision: u64,
});
impl_aos_decode_from_slice!(SetMusubiArtifactTakedownV1 {
    decision: MusubiGovernanceDecisionV1,
    release: MusubiReleaseIdV1,
    reason: MusubiReasonV1,
    expected_artifact_governance_revision: u64,
});
impl_aos_decode_from_slice!(SetMusubiRegistryPolicyV1 {
    decision: MusubiGovernanceDecisionV1,
    policy: MusubiRegistryPolicyV1,
    expected_policy_revision: u64,
});
impl_aos_decode_from_slice!(AssertMusubiReleaseDigestV1 {
    release: MusubiReleaseIdV1,
    expected_digest: MusubiReleaseDigestV1,
});
#[cfg(test)]
pub(crate) mod generated_identity_values;
#[cfg(test)]
mod pin_outbox_check_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::assert_slice_roundtrip;
    use crate::{
        account::{MultisigMember, MultisigPolicy},
        block::BlockHeader,
        musubi::{
            ArchiveId, MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1, MUSUBI_REGISTRY_VERSION_V1,
            MusubiAbiBindingV1, MusubiContentDigestV1, MusubiKotodamaEditionV1,
            MusubiPackageScopeV1, MusubiProviderBundleAttestationSetDigestV1,
            MusubiProviderBundleVerificationApprovalV1,
            MusubiProviderBundleVerificationAttestationV1,
            MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
            MusubiRegistrySnapshotV1, MusubiReleaseManifestV1, MusubiReleaseMetadataV1,
            MusubiResolutionProofV1, MusubiSemanticReleaseDigestV1, MusubiVerificationLockDigestV1,
            MusubiVerificationLockV1, musubi_provider_bundle_attestation_set_digest_v1,
        },
        sorafs::{
            capacity::ProviderId,
            pin_registry::{
                ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
                ProviderIngestFinalizedAnchorV1,
            },
        },
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
    use iroha_model_base::topology::DataSpaceId;
    fn package() -> MusubiPackageIdV1 {
        MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "math".parse().expect("package name"),
        )
    }
    fn release() -> MusubiReleaseIdV1 {
        MusubiReleaseIdV1::new(package(), "1.2.3".parse().expect("version"))
    }
    #[test]
    fn pin_outbox_advance_record_binds_all_lineage_fields_and_roundtrips() {
        let keypair = KeyPair::try_from_seed(vec![0x41; 32], Algorithm::Ed25519)
            .expect("pin authority keypair");
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = crate::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0x42; 32])),
        );
        let mut advance = AdvanceMusubiPinOutboxV1 {
            network_id,
            pin_authority: authority.clone(),
            session_id: [0x43; 32],
            expected_revision: 0,
            expected_inventory_digest: [0; 32],
            inventory_digest: [0x44; 32],
        };
        advance.validate().expect("initial advance is canonical");
        assert_slice_roundtrip(advance.clone());
        let record = advance
            .recorded_high_water(7, [0x45; 32])
            .expect("derived high-water");
        assert_eq!(record.pin_authority, authority);
        assert_eq!(record.revision, 1);
        record.validate().expect("derived record is valid");
        advance.expected_revision = 1;
        assert!(
            advance.validate().is_err(),
            "predecessor digest is required"
        );
        advance.expected_inventory_digest = record.inventory_digest;
        advance.inventory_digest = record.inventory_digest;
        assert!(
            advance.validate().is_err(),
            "unchanged inventory cannot ratchet"
        );
        advance.inventory_digest = [0; 32];
        assert!(advance.validate().is_err(), "next digest must be nonzero");
        advance.inventory_digest = [0x46; 32];
        assert_eq!(
            advance
                .recorded_high_water(8, [0x47; 32])
                .expect("successor record")
                .revision,
            2
        );
        assert!(advance.recorded_high_water(0, [0x47; 32]).is_err());
        assert!(advance.recorded_high_water(8, [0; 32]).is_err());
        advance.expected_revision = u64::MAX;
        assert!(advance.recorded_high_water(8, [0x47; 32]).is_err());
    }
    fn provider_attestation() -> MusubiProviderBundleVerificationAttestationV1 {
        let keypair =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("provider keypair");
        let owner = AccountId::new(keypair.public_key().clone());
        let binding = MusubiProviderBundleVerificationBindingV1 {
            network_id: crate::NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0x52; 32])),
            ),
            provider_id: ProviderId::new([0x53; 32]),
            completed_by: owner.clone(),
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                owner.clone(),
                owner,
                ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: [0x54; 32],
                    revision: 1,
                    predecessor_digest: None,
                    policy_digest: [0x55; 32],
                },
            ),
            replication_order: ReplicationOrderId::new([0x56; 32]),
            assignment_revision: 1,
            completion_epoch: 2,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 3,
                block_hash: [0x57; 32],
            },
            archive_id: ArchiveId::new([0x58; 32]),
            bundle_digest: MusubiContentDigestV1::new([0x59; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x5A; 32]),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([0x5B; 32]),
            verification_lock_digest: MusubiVerificationLockDigestV1::new([0x5C; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x5D; 32]),
        };
        let payload = MusubiProviderBundleVerificationPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            binding,
        };
        let attestation = MusubiProviderBundleVerificationAttestationV1 {
            approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                public_key: keypair.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    keypair.private_key(),
                    payload.signing_hash(),
                )
                .expect("provider approval"),
            }],
            payload,
        };
        attestation.validate().expect("provider attestation");
        attestation
    }
    fn oversized_account() -> AccountId {
        let members = (0_u16..256)
            .map(|index| {
                let mut seed = [0xB5; 32];
                seed[..2].copy_from_slice(&index.to_le_bytes());
                let keypair = KeyPair::try_from_seed(seed.to_vec(), Algorithm::Ed25519)
                    .expect("oversized account keypair");
                MultisigMember::new(keypair.public_key().clone(), 1)
                    .expect("oversized account member")
            })
            .collect();
        let account = AccountId::new_multisig(
            MultisigPolicy::new(1, members).expect("oversized account controller"),
        );
        assert!(
            norito::to_bytes(&account)
                .expect("account canonical encoding")
                .len()
                > MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1
        );
        account
    }
    #[test]
    fn exact_digest_and_reversible_yank_roundtrip() {
        assert_slice_roundtrip(AssertMusubiReleaseDigestV1::new(
            release(),
            MusubiReleaseDigestV1::new([0x33; 32]),
        ));
        assert_slice_roundtrip(SetMusubiReleaseYankV1::new(
            release(),
            false,
            "restored".parse().expect("reason"),
            4,
        ));
    }
    #[test]
    fn pending_invitation_revoke_roundtrips() {
        assert_slice_roundtrip(RevokeMusubiPackageMaintainerInvitationV1 {
            package: package(),
            invite_id: crate::musubi::MusubiInviteIdV1::new([0x34; 32]),
            expected_governance_revision: 9,
        });
    }
    #[test]
    fn provider_attestation_registration_and_location_commitment_roundtrip() {
        let attestation = provider_attestation();
        let registration = RegisterMusubiProviderBundleAttestationV1::new(attestation.clone(), 7);
        registration.validate().expect("valid registration");
        assert_slice_roundtrip(registration.clone());
        let boxed = InstructionBox::from(registration.clone());
        assert_eq!(
            crate::isi::instruction_wire_id(&boxed),
            Some(RegisterMusubiProviderBundleAttestationV1::WIRE_ID)
        );
        assert_eq!(
            boxed
                .as_any()
                .downcast_ref::<RegisterMusubiProviderBundleAttestationV1>(),
            Some(&registration)
        );
        let binding = &attestation.payload.binding;
        let set_digest = musubi_provider_bundle_attestation_set_digest_v1(
            binding.archive_id,
            binding.replication_order,
            &[attestation.reference()],
        )
        .expect("provider set digest");
        let mut location = AddMusubiArchiveLocationV1 {
            archive_id: binding.archive_id,
            location_id: MusubiArchiveLocationIdV1::new([0x61; 32]),
            pin_manifest: ManifestDigest::new([0x62; 32]),
            replication_order: binding.replication_order,
            provider_attestation_set_digest: set_digest,
            renew_after_epoch: 10,
            expires_at_epoch: 20,
            expected_location_revision: 8,
        };
        location.validate().expect("valid compact location request");
        assert_slice_roundtrip(location.clone());
        location.provider_attestation_set_digest =
            MusubiProviderBundleAttestationSetDigestV1::new([0; 32]);
        assert!(location.validate().is_err());
        let invalid_registration = RegisterMusubiProviderBundleAttestationV1::new(attestation, 0);
        assert!(invalid_registration.validate().is_err());
    }
    #[test]
    fn account_bearing_governance_instructions_enforce_the_shared_bound() {
        let account = oversized_account();
        let package = package();
        let invitation = InviteMusubiPackageMaintainerV1 {
            package: package.clone(),
            invite_id: crate::musubi::MusubiInviteIdV1::new([0x71; 32]),
            invited_account: account.clone(),
            role: MusubiPackageRoleV1::Owner,
            expires_at_height: 10,
            expected_governance_revision: 1,
        };
        let role = SetMusubiPackageMaintainerRoleV1 {
            package: package.clone(),
            account: account.clone(),
            role: MusubiPackageRoleV1::Owner,
            expected_governance_revision: 1,
        };
        let removal = RemoveMusubiPackageMaintainerV1 {
            package,
            account,
            expected_governance_revision: 1,
        };
        assert!(invitation.validate().is_err());
        assert!(role.validate().is_err());
        assert!(removal.validate().is_err());
    }
    #[test]
    fn publish_namespace_is_explicit_in_wire_roundtrip() {
        let release = release();
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let publication = MusubiPublicationV1 {
            manifest: MusubiReleaseManifestV1 {
                release,
                edition: MusubiKotodamaEditionV1::V1,
                abi: MusubiAbiBindingV1::new([0x41; 32]).expect("ABI"),
                dependencies: Vec::new(),
                exports: Vec::new(),
                interface_digest: MusubiContentDigestV1::new([0x42; 32]),
                metadata: MusubiReleaseMetadataV1::default(),
                archive_id: ArchiveId::new([0x43; 32]),
                verification_lock_digest: lock.digest(),
            },
            resolution: MusubiResolutionProofV1 {
                snapshot: MusubiRegistrySnapshotV1 {
                    finalized_height: 7,
                    finalized_block_hash: [0x44; 32],
                    index_revision: 3,
                },
                lock,
            },
        };
        let instruction = PublishMusubiReleaseV1::new(
            "universal".parse().expect("namespace"),
            publication,
            None,
            5,
            None,
        );
        assert_slice_roundtrip(instruction);
    }
    #[test]
    fn legacy_wire_identifiers_are_not_reused() {
        let ids = [
            RegisterMusubiNamespaceBindingV1::WIRE_ID,
            RegisterMusubiArchiveV1::WIRE_ID,
            AdvanceMusubiPinOutboxV1::WIRE_ID,
            CheckMusubiPinOutboxV1::WIRE_ID,
            RegisterMusubiProviderBundleAttestationV1::WIRE_ID,
            AddMusubiArchiveLocationV1::WIRE_ID,
            RetireMusubiArchiveLocationV1::WIRE_ID,
            PublishMusubiReleaseV1::WIRE_ID,
            SetMusubiReleaseYankV1::WIRE_ID,
            SetMusubiPackageMetadataV1::WIRE_ID,
            InviteMusubiPackageMaintainerV1::WIRE_ID,
            AcceptMusubiPackageMaintainerV1::WIRE_ID,
            RevokeMusubiPackageMaintainerInvitationV1::WIRE_ID,
            SetMusubiPackageMaintainerRoleV1::WIRE_ID,
            RemoveMusubiPackageMaintainerV1::WIRE_ID,
            RegisterMusubiAliasV1::WIRE_ID,
            RecoverMusubiPackageV1::WIRE_ID,
            RetargetMusubiAliasV1::WIRE_ID,
            SetMusubiArtifactTakedownV1::WIRE_ID,
            SetMusubiRegistryPolicyV1::WIRE_ID,
            AssertMusubiReleaseDigestV1::WIRE_ID,
        ];
        let unique = ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), ids.len());
        assert!(ids.iter().all(|id| id.contains(".v1.")));
        assert!(!ids.contains(&"iroha.musubi.release.publish"));
    }

    #[test]
    fn v1_instruction_json_is_serializable_and_rejects_unknown_secret_fields() {
        let instruction = SetMusubiReleaseYankV1::new(
            release(),
            true,
            "security review".parse().expect("reason"),
            7,
        );
        let canonical = norito::json::to_json(&instruction)
            .expect("canonical Musubi V1 instruction JSON encodes");
        assert_eq!(
            norito::json::from_json::<SetMusubiReleaseYankV1>(&canonical)
                .expect("canonical Musubi V1 instruction JSON decodes"),
            instruction
        );
        let hostile = canonical.replacen('{', "{\"private_key\":\"must-not-be-accepted\",", 1);
        assert_ne!(hostile, canonical);
        assert!(
            norito::json::from_json::<SetMusubiReleaseYankV1>(&hostile).is_err(),
            "Musubi V1 instruction JSON must reject unknown secret-bearing fields"
        );
    }
}
