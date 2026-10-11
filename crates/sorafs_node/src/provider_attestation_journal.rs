//! Durable, approval-only handoff for completed Musubi provider attestations.
//!
//! The native daemon supervises this shared journal and bounded capture driver through explicit
//! retained custody. This module itself launches no task and owns no transaction ingress.
//! An approval intent retains the exact finalized evidence identity while deliberately omitting the
//! opaque approval request. After restart, callers must rederive that request from a fresh
//! completed-row claim and lifecycle-leased bundle verification.
#[cfg(test)]
use crate::provider_attestation_clock::MusubiProviderAttestationClockErrorV1;
#[cfg(test)]
use crate::provider_attestation_clock::MusubiProviderAttestationSealedUnixClockV1;
use crate::{
    provider_attestation_clock::{
        MusubiProviderAttestationClockScopeV1, MusubiProviderAttestationJournalCheckpointScopeV1,
    },
    provider_ingest_outbox::ProviderIngestFinalizedCursorV1,
    provider_ingest_runtime::{
        ProviderIngestFutureV1, ProviderIngestMusubiAttestationApprovalRequestV1,
    },
};
use iroha_config::parameters::{
    defaults::sorafs::storage::provider_ingest_runtime::provider_attestation_journal as provider_attestation_journal_defaults,
    is_production_runtime_handle,
};
use iroha_data_model::musubi::MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    musubi::{
        MUSUBI_MAX_LOCATION_PROVIDERS_V1, MusubiProviderBundleAttestationDigestV1,
        MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleVerificationAttestationV1,
        MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{ProviderIngestCompletionSignerPolicyV1, ReplicationOrderId},
    },
};
use norito::DecodeLimits;
use norito::derive::{NoritoDeserialize, NoritoSerialize};
use std::collections::BTreeSet;
use std::{fmt, sync::Arc, time::Duration};
use thiserror::Error;
const APPROVAL_SIGNER_QUALIFICATION_VERSION_V1: u8 = 1;
const INVENTORY_RUNTIME_QUALIFICATION_VERSION_V1: u8 = 1;
const JOURNAL_CHECKPOINT_VERSION_V1: u8 = 1;
const APPROVAL_ID_DOMAIN_V1: &[u8] = b"sorafs.musubi.provider-attestation.approval.v1\0";
const INVENTORY_HANDOFF_ID_DOMAIN_V1: &[u8] =
    b"sorafs.musubi.provider-attestation.inventory-handoff.v1\0";
const JOURNAL_CHECKPOINT_REVISION_DOMAIN_V1: &[u8] =
    b"sorafs.musubi.provider-attestation.journal-checkpoint.v1\0";
const JOURNAL_POLICY_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.musubi.provider-attestation.journal-policy.v1\0";
const CONTROLLER_POLICY_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.musubi.provider-attestation.controller-policy.v1\0";
/// Hard upper bound admitted by the journal decoder regardless of runtime policy.
pub const MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1: usize =
    provider_attestation_journal_defaults::CHECKPOINT_MAX_BYTES_LIMIT;
/// Hard upper bound on journal entries regardless of runtime policy.
pub const MUSUBI_PROVIDER_ATTESTATION_JOURNAL_MAX_ENTRIES_V1: usize =
    provider_attestation_journal_defaults::MAX_ENTRIES_LIMIT;
/// Maximum number of ready work identities returned by one restart scan.
pub const MUSUBI_PROVIDER_ATTESTATION_READY_PAGE_MAX_V1: usize = 256;
/// Hard upper bound for one external signer or inventory operation.
pub const MUSUBI_PROVIDER_ATTESTATION_EXTERNAL_TIMEOUT_MAX_MS_V1: u64 =
    provider_attestation_journal_defaults::EXTERNAL_TIMEOUT_MAX_MS;
const JOURNAL_CHECKPOINT_MAX_SEQUENCE_LENGTH_V1: usize =
    MUSUBI_PROVIDER_ATTESTATION_JOURNAL_MAX_ENTRIES_V1;
// Norito charges byte-vector members as elements, including controller keys and
// signatures. A canonical checkpoint cannot contain more charged elements than
// bytes, so the hard byte ceiling is also a complete element ceiling.
const JOURNAL_CHECKPOINT_MAX_TOTAL_ELEMENTS_V1: usize =
    MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1;
const JOURNAL_ACTIVE_ENTRY_WRAPPER_MARGIN_BYTES_V1: usize =
    provider_attestation_journal_defaults::ACTIVE_ENTRY_WRAPPER_MARGIN_BYTES_V1;
const JOURNAL_CHECKPOINT_HEADER_FOOTPRINT_BYTES_V1: usize =
    provider_attestation_journal_defaults::CHECKPOINT_HEADER_FOOTPRINT_BYTES_V1;
const JOURNAL_CHECKPOINT_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    JOURNAL_CHECKPOINT_MAX_SEQUENCE_LENGTH_V1,
    MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1,
    JOURNAL_CHECKPOINT_MAX_TOTAL_ELEMENTS_V1,
    MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1 * 4,
    128,
);
/// Payload-free public qualification of an approval-only attestation signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationSignerQualificationV1 {
    /// Qualification schema version.
    pub version: u8,
    /// Non-zero adapter-local revision fenced across one approval operation.
    pub adapter_revision: u64,
    /// Non-zero deployment policy digest for the signer adapter itself.
    ///
    /// This is independent of both the governed signer policy and the authority controller digest,
    /// which may change without replacing the deployment adapter.
    pub adapter_policy_digest: [u8; 32],
    /// Exact governed signer policy currently implemented by the adapter.
    pub signer_policy: ProviderIngestCompletionSignerPolicyV1,
    /// Completion-signer account whose controller quorum the adapter represents.
    pub authority: AccountId,
    /// Non-zero digest of the adapter's exact public controller-key configuration.
    pub controller_policy_digest: [u8; 32],
}
impl MusubiProviderAttestationSignerQualificationV1 {
    /// Construct a first-release approval-only signer qualification.
    #[must_use]
    pub const fn new(
        adapter_revision: u64,
        adapter_policy_digest: [u8; 32],
        signer_policy: ProviderIngestCompletionSignerPolicyV1,
        authority: AccountId,
        controller_policy_digest: [u8; 32],
    ) -> Self {
        Self {
            version: APPROVAL_SIGNER_QUALIFICATION_VERSION_V1,
            adapter_revision,
            adapter_policy_digest,
            signer_policy,
            authority,
            controller_policy_digest,
        }
    }
    /// Return the deployment adapter revision fenced across approval.
    #[must_use]
    pub const fn adapter_revision(&self) -> u64 {
        self.adapter_revision
    }
    /// Return the independently governed deployment adapter policy digest.
    #[must_use]
    pub const fn adapter_policy_digest(&self) -> [u8; 32] {
        self.adapter_policy_digest
    }
    /// Validate bounded schema, revision, policy lineage, and key-set identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or inert identity component.
    pub fn validate(&self) -> Result<(), MusubiProviderAttestationSignerBindingErrorV1> {
        if self.version != APPROVAL_SIGNER_QUALIFICATION_VERSION_V1
            || self.adapter_revision == 0
            || self.adapter_policy_digest == [0; 32]
            || !self.signer_policy.is_valid()
            || self.controller_policy_digest == [0; 32]
        {
            return Err(MusubiProviderAttestationSignerBindingErrorV1::InvalidQualification);
        }
        Ok(())
    }
}
/// Derive the canonical domain-separated digest of an authority controller.
///
/// Signer adapters place this digest in their qualification so the coordinator
/// can bind the adapter's claimed controller configuration to the exact
/// completion-signer controller carried by finalized completion evidence.
///
/// # Errors
///
/// Returns an error only if canonical Norito encoding fails or yields the
/// forbidden all-zero sentinel.
pub fn musubi_provider_attestation_controller_policy_digest_v1(
    authority: &AccountId,
) -> Result<[u8; 32], MusubiProviderAttestationSignerBindingErrorV1> {
    let digest = domain_hash_norito(CONTROLLER_POLICY_DIGEST_DOMAIN_V1, authority.controller())
        .ok_or(MusubiProviderAttestationSignerBindingErrorV1::InvalidQualification)?;
    if digest == [0; 32] {
        return Err(MusubiProviderAttestationSignerBindingErrorV1::InvalidQualification);
    }
    Ok(digest)
}
/// Invalid public binding exposed by an approval-only provider signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationSignerBindingErrorV1 {
    /// The stable signer handle is malformed or marked for test/development use.
    #[error("Musubi provider-attestation signer handle is not production-safe")]
    InvalidRuntimeHandle,
    /// The signer qualification is malformed or inert.
    #[error("Musubi provider-attestation signer qualification is invalid")]
    InvalidQualification,
}
/// Bounded failure returned by an isolated approval-only signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationSignerErrorV1 {
    /// The qualified signer is temporarily unavailable.
    #[error("Musubi provider-attestation signer is unavailable")]
    Unavailable,
    /// The exact request or live policy is no longer eligible.
    #[error("Musubi provider-attestation request was rejected")]
    Rejected,
}
/// Isolated signer capable only of producing complete Musubi provider attestations.
///
/// The trait intentionally has no transaction payload, signed transaction,
/// queue, or registry-submission surface.
pub trait MusubiProviderAttestationSignerV1: Send + Sync + 'static {
    /// Return the stable credential-free signing-adapter identity.
    ///
    /// This getter must be a bounded, non-blocking local snapshot.
    fn runtime_handle(&self) -> &str;
    /// Return the completion-signer account controlled by this signer.
    ///
    /// This getter must be a bounded, non-blocking local snapshot.
    fn authority(&self) -> &AccountId;
    /// Return the deployment-qualified, payload-free adapter binding.
    ///
    /// This getter must be a bounded, non-blocking local snapshot; any remote or blocking provider
    /// readiness belongs in the timed approval future.
    fn qualification(
        &self,
    ) -> Result<
        MusubiProviderAttestationSignerQualificationV1,
        MusubiProviderAttestationSignerErrorV1,
    >;
    /// Return the signer's configured governed policy identity.
    ///
    /// This getter must be a bounded, non-blocking local snapshot.
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1;
    /// Revalidate the locally maintained live eligibility snapshot.
    ///
    /// This must be a bounded, non-blocking read. The timed approval operation
    /// remains responsible for the signer-side atomic revocation check.
    fn current_eligibility(
        &self,
    ) -> Result<ProviderIngestCompletionSignerPolicyV1, MusubiProviderAttestationSignerErrorV1>;
    /// Approve only the supplied opaque, post-completion request.
    ///
    /// Repeating one exact request under an unchanged qualification must yield the same canonical
    /// attestation, including the same sorted controller approval set. This replay-stability
    /// requirement prevents retries from selecting different valid multisig subsets.
    fn approve<'a>(
        &'a self,
        request: &'a ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderBundleVerificationAttestationV1,
            MusubiProviderAttestationSignerErrorV1,
        >,
    >;
}
/// Coordinator-side failure while invoking an approval-only signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationApprovalErrorV1 {
    /// The opaque request is internally inconsistent.
    #[error("Musubi provider-attestation approval request is invalid")]
    InvalidRequest,
    /// The configured or injected signer handle is not production-safe.
    #[error("Musubi provider-attestation signer handle is invalid")]
    InvalidSignerHandle,
    /// The signer qualification or authority contradicts the request.
    #[error("Musubi provider-attestation signer qualification is inconsistent")]
    InvalidSignerQualification,
    /// The signer was unavailable before or during the approval operation.
    #[error("Musubi provider-attestation signer is unavailable")]
    SignerUnavailable,
    /// The signer rejected the exact request.
    #[error("Musubi provider-attestation signer rejected the request")]
    SignerRejected,
    /// The signer did not finish within the bounded approval interval.
    #[error("Musubi provider-attestation signer timed out")]
    SignerTimedOut,
    /// Eligibility or qualification changed across the signing boundary.
    #[error("Musubi provider-attestation signer eligibility changed")]
    EligibilityChanged,
    /// The signer returned a different payload or an invalid approval quorum.
    #[error("Musubi provider-attestation signer returned invalid evidence")]
    InvalidAttestation,
}
/// Validate, invoke, and revalidate one approval-only provider signer.
///
/// The coordinator checks the production handle, exact completion-signer authority, governed policy,
/// and eligibility both before and after signing. It then requires byte-for-byte payload equality
/// and verifies the complete controller approval quorum. `timeout_ms` is a non-zero upper bound for
/// the external signer operation.
///
/// # Errors
///
/// Returns a closed failure when the request, signer binding, live policy, or
/// resulting attestation is unavailable, rejected, substituted, or invalid.
pub async fn approve_musubi_provider_attestation_v1<Signer>(
    signer: &Signer,
    request: &ProviderIngestMusubiAttestationApprovalRequestV1,
    timeout_ms: u64,
) -> Result<MusubiProviderBundleVerificationAttestationV1, MusubiProviderAttestationApprovalErrorV1>
where
    Signer: MusubiProviderAttestationSignerV1 + ?Sized,
{
    validate_approval_request(request)?;
    if timeout_ms == 0 || timeout_ms > MUSUBI_PROVIDER_ATTESTATION_EXTERNAL_TIMEOUT_MAX_MS_V1 {
        return Err(MusubiProviderAttestationApprovalErrorV1::InvalidRequest);
    }
    let handle_before = signer.runtime_handle().to_owned();
    if !is_production_runtime_handle(&handle_before) {
        return Err(MusubiProviderAttestationApprovalErrorV1::InvalidSignerHandle);
    }
    let qualification_before = qualified_signer_snapshot(signer, request)?;
    let signer_deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or(MusubiProviderAttestationApprovalErrorV1::InvalidRequest)?;
    let attestation = tokio::time::timeout_at(signer_deadline, signer.approve(request))
        .await
        .map_err(|_| MusubiProviderAttestationApprovalErrorV1::SignerTimedOut)?
        .map_err(|error| match error {
            MusubiProviderAttestationSignerErrorV1::Unavailable => {
                MusubiProviderAttestationApprovalErrorV1::SignerUnavailable
            }
            MusubiProviderAttestationSignerErrorV1::Rejected => {
                MusubiProviderAttestationApprovalErrorV1::SignerRejected
            }
        })?;
    let handle_after = signer.runtime_handle();
    if handle_after != handle_before || !is_production_runtime_handle(handle_after) {
        return Err(MusubiProviderAttestationApprovalErrorV1::EligibilityChanged);
    }
    let qualification_after = qualified_signer_snapshot(signer, request).map_err(|error| {
        if error == MusubiProviderAttestationApprovalErrorV1::SignerUnavailable {
            error
        } else {
            MusubiProviderAttestationApprovalErrorV1::EligibilityChanged
        }
    })?;
    if qualification_after != qualification_before {
        return Err(MusubiProviderAttestationApprovalErrorV1::EligibilityChanged);
    }
    if &attestation.payload != request.payload()
        || attestation.verify(&request.payload().binding).is_err()
    {
        return Err(MusubiProviderAttestationApprovalErrorV1::InvalidAttestation);
    }
    Ok(attestation)
}
fn validate_approval_request(
    request: &ProviderIngestMusubiAttestationApprovalRequestV1,
) -> Result<(), MusubiProviderAttestationApprovalErrorV1> {
    let cursor = request.observed_finalized_cursor();
    let anchor = request.payload().binding.finalized_anchor;
    if request.payload().validate().is_err()
        || request.payload().binding.network_id.as_bytes()[31] & 1 != 1
        || request.completion_claim_digest() == [0; 32]
        || cursor.height == 0
        || cursor.block_hash == [0; 32]
        || !request.signer_policy().is_valid()
        || request.payload().binding.completion_authority.signer_policy != request.signer_policy()
        || request.payload().binding.completed_by
            != request
                .payload()
                .binding
                .completion_authority
                .completion_signer
        || anchor.height > cursor.height
        || anchor.height == cursor.height && anchor.block_hash != cursor.block_hash
    {
        return Err(MusubiProviderAttestationApprovalErrorV1::InvalidRequest);
    }
    Ok(())
}
fn qualified_signer_snapshot<Signer>(
    signer: &Signer,
    request: &ProviderIngestMusubiAttestationApprovalRequestV1,
) -> Result<MusubiProviderAttestationSignerQualificationV1, MusubiProviderAttestationApprovalErrorV1>
where
    Signer: MusubiProviderAttestationSignerV1 + ?Sized,
{
    let qualification = signer.qualification().map_err(|error| match error {
        MusubiProviderAttestationSignerErrorV1::Unavailable => {
            MusubiProviderAttestationApprovalErrorV1::SignerUnavailable
        }
        MusubiProviderAttestationSignerErrorV1::Rejected => {
            MusubiProviderAttestationApprovalErrorV1::SignerRejected
        }
    })?;
    qualification
        .validate()
        .map_err(|_| MusubiProviderAttestationApprovalErrorV1::InvalidSignerQualification)?;
    let eligibility = signer.current_eligibility().map_err(|error| match error {
        MusubiProviderAttestationSignerErrorV1::Unavailable => {
            MusubiProviderAttestationApprovalErrorV1::SignerUnavailable
        }
        MusubiProviderAttestationSignerErrorV1::Rejected => {
            MusubiProviderAttestationApprovalErrorV1::SignerRejected
        }
    })?;
    let expected_owner = &request.payload().binding.completed_by;
    let expected_policy = request.signer_policy();
    let expected_controller_policy_digest =
        musubi_provider_attestation_controller_policy_digest_v1(expected_owner)
            .map_err(|_| MusubiProviderAttestationApprovalErrorV1::InvalidSignerQualification)?;
    if signer.authority() != expected_owner
        || &qualification.authority != expected_owner
        || qualification.signer_policy != expected_policy
        || qualification.controller_policy_digest != expected_controller_policy_digest
        || signer.signer_policy() != expected_policy
        || eligibility != expected_policy
    {
        return Err(MusubiProviderAttestationApprovalErrorV1::InvalidSignerQualification);
    }
    Ok(qualification)
}
/// Stable domain-separated identity of one exact approval intent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, NoritoSerialize, NoritoDeserialize,
)]
pub struct MusubiProviderAttestationApprovalIdV1([u8; 32]);
impl MusubiProviderAttestationApprovalIdV1 {
    /// Return exact approval-identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    fn is_valid(self) -> bool {
        self.0 != [0; 32]
    }
}
/// Stable domain-separated identity of one coordinator-inventory handoff.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, NoritoSerialize, NoritoDeserialize,
)]
pub struct MusubiProviderAttestationInventoryHandoffIdV1([u8; 32]);
impl MusubiProviderAttestationInventoryHandoffIdV1 {
    /// Return exact inventory-handoff identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    fn is_valid(self) -> bool {
        self.0 != [0; 32]
    }
}
/// Deployment and archive/order scope of a coordinator attestation inventory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize)]
pub struct MusubiProviderAttestationInventoryScopeV1 {
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Exact canonical archive identity.
    pub archive_id: iroha_data_model::musubi::ArchiveId,
    /// Exact replication order shared by the inventory.
    pub replication_order: ReplicationOrderId,
}
impl MusubiProviderAttestationInventoryScopeV1 {
    /// Derive the scope selected by one exact verified binding.
    #[must_use]
    pub fn from_binding(binding: &MusubiProviderBundleVerificationBindingV1) -> Self {
        Self {
            network_id: binding.network_id,
            archive_id: binding.archive_id,
            replication_order: binding.replication_order,
        }
    }
    /// Validate every scope identity component.
    ///
    /// # Errors
    ///
    /// Returns an error for an inert genesis, archive, or order identity.
    pub fn validate(&self) -> Result<(), MusubiProviderAttestationInventoryErrorV1> {
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.archive_id.is_zero()
            || self.replication_order.as_bytes() == &[0; 32]
        {
            return Err(MusubiProviderAttestationInventoryErrorV1::InvalidItem);
        }
        Ok(())
    }
}
/// One immutable full attestation prepared for idempotent coordinator handoff.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct MusubiProviderAttestationInventoryItemV1 {
    scope: MusubiProviderAttestationInventoryScopeV1,
    key: MusubiProviderBundleAttestationKeyV1,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
    attestation: MusubiProviderBundleVerificationAttestationV1,
    handoff_id: MusubiProviderAttestationInventoryHandoffIdV1,
}
impl MusubiProviderAttestationInventoryItemV1 {
    /// Construct a canonical item from one complete verified attestation.
    ///
    /// # Errors
    ///
    /// Returns an error when the attestation, scope, identity, or digest is invalid.
    pub fn new(
        attestation: MusubiProviderBundleVerificationAttestationV1,
    ) -> Result<Self, MusubiProviderAttestationInventoryErrorV1> {
        attestation
            .verify(&attestation.payload.binding)
            .map_err(|_| MusubiProviderAttestationInventoryErrorV1::InvalidItem)?;
        let scope =
            MusubiProviderAttestationInventoryScopeV1::from_binding(&attestation.payload.binding);
        let key = attestation.key();
        let attestation_digest = attestation.digest();
        let handoff_id =
            musubi_provider_attestation_inventory_handoff_id_v1(&scope, key, attestation_digest)?;
        let item = Self {
            scope,
            key,
            attestation_digest,
            attestation,
            handoff_id,
        };
        item.validate()?;
        Ok(item)
    }
    /// Return the exact deployment/archive/order inventory scope.
    #[must_use]
    pub const fn scope(&self) -> &MusubiProviderAttestationInventoryScopeV1 {
        &self.scope
    }
    /// Return the immutable archive/order/provider key.
    #[must_use]
    pub const fn key(&self) -> MusubiProviderBundleAttestationKeyV1 {
        self.key
    }
    /// Return the digest of the complete canonical attestation.
    #[must_use]
    pub const fn attestation_digest(&self) -> MusubiProviderBundleAttestationDigestV1 {
        self.attestation_digest
    }
    /// Borrow the complete signed provider attestation.
    #[must_use]
    pub const fn attestation(&self) -> &MusubiProviderBundleVerificationAttestationV1 {
        &self.attestation
    }
    /// Return the stable idempotency identity for this handoff.
    #[must_use]
    pub const fn handoff_id(&self) -> MusubiProviderAttestationInventoryHandoffIdV1 {
        self.handoff_id
    }
    /// Validate scope, exact attestation projection, digest, and handoff identity.
    ///
    /// # Errors
    ///
    /// Returns an error if any field is malformed or substituted.
    pub fn validate(&self) -> Result<(), MusubiProviderAttestationInventoryErrorV1> {
        self.scope.validate()?;
        self.key
            .validate()
            .map_err(|_| MusubiProviderAttestationInventoryErrorV1::InvalidItem)?;
        self.attestation
            .verify(&self.attestation.payload.binding)
            .map_err(|_| MusubiProviderAttestationInventoryErrorV1::InvalidItem)?;
        let expected_scope = MusubiProviderAttestationInventoryScopeV1::from_binding(
            &self.attestation.payload.binding,
        );
        let expected_handoff = musubi_provider_attestation_inventory_handoff_id_v1(
            &self.scope,
            self.key,
            self.attestation_digest,
        )?;
        if self.scope != expected_scope
            || self.key != self.attestation.key()
            || self.attestation_digest != self.attestation.digest()
            || !self.handoff_id.is_valid()
            || self.handoff_id != expected_handoff
        {
            return Err(MusubiProviderAttestationInventoryErrorV1::InvalidItem);
        }
        Ok(())
    }
}
/// One authenticated exact inventory read with its authoritative revision.
///
/// The value is intentionally not a wire receipt and carries no authentication authority by itself.
/// A deployment-qualified inventory reader constructs it only after authenticating the
/// coordinator's response, and the crate-private handoff driver still compares both fields with the
/// immediately preceding idempotent `put` before recording delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationInventoryReadbackV1 {
    item: MusubiProviderAttestationInventoryItemV1,
    inventory_revision: u64,
}
impl MusubiProviderAttestationInventoryReadbackV1 {
    /// Construct one structurally validated inventory readback.
    ///
    /// This constructor does not authenticate the source of `item` or `inventory_revision`;
    /// implementations of [`MusubiProviderAttestationInventoryReaderV1`] must do so before calling
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid item or zero inventory revision.
    pub fn try_new(
        item: MusubiProviderAttestationInventoryItemV1,
        inventory_revision: u64,
    ) -> Result<Self, MusubiProviderAttestationInventoryErrorV1> {
        item.validate()?;
        if inventory_revision == 0 {
            return Err(MusubiProviderAttestationInventoryErrorV1::InvalidReceipt);
        }
        Ok(Self {
            item,
            inventory_revision,
        })
    }
    /// Borrow the exact immutable item returned by the inventory.
    #[must_use]
    pub const fn item(&self) -> &MusubiProviderAttestationInventoryItemV1 {
        &self.item
    }
    /// Return the authoritative revision paired with the exact item.
    #[must_use]
    pub const fn inventory_revision(&self) -> u64 {
        self.inventory_revision
    }
    fn matches(
        &self,
        item: &MusubiProviderAttestationInventoryItemV1,
        inventory_revision: u64,
    ) -> bool {
        inventory_revision != 0
            && self.inventory_revision == inventory_revision
            && &self.item == item
            && self.item.validate().is_ok()
    }
}
/// Bounded opaque acknowledgement retained after a trusted inventory handoff.
///
/// The receipt deliberately has neither a public constructor nor public Norito codecs. It is
/// constructed only inside the journal after a trusted sink's non-zero revision is confirmed by an
/// authenticated exact readback, so downstream safe Rust cannot mint or decode an acknowledgement
/// to bypass that boundary.
///
/// ```compile_fail
/// use sorafs_node::{
///     MusubiProviderAttestationInventoryItemV1,
///     MusubiProviderAttestationInventoryReceiptV1,
/// };
///
/// fn forge(item: &MusubiProviderAttestationInventoryItemV1) {
///     let _ = MusubiProviderAttestationInventoryReceiptV1::new(item, 1);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationInventoryReceiptV1 {
    scope: MusubiProviderAttestationInventoryScopeV1,
    key: MusubiProviderBundleAttestationKeyV1,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
    handoff_id: MusubiProviderAttestationInventoryHandoffIdV1,
    inventory_revision: u64,
}
impl MusubiProviderAttestationInventoryReceiptV1 {
    /// Construct a crate-qualified acknowledgement bound to one exact item.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid item or zero inventory revision.
    pub(crate) fn new(
        item: &MusubiProviderAttestationInventoryItemV1,
        inventory_revision: u64,
    ) -> Result<Self, MusubiProviderAttestationInventoryErrorV1> {
        item.validate()?;
        if inventory_revision == 0 {
            return Err(MusubiProviderAttestationInventoryErrorV1::InvalidReceipt);
        }
        Ok(Self {
            scope: item.scope.clone(),
            key: item.key,
            attestation_digest: item.attestation_digest,
            handoff_id: item.handoff_id,
            inventory_revision,
        })
    }
    /// Return the stable handoff identity acknowledged by the inventory.
    #[must_use]
    pub const fn handoff_id(&self) -> MusubiProviderAttestationInventoryHandoffIdV1 {
        self.handoff_id
    }
    /// Return the coordinator inventory revision at acknowledgement.
    #[must_use]
    pub const fn inventory_revision(&self) -> u64 {
        self.inventory_revision
    }
    /// Return whether this receipt acknowledges exactly `item`.
    #[must_use]
    pub fn matches(&self, item: &MusubiProviderAttestationInventoryItemV1) -> bool {
        self.inventory_revision != 0
            && self.scope == item.scope
            && self.key == item.key
            && self.attestation_digest == item.attestation_digest
            && self.handoff_id == item.handoff_id
            && item.validate().is_ok()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredInventoryReceiptV1 {
    scope: MusubiProviderAttestationInventoryScopeV1,
    key: MusubiProviderBundleAttestationKeyV1,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
    handoff_id: MusubiProviderAttestationInventoryHandoffIdV1,
    inventory_revision: u64,
}
impl StoredInventoryReceiptV1 {
    fn from_public(receipt: &MusubiProviderAttestationInventoryReceiptV1) -> Self {
        Self {
            scope: receipt.scope.clone(),
            key: receipt.key,
            attestation_digest: receipt.attestation_digest,
            handoff_id: receipt.handoff_id,
            inventory_revision: receipt.inventory_revision,
        }
    }
    fn matches(&self, item: &MusubiProviderAttestationInventoryItemV1) -> bool {
        self.inventory_revision != 0
            && self.scope == item.scope
            && self.key == item.key
            && self.attestation_digest == item.attestation_digest
            && self.handoff_id == item.handoff_id
            && item.validate().is_ok()
    }
}
/// Provider-sorted, duplicate-free inventory for one archive and replication order.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct MusubiProviderAttestationInventoryV1 {
    scope: MusubiProviderAttestationInventoryScopeV1,
    items: Vec<MusubiProviderAttestationInventoryItemV1>,
}
impl MusubiProviderAttestationInventoryV1 {
    /// Canonicalize an unordered bounded item set by provider identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, invalid, cross-scope, or
    /// duplicate-provider item set.
    pub fn new(
        scope: MusubiProviderAttestationInventoryScopeV1,
        mut items: Vec<MusubiProviderAttestationInventoryItemV1>,
    ) -> Result<Self, MusubiProviderAttestationInventoryErrorV1> {
        scope.validate()?;
        if items.is_empty() || items.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1 {
            return Err(MusubiProviderAttestationInventoryErrorV1::InvalidInventory);
        }
        items.sort_by_key(|item| item.key.provider_id);
        let inventory = Self { scope, items };
        inventory.validate()?;
        Ok(inventory)
    }
    /// Return the common deployment/archive/order scope.
    #[must_use]
    pub const fn scope(&self) -> &MusubiProviderAttestationInventoryScopeV1 {
        &self.scope
    }
    /// Return provider-sorted immutable inventory items.
    #[must_use]
    pub fn items(&self) -> &[MusubiProviderAttestationInventoryItemV1] {
        &self.items
    }
    /// Validate the common scope and strict provider ordering.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, empty, oversized, unsorted, duplicate, or
    /// cross-scope inventory contents.
    pub fn validate(&self) -> Result<(), MusubiProviderAttestationInventoryErrorV1> {
        self.scope.validate()?;
        if self.items.is_empty()
            || self.items.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1
            || self
                .items
                .windows(2)
                .any(|pair| pair[0].key.provider_id >= pair[1].key.provider_id)
        {
            return Err(MusubiProviderAttestationInventoryErrorV1::InvalidInventory);
        }
        self.items.iter().try_for_each(|item| {
            item.validate()?;
            if item.scope != self.scope {
                return Err(MusubiProviderAttestationInventoryErrorV1::InvalidInventory);
            }
            Ok(())
        })
    }
}
/// Closed coordinator inventory or transport failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationInventoryErrorV1 {
    /// The immutable item is malformed or substituted.
    #[error("Musubi provider-attestation inventory item is invalid")]
    InvalidItem,
    /// The inventory page is empty, oversized, cross-scope, or noncanonical.
    #[error("Musubi provider-attestation inventory is invalid")]
    InvalidInventory,
    /// The handoff acknowledgement is malformed or inconsistent.
    #[error("Musubi provider-attestation inventory receipt is invalid")]
    InvalidReceipt,
    /// A different attestation already occupies the immutable scope/key.
    #[error("Musubi provider-attestation inventory contains a conflicting digest")]
    Conflict,
    /// The inventory adapter is temporarily unavailable.
    #[error("Musubi provider-attestation inventory is unavailable")]
    Unavailable,
    /// The inventory adapter permanently rejected the item or request.
    #[error("Musubi provider-attestation inventory rejected the request")]
    Rejected,
}
/// Payload-free deployment qualification of a coordinator inventory adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MusubiProviderAttestationInventoryQualificationV1 {
    /// Qualification schema version.
    pub version: u8,
    /// Non-zero adapter-local revision fenced across each handoff.
    pub adapter_revision: u64,
    /// Non-zero digest of the adapter's independently governed public policy.
    pub policy_digest: [u8; 32],
}
impl MusubiProviderAttestationInventoryQualificationV1 {
    /// Construct a first-release inventory-adapter qualification.
    #[must_use]
    pub const fn new(adapter_revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            version: INVENTORY_RUNTIME_QUALIFICATION_VERSION_V1,
            adapter_revision,
            policy_digest,
        }
    }
    /// Return the adapter-local qualification revision.
    #[must_use]
    pub const fn adapter_revision(&self) -> u64 {
        self.adapter_revision
    }
    /// Return the independently governed public adapter-policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    /// Validate the V1 schema and non-zero deployment binding.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version or inert binding field.
    pub fn validate(&self) -> Result<(), MusubiProviderAttestationInventoryBindingErrorV1> {
        if self.version != INVENTORY_RUNTIME_QUALIFICATION_VERSION_V1
            || self.adapter_revision == 0
            || self.policy_digest == [0; 32]
        {
            return Err(MusubiProviderAttestationInventoryBindingErrorV1::InvalidQualification);
        }
        Ok(())
    }
}
/// Invalid public deployment binding exposed by an inventory adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationInventoryBindingErrorV1 {
    /// The stable inventory handle is malformed or marked for test/development use.
    #[error("Musubi provider-attestation inventory handle is not production-safe")]
    InvalidRuntimeHandle,
    /// The inventory qualification is malformed or inert.
    #[error("Musubi provider-attestation inventory qualification is invalid")]
    InvalidQualification,
}
/// Payload-free failure returned by a qualified inventory runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationInventoryRuntimeErrorV1 {
    /// The adapter or its authenticated coordinator is temporarily unavailable.
    #[error("Musubi provider-attestation inventory runtime is unavailable")]
    Unavailable,
    /// The adapter is revoked, stale, unauthorized, or otherwise ineligible.
    #[error("Musubi provider-attestation inventory runtime rejected qualification")]
    Rejected,
}
/// Idempotent trusted write boundary for the coordinator's immutable inventory.
///
/// Implementations are deployment-qualified adapters. A successful response is the non-zero
/// coordinator revision for this exact item; the journal converts it into an opaque local
/// acknowledgement only after validating the item and revision.
pub trait MusubiProviderAttestationInventorySinkV1: Send + Sync + 'static {
    /// Insert or replay one exact immutable item.
    ///
    /// An identical replay must return the exact same non-zero inventory
    /// revision. A different digest at the same scope/key must return
    /// [`MusubiProviderAttestationInventoryErrorV1::Conflict`].
    fn put<'a>(
        &'a self,
        item: MusubiProviderAttestationInventoryItemV1,
    ) -> ProviderIngestFutureV1<'a, Result<u64, MusubiProviderAttestationInventoryErrorV1>>;
}
/// Read-only boundary for exact and archive/order-scoped coordinator inventory.
pub trait MusubiProviderAttestationInventoryReaderV1: Send + Sync + 'static {
    /// Read one exact immutable scope/key entry and its authoritative revision.
    ///
    /// Implementations must authenticate the coordinator response before
    /// constructing the readback. An exact replay must retain the same non-zero
    /// revision returned by [`MusubiProviderAttestationInventorySinkV1::put`].
    fn get<'a>(
        &'a self,
        scope: &'a MusubiProviderAttestationInventoryScopeV1,
        key: MusubiProviderBundleAttestationKeyV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            Option<MusubiProviderAttestationInventoryReadbackV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    >;
    /// Read the complete bounded provider-sorted inventory for one scope.
    fn inventory<'a>(
        &'a self,
        scope: &'a MusubiProviderAttestationInventoryScopeV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            Option<MusubiProviderAttestationInventoryV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    >;
}
/// Deployment-qualified write/read boundary for coordinator inventory handoff.
///
/// Implementations own authentication material and transport diagnostics. The public handle and
/// qualification contain no credentials or attestation payload. `check_readiness` must be
/// non-mutating; callers execute its future under the same hard deadline as the associated handoff.
/// This trait exposes no transaction, queue, or registry-mutation surface. Runtime snapshots
/// establish structural validity and operation-local stability only; a daemon integration must also
/// compare handle, revision, and policy digest with its exact independently configured binding on
/// every call, not only at startup.
pub trait MusubiProviderAttestationInventoryRuntimeV1:
    MusubiProviderAttestationInventorySinkV1 + MusubiProviderAttestationInventoryReaderV1
{
    /// Return the stable credential-free deployment adapter identity.
    ///
    /// This getter must be a bounded, non-blocking local snapshot.
    fn runtime_handle(&self) -> &str;
    /// Return the current payload-free adapter and public-policy binding.
    ///
    /// This getter must be a bounded, non-blocking local snapshot; remote
    /// authentication/readiness belongs in `check_readiness`.
    fn qualification(
        &self,
    ) -> Result<
        MusubiProviderAttestationInventoryQualificationV1,
        MusubiProviderAttestationInventoryRuntimeErrorV1,
    >;
    /// Perform a non-mutating authenticated readiness probe.
    ///
    /// The returned `Send` future is always polled under the journal's bounded
    /// handoff deadline. It must not insert, remove, or alter inventory data.
    fn check_readiness<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<'a, Result<(), MusubiProviderAttestationInventoryRuntimeErrorV1>>;
}
/// Validate one credential-free inventory runtime binding.
///
/// # Errors
///
/// Returns an error when the handle is malformed or test-marked, or when the
/// qualification has an unsupported version or inert field.
pub fn validate_musubi_provider_attestation_inventory_binding_v1(
    runtime_handle: &str,
    qualification: &MusubiProviderAttestationInventoryQualificationV1,
) -> Result<(), MusubiProviderAttestationInventoryBindingErrorV1> {
    if !is_production_runtime_handle(runtime_handle) {
        return Err(MusubiProviderAttestationInventoryBindingErrorV1::InvalidRuntimeHandle);
    }
    qualification.validate()
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_attestation_journal::ApprovalIdPreimageV1")]
struct ApprovalIdPreimageV1 {
    key: MusubiProviderBundleAttestationKeyV1,
    payload_signing_hash: [u8; 32],
    completion_claim_digest: [u8; 32],
    signer_policy: ProviderIngestCompletionSignerPolicyV1,
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_attestation_journal::InventoryHandoffIdPreimageV1")]
struct InventoryHandoffIdPreimageV1 {
    scope: MusubiProviderAttestationInventoryScopeV1,
    key: MusubiProviderBundleAttestationKeyV1,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
}
/// Derive the approval identity from the exact key, payload hash, completed
/// claim digest, and governed signer policy.
///
/// # Errors
///
/// Returns an error when the opaque request is invalid or canonical encoding fails.
pub fn musubi_provider_attestation_approval_id_v1(
    request: &ProviderIngestMusubiAttestationApprovalRequestV1,
) -> Result<MusubiProviderAttestationApprovalIdV1, MusubiProviderAttestationJournalErrorV1> {
    validate_approval_request(request)
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
    derive_approval_id(
        request.payload(),
        request.completion_claim_digest(),
        request.signer_policy(),
    )
}
fn derive_approval_id(
    payload: &MusubiProviderBundleVerificationPayloadV1,
    completion_claim_digest: [u8; 32],
    signer_policy: ProviderIngestCompletionSignerPolicyV1,
) -> Result<MusubiProviderAttestationApprovalIdV1, MusubiProviderAttestationJournalErrorV1> {
    let signing_hash = payload.signing_hash();
    let preimage = ApprovalIdPreimageV1 {
        key: MusubiProviderBundleAttestationKeyV1 {
            archive_id: payload.binding.archive_id,
            replication_order: payload.binding.replication_order,
            provider_id: payload.binding.provider_id,
        },
        payload_signing_hash: *signing_hash.as_ref(),
        completion_claim_digest,
        signer_policy,
    };
    let digest = domain_hash_norito(APPROVAL_ID_DOMAIN_V1, &preimage)
        .ok_or(MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
    let id = MusubiProviderAttestationApprovalIdV1(digest);
    if !id.is_valid() {
        return Err(MusubiProviderAttestationJournalErrorV1::InvalidIntent);
    }
    Ok(id)
}
/// Derive the idempotent coordinator handoff identity from exact scope, key,
/// and complete attestation digest.
///
/// # Errors
///
/// Returns an error when a component is invalid or canonical encoding fails.
pub fn musubi_provider_attestation_inventory_handoff_id_v1(
    scope: &MusubiProviderAttestationInventoryScopeV1,
    key: MusubiProviderBundleAttestationKeyV1,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
) -> Result<MusubiProviderAttestationInventoryHandoffIdV1, MusubiProviderAttestationInventoryErrorV1>
{
    scope.validate()?;
    key.validate()
        .map_err(|_| MusubiProviderAttestationInventoryErrorV1::InvalidItem)?;
    if key.archive_id != scope.archive_id
        || key.replication_order != scope.replication_order
        || attestation_digest.is_zero()
    {
        return Err(MusubiProviderAttestationInventoryErrorV1::InvalidItem);
    }
    let preimage = InventoryHandoffIdPreimageV1 {
        scope: scope.clone(),
        key,
        attestation_digest,
    };
    let digest = domain_hash_norito(INVENTORY_HANDOFF_ID_DOMAIN_V1, &preimage)
        .ok_or(MusubiProviderAttestationInventoryErrorV1::InvalidItem)?;
    let id = MusubiProviderAttestationInventoryHandoffIdV1(digest);
    if !id.is_valid() {
        return Err(MusubiProviderAttestationInventoryErrorV1::InvalidItem);
    }
    Ok(id)
}
fn domain_hash_norito<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Option<[u8; 32]> {
    let canonical = norito::encode_canonical(value).ok()?;
    let domain_len = u64::try_from(domain.len()).ok()?;
    let canonical_len = u64::try_from(canonical.len()).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&domain_len.to_be_bytes());
    hasher.update(domain);
    hasher.update(&canonical_len.to_be_bytes());
    hasher.update(&canonical);
    Some(*hasher.finalize().as_bytes())
}
/// Bounded persistence, lease, retry, and CAS policy for the attestation journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MusubiProviderAttestationJournalPolicyV1 {
    /// Maximum retained active and terminal entries.
    pub max_entries: usize,
    /// Maximum approval or inventory-handoff attempts per stage.
    pub max_attempts: u32,
    /// Lease duration for approval and inventory-handoff claims.
    pub lease_ttl_ms: u64,
    /// Maximum external approval-signer operation duration.
    pub approval_timeout_ms: u64,
    /// Maximum external coordinator-inventory operation duration.
    pub handoff_timeout_ms: u64,
    /// Delay before retrying a transient stage failure.
    pub retry_delay_ms: u64,
    /// Maximum canonical checkpoint bytes, including the shared reserve for one
    /// active intent's worst-case future attestation state.
    pub checkpoint_max_bytes: usize,
    /// Maximum CAS conflicts retried by one journal operation.
    pub max_cas_retries: u32,
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_attestation_journal::JournalPolicyDigestMaterialV1")]
struct JournalPolicyDigestMaterialV1 {
    version: u8,
    max_entries: u64,
    max_attempts: u32,
    lease_ttl_ms: u64,
    approval_timeout_ms: u64,
    handoff_timeout_ms: u64,
    retry_delay_ms: u64,
    checkpoint_max_bytes: u64,
    max_cas_retries: u32,
}
impl Default for MusubiProviderAttestationJournalPolicyV1 {
    fn default() -> Self {
        Self {
            max_entries: provider_attestation_journal_defaults::MAX_ENTRIES,
            max_attempts: provider_attestation_journal_defaults::MAX_ATTEMPTS,
            lease_ttl_ms: provider_attestation_journal_defaults::LEASE_TTL_MS,
            approval_timeout_ms: provider_attestation_journal_defaults::APPROVAL_TIMEOUT_MS,
            handoff_timeout_ms: provider_attestation_journal_defaults::HANDOFF_TIMEOUT_MS,
            retry_delay_ms: provider_attestation_journal_defaults::RETRY_DELAY_MS,
            checkpoint_max_bytes: usize::try_from(
                provider_attestation_journal_defaults::CHECKPOINT_MAX_BYTES.0,
            )
            .expect("Musubi provider-attestation journal default fits supported usize"),
            max_cas_retries: provider_attestation_journal_defaults::MAX_CAS_RETRIES,
        }
    }
}
impl MusubiProviderAttestationJournalPolicyV1 {
    /// Validate every hard and runtime bound.
    ///
    /// # Errors
    ///
    /// Returns an error when a bound falls outside its hard runtime or decoder limits.
    pub fn validate(self) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
        if self.max_entries == 0
            || self.max_entries > MUSUBI_PROVIDER_ATTESTATION_JOURNAL_MAX_ENTRIES_V1
            || self.max_attempts == 0
            || self.max_attempts > provider_attestation_journal_defaults::MAX_ATTEMPTS_LIMIT
            || self.lease_ttl_ms == 0
            || self.lease_ttl_ms > provider_attestation_journal_defaults::LEASE_TTL_MAX_MS
            || self.approval_timeout_ms == 0
            || self.approval_timeout_ms > MUSUBI_PROVIDER_ATTESTATION_EXTERNAL_TIMEOUT_MAX_MS_V1
            || self.approval_timeout_ms >= self.lease_ttl_ms
            || self.handoff_timeout_ms == 0
            || self.handoff_timeout_ms > MUSUBI_PROVIDER_ATTESTATION_EXTERNAL_TIMEOUT_MAX_MS_V1
            || self.handoff_timeout_ms >= self.lease_ttl_ms
            || self.retry_delay_ms == 0
            || self.retry_delay_ms > provider_attestation_journal_defaults::RETRY_DELAY_MAX_MS
            || self.checkpoint_max_bytes
                < provider_attestation_journal_defaults::CHECKPOINT_MIN_BYTES
            || self.checkpoint_max_bytes
                > MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1
            || self.max_cas_retries == 0
            || self.max_cas_retries > provider_attestation_journal_defaults::MAX_CAS_RETRIES_LIMIT
        {
            return Err(MusubiProviderAttestationJournalErrorV1::InvalidPolicy);
        }
        Ok(())
    }
    /// Return the canonical cross-hardware commitment to every journal bound.
    ///
    /// The checkpoint-head seal includes this digest in its deployment scope,
    /// so a policy change cannot silently reinterpret retained checkpoint
    /// bytes or reuse another policy's monotonic head.
    ///
    /// # Errors
    ///
    /// Returns [`MusubiProviderAttestationJournalErrorV1::InvalidPolicy`] when
    /// a bound is invalid or cannot be represented canonically.
    pub fn digest(self) -> Result<[u8; 32], MusubiProviderAttestationJournalErrorV1> {
        self.validate()?;
        let material = JournalPolicyDigestMaterialV1 {
            version: 1,
            max_entries: u64::try_from(self.max_entries)
                .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidPolicy)?,
            max_attempts: self.max_attempts,
            lease_ttl_ms: self.lease_ttl_ms,
            approval_timeout_ms: self.approval_timeout_ms,
            handoff_timeout_ms: self.handoff_timeout_ms,
            retry_delay_ms: self.retry_delay_ms,
            checkpoint_max_bytes: u64::try_from(self.checkpoint_max_bytes)
                .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidPolicy)?,
            max_cas_retries: self.max_cas_retries,
        };
        domain_hash_norito(JOURNAL_POLICY_DIGEST_DOMAIN_V1, &material)
            .filter(|digest| *digest != [0; 32])
            .ok_or(MusubiProviderAttestationJournalErrorV1::InvalidPolicy)
    }
}
/// Opaque non-zero runtime owner of one journal lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusubiProviderAttestationClaimOwnerV1([u8; 32]);
impl MusubiProviderAttestationClaimOwnerV1 {
    /// Construct an owner identity from runtime entropy.
    ///
    /// # Errors
    ///
    /// Returns an error for the all-zero sentinel.
    pub fn new(bytes: [u8; 32]) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        if bytes == [0; 32] {
            return Err(MusubiProviderAttestationJournalErrorV1::InvalidClaimOwner);
        }
        Ok(Self(bytes))
    }
    /// Return exact owner-identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Crate-internal snapshot returned by the qualified CAS store boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MusubiProviderAttestationJournalStoreSnapshotV1 {
    revision: Option<[u8; 32]>,
    checkpoint_bytes: Option<Vec<u8>>,
}
impl MusubiProviderAttestationJournalStoreSnapshotV1 {
    /// Construct the unique empty-store snapshot.
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            revision: None,
            checkpoint_bytes: None,
        }
    }
    /// Construct a content-addressed snapshot from exact checkpoint bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or hard-oversized bytes.
    pub(crate) fn from_checkpoint_bytes(
        checkpoint_bytes: Vec<u8>,
    ) -> Result<Self, MusubiProviderAttestationJournalStoreErrorV1> {
        if checkpoint_bytes.is_empty()
            || checkpoint_bytes.len() > MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1
        {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        let revision =
            musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint_bytes);
        Ok(Self {
            revision: Some(revision),
            checkpoint_bytes: Some(checkpoint_bytes),
        })
    }
    /// Return the content-addressed revision, absent only for an empty store.
    #[must_use]
    pub(crate) const fn revision(&self) -> Option<[u8; 32]> {
        self.revision
    }
    /// Borrow exact checkpoint bytes, absent only for an empty store.
    #[must_use]
    pub(crate) fn checkpoint_bytes(&self) -> Option<&[u8]> {
        self.checkpoint_bytes.as_deref()
    }
    fn validate(&self) -> bool {
        match (&self.revision, &self.checkpoint_bytes) {
            (None, None) => true,
            (Some(revision), Some(bytes)) => {
                !bytes.is_empty()
                    && bytes.len() <= MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1
                    && *revision
                        == musubi_provider_attestation_journal_checkpoint_revision_v1(bytes)
            }
            _ => false,
        }
    }
}
/// Outcome of one content-addressed compare-and-swap operation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MusubiProviderAttestationJournalCasOutcomeV1 {
    /// The replacement became, or was already, the latest durable checkpoint.
    Stored {
        /// Content-addressed revision of the exact replacement bytes.
        revision: [u8; 32],
    },
    /// The expected revision was stale and no replacement occurred.
    Conflict,
}
/// Payload-free error returned by the abstract journal checkpoint store.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum MusubiProviderAttestationJournalStoreErrorV1 {
    /// The backing store is temporarily unavailable.
    #[error("Musubi provider-attestation journal store is unavailable")]
    Unavailable,
    /// The store rejected malformed, oversized, or non-monotonic state.
    #[error("Musubi provider-attestation journal store rejected the checkpoint")]
    Rejected,
}
/// Abstract content-addressed compare-and-swap checkpoint store.
///
/// Implementations must durably persist replacement bytes before returning
/// [`MusubiProviderAttestationJournalCasOutcomeV1::Stored`]. If the exact
/// replacement bytes are already current, they must return `Stored` as an
/// idempotent no-op regardless of the retained predecessor revision. Every
/// differing replacement is installed only at the exact expected revision.
pub(crate) trait MusubiProviderAttestationJournalStoreV1: Send + Sync + 'static {
    /// Load the latest exact checkpoint or the unique empty snapshot.
    fn load<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderAttestationJournalStoreSnapshotV1,
            MusubiProviderAttestationJournalStoreErrorV1,
        >,
    >;
    /// Atomically replace the latest bytes only at `expected_revision`, or
    /// confirm an exact-current replacement as an idempotent no-op.
    fn compare_and_swap<'a>(
        &'a self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderAttestationJournalCasOutcomeV1,
            MusubiProviderAttestationJournalStoreErrorV1,
        >,
    >;
}
/// Derive the deterministic revision of exact canonical checkpoint bytes.
#[must_use]
pub(crate) fn musubi_provider_attestation_journal_checkpoint_revision_v1(
    checkpoint_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_CHECKPOINT_REVISION_DOMAIN_V1);
    hasher.update(
        &u64::try_from(checkpoint_bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(checkpoint_bytes);
    *hasher.finalize().as_bytes()
}
/// Exact serializable intent retained before approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationApprovalIntentV1 {
    approval_id: MusubiProviderAttestationApprovalIdV1,
    payload: MusubiProviderBundleVerificationPayloadV1,
    completion_claim_digest: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    signer_policy: ProviderIngestCompletionSignerPolicyV1,
    attestation_key: MusubiProviderBundleAttestationKeyV1,
    sequence: u64,
}
impl MusubiProviderAttestationApprovalIntentV1 {
    /// Return the stable approval identity.
    #[must_use]
    pub const fn approval_id(&self) -> MusubiProviderAttestationApprovalIdV1 {
        self.approval_id
    }
    /// Borrow the exact full unsigned attestation payload.
    #[must_use]
    pub const fn payload(&self) -> &MusubiProviderBundleVerificationPayloadV1 {
        &self.payload
    }
    /// Return the stable digest of finalized completed-row evidence.
    ///
    /// The observation cursor is retained separately so the same completed row
    /// can be reverified at a later finalized head after restart.
    #[must_use]
    pub const fn completion_claim_digest(&self) -> [u8; 32] {
        self.completion_claim_digest
    }
    /// Return the finalized cursor at which the completed row was observed.
    #[must_use]
    pub const fn observed_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.observed_finalized_cursor
    }
    /// Return the exact governed signer policy.
    #[must_use]
    pub const fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.signer_policy
    }
    /// Return the immutable archive/order/provider key.
    #[must_use]
    pub const fn attestation_key(&self) -> MusubiProviderBundleAttestationKeyV1 {
        self.attestation_key
    }
    /// Return the insertion sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Return whether a freshly rederived opaque request is exactly this intent.
    #[must_use]
    pub fn matches_request(
        &self,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> bool {
        validate_approval_request(request).is_ok()
            && self.payload == *request.payload()
            && self.completion_claim_digest == request.completion_claim_digest()
            && finalized_cursor_is_same_or_later(
                request.observed_finalized_cursor(),
                self.observed_finalized_cursor,
            )
            && self.signer_policy == request.signer_policy()
            && self.attestation_key == attestation_key(request.payload())
            && derive_approval_id(
                request.payload(),
                request.completion_claim_digest(),
                request.signer_policy(),
            )
            .is_ok_and(|approval_id| approval_id == self.approval_id)
    }
}
/// Public stage of one durable approval/handoff entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusubiProviderAttestationJournalStageV1 {
    /// Exact intent is durable and ready for a freshly derived approval request.
    AwaitingApproval,
    /// One runtime owns a bounded approval lease.
    ApprovalClaimed,
    /// A complete verified attestation is durable and ready for inventory handoff.
    ApprovedPendingHandoff,
    /// One runtime owns a bounded inventory-handoff lease.
    HandoffClaimed,
    /// The exact immutable inventory receipt is durable.
    Delivered,
    /// The entry reached a terminal bounded failure.
    DeadLetter,
}
/// Read-only journal status for one approval identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationJournalStatusV1 {
    /// Exact retained approval intent.
    pub intent: MusubiProviderAttestationApprovalIntentV1,
    /// Current crash-safe stage.
    pub stage: MusubiProviderAttestationJournalStageV1,
    /// Monotonic entry generation used to fence stale claims.
    pub generation: u64,
    /// Terminal reason, present only while the entry is a dead letter.
    pub dead_letter_reason: Option<MusubiProviderAttestationDeadLetterReasonV1>,
    /// Whether a handoff dead letter retains its complete approved attestation.
    pub dead_letter_has_approved_attestation: bool,
    /// Attempts consumed at terminal transition, present only for dead letters.
    pub dead_letter_attempts: Option<u32>,
    /// Durable UNIX epoch millisecond of the terminal transition.
    pub dead_lettered_at_unix_ms: Option<u64>,
}
/// Stable exclusive cursor and work identity for one deterministic journal scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MusubiProviderAttestationJournalScanKeyV1 {
    sequence: u64,
    approval_id: MusubiProviderAttestationApprovalIdV1,
}
impl MusubiProviderAttestationJournalScanKeyV1 {
    /// Return the unique insertion sequence used as the primary scan cursor.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Return the approval identity discovered at this cursor.
    #[must_use]
    pub const fn approval_id(self) -> MusubiProviderAttestationApprovalIdV1 {
        self.approval_id
    }
    fn is_valid(self) -> bool {
        self.sequence != 0 && self.approval_id.is_valid()
    }
}
/// Exact approval lease returned to an isolated worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationApprovalClaimV1 {
    intent: MusubiProviderAttestationApprovalIntentV1,
    owner: MusubiProviderAttestationClaimOwnerV1,
    generation: u64,
    lease_expires_at_ms: u64,
}
impl MusubiProviderAttestationApprovalClaimV1 {
    /// Borrow the persisted approval intent.
    #[must_use]
    pub const fn intent(&self) -> &MusubiProviderAttestationApprovalIntentV1 {
        &self.intent
    }
    /// Return the runtime lease owner.
    #[must_use]
    pub const fn owner(&self) -> MusubiProviderAttestationClaimOwnerV1 {
        self.owner
    }
    /// Return the fenced entry generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Return the lease expiry as durable UNIX epoch milliseconds.
    #[must_use]
    pub const fn lease_expires_at_ms(&self) -> u64 {
        self.lease_expires_at_ms
    }
}
/// Exact inventory-handoff lease returned after approval is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationHandoffClaimV1 {
    approval_id: MusubiProviderAttestationApprovalIdV1,
    item: MusubiProviderAttestationInventoryItemV1,
    owner: MusubiProviderAttestationClaimOwnerV1,
    generation: u64,
    lease_expires_at_ms: u64,
}
impl MusubiProviderAttestationHandoffClaimV1 {
    /// Return the originating approval identity.
    #[must_use]
    pub const fn approval_id(&self) -> MusubiProviderAttestationApprovalIdV1 {
        self.approval_id
    }
    /// Borrow the exact immutable inventory item.
    #[must_use]
    pub const fn item(&self) -> &MusubiProviderAttestationInventoryItemV1 {
        &self.item
    }
    /// Return the runtime lease owner.
    #[must_use]
    pub const fn owner(&self) -> MusubiProviderAttestationClaimOwnerV1 {
        self.owner
    }
    /// Return the fenced entry generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Return the lease expiry as durable UNIX epoch milliseconds.
    #[must_use]
    pub const fn lease_expires_at_ms(&self) -> u64 {
        self.lease_expires_at_ms
    }
}
/// Result of durably inserting or replaying an exact intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusubiProviderAttestationEnqueueOutcomeV1 {
    /// A new approval intent was inserted.
    Inserted {
        /// Stable approval identity.
        approval_id: MusubiProviderAttestationApprovalIdV1,
    },
    /// The exact intent was already retained in any stage.
    Existing {
        /// Stable approval identity.
        approval_id: MusubiProviderAttestationApprovalIdV1,
    },
}
impl MusubiProviderAttestationEnqueueOutcomeV1 {
    /// Return the stable approval identity.
    #[must_use]
    pub const fn approval_id(self) -> MusubiProviderAttestationApprovalIdV1 {
        match self {
            Self::Inserted { approval_id } | Self::Existing { approval_id } => approval_id,
        }
    }
}
/// Read-only admission result before the journal's final enqueue CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MusubiProviderAttestationPreEnqueueProbeV1 {
    /// The exact approval intent remains retained in the local journal.
    RetainedExact,
    /// The authenticated coordinator inventory already retains the exact payload.
    InventoryExact,
    /// Neither the journal nor the exact coordinator inventory retains the request.
    Absent,
}
/// Result of persisting a complete approved attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusubiProviderAttestationApprovalStoreOutcomeV1 {
    /// This call advanced the entry to durable approved state.
    Stored,
    /// The same complete attestation was already durable.
    Existing,
}
/// Result of recording a stage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusubiProviderAttestationRetryOutcomeV1 {
    /// The entry was scheduled for a later retry.
    RetryScheduled,
    /// The entry moved to its bounded terminal dead-letter state.
    DeadLettered,
}
/// Result of persisting an exact inventory receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusubiProviderAttestationDeliveryOutcomeV1 {
    /// This call durably completed the handoff.
    Delivered,
    /// The same receipt was already durable.
    Existing,
}
/// Runtime classification of an approval or handoff failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusubiProviderAttestationFailureClassV1 {
    /// Retry after the configured delay while attempts remain.
    Retryable,
    /// Move immediately to a terminal dead letter.
    Permanent,
}
/// Payload-free reason retained for a terminal journal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub enum MusubiProviderAttestationDeadLetterReasonV1 {
    /// Approval retries or expired approval claims consumed the bound.
    ApprovalRetryExhausted,
    /// The approval operation failed permanently.
    ApprovalRejected,
    /// Inventory retries or expired handoff claims consumed the bound.
    HandoffRetryExhausted,
    /// The coordinator inventory permanently rejected the item.
    HandoffRejected,
}
/// Journal validation, state-transition, or persistence failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MusubiProviderAttestationJournalErrorV1 {
    /// The configured journal policy is zero or exceeds a hard bound.
    #[error("Musubi provider-attestation journal policy is invalid")]
    InvalidPolicy,
    /// The approval intent or freshly rederived request is malformed.
    #[error("Musubi provider-attestation approval intent is invalid")]
    InvalidIntent,
    /// The runtime claim owner is the forbidden all-zero sentinel.
    #[error("Musubi provider-attestation claim owner is invalid")]
    InvalidClaimOwner,
    /// A ready-work page limit is zero or exceeds the hard scan bound.
    #[error("Musubi provider-attestation ready-work page limit is invalid")]
    InvalidPageLimit,
    /// A transition timestamp is zero or older than the durable clock floor.
    #[error("Musubi provider-attestation journal UNIX clock moved backwards")]
    ClockRollback,
    /// The qualified rollback-resistant clock or its seal is unavailable.
    #[error("Musubi provider-attestation journal clock is unavailable")]
    ClockUnavailable,
    /// The qualified clock seal rejected or contradicted its configured binding.
    #[error("Musubi provider-attestation journal clock seal rejected the operation")]
    ClockSealRejected,
    /// The bounded journal has no capacity for another retained identity.
    #[error("Musubi provider-attestation journal capacity is exhausted")]
    CapacityExceeded,
    /// A different intent already occupies the immutable attestation key.
    #[error("Musubi provider-attestation approval intent conflicts with retained state")]
    IntentConflict,
    /// No journal entry exists for the requested approval identity.
    #[error("Musubi provider-attestation approval identity was not found")]
    NotFound,
    /// A claim no longer matches the durable owner, generation, or live lease.
    #[error("Musubi provider-attestation claim is stale")]
    StaleClaim,
    /// The complete attestation is invalid or differs from retained evidence.
    #[error("Musubi provider-attestation approval evidence is invalid")]
    InvalidAttestation,
    /// A different complete attestation is already durable for this intent.
    #[error("Musubi provider-attestation approval evidence conflicts")]
    AttestationConflict,
    /// The qualified approval signer is temporarily unavailable or timed out.
    #[error("Musubi provider-attestation approval signer is unavailable")]
    SignerUnavailable,
    /// The qualified signer rejected or contradicted the retained intent.
    #[error("Musubi provider-attestation approval signer rejected the intent")]
    SignerRejected,
    /// The inventory acknowledgement is invalid or conflicts with durable state.
    #[error("Musubi provider-attestation inventory acknowledgement is invalid")]
    InvalidInventoryReceipt,
    /// The trusted coordinator inventory is temporarily unavailable or timed out.
    #[error("Musubi provider-attestation coordinator inventory is unavailable")]
    InventoryUnavailable,
    /// The trusted coordinator inventory rejected or conflicted with the item.
    #[error("Musubi provider-attestation coordinator inventory rejected the item")]
    InventoryRejected,
    /// The persisted checkpoint is malformed, noncanonical, or violates bounds.
    #[error("Musubi provider-attestation journal checkpoint is corrupt")]
    CorruptCheckpoint,
    /// The abstract checkpoint store is temporarily unavailable.
    #[error("Musubi provider-attestation journal store is unavailable")]
    StoreUnavailable,
    /// The abstract checkpoint store rejected the operation.
    #[error("Musubi provider-attestation journal store rejected the operation")]
    StoreRejected,
    /// Concurrent writers exceeded the bounded CAS retry budget.
    #[error("Musubi provider-attestation journal CAS retry budget is exhausted")]
    CasRetryExhausted,
    /// A counter, lease, or retry timestamp overflowed.
    #[error("Musubi provider-attestation journal counter overflowed")]
    ArithmeticOverflow,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_attestation_journal::StoredApprovalIntentV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredApprovalIntentV1 {
    approval_id: MusubiProviderAttestationApprovalIdV1,
    payload: MusubiProviderBundleVerificationPayloadV1,
    completion_claim_digest: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    signer_policy: ProviderIngestCompletionSignerPolicyV1,
    attestation_key: MusubiProviderBundleAttestationKeyV1,
    sequence: u64,
}
impl StoredApprovalIntentV1 {
    fn public(&self) -> MusubiProviderAttestationApprovalIntentV1 {
        MusubiProviderAttestationApprovalIntentV1 {
            approval_id: self.approval_id,
            payload: self.payload.clone(),
            completion_claim_digest: self.completion_claim_digest,
            observed_finalized_cursor: self.observed_finalized_cursor,
            signer_policy: self.signer_policy,
            attestation_key: self.attestation_key,
            sequence: self.sequence,
        }
    }
    fn validate(&self) -> bool {
        let cursor = self.observed_finalized_cursor;
        let anchor = self.payload.binding.finalized_anchor;
        self.approval_id.is_valid()
            && self.sequence != 0
            && self.completion_claim_digest != [0; 32]
            && self.payload.binding.network_id.as_bytes()[31] & 1 == 1
            && cursor.height != 0
            && cursor.block_hash != [0; 32]
            && anchor.height <= cursor.height
            && (anchor.height != cursor.height || anchor.block_hash == cursor.block_hash)
            && self.payload.validate().is_ok()
            && self.signer_policy.is_valid()
            && self.payload.binding.completion_authority.signer_policy == self.signer_policy
            && self.attestation_key == attestation_key(&self.payload)
            && derive_approval_id(
                &self.payload,
                self.completion_claim_digest,
                self.signer_policy,
            )
            .is_ok_and(|approval_id| approval_id == self.approval_id)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
enum StoredJournalStateV1 {
    AwaitingApproval {
        attempts: u32,
        next_attempt_after_ms: u64,
    },
    ApprovalClaimed {
        attempts: u32,
        owner: [u8; 32],
        lease_expires_at_ms: u64,
    },
    ApprovedPendingHandoff {
        attestation: Box<MusubiProviderBundleVerificationAttestationV1>,
        attempts: u32,
        next_attempt_after_ms: u64,
    },
    HandoffClaimed {
        attestation: Box<MusubiProviderBundleVerificationAttestationV1>,
        attempts: u32,
        owner: [u8; 32],
        lease_expires_at_ms: u64,
    },
    Delivered {
        attestation: Box<MusubiProviderBundleVerificationAttestationV1>,
        receipt: Box<StoredInventoryReceiptV1>,
    },
    DeadLetter {
        reason: MusubiProviderAttestationDeadLetterReasonV1,
        attestation: Option<Box<MusubiProviderBundleVerificationAttestationV1>>,
        attempts: u32,
        dead_lettered_at_unix_ms: u64,
    },
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_attestation_journal::StoredJournalEntryV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredJournalEntryV1 {
    intent: StoredApprovalIntentV1,
    generation: u64,
    state: StoredJournalStateV1,
}
impl StoredJournalEntryV1 {
    fn status(&self) -> MusubiProviderAttestationJournalStatusV1 {
        let (
            stage,
            dead_letter_reason,
            dead_letter_has_approved_attestation,
            dead_letter_attempts,
            dead_lettered_at_unix_ms,
        ) = match &self.state {
            StoredJournalStateV1::AwaitingApproval { .. } => (
                MusubiProviderAttestationJournalStageV1::AwaitingApproval,
                None,
                false,
                None,
                None,
            ),
            StoredJournalStateV1::ApprovalClaimed { .. } => (
                MusubiProviderAttestationJournalStageV1::ApprovalClaimed,
                None,
                false,
                None,
                None,
            ),
            StoredJournalStateV1::ApprovedPendingHandoff { .. } => (
                MusubiProviderAttestationJournalStageV1::ApprovedPendingHandoff,
                None,
                false,
                None,
                None,
            ),
            StoredJournalStateV1::HandoffClaimed { .. } => (
                MusubiProviderAttestationJournalStageV1::HandoffClaimed,
                None,
                false,
                None,
                None,
            ),
            StoredJournalStateV1::Delivered { .. } => (
                MusubiProviderAttestationJournalStageV1::Delivered,
                None,
                false,
                None,
                None,
            ),
            StoredJournalStateV1::DeadLetter {
                reason,
                attestation,
                attempts,
                dead_lettered_at_unix_ms,
            } => (
                MusubiProviderAttestationJournalStageV1::DeadLetter,
                Some(*reason),
                attestation.is_some(),
                Some(*attempts),
                Some(*dead_lettered_at_unix_ms),
            ),
        };
        MusubiProviderAttestationJournalStatusV1 {
            intent: self.intent.public(),
            stage,
            generation: self.generation,
            dead_letter_reason,
            dead_letter_has_approved_attestation,
            dead_letter_attempts,
            dead_lettered_at_unix_ms,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_attestation_journal::StoredJournalCheckpointV1")]
struct StoredJournalCheckpointV1 {
    version: u8,
    checkpoint_sequence: u64,
    next_intent_sequence: u64,
    last_observed_unix_ms: u64,
    entries: Vec<StoredJournalEntryV1>,
}
impl StoredJournalCheckpointV1 {
    const fn empty() -> Self {
        Self {
            version: JOURNAL_CHECKPOINT_VERSION_V1,
            checkpoint_sequence: 0,
            next_intent_sequence: 1,
            last_observed_unix_ms: 0,
            entries: Vec::new(),
        }
    }
    fn validate(&self, policy: MusubiProviderAttestationJournalPolicyV1) -> bool {
        if self.version != JOURNAL_CHECKPOINT_VERSION_V1
            || self.next_intent_sequence == 0
            || self
                .checkpoint_sequence
                .checked_add(1)
                .is_none_or(|maximum| self.next_intent_sequence > maximum)
            || self.entries.len() > policy.max_entries
            || self.entries.len() > MUSUBI_PROVIDER_ATTESTATION_JOURNAL_MAX_ENTRIES_V1
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].intent.approval_id >= pair[1].intent.approval_id)
        {
            return false;
        }
        if self.checkpoint_sequence == 0 && !self.entries.is_empty() {
            return false;
        }
        if self.entries.iter().any(|entry| entry.generation != 0) && self.last_observed_unix_ms == 0
        {
            return false;
        }
        let Some(minimum_checkpoint_sequence) = self
            .entries
            .iter()
            .try_fold(self.next_intent_sequence - 1, |minimum, entry| {
                minimum.checked_add(entry.generation)
            })
        else {
            return false;
        };
        if self.checkpoint_sequence < minimum_checkpoint_sequence {
            return false;
        }
        let mut keys = BTreeSet::new();
        let mut sequences = BTreeSet::new();
        for entry in &self.entries {
            if !entry.intent.validate()
                || entry.intent.sequence >= self.next_intent_sequence
                || entry.generation > self.checkpoint_sequence
                || !keys.insert(entry.intent.attestation_key)
                || !sequences.insert(entry.intent.sequence)
                || !validate_stored_state(entry, policy, self.last_observed_unix_ms)
            {
                return false;
            }
        }
        true
    }
}
fn validate_stored_state(
    entry: &StoredJournalEntryV1,
    policy: MusubiProviderAttestationJournalPolicyV1,
    clock_floor_unix_ms: u64,
) -> bool {
    let valid_attestation = |attestation: &MusubiProviderBundleVerificationAttestationV1| {
        attestation.payload == entry.intent.payload
            && attestation.verify(&entry.intent.payload.binding).is_ok()
    };
    match &entry.state {
        StoredJournalStateV1::AwaitingApproval {
            attempts,
            next_attempt_after_ms,
        } => {
            let retry_is_bounded = *next_attempt_after_ms == 0
                || clock_floor_unix_ms
                    .checked_add(policy.retry_delay_ms)
                    .is_some_and(|maximum| *next_attempt_after_ms <= maximum);
            *attempts < policy.max_attempts
                && u64::from(*attempts) <= entry.generation
                && ((*attempts == 0 && *next_attempt_after_ms == 0 && entry.generation == 0)
                    || (*attempts != 0 && *next_attempt_after_ms != 0 && entry.generation != 0))
                && retry_is_bounded
        }
        StoredJournalStateV1::ApprovalClaimed {
            attempts,
            owner,
            lease_expires_at_ms,
        } => {
            *attempts != 0
                && *attempts <= policy.max_attempts
                && u64::from(*attempts) <= entry.generation
                && *owner != [0; 32]
                && *lease_expires_at_ms != 0
                && clock_floor_unix_ms
                    .checked_add(policy.lease_ttl_ms)
                    .is_some_and(|maximum| *lease_expires_at_ms <= maximum)
                && entry.generation != 0
        }
        StoredJournalStateV1::ApprovedPendingHandoff {
            attestation,
            attempts,
            next_attempt_after_ms,
        } => {
            let retry_is_bounded = *next_attempt_after_ms == 0
                || clock_floor_unix_ms
                    .checked_add(policy.retry_delay_ms)
                    .is_some_and(|maximum| *next_attempt_after_ms <= maximum);
            valid_attestation(attestation)
                && *attempts < policy.max_attempts
                && u64::from(*attempts) <= entry.generation
                && entry.generation != 0
                && ((*attempts == 0 && *next_attempt_after_ms == 0)
                    || (*attempts != 0 && *next_attempt_after_ms != 0))
                && retry_is_bounded
        }
        StoredJournalStateV1::HandoffClaimed {
            attestation,
            attempts,
            owner,
            lease_expires_at_ms,
        } => {
            valid_attestation(attestation)
                && *attempts != 0
                && *attempts <= policy.max_attempts
                && u64::from(*attempts) <= entry.generation
                && *owner != [0; 32]
                && *lease_expires_at_ms != 0
                && clock_floor_unix_ms
                    .checked_add(policy.lease_ttl_ms)
                    .is_some_and(|maximum| *lease_expires_at_ms <= maximum)
                && entry.generation != 0
        }
        StoredJournalStateV1::Delivered {
            attestation,
            receipt,
        } => MusubiProviderAttestationInventoryItemV1::new((**attestation).clone()).is_ok_and(
            |item| {
                entry.generation != 0 && valid_attestation(attestation) && receipt.matches(&item)
            },
        ),
        StoredJournalStateV1::DeadLetter {
            reason,
            attestation,
            attempts,
            dead_lettered_at_unix_ms,
        } => {
            let evidence_shape_is_valid = match reason {
                MusubiProviderAttestationDeadLetterReasonV1::ApprovalRetryExhausted
                | MusubiProviderAttestationDeadLetterReasonV1::ApprovalRejected => {
                    attestation.is_none()
                }
                MusubiProviderAttestationDeadLetterReasonV1::HandoffRetryExhausted
                | MusubiProviderAttestationDeadLetterReasonV1::HandoffRejected => {
                    attestation.as_deref().is_some_and(&valid_attestation)
                }
            };
            entry.generation != 0
                && *attempts != 0
                && *attempts <= policy.max_attempts
                && u64::from(*attempts) <= entry.generation
                && *dead_lettered_at_unix_ms != 0
                && *dead_lettered_at_unix_ms <= clock_floor_unix_ms
                && evidence_shape_is_valid
        }
    }
}
fn attestation_key(
    payload: &MusubiProviderBundleVerificationPayloadV1,
) -> MusubiProviderBundleAttestationKeyV1 {
    MusubiProviderBundleAttestationKeyV1 {
        archive_id: payload.binding.archive_id,
        replication_order: payload.binding.replication_order,
        provider_id: payload.binding.provider_id,
    }
}
fn finalized_cursor_is_same_or_later(
    candidate: ProviderIngestFinalizedCursorV1,
    retained: ProviderIngestFinalizedCursorV1,
) -> bool {
    candidate.height > retained.height
        || candidate.height == retained.height && candidate.block_hash == retained.block_hash
}
fn validate_scan_bounds(
    after: Option<MusubiProviderAttestationJournalScanKeyV1>,
    limit: usize,
) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
    if after.is_some_and(|cursor| !cursor.is_valid())
        || limit == 0
        || limit > MUSUBI_PROVIDER_ATTESTATION_READY_PAGE_MAX_V1
    {
        return Err(MusubiProviderAttestationJournalErrorV1::InvalidPageLimit);
    }
    Ok(())
}
fn validate_observed_unix_time(
    checkpoint: &StoredJournalCheckpointV1,
    now_unix_ms: u64,
) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
    if now_unix_ms == 0 || now_unix_ms < checkpoint.last_observed_unix_ms {
        return Err(MusubiProviderAttestationJournalErrorV1::ClockRollback);
    }
    Ok(())
}
fn ordered_entry_page<Predicate>(
    checkpoint: &StoredJournalCheckpointV1,
    after: Option<MusubiProviderAttestationJournalScanKeyV1>,
    limit: usize,
    mut predicate: Predicate,
) -> Vec<MusubiProviderAttestationJournalScanKeyV1>
where
    Predicate: FnMut(&StoredJournalEntryV1) -> bool,
{
    let mut ready = checkpoint
        .entries
        .iter()
        .filter(|entry| predicate(entry))
        .map(|entry| MusubiProviderAttestationJournalScanKeyV1 {
            sequence: entry.intent.sequence,
            approval_id: entry.intent.approval_id,
        })
        .filter(|cursor| after.is_none_or(|after| *cursor > after))
        .collect::<Vec<_>>();
    ready.sort_unstable();
    ready.into_iter().take(limit).collect()
}
fn retained_request_is_exact(
    checkpoint: &StoredJournalCheckpointV1,
    request: &ProviderIngestMusubiAttestationApprovalRequestV1,
    requested_approval_id: MusubiProviderAttestationApprovalIdV1,
    requested_key: MusubiProviderBundleAttestationKeyV1,
) -> Result<bool, MusubiProviderAttestationJournalErrorV1> {
    let Some(existing) = checkpoint
        .entries
        .iter()
        .find(|entry| entry.intent.attestation_key == requested_key)
    else {
        return Ok(false);
    };
    if existing.intent.approval_id == requested_approval_id
        && existing.intent.public().matches_request(request)
    {
        return Ok(true);
    }
    Err(MusubiProviderAttestationJournalErrorV1::IntentConflict)
}
fn intent_from_request(
    request: &ProviderIngestMusubiAttestationApprovalRequestV1,
    sequence: u64,
) -> Result<StoredApprovalIntentV1, MusubiProviderAttestationJournalErrorV1> {
    validate_approval_request(request)
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
    let approval_id = musubi_provider_attestation_approval_id_v1(request)?;
    let intent = StoredApprovalIntentV1 {
        approval_id,
        payload: request.payload().clone(),
        completion_claim_digest: request.completion_claim_digest(),
        observed_finalized_cursor: request.observed_finalized_cursor(),
        signer_policy: request.signer_policy(),
        attestation_key: attestation_key(request.payload()),
        sequence,
    };
    if !intent.validate() {
        return Err(MusubiProviderAttestationJournalErrorV1::InvalidIntent);
    }
    Ok(intent)
}
fn increment_generation(
    entry: &mut StoredJournalEntryV1,
) -> Result<u64, MusubiProviderAttestationJournalErrorV1> {
    entry.generation = entry
        .generation
        .checked_add(1)
        .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
    Ok(entry.generation)
}
fn approval_claim_from_entry(
    entry: &StoredJournalEntryV1,
) -> Option<MusubiProviderAttestationApprovalClaimV1> {
    let StoredJournalStateV1::ApprovalClaimed {
        owner,
        lease_expires_at_ms,
        ..
    } = &entry.state
    else {
        return None;
    };
    Some(MusubiProviderAttestationApprovalClaimV1 {
        intent: entry.intent.public(),
        owner: MusubiProviderAttestationClaimOwnerV1(*owner),
        generation: entry.generation,
        lease_expires_at_ms: *lease_expires_at_ms,
    })
}
fn handoff_claim_from_entry(
    entry: &StoredJournalEntryV1,
) -> Option<MusubiProviderAttestationHandoffClaimV1> {
    let StoredJournalStateV1::HandoffClaimed {
        attestation,
        owner,
        lease_expires_at_ms,
        ..
    } = &entry.state
    else {
        return None;
    };
    let item = MusubiProviderAttestationInventoryItemV1::new((**attestation).clone()).ok()?;
    Some(MusubiProviderAttestationHandoffClaimV1 {
        approval_id: entry.intent.approval_id,
        item,
        owner: MusubiProviderAttestationClaimOwnerV1(*owner),
        generation: entry.generation,
        lease_expires_at_ms: *lease_expires_at_ms,
    })
}
enum JournalMutationV1<T> {
    NoWrite(T),
    Write(T),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalCoordinationPhaseV1 {
    Preflight,
    External,
    SealTime,
    Persist,
}
pub(crate) trait MusubiProviderAttestationJournalTimeV1: Send + Sync {
    fn now_unix_ms<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<'a, Result<u64, MusubiProviderAttestationJournalErrorV1>>;
}
#[cfg(test)]
impl MusubiProviderAttestationJournalTimeV1 for MusubiProviderAttestationSealedUnixClockV1 {
    fn now_unix_ms<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<'a, Result<u64, MusubiProviderAttestationJournalErrorV1>> {
        Box::pin(async move {
            MusubiProviderAttestationSealedUnixClockV1::now_unix_ms(self)
                .await
                .map_err(map_clock_error)
        })
    }
}
/// Durable bounded state machine for approval-only signing and inventory handoff.
///
/// Every `now_unix_ms` argument is an absolute UNIX epoch millisecond supplied
/// by a durable deployment clock. The checkpoint persists the greatest
/// observed value and rejects rollback after process or machine restart.
pub(crate) struct MusubiProviderAttestationJournalV1 {
    store: Arc<dyn MusubiProviderAttestationJournalStoreV1>,
    policy: MusubiProviderAttestationJournalPolicyV1,
}
impl MusubiProviderAttestationJournalV1 {
    /// Bind the journal to one abstract durable CAS store and validated policy.
    ///
    /// # Errors
    ///
    /// Returns an error when any policy bound is invalid.
    pub(crate) fn new(
        store: Arc<dyn MusubiProviderAttestationJournalStoreV1>,
        policy: MusubiProviderAttestationJournalPolicyV1,
    ) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        policy.validate()?;
        Ok(Self { store, policy })
    }
    /// Return the validated persistence and retry policy.
    #[must_use]
    pub(crate) const fn policy(&self) -> MusubiProviderAttestationJournalPolicyV1 {
        self.policy
    }
    /// Check retained intent first, then the authenticated exact inventory entry.
    ///
    /// This read-only probe never reserves journal capacity or manufactures a delivery receipt.
    /// Callers must still invoke [`Self::enqueue`] for an absent result so its compare-and-set
    /// transition resolves concurrent journal changes. The inventory operation is bounded by the
    /// same hard deadline as a handoff and fences runtime identity, qualification, and readiness
    /// before and after the exact read.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, a retained immutable-key
    /// conflict, corrupt persistence, inventory timeout or unavailability, an
    /// unqualified runtime, or a substituted/conflicting readback.
    pub(crate) async fn probe_pre_enqueue_with_inventory<Inventory>(
        &self,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
        inventory: &Inventory,
    ) -> Result<MusubiProviderAttestationPreEnqueueProbeV1, MusubiProviderAttestationJournalErrorV1>
    where
        Inventory: MusubiProviderAttestationInventoryRuntimeV1 + ?Sized,
    {
        validate_approval_request(request)
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
        let requested_approval_id = musubi_provider_attestation_approval_id_v1(request)?;
        let requested_key = attestation_key(request.payload());
        let checkpoint = self.load_checkpoint().await?;
        if retained_request_is_exact(&checkpoint, request, requested_approval_id, requested_key)? {
            return Ok(MusubiProviderAttestationPreEnqueueProbeV1::RetainedExact);
        }
        let scope =
            MusubiProviderAttestationInventoryScopeV1::from_binding(&request.payload().binding);
        scope
            .validate()
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
        requested_key
            .validate()
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
        if requested_key.archive_id != scope.archive_id
            || requested_key.replication_order != scope.replication_order
        {
            return Err(MusubiProviderAttestationJournalErrorV1::InvalidIntent);
        }
        let monotonic_deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(self.policy.handoff_timeout_ms))
            .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
        tokio::time::timeout_at(monotonic_deadline, async {
            let runtime_before = qualified_inventory_runtime_snapshot(inventory).await?;
            let readback = inventory
                .get(&scope, requested_key)
                .await
                .map_err(map_inventory_error);
            let runtime_after = qualified_inventory_runtime_snapshot(inventory).await?;
            if runtime_after != runtime_before {
                return Err(MusubiProviderAttestationJournalErrorV1::InventoryRejected);
            }
            let Some(readback) = readback? else {
                return Ok(MusubiProviderAttestationPreEnqueueProbeV1::Absent);
            };
            let item = readback.item();
            if readback.inventory_revision() == 0
                || item.validate().is_err()
                || item.scope() != &scope
                || item.key() != requested_key
                || &item.attestation().payload != request.payload()
            {
                return Err(MusubiProviderAttestationJournalErrorV1::InventoryRejected);
            }
            Ok(MusubiProviderAttestationPreEnqueueProbeV1::InventoryExact)
        })
        .await
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::InventoryUnavailable)?
    }
    /// Insert or idempotently replay one exact opaque approval request.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, capacity exhaustion, an immutable
    /// key conflict, corrupt persistence, or store failure.
    pub(crate) async fn enqueue(
        &self,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> Result<MusubiProviderAttestationEnqueueOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        validate_approval_request(request)
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidIntent)?;
        let requested_approval_id = musubi_provider_attestation_approval_id_v1(request)?;
        let requested_key = attestation_key(request.payload());
        self.mutate(|checkpoint| {
            if retained_request_is_exact(checkpoint, request, requested_approval_id, requested_key)?
            {
                return Ok(JournalMutationV1::NoWrite(
                    MusubiProviderAttestationEnqueueOutcomeV1::Existing {
                        approval_id: requested_approval_id,
                    },
                ));
            }
            let candidate = intent_from_request(request, checkpoint.next_intent_sequence)?;
            if checkpoint.entries.len() >= self.policy.max_entries {
                if let Some((oldest_delivered_index, _)) = checkpoint
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| {
                        matches!(&entry.state, StoredJournalStateV1::Delivered { .. })
                    })
                    .min_by_key(|(_, entry)| entry.intent.sequence)
                {
                    checkpoint.entries.remove(oldest_delivered_index);
                }
            }
            if checkpoint.entries.len() >= self.policy.max_entries {
                return Err(MusubiProviderAttestationJournalErrorV1::CapacityExceeded);
            }
            checkpoint.next_intent_sequence = checkpoint
                .next_intent_sequence
                .checked_add(1)
                .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
            checkpoint.entries.push(StoredJournalEntryV1 {
                intent: candidate,
                generation: 0,
                state: StoredJournalStateV1::AwaitingApproval {
                    attempts: 0,
                    next_attempt_after_ms: 0,
                },
            });
            checkpoint
                .entries
                .sort_by_key(|entry| entry.intent.approval_id);
            Ok(JournalMutationV1::Write(
                MusubiProviderAttestationEnqueueOutcomeV1::Inserted {
                    approval_id: requested_approval_id,
                },
            ))
        })
        .await
    }
    /// Read one durable journal status without modifying its checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt persistence or store failure.
    pub(crate) async fn status(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
    ) -> Result<
        Option<MusubiProviderAttestationJournalStatusV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        let snapshot = self.load_checkpoint().await?;
        Ok(snapshot
            .entries
            .iter()
            .find(|entry| entry.intent.approval_id == approval_id)
            .map(StoredJournalEntryV1::status))
    }
    /// Return a deterministic bounded page of approval identities ready now.
    ///
    /// This restart-safe scan includes due awaiting entries and expired claims,
    /// ordered by insertion sequence and then approval identity. Claim fencing
    /// still resolves races between workers after discovery.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page bound, clock rollback, corrupt
    /// persistence, or store failure.
    pub(crate) async fn ready_approval_page(
        &self,
        now_unix_ms: u64,
        after: Option<MusubiProviderAttestationJournalScanKeyV1>,
        limit: usize,
    ) -> Result<
        Vec<MusubiProviderAttestationJournalScanKeyV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        validate_scan_bounds(after, limit)?;
        let checkpoint = self.load_checkpoint().await?;
        validate_observed_unix_time(&checkpoint, now_unix_ms)?;
        Ok(ordered_entry_page(
            &checkpoint,
            after,
            limit,
            |entry| match &entry.state {
                StoredJournalStateV1::AwaitingApproval {
                    next_attempt_after_ms,
                    ..
                } => now_unix_ms >= *next_attempt_after_ms,
                StoredJournalStateV1::ApprovalClaimed {
                    lease_expires_at_ms,
                    ..
                } => now_unix_ms >= *lease_expires_at_ms,
                _ => false,
            },
        ))
    }
    /// Return a deterministic bounded page of handoff identities ready now.
    ///
    /// This restart-safe scan includes due approved entries and expired
    /// handoff claims, ordered by insertion sequence and approval identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page bound, clock rollback, corrupt
    /// persistence, or store failure.
    pub(crate) async fn ready_handoff_page(
        &self,
        now_unix_ms: u64,
        after: Option<MusubiProviderAttestationJournalScanKeyV1>,
        limit: usize,
    ) -> Result<
        Vec<MusubiProviderAttestationJournalScanKeyV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        validate_scan_bounds(after, limit)?;
        let checkpoint = self.load_checkpoint().await?;
        validate_observed_unix_time(&checkpoint, now_unix_ms)?;
        Ok(ordered_entry_page(
            &checkpoint,
            after,
            limit,
            |entry| match &entry.state {
                StoredJournalStateV1::ApprovedPendingHandoff {
                    next_attempt_after_ms,
                    ..
                } => now_unix_ms >= *next_attempt_after_ms,
                StoredJournalStateV1::HandoffClaimed {
                    lease_expires_at_ms,
                    ..
                } => now_unix_ms >= *lease_expires_at_ms,
                _ => false,
            },
        ))
    }
    /// Return a deterministic bounded page of retained dead-letter identities.
    ///
    /// Operators can rediscover terminal work after restart without a second durable index, inspect
    /// status, and then explicitly requeue or acknowledge it using generation fencing.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page bound, corrupt persistence, or store failure.
    pub(crate) async fn dead_letter_page(
        &self,
        after: Option<MusubiProviderAttestationJournalScanKeyV1>,
        limit: usize,
    ) -> Result<
        Vec<MusubiProviderAttestationJournalScanKeyV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        validate_scan_bounds(after, limit)?;
        let checkpoint = self.load_checkpoint().await?;
        Ok(ordered_entry_page(&checkpoint, after, limit, |entry| {
            matches!(&entry.state, StoredJournalStateV1::DeadLetter { .. })
        }))
    }
    /// Explicitly requeue one generation-fenced dead letter for operator repair.
    ///
    /// Approval dead letters return to approval. Handoff dead letters retain
    /// and reuse their already-verified attestation, returning directly to
    /// pending handoff without another signature operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is absent, the expected generation is
    /// stale, the UNIX clock rolls back, or persistence fails.
    pub(crate) async fn requeue_dead_letter(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        expected_generation: u64,
        now_unix_ms: u64,
    ) -> Result<MusubiProviderAttestationJournalStageV1, MusubiProviderAttestationJournalErrorV1>
    {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let entry = checkpoint
                .entries
                .iter_mut()
                .find(|entry| entry.intent.approval_id == approval_id)
                .ok_or(MusubiProviderAttestationJournalErrorV1::NotFound)?;
            if entry.generation != expected_generation {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            }
            let StoredJournalStateV1::DeadLetter { attestation, .. } = &entry.state else {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            };
            let attestation = attestation.clone();
            increment_generation(entry)?;
            let stage = if let Some(attestation) = attestation {
                entry.state = StoredJournalStateV1::ApprovedPendingHandoff {
                    attestation,
                    attempts: 0,
                    next_attempt_after_ms: 0,
                };
                MusubiProviderAttestationJournalStageV1::ApprovedPendingHandoff
            } else {
                entry.state = StoredJournalStateV1::AwaitingApproval {
                    attempts: 0,
                    next_attempt_after_ms: 0,
                };
                MusubiProviderAttestationJournalStageV1::AwaitingApproval
            };
            Ok(JournalMutationV1::Write(stage))
        })
        .await
    }
    /// Explicitly remove one inspected generation-fenced dead letter.
    ///
    /// This is the only dead-letter removal API. Normal capacity handling
    /// never deletes a dead letter, active claim, or unacknowledged attestation.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is absent, the expected generation is
    /// stale, the entry is not a dead letter, or persistence fails.
    pub(crate) async fn acknowledge_dead_letter(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        expected_generation: u64,
    ) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
        self.mutate(|checkpoint| {
            let index = checkpoint
                .entries
                .iter()
                .position(|entry| entry.intent.approval_id == approval_id)
                .ok_or(MusubiProviderAttestationJournalErrorV1::NotFound)?;
            let entry = &checkpoint.entries[index];
            if entry.generation != expected_generation
                || !matches!(&entry.state, StoredJournalStateV1::DeadLetter { .. })
            {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            }
            checkpoint.entries.remove(index);
            Ok(JournalMutationV1::Write(()))
        })
        .await
    }
    /// Claim ready approval work or reclaim an expired approval lease.
    ///
    /// An unexpired claim owned by the same runtime replays exactly. Another
    /// owner's live claim, a future retry time, or a later stage returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid owner, arithmetic overflow, corrupt
    /// persistence, or store failure.
    pub(crate) async fn claim_approval(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        owner: MusubiProviderAttestationClaimOwnerV1,
        now_unix_ms: u64,
    ) -> Result<
        Option<MusubiProviderAttestationApprovalClaimV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let Some(index) = checkpoint
                .entries
                .iter()
                .position(|entry| entry.intent.approval_id == approval_id)
            else {
                return Ok(JournalMutationV1::NoWrite(None));
            };
            let entry = &mut checkpoint.entries[index];
            match entry.state.clone() {
                StoredJournalStateV1::AwaitingApproval {
                    attempts,
                    next_attempt_after_ms,
                } => {
                    if now_unix_ms < next_attempt_after_ms {
                        return Ok(JournalMutationV1::NoWrite(None));
                    }
                    if attempts >= self.policy.max_attempts {
                        increment_generation(entry)?;
                        entry.state = StoredJournalStateV1::DeadLetter {
                            reason:
                                MusubiProviderAttestationDeadLetterReasonV1::ApprovalRetryExhausted,
                            attestation: None,
                            attempts,
                            dead_lettered_at_unix_ms: now_unix_ms,
                        };
                        return Ok(JournalMutationV1::Write(None));
                    }
                    claim_approval_entry(entry, owner, now_unix_ms, self.policy, attempts)
                }
                StoredJournalStateV1::ApprovalClaimed {
                    attempts,
                    owner: retained_owner,
                    lease_expires_at_ms,
                } => {
                    if now_unix_ms < lease_expires_at_ms {
                        if retained_owner == owner.0 {
                            return Ok(JournalMutationV1::NoWrite(approval_claim_from_entry(
                                entry,
                            )));
                        }
                        return Ok(JournalMutationV1::NoWrite(None));
                    }
                    if attempts >= self.policy.max_attempts {
                        increment_generation(entry)?;
                        entry.state = StoredJournalStateV1::DeadLetter {
                            reason:
                                MusubiProviderAttestationDeadLetterReasonV1::ApprovalRetryExhausted,
                            attestation: None,
                            attempts,
                            dead_lettered_at_unix_ms: now_unix_ms,
                        };
                        return Ok(JournalMutationV1::Write(None));
                    }
                    claim_approval_entry(entry, owner, now_unix_ms, self.policy, attempts)
                }
                _ => Ok(JournalMutationV1::NoWrite(None)),
            }
        })
        .await
    }
    /// Return a claimed approval to retry or move it to a terminal dead letter.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, arithmetic overflow, corrupt
    /// persistence, or store failure.
    pub(crate) async fn record_approval_failure(
        &self,
        claim: &MusubiProviderAttestationApprovalClaimV1,
        now_unix_ms: u64,
        failure: MusubiProviderAttestationFailureClassV1,
    ) -> Result<MusubiProviderAttestationRetryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let entry = exact_approval_claim_entry(checkpoint, claim, now_unix_ms)?;
            let StoredJournalStateV1::ApprovalClaimed { attempts, .. } = &entry.state else {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            };
            let attempts = *attempts;
            increment_generation(entry)?;
            if failure == MusubiProviderAttestationFailureClassV1::Permanent
                || attempts >= self.policy.max_attempts
            {
                entry.state = StoredJournalStateV1::DeadLetter {
                    reason: if failure == MusubiProviderAttestationFailureClassV1::Permanent {
                        MusubiProviderAttestationDeadLetterReasonV1::ApprovalRejected
                    } else {
                        MusubiProviderAttestationDeadLetterReasonV1::ApprovalRetryExhausted
                    },
                    attestation: None,
                    attempts,
                    dead_lettered_at_unix_ms: now_unix_ms,
                };
                return Ok(JournalMutationV1::Write(
                    MusubiProviderAttestationRetryOutcomeV1::DeadLettered,
                ));
            }
            let retry_at = now_unix_ms
                .checked_add(self.policy.retry_delay_ms)
                .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
            entry.state = StoredJournalStateV1::AwaitingApproval {
                attempts,
                next_attempt_after_ms: retry_at,
            };
            Ok(JournalMutationV1::Write(
                MusubiProviderAttestationRetryOutcomeV1::RetryScheduled,
            ))
        })
        .await
    }
    /// Invoke the qualified approval-only signer and durably store its exact result.
    ///
    /// The signer timeout must fit wholly inside the retained approval lease. The low-level state
    /// transition is not exposed outside this crate, so a downstream caller cannot bypass live
    /// signer qualification by supplying an independently constructed attestation.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim/request, signer failure, invalid or
    /// conflicting evidence, corrupt persistence, or store failure.
    pub(crate) async fn approve_claim_with_signer<Signer, Clock>(
        &self,
        claim: &MusubiProviderAttestationApprovalClaimV1,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
        signer: &Signer,
        clock: &Clock,
    ) -> Result<
        MusubiProviderAttestationApprovalStoreOutcomeV1,
        MusubiProviderAttestationJournalErrorV1,
    >
    where
        Signer: MusubiProviderAttestationSignerV1 + ?Sized,
        Clock: MusubiProviderAttestationJournalTimeV1 + ?Sized,
    {
        if !claim.intent.matches_request(request) {
            return Err(MusubiProviderAttestationJournalErrorV1::InvalidAttestation);
        }
        let now_unix_ms = clock.now_unix_ms().await?;
        let operation_deadline = now_unix_ms
            .checked_add(self.policy.approval_timeout_ms)
            .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
        if operation_deadline >= claim.lease_expires_at_ms {
            return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
        }
        let started = tokio::time::Instant::now();
        let monotonic_deadline = started
            .checked_add(Duration::from_millis(self.policy.approval_timeout_ms))
            .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
        let mut phase = ExternalCoordinationPhaseV1::Preflight;
        tokio::time::timeout_at(monotonic_deadline, async {
            if self.preflight_approval_claim(claim, now_unix_ms).await? {
                return Ok(MusubiProviderAttestationApprovalStoreOutcomeV1::Existing);
            }
            phase = ExternalCoordinationPhaseV1::External;
            let attestation = approve_musubi_provider_attestation_v1(
                signer,
                request,
                self.policy.approval_timeout_ms,
            )
            .await
            .map_err(map_approval_error)?;
            phase = ExternalCoordinationPhaseV1::SealTime;
            let completed_at_unix_ms = clock.now_unix_ms().await?;
            if completed_at_unix_ms >= operation_deadline {
                return Err(MusubiProviderAttestationJournalErrorV1::SignerUnavailable);
            }
            if completed_at_unix_ms >= claim.lease_expires_at_ms {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            }
            phase = ExternalCoordinationPhaseV1::Persist;
            self.store_approved(claim, request, attestation, completed_at_unix_ms)
                .await
        })
        .await
        .map_err(|_| match phase {
            ExternalCoordinationPhaseV1::External => {
                MusubiProviderAttestationJournalErrorV1::SignerUnavailable
            }
            ExternalCoordinationPhaseV1::SealTime => {
                MusubiProviderAttestationJournalErrorV1::ClockUnavailable
            }
            ExternalCoordinationPhaseV1::Preflight | ExternalCoordinationPhaseV1::Persist => {
                MusubiProviderAttestationJournalErrorV1::StoreUnavailable
            }
        })?
    }
    /// Persist a complete signer-validated attestation under an exact live claim.
    ///
    /// A caller must supply the freshly rederived opaque request used for
    /// signing; persisted intent alone can never authorize approval after a restart.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim/request, invalid or conflicting
    /// attestation, corrupt persistence, or store failure.
    pub(crate) async fn store_approved(
        &self,
        claim: &MusubiProviderAttestationApprovalClaimV1,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
        attestation: MusubiProviderBundleVerificationAttestationV1,
        now_unix_ms: u64,
    ) -> Result<
        MusubiProviderAttestationApprovalStoreOutcomeV1,
        MusubiProviderAttestationJournalErrorV1,
    > {
        if !claim.intent.matches_request(request)
            || attestation.payload != *request.payload()
            || attestation.verify(&request.payload().binding).is_err()
        {
            return Err(MusubiProviderAttestationJournalErrorV1::InvalidAttestation);
        }
        self.mutate_at(now_unix_ms, |checkpoint| {
            let Some(entry) = checkpoint
                .entries
                .iter_mut()
                .find(|entry| entry.intent.approval_id == claim.intent.approval_id)
            else {
                return Err(MusubiProviderAttestationJournalErrorV1::NotFound);
            };
            match &entry.state {
                StoredJournalStateV1::ApprovedPendingHandoff {
                    attestation: retained,
                    ..
                }
                | StoredJournalStateV1::HandoffClaimed {
                    attestation: retained,
                    ..
                }
                | StoredJournalStateV1::Delivered {
                    attestation: retained,
                    ..
                } => {
                    return if retained.as_ref() == &attestation {
                        Ok(JournalMutationV1::NoWrite(
                            MusubiProviderAttestationApprovalStoreOutcomeV1::Existing,
                        ))
                    } else {
                        Err(MusubiProviderAttestationJournalErrorV1::AttestationConflict)
                    };
                }
                StoredJournalStateV1::DeadLetter { .. } => {
                    return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
                }
                _ => {}
            }
            validate_exact_approval_claim(entry, claim, now_unix_ms)?;
            increment_generation(entry)?;
            entry.state = StoredJournalStateV1::ApprovedPendingHandoff {
                attestation: Box::new(attestation.clone()),
                attempts: 0,
                next_attempt_after_ms: 0,
            };
            Ok(JournalMutationV1::Write(
                MusubiProviderAttestationApprovalStoreOutcomeV1::Stored,
            ))
        })
        .await
    }
    /// Claim approved inventory work or reclaim an expired handoff lease.
    ///
    /// # Errors
    ///
    /// Returns an error for arithmetic overflow, invalid retained evidence,
    /// corrupt persistence, or store failure.
    pub(crate) async fn claim_handoff(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        owner: MusubiProviderAttestationClaimOwnerV1,
        now_unix_ms: u64,
    ) -> Result<
        Option<MusubiProviderAttestationHandoffClaimV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let Some(index) = checkpoint
                .entries
                .iter()
                .position(|entry| entry.intent.approval_id == approval_id)
            else {
                return Ok(JournalMutationV1::NoWrite(None));
            };
            let entry = &mut checkpoint.entries[index];
            match entry.state.clone() {
                StoredJournalStateV1::ApprovedPendingHandoff {
                    attestation,
                    attempts,
                    next_attempt_after_ms,
                } => {
                    if now_unix_ms < next_attempt_after_ms {
                        return Ok(JournalMutationV1::NoWrite(None));
                    }
                    if attempts >= self.policy.max_attempts {
                        increment_generation(entry)?;
                        entry.state = StoredJournalStateV1::DeadLetter {
                            reason:
                                MusubiProviderAttestationDeadLetterReasonV1::HandoffRetryExhausted,
                            attestation: Some(attestation),
                            attempts,
                            dead_lettered_at_unix_ms: now_unix_ms,
                        };
                        return Ok(JournalMutationV1::Write(None));
                    }
                    claim_handoff_entry(
                        entry,
                        owner,
                        now_unix_ms,
                        self.policy,
                        attestation,
                        attempts,
                    )
                }
                StoredJournalStateV1::HandoffClaimed {
                    attestation,
                    attempts,
                    owner: retained_owner,
                    lease_expires_at_ms,
                } => {
                    if now_unix_ms < lease_expires_at_ms {
                        if retained_owner == owner.0 {
                            return Ok(JournalMutationV1::NoWrite(handoff_claim_from_entry(entry)));
                        }
                        return Ok(JournalMutationV1::NoWrite(None));
                    }
                    if attempts >= self.policy.max_attempts {
                        increment_generation(entry)?;
                        entry.state = StoredJournalStateV1::DeadLetter {
                            reason:
                                MusubiProviderAttestationDeadLetterReasonV1::HandoffRetryExhausted,
                            attestation: Some(attestation),
                            attempts,
                            dead_lettered_at_unix_ms: now_unix_ms,
                        };
                        return Ok(JournalMutationV1::Write(None));
                    }
                    claim_handoff_entry(
                        entry,
                        owner,
                        now_unix_ms,
                        self.policy,
                        attestation,
                        attempts,
                    )
                }
                _ => Ok(JournalMutationV1::NoWrite(None)),
            }
        })
        .await
    }
    /// Return a claimed inventory handoff to retry or dead-letter it.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, arithmetic overflow, corrupt
    /// persistence, or store failure.
    pub(crate) async fn record_handoff_failure(
        &self,
        claim: &MusubiProviderAttestationHandoffClaimV1,
        now_unix_ms: u64,
        failure: MusubiProviderAttestationFailureClassV1,
    ) -> Result<MusubiProviderAttestationRetryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let entry = exact_handoff_claim_entry(checkpoint, claim, now_unix_ms)?;
            let StoredJournalStateV1::HandoffClaimed {
                attestation,
                attempts,
                ..
            } = &entry.state
            else {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            };
            let attestation = attestation.clone();
            let attempts = *attempts;
            increment_generation(entry)?;
            if failure == MusubiProviderAttestationFailureClassV1::Permanent
                || attempts >= self.policy.max_attempts
            {
                entry.state = StoredJournalStateV1::DeadLetter {
                    reason: if failure == MusubiProviderAttestationFailureClassV1::Permanent {
                        MusubiProviderAttestationDeadLetterReasonV1::HandoffRejected
                    } else {
                        MusubiProviderAttestationDeadLetterReasonV1::HandoffRetryExhausted
                    },
                    attestation: Some(attestation),
                    attempts,
                    dead_lettered_at_unix_ms: now_unix_ms,
                };
                return Ok(JournalMutationV1::Write(
                    MusubiProviderAttestationRetryOutcomeV1::DeadLettered,
                ));
            }
            let retry_at = now_unix_ms
                .checked_add(self.policy.retry_delay_ms)
                .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
            entry.state = StoredJournalStateV1::ApprovedPendingHandoff {
                attestation,
                attempts,
                next_attempt_after_ms: retry_at,
            };
            Ok(JournalMutationV1::Write(
                MusubiProviderAttestationRetryOutcomeV1::RetryScheduled,
            ))
        })
        .await
    }
    /// Send one exact item through the trusted idempotent inventory boundary
    /// and durably retain its acknowledgement.
    ///
    /// The handoff timeout must fit wholly inside the retained handoff lease. The combined
    /// sink/reader/runtime is a deployment-qualified adapter which authenticates its remote
    /// coordinator. This driver remains crate-private, so a downstream trait implementation cannot
    /// directly manufacture durable delivery state. A successful `put` is always followed by an
    /// exact readback, and both its item and authoritative revision must match before delivery.
    /// Handle, qualification, and readiness are fenced before and after those calls.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, timeout, inventory rejection,
    /// substituted readback, corrupt persistence, or store failure.
    pub(crate) async fn handoff_claim_with_inventory<Inventory, Clock>(
        &self,
        claim: &MusubiProviderAttestationHandoffClaimV1,
        inventory: &Inventory,
        clock: &Clock,
    ) -> Result<MusubiProviderAttestationDeliveryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    where
        Inventory: MusubiProviderAttestationInventoryRuntimeV1 + ?Sized,
        Clock: MusubiProviderAttestationJournalTimeV1 + ?Sized,
    {
        let now_unix_ms = clock.now_unix_ms().await?;
        let operation_deadline = now_unix_ms
            .checked_add(self.policy.handoff_timeout_ms)
            .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
        if operation_deadline >= claim.lease_expires_at_ms {
            return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
        }
        let started = tokio::time::Instant::now();
        let monotonic_deadline = started
            .checked_add(Duration::from_millis(self.policy.handoff_timeout_ms))
            .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
        let mut phase = ExternalCoordinationPhaseV1::Preflight;
        tokio::time::timeout_at(monotonic_deadline, async {
            if self.preflight_handoff_claim(claim, now_unix_ms).await? {
                return Ok(MusubiProviderAttestationDeliveryOutcomeV1::Existing);
            }
            phase = ExternalCoordinationPhaseV1::External;
            let runtime_before = qualified_inventory_runtime_snapshot(inventory).await?;
            let external_result = async {
                let inventory_revision = inventory
                    .put(claim.item.clone())
                    .await
                    .map_err(map_inventory_error)?;
                let readback = inventory
                    .get(claim.item.scope(), claim.item.key())
                    .await
                    .map_err(map_inventory_error)?
                    .ok_or(MusubiProviderAttestationJournalErrorV1::InvalidInventoryReceipt)?;
                if !readback.matches(&claim.item, inventory_revision) {
                    return Err(MusubiProviderAttestationJournalErrorV1::InvalidInventoryReceipt);
                }
                Ok(readback)
            }
            .await;
            let runtime_after = qualified_inventory_runtime_snapshot(inventory).await?;
            if runtime_after != runtime_before {
                return Err(MusubiProviderAttestationJournalErrorV1::InventoryRejected);
            }
            let readback = external_result?;
            phase = ExternalCoordinationPhaseV1::SealTime;
            let completed_at_unix_ms = clock.now_unix_ms().await?;
            if completed_at_unix_ms >= operation_deadline {
                return Err(MusubiProviderAttestationJournalErrorV1::InventoryUnavailable);
            }
            if completed_at_unix_ms >= claim.lease_expires_at_ms {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            }
            let receipt = MusubiProviderAttestationInventoryReceiptV1::new(
                readback.item(),
                readback.inventory_revision(),
            )
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidInventoryReceipt)?;
            phase = ExternalCoordinationPhaseV1::Persist;
            self.mark_delivered(claim, receipt, completed_at_unix_ms)
                .await
        })
        .await
        .map_err(|_| match phase {
            ExternalCoordinationPhaseV1::External => {
                MusubiProviderAttestationJournalErrorV1::InventoryUnavailable
            }
            ExternalCoordinationPhaseV1::SealTime => {
                MusubiProviderAttestationJournalErrorV1::ClockUnavailable
            }
            ExternalCoordinationPhaseV1::Preflight | ExternalCoordinationPhaseV1::Persist => {
                MusubiProviderAttestationJournalErrorV1::StoreUnavailable
            }
        })?
    }
    /// Durably record an exact idempotent coordinator inventory receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, substituted acknowledgement,
    /// corrupt persistence, or store failure.
    pub(crate) async fn mark_delivered(
        &self,
        claim: &MusubiProviderAttestationHandoffClaimV1,
        receipt: MusubiProviderAttestationInventoryReceiptV1,
        now_unix_ms: u64,
    ) -> Result<MusubiProviderAttestationDeliveryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        if !receipt.matches(&claim.item) {
            return Err(MusubiProviderAttestationJournalErrorV1::InvalidInventoryReceipt);
        }
        let stored_receipt = StoredInventoryReceiptV1::from_public(&receipt);
        self.mutate_at(now_unix_ms, |checkpoint| {
            let Some(entry) = checkpoint
                .entries
                .iter_mut()
                .find(|entry| entry.intent.approval_id == claim.approval_id)
            else {
                return Err(MusubiProviderAttestationJournalErrorV1::NotFound);
            };
            if let StoredJournalStateV1::Delivered {
                receipt: retained, ..
            } = &entry.state
            {
                return if retained.as_ref() == &stored_receipt {
                    Ok(JournalMutationV1::NoWrite(
                        MusubiProviderAttestationDeliveryOutcomeV1::Existing,
                    ))
                } else {
                    Err(MusubiProviderAttestationJournalErrorV1::InvalidInventoryReceipt)
                };
            }
            validate_exact_handoff_claim(entry, claim, now_unix_ms)?;
            let StoredJournalStateV1::HandoffClaimed { attestation, .. } = &entry.state else {
                return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
            };
            let attestation = attestation.clone();
            increment_generation(entry)?;
            entry.state = StoredJournalStateV1::Delivered {
                attestation,
                receipt: Box::new(stored_receipt.clone()),
            };
            Ok(JournalMutationV1::Write(
                MusubiProviderAttestationDeliveryOutcomeV1::Delivered,
            ))
        })
        .await
    }
    async fn load_checkpoint(
        &self,
    ) -> Result<StoredJournalCheckpointV1, MusubiProviderAttestationJournalErrorV1> {
        let snapshot = self.store.load().await.map_err(map_store_error)?;
        decode_checkpoint(&snapshot, self.policy)
    }
    async fn preflight_approval_claim(
        &self,
        claim: &MusubiProviderAttestationApprovalClaimV1,
        now_unix_ms: u64,
    ) -> Result<bool, MusubiProviderAttestationJournalErrorV1> {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let entry = checkpoint
                .entries
                .iter()
                .find(|entry| entry.intent.approval_id == claim.intent.approval_id)
                .ok_or(MusubiProviderAttestationJournalErrorV1::NotFound)?;
            if let StoredJournalStateV1::ApprovedPendingHandoff { attestation, .. }
            | StoredJournalStateV1::HandoffClaimed { attestation, .. }
            | StoredJournalStateV1::Delivered { attestation, .. } = &entry.state
            {
                if attestation.payload == entry.intent.payload
                    && attestation.verify(&entry.intent.payload.binding).is_ok()
                {
                    return Ok(JournalMutationV1::NoWrite(true));
                }
                return Err(MusubiProviderAttestationJournalErrorV1::InvalidAttestation);
            }
            validate_exact_approval_claim(entry, claim, now_unix_ms)?;
            Ok(JournalMutationV1::Write(false))
        })
        .await
    }
    async fn preflight_handoff_claim(
        &self,
        claim: &MusubiProviderAttestationHandoffClaimV1,
        now_unix_ms: u64,
    ) -> Result<bool, MusubiProviderAttestationJournalErrorV1> {
        self.mutate_at(now_unix_ms, |checkpoint| {
            let entry = checkpoint
                .entries
                .iter()
                .find(|entry| entry.intent.approval_id == claim.approval_id)
                .ok_or(MusubiProviderAttestationJournalErrorV1::NotFound)?;
            if let StoredJournalStateV1::Delivered {
                attestation,
                receipt,
            } = &entry.state
            {
                let item =
                    MusubiProviderAttestationInventoryItemV1::new((**attestation).clone())
                        .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidAttestation)?;
                if item == claim.item && receipt.matches(&item) {
                    return Ok(JournalMutationV1::NoWrite(true));
                }
                return Err(MusubiProviderAttestationJournalErrorV1::InvalidInventoryReceipt);
            }
            validate_exact_handoff_claim(entry, claim, now_unix_ms)?;
            Ok(JournalMutationV1::Write(false))
        })
        .await
    }
    async fn mutate_at<T, Transition>(
        &self,
        now_unix_ms: u64,
        mut transition: Transition,
    ) -> Result<T, MusubiProviderAttestationJournalErrorV1>
    where
        Transition: FnMut(
            &mut StoredJournalCheckpointV1,
        )
            -> Result<JournalMutationV1<T>, MusubiProviderAttestationJournalErrorV1>,
    {
        self.mutate(|checkpoint| {
            validate_observed_unix_time(checkpoint, now_unix_ms)?;
            match transition(checkpoint)? {
                JournalMutationV1::NoWrite(result) => Ok(JournalMutationV1::NoWrite(result)),
                JournalMutationV1::Write(result) => {
                    checkpoint.last_observed_unix_ms = now_unix_ms;
                    Ok(JournalMutationV1::Write(result))
                }
            }
        })
        .await
    }
    async fn mutate<T, Transition>(
        &self,
        mut transition: Transition,
    ) -> Result<T, MusubiProviderAttestationJournalErrorV1>
    where
        Transition: FnMut(
            &mut StoredJournalCheckpointV1,
        )
            -> Result<JournalMutationV1<T>, MusubiProviderAttestationJournalErrorV1>,
    {
        for _ in 0..self.policy.max_cas_retries {
            let snapshot = self.store.load().await.map_err(map_store_error)?;
            let expected_revision = snapshot.revision();
            let mut checkpoint = decode_checkpoint(&snapshot, self.policy)?;
            let pruneable_delivered = checkpoint
                .entries
                .iter()
                .filter(|entry| matches!(&entry.state, StoredJournalStateV1::Delivered { .. }))
                .map(|entry| entry.intent.approval_id)
                .collect::<BTreeSet<_>>();
            let result = match transition(&mut checkpoint)? {
                JournalMutationV1::NoWrite(result) => return Ok(result),
                JournalMutationV1::Write(result) => result,
            };
            checkpoint.checkpoint_sequence = checkpoint
                .checkpoint_sequence
                .checked_add(1)
                .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
            let replacement = encode_checkpoint_pruning_delivered(
                &mut checkpoint,
                self.policy,
                &pruneable_delivered,
            )?;
            let expected_stored_revision =
                musubi_provider_attestation_journal_checkpoint_revision_v1(&replacement);
            match self
                .store
                .compare_and_swap(expected_revision, replacement)
                .await
                .map_err(map_store_error)?
            {
                MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision }
                    if revision == expected_stored_revision =>
                {
                    return Ok(result);
                }
                MusubiProviderAttestationJournalCasOutcomeV1::Stored { .. } => {
                    return Err(MusubiProviderAttestationJournalErrorV1::StoreRejected);
                }
                MusubiProviderAttestationJournalCasOutcomeV1::Conflict => {}
            }
        }
        Err(MusubiProviderAttestationJournalErrorV1::CasRetryExhausted)
    }
}
/// Daemon-facing journal which owns one qualified rollback-resistant clock.
///
/// Timed operations deliberately expose no caller-supplied timestamp. The raw
/// state machine remains crate-private for focused transition testing, while
/// daemon integrations must advance the configured external monotonic seal
/// before scanning, claiming, retrying, signing, or handing off work.
///
/// The runtime deliberately does not expose a per-call signer injection:
///
/// ```compile_fail
/// use sorafs_node::{
///     MusubiProviderAttestationApprovalClaimV1,
///     MusubiProviderAttestationJournalRuntimeV1,
///     MusubiProviderAttestationSignerV1,
///     ProviderIngestMusubiAttestationApprovalRequestV1,
/// };
///
/// fn bypass_configured_signer<Signer: MusubiProviderAttestationSignerV1>(
///     runtime: &MusubiProviderAttestationJournalRuntimeV1,
///     claim: &MusubiProviderAttestationApprovalClaimV1,
///     request: &ProviderIngestMusubiAttestationApprovalRequestV1,
///     signer: &Signer,
/// ) {
///     let _ = runtime.approve_claim_with_signer(claim, request, signer);
/// }
/// ```
pub struct MusubiProviderAttestationJournalRuntimeV1 {
    journal: MusubiProviderAttestationJournalV1,
    clock: JournalClockV1,
    binding: MusubiProviderAttestationJournalRuntimeBindingV1,
}
/// Closed clock selection: native files do not claim external rollback-seal authority.
#[derive(Debug)]
enum JournalClockV1 {
    #[cfg(test)]
    External(Arc<MusubiProviderAttestationSealedUnixClockV1>),
    Native(Arc<crate::provider_attestation_native::NativeStore>),
}
impl MusubiProviderAttestationJournalTimeV1 for JournalClockV1 {
    fn now_unix_ms<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<'a, Result<u64, MusubiProviderAttestationJournalErrorV1>> {
        Box::pin(async move {
            match self {
                #[cfg(test)]
                Self::External(clock) => clock.now_unix_ms().await.map_err(map_clock_error),
                Self::Native(clock) => clock.now_unix_ms().await,
            }
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MusubiProviderAttestationJournalRuntimeBindingV1 {
    network_id: NetworkId,
    provider_id: ProviderId,
    policy_digest: [u8; 32],
    clock_scope_digest: [u8; 32],
    checkpoint_scope_digest: [u8; 32],
    opened_existing: bool,
}
impl fmt::Debug for MusubiProviderAttestationJournalRuntimeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiProviderAttestationJournalRuntimeV1")
            .field("policy", &self.journal.policy())
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}
impl MusubiProviderAttestationJournalRuntimeV1 {
    /// Construct only from the concrete ordinary-open native owner, never an injected store.
    pub(crate) fn new_native_opened(
        store: Arc<crate::provider_attestation_native::NativeStore>,
        policy: MusubiProviderAttestationJournalPolicyV1,
        clock: Arc<crate::provider_attestation_native::NativeStore>,
        network_id: NetworkId,
        provider_id: ProviderId,
    ) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        if !Arc::ptr_eq(&store, &clock) {
            return Err(MusubiProviderAttestationJournalErrorV1::StoreRejected);
        }
        let policy_digest = policy.digest()?;
        let clock_scope_digest =
            MusubiProviderAttestationClockScopeV1::try_new(network_id, provider_id)
                .and_then(|scope| scope.scope_digest())
                .map_err(|_| MusubiProviderAttestationJournalErrorV1::StoreRejected)?;
        let checkpoint_scope_digest = MusubiProviderAttestationJournalCheckpointScopeV1::try_new(
            network_id,
            provider_id,
            policy_digest,
        )
        .and_then(|scope| scope.scope_digest())
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::StoreRejected)?;
        Ok(Self {
            journal: MusubiProviderAttestationJournalV1::new(store, policy)?,
            clock: JournalClockV1::Native(clock),
            binding: MusubiProviderAttestationJournalRuntimeBindingV1 {
                network_id,
                provider_id,
                policy_digest,
                clock_scope_digest,
                checkpoint_scope_digest,
                opened_existing: true,
            },
        })
    }
    /// Bind a validated journal store to one already initialized qualified clock.
    ///
    /// # Errors
    ///
    /// Returns an error when any journal policy bound is invalid.
    #[cfg(test)]
    pub(crate) fn new_initialized(
        store: Arc<dyn MusubiProviderAttestationJournalStoreV1>,
        policy: MusubiProviderAttestationJournalPolicyV1,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
        checkpoint_scope: MusubiProviderAttestationJournalCheckpointScopeV1,
    ) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        Self::new(store, policy, clock, checkpoint_scope, false)
    }
    /// Bind a journal runtime only after ordinary open proved an existing H0.
    #[cfg(test)]
    pub(crate) fn new_opened(
        store: Arc<dyn MusubiProviderAttestationJournalStoreV1>,
        policy: MusubiProviderAttestationJournalPolicyV1,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
        checkpoint_scope: MusubiProviderAttestationJournalCheckpointScopeV1,
    ) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        Self::new(store, policy, clock, checkpoint_scope, true)
    }
    #[cfg(test)]
    fn new(
        store: Arc<dyn MusubiProviderAttestationJournalStoreV1>,
        policy: MusubiProviderAttestationJournalPolicyV1,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
        checkpoint_scope: MusubiProviderAttestationJournalCheckpointScopeV1,
        opened_existing: bool,
    ) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        let network_id = *checkpoint_scope.network_id();
        let provider_id = checkpoint_scope.provider_id();
        let policy_digest = policy.digest()?;
        if checkpoint_scope.journal_policy_digest() != policy_digest {
            return Err(MusubiProviderAttestationJournalErrorV1::StoreRejected);
        }
        let clock_scope_digest =
            MusubiProviderAttestationClockScopeV1::try_new(network_id, provider_id)
                .map_err(|_| MusubiProviderAttestationJournalErrorV1::StoreRejected)?
                .scope_digest()
                .map_err(|_| MusubiProviderAttestationJournalErrorV1::StoreRejected)?;
        if clock.scope_digest() != clock_scope_digest {
            return Err(MusubiProviderAttestationJournalErrorV1::StoreRejected);
        }
        let checkpoint_scope_digest = checkpoint_scope
            .scope_digest()
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::StoreRejected)?;
        Ok(Self {
            journal: MusubiProviderAttestationJournalV1::new(store, policy)?,
            clock: JournalClockV1::External(clock),
            binding: MusubiProviderAttestationJournalRuntimeBindingV1 {
                network_id,
                provider_id,
                policy_digest,
                clock_scope_digest,
                checkpoint_scope_digest,
                opened_existing,
            },
        })
    }
    /// Check the complete private deployment scope without exposing it.
    pub(crate) fn matches_binding(
        &self,
        network_id: NetworkId,
        provider_id: ProviderId,
        policy: MusubiProviderAttestationJournalPolicyV1,
    ) -> bool {
        let Ok(policy_digest) = policy.digest() else {
            return false;
        };
        let Ok(clock_scope) =
            MusubiProviderAttestationClockScopeV1::try_new(network_id, provider_id)
        else {
            return false;
        };
        let Ok(clock_scope_digest) = clock_scope.scope_digest() else {
            return false;
        };
        let Ok(checkpoint_scope) = MusubiProviderAttestationJournalCheckpointScopeV1::try_new(
            network_id,
            provider_id,
            policy_digest,
        ) else {
            return false;
        };
        let Ok(checkpoint_scope_digest) = checkpoint_scope.scope_digest() else {
            return false;
        };
        self.journal.policy() == policy
            && self.binding.opened_existing
            && self.binding
                == MusubiProviderAttestationJournalRuntimeBindingV1 {
                    network_id,
                    provider_id,
                    policy_digest,
                    clock_scope_digest,
                    checkpoint_scope_digest,
                    opened_existing: true,
                }
    }
    pub(crate) const fn raw_journal(&self) -> &MusubiProviderAttestationJournalV1 {
        &self.journal
    }
    /// Return the validated persistence and retry policy.
    #[must_use]
    pub const fn policy(&self) -> MusubiProviderAttestationJournalPolicyV1 {
        self.journal.policy()
    }
    /// Insert or idempotently replay one exact opaque approval request.
    ///
    /// # Errors
    ///
    /// Returns the underlying bounded journal validation or persistence error.
    pub async fn enqueue(
        &self,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> Result<MusubiProviderAttestationEnqueueOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        self.journal.enqueue(request).await
    }
    /// Read one durable journal status.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt or unavailable persistence.
    pub async fn status(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
    ) -> Result<
        Option<MusubiProviderAttestationJournalStatusV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        self.journal.status(approval_id).await
    }
    /// Return a bounded page of approvals ready at the selected durable clock.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, page-bound, or persistence failure.
    pub async fn ready_approval_page(
        &self,
        after: Option<MusubiProviderAttestationJournalScanKeyV1>,
        limit: usize,
    ) -> Result<
        Vec<MusubiProviderAttestationJournalScanKeyV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        let now = self.now_unix_ms().await?;
        self.journal.ready_approval_page(now, after, limit).await
    }
    /// Return a bounded page of handoffs ready at the selected durable clock.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, page-bound, or persistence failure.
    pub async fn ready_handoff_page(
        &self,
        after: Option<MusubiProviderAttestationJournalScanKeyV1>,
        limit: usize,
    ) -> Result<
        Vec<MusubiProviderAttestationJournalScanKeyV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        let now = self.now_unix_ms().await?;
        self.journal.ready_handoff_page(now, after, limit).await
    }
    /// Return a bounded page of retained dead-letter identities.
    ///
    /// # Errors
    ///
    /// Returns an error for page-bound or persistence failure.
    pub async fn dead_letter_page(
        &self,
        after: Option<MusubiProviderAttestationJournalScanKeyV1>,
        limit: usize,
    ) -> Result<
        Vec<MusubiProviderAttestationJournalScanKeyV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        self.journal.dead_letter_page(after, limit).await
    }
    /// Explicitly requeue one generation-fenced dead letter at durable lease time.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, fencing, or persistence failure.
    pub async fn requeue_dead_letter(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        expected_generation: u64,
    ) -> Result<MusubiProviderAttestationJournalStageV1, MusubiProviderAttestationJournalErrorV1>
    {
        let now = self.now_unix_ms().await?;
        self.journal
            .requeue_dead_letter(approval_id, expected_generation, now)
            .await
    }
    /// Remove one inspected generation-fenced dead letter.
    ///
    /// # Errors
    ///
    /// Returns an error for stale fencing or persistence failure.
    pub async fn acknowledge_dead_letter(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        expected_generation: u64,
    ) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
        self.journal
            .acknowledge_dead_letter(approval_id, expected_generation)
            .await
    }
    /// Claim approval work under a lease starting at durable lease time.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, claim, or persistence failure.
    pub async fn claim_approval(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        owner: MusubiProviderAttestationClaimOwnerV1,
    ) -> Result<
        Option<MusubiProviderAttestationApprovalClaimV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        let now = self.now_unix_ms().await?;
        self.journal.claim_approval(approval_id, owner, now).await
    }
    /// Return a claimed approval to retry or dead-letter it at durable lease time.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, stale claim, or persistence failure.
    pub async fn record_approval_failure(
        &self,
        claim: &MusubiProviderAttestationApprovalClaimV1,
        failure: MusubiProviderAttestationFailureClassV1,
    ) -> Result<MusubiProviderAttestationRetryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        let now = self.now_unix_ms().await?;
        self.journal
            .record_approval_failure(claim, now, failure)
            .await
    }
    /// Invoke one structurally qualified signer inside the live durable-time lease.
    ///
    /// The standard daemon composer supplies a governed signer that fences the configured handle,
    /// revision, policy, deployment context, and full finalized completion authority around every approval. This
    /// operation additionally enforces the signer's structural validity and snapshot stability.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, stale request/claim, signer, or persistence failure.
    pub(crate) async fn approve_claim_with_signer<Signer>(
        &self,
        claim: &MusubiProviderAttestationApprovalClaimV1,
        request: &ProviderIngestMusubiAttestationApprovalRequestV1,
        signer: &Signer,
    ) -> Result<
        MusubiProviderAttestationApprovalStoreOutcomeV1,
        MusubiProviderAttestationJournalErrorV1,
    >
    where
        Signer: MusubiProviderAttestationSignerV1 + ?Sized,
    {
        self.journal
            .approve_claim_with_signer(claim, request, signer, &self.clock)
            .await
    }
    /// Claim inventory-handoff work under a lease starting at durable lease time.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, retained evidence, or persistence failure.
    pub async fn claim_handoff(
        &self,
        approval_id: MusubiProviderAttestationApprovalIdV1,
        owner: MusubiProviderAttestationClaimOwnerV1,
    ) -> Result<
        Option<MusubiProviderAttestationHandoffClaimV1>,
        MusubiProviderAttestationJournalErrorV1,
    > {
        let now = self.now_unix_ms().await?;
        self.journal.claim_handoff(approval_id, owner, now).await
    }
    /// Return a claimed handoff to retry or dead-letter it at durable lease time.
    ///
    /// # Errors
    ///
    /// Returns an error for clock, stale claim, or persistence failure.
    pub async fn record_handoff_failure(
        &self,
        claim: &MusubiProviderAttestationHandoffClaimV1,
        failure: MusubiProviderAttestationFailureClassV1,
    ) -> Result<MusubiProviderAttestationRetryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    {
        let now = self.now_unix_ms().await?;
        self.journal
            .record_handoff_failure(claim, now, failure)
            .await
    }
    // The standard daemon composer supplies a governed inventory that fences
    // configured handle, revision, policy, and local scope around readiness and
    // every fallible call. This operation additionally enforces structural
    // validity and snapshot stability.
    pub(crate) async fn handoff_claim_with_inventory<Inventory>(
        &self,
        claim: &MusubiProviderAttestationHandoffClaimV1,
        inventory: &Inventory,
    ) -> Result<MusubiProviderAttestationDeliveryOutcomeV1, MusubiProviderAttestationJournalErrorV1>
    where
        Inventory: MusubiProviderAttestationInventoryRuntimeV1 + ?Sized,
    {
        self.journal
            .handoff_claim_with_inventory(claim, inventory, &self.clock)
            .await
    }
    async fn now_unix_ms(&self) -> Result<u64, MusubiProviderAttestationJournalErrorV1> {
        self.clock.now_unix_ms().await
    }
}
#[cfg(test)]
fn map_clock_error(
    error: MusubiProviderAttestationClockErrorV1,
) -> MusubiProviderAttestationJournalErrorV1 {
    match error {
        MusubiProviderAttestationClockErrorV1::ClockRollback => {
            MusubiProviderAttestationJournalErrorV1::ClockRollback
        }
        MusubiProviderAttestationClockErrorV1::SealUnavailable => {
            MusubiProviderAttestationJournalErrorV1::ClockUnavailable
        }
        MusubiProviderAttestationClockErrorV1::InvalidScope
        | MusubiProviderAttestationClockErrorV1::InvalidSealBinding
        | MusubiProviderAttestationClockErrorV1::Uninitialized
        | MusubiProviderAttestationClockErrorV1::AlreadyInitialized
        | MusubiProviderAttestationClockErrorV1::InvalidSealRecord
        | MusubiProviderAttestationClockErrorV1::SealRejected
        | MusubiProviderAttestationClockErrorV1::SealAmbiguous => {
            MusubiProviderAttestationJournalErrorV1::ClockSealRejected
        }
        MusubiProviderAttestationClockErrorV1::ArithmeticOverflow => {
            MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow
        }
    }
}
fn claim_approval_entry(
    entry: &mut StoredJournalEntryV1,
    owner: MusubiProviderAttestationClaimOwnerV1,
    now_ms: u64,
    policy: MusubiProviderAttestationJournalPolicyV1,
    attempts: u32,
) -> Result<
    JournalMutationV1<Option<MusubiProviderAttestationApprovalClaimV1>>,
    MusubiProviderAttestationJournalErrorV1,
> {
    let attempts = attempts
        .checked_add(1)
        .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
    let lease_expires_at_ms = now_ms
        .checked_add(policy.lease_ttl_ms)
        .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
    increment_generation(entry)?;
    entry.state = StoredJournalStateV1::ApprovalClaimed {
        attempts,
        owner: owner.0,
        lease_expires_at_ms,
    };
    Ok(JournalMutationV1::Write(approval_claim_from_entry(entry)))
}
fn claim_handoff_entry(
    entry: &mut StoredJournalEntryV1,
    owner: MusubiProviderAttestationClaimOwnerV1,
    now_ms: u64,
    policy: MusubiProviderAttestationJournalPolicyV1,
    attestation: Box<MusubiProviderBundleVerificationAttestationV1>,
    attempts: u32,
) -> Result<
    JournalMutationV1<Option<MusubiProviderAttestationHandoffClaimV1>>,
    MusubiProviderAttestationJournalErrorV1,
> {
    let attempts = attempts
        .checked_add(1)
        .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
    let lease_expires_at_ms = now_ms
        .checked_add(policy.lease_ttl_ms)
        .ok_or(MusubiProviderAttestationJournalErrorV1::ArithmeticOverflow)?;
    increment_generation(entry)?;
    entry.state = StoredJournalStateV1::HandoffClaimed {
        attestation,
        attempts,
        owner: owner.0,
        lease_expires_at_ms,
    };
    let claim = handoff_claim_from_entry(entry)
        .ok_or(MusubiProviderAttestationJournalErrorV1::InvalidAttestation)?;
    Ok(JournalMutationV1::Write(Some(claim)))
}
fn validate_exact_approval_claim(
    entry: &StoredJournalEntryV1,
    claim: &MusubiProviderAttestationApprovalClaimV1,
    now_ms: u64,
) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
    let StoredJournalStateV1::ApprovalClaimed {
        owner,
        lease_expires_at_ms,
        ..
    } = &entry.state
    else {
        return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
    };
    if entry.intent.public() != claim.intent
        || entry.generation != claim.generation
        || *owner != claim.owner.0
        || *lease_expires_at_ms != claim.lease_expires_at_ms
        || now_ms >= *lease_expires_at_ms
    {
        return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
    }
    Ok(())
}
fn exact_approval_claim_entry<'a>(
    checkpoint: &'a mut StoredJournalCheckpointV1,
    claim: &MusubiProviderAttestationApprovalClaimV1,
    now_ms: u64,
) -> Result<&'a mut StoredJournalEntryV1, MusubiProviderAttestationJournalErrorV1> {
    let entry = checkpoint
        .entries
        .iter_mut()
        .find(|entry| entry.intent.approval_id == claim.intent.approval_id)
        .ok_or(MusubiProviderAttestationJournalErrorV1::NotFound)?;
    validate_exact_approval_claim(entry, claim, now_ms)?;
    Ok(entry)
}
fn validate_exact_handoff_claim(
    entry: &StoredJournalEntryV1,
    claim: &MusubiProviderAttestationHandoffClaimV1,
    now_ms: u64,
) -> Result<(), MusubiProviderAttestationJournalErrorV1> {
    let StoredJournalStateV1::HandoffClaimed {
        attestation,
        owner,
        lease_expires_at_ms,
        ..
    } = &entry.state
    else {
        return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
    };
    let retained_item = MusubiProviderAttestationInventoryItemV1::new((**attestation).clone())
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::InvalidAttestation)?;
    if entry.intent.approval_id != claim.approval_id
        || retained_item != claim.item
        || entry.generation != claim.generation
        || *owner != claim.owner.0
        || *lease_expires_at_ms != claim.lease_expires_at_ms
        || now_ms >= *lease_expires_at_ms
    {
        return Err(MusubiProviderAttestationJournalErrorV1::StaleClaim);
    }
    Ok(())
}
fn exact_handoff_claim_entry<'a>(
    checkpoint: &'a mut StoredJournalCheckpointV1,
    claim: &MusubiProviderAttestationHandoffClaimV1,
    now_ms: u64,
) -> Result<&'a mut StoredJournalEntryV1, MusubiProviderAttestationJournalErrorV1> {
    let entry = checkpoint
        .entries
        .iter_mut()
        .find(|entry| entry.intent.approval_id == claim.approval_id)
        .ok_or(MusubiProviderAttestationJournalErrorV1::NotFound)?;
    validate_exact_handoff_claim(entry, claim, now_ms)?;
    Ok(entry)
}
fn map_store_error(
    error: MusubiProviderAttestationJournalStoreErrorV1,
) -> MusubiProviderAttestationJournalErrorV1 {
    match error {
        MusubiProviderAttestationJournalStoreErrorV1::Unavailable => {
            MusubiProviderAttestationJournalErrorV1::StoreUnavailable
        }
        MusubiProviderAttestationJournalStoreErrorV1::Rejected => {
            MusubiProviderAttestationJournalErrorV1::StoreRejected
        }
    }
}
fn map_approval_error(
    error: MusubiProviderAttestationApprovalErrorV1,
) -> MusubiProviderAttestationJournalErrorV1 {
    match error {
        MusubiProviderAttestationApprovalErrorV1::SignerUnavailable
        | MusubiProviderAttestationApprovalErrorV1::SignerTimedOut => {
            MusubiProviderAttestationJournalErrorV1::SignerUnavailable
        }
        MusubiProviderAttestationApprovalErrorV1::SignerRejected
        | MusubiProviderAttestationApprovalErrorV1::EligibilityChanged
        | MusubiProviderAttestationApprovalErrorV1::InvalidSignerHandle
        | MusubiProviderAttestationApprovalErrorV1::InvalidSignerQualification => {
            MusubiProviderAttestationJournalErrorV1::SignerRejected
        }
        MusubiProviderAttestationApprovalErrorV1::InvalidRequest
        | MusubiProviderAttestationApprovalErrorV1::InvalidAttestation => {
            MusubiProviderAttestationJournalErrorV1::InvalidAttestation
        }
    }
}
fn map_inventory_error(
    error: MusubiProviderAttestationInventoryErrorV1,
) -> MusubiProviderAttestationJournalErrorV1 {
    match error {
        MusubiProviderAttestationInventoryErrorV1::Unavailable => {
            MusubiProviderAttestationJournalErrorV1::InventoryUnavailable
        }
        MusubiProviderAttestationInventoryErrorV1::InvalidItem
        | MusubiProviderAttestationInventoryErrorV1::InvalidInventory
        | MusubiProviderAttestationInventoryErrorV1::InvalidReceipt
        | MusubiProviderAttestationInventoryErrorV1::Conflict
        | MusubiProviderAttestationInventoryErrorV1::Rejected => {
            MusubiProviderAttestationJournalErrorV1::InventoryRejected
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct QualifiedInventoryRuntimeSnapshotV1 {
    runtime_handle: String,
    qualification: MusubiProviderAttestationInventoryQualificationV1,
}
async fn qualified_inventory_runtime_snapshot<Inventory>(
    inventory: &Inventory,
) -> Result<QualifiedInventoryRuntimeSnapshotV1, MusubiProviderAttestationJournalErrorV1>
where
    Inventory: MusubiProviderAttestationInventoryRuntimeV1 + ?Sized,
{
    let runtime_handle_before = inventory.runtime_handle().to_owned();
    let qualification_before = inventory
        .qualification()
        .map_err(map_inventory_runtime_error)?;
    validate_musubi_provider_attestation_inventory_binding_v1(
        &runtime_handle_before,
        &qualification_before,
    )
    .map_err(|_| MusubiProviderAttestationJournalErrorV1::InventoryRejected)?;
    inventory
        .check_readiness()
        .await
        .map_err(map_inventory_runtime_error)?;
    let runtime_handle_after = inventory.runtime_handle().to_owned();
    let qualification_after = inventory
        .qualification()
        .map_err(map_inventory_runtime_error)?;
    validate_musubi_provider_attestation_inventory_binding_v1(
        &runtime_handle_after,
        &qualification_after,
    )
    .map_err(|_| MusubiProviderAttestationJournalErrorV1::InventoryRejected)?;
    if runtime_handle_after != runtime_handle_before || qualification_after != qualification_before
    {
        return Err(MusubiProviderAttestationJournalErrorV1::InventoryRejected);
    }
    Ok(QualifiedInventoryRuntimeSnapshotV1 {
        runtime_handle: runtime_handle_after,
        qualification: qualification_after,
    })
}
fn map_inventory_runtime_error(
    error: MusubiProviderAttestationInventoryRuntimeErrorV1,
) -> MusubiProviderAttestationJournalErrorV1 {
    match error {
        MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable => {
            MusubiProviderAttestationJournalErrorV1::InventoryUnavailable
        }
        MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected => {
            MusubiProviderAttestationJournalErrorV1::InventoryRejected
        }
    }
}
fn decode_checkpoint(
    snapshot: &MusubiProviderAttestationJournalStoreSnapshotV1,
    policy: MusubiProviderAttestationJournalPolicyV1,
) -> Result<StoredJournalCheckpointV1, MusubiProviderAttestationJournalErrorV1> {
    if !snapshot.validate() {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    let Some(bytes) = snapshot.checkpoint_bytes() else {
        return Ok(StoredJournalCheckpointV1::empty());
    };
    if bytes.len() > policy.checkpoint_max_bytes {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    let checkpoint: StoredJournalCheckpointV1 =
        norito::decode_canonical_with_limits(bytes, JOURNAL_CHECKPOINT_DECODE_LIMITS_V1)
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint)?;
    if checkpoint.checkpoint_sequence == 0 || !checkpoint.validate(policy) {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    Ok(checkpoint)
}
/// Validate one canonical checkpoint and return its sequence and UNIX floor.
///
/// The checkpoint-seal protocol uses this crate-private projection to prove
/// that its public head metadata describes the exact private DTO bytes without
/// exposing any entry, receipt, or retry-state fields.
pub(crate) fn validate_musubi_provider_attestation_journal_checkpoint_metadata_v1(
    bytes: &[u8],
    policy: MusubiProviderAttestationJournalPolicyV1,
    network_id: &NetworkId,
    provider_id: ProviderId,
) -> Result<(u64, u64), MusubiProviderAttestationJournalErrorV1> {
    policy.validate()?;
    if bytes.is_empty() || bytes.len() > policy.checkpoint_max_bytes {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    let checkpoint: StoredJournalCheckpointV1 =
        norito::decode_canonical_with_limits(bytes, JOURNAL_CHECKPOINT_DECODE_LIMITS_V1)
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint)?;
    if checkpoint.checkpoint_sequence == 0
        || !checkpoint.validate(policy)
        || checkpoint.entries.iter().any(|entry| {
            let binding = &entry.intent.payload.binding;
            &binding.network_id != network_id || binding.provider_id != provider_id
        })
    {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    Ok((
        checkpoint.checkpoint_sequence,
        checkpoint.last_observed_unix_ms,
    ))
}
/// Encode a valid entry-free checkpoint for file-store conformance tests.
#[cfg(test)]
pub(crate) fn musubi_provider_attestation_journal_test_checkpoint_bytes_v1(
    checkpoint_sequence: u64,
    last_observed_unix_ms: u64,
) -> Vec<u8> {
    assert_ne!(
        checkpoint_sequence, 0,
        "test checkpoint sequence is nonzero"
    );
    let checkpoint = StoredJournalCheckpointV1 {
        version: JOURNAL_CHECKPOINT_VERSION_V1,
        checkpoint_sequence,
        next_intent_sequence: 1,
        last_observed_unix_ms,
        entries: Vec::new(),
    };
    assert!(checkpoint.validate(MusubiProviderAttestationJournalPolicyV1::default()));
    norito::encode_canonical(&checkpoint).expect("encode file-store test checkpoint")
}
fn encode_checkpoint(
    checkpoint: &StoredJournalCheckpointV1,
    policy: MusubiProviderAttestationJournalPolicyV1,
) -> Result<Vec<u8>, MusubiProviderAttestationJournalErrorV1> {
    if checkpoint.checkpoint_sequence == 0 || !checkpoint.validate(policy) {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    let bytes = norito::encode_canonical(checkpoint)
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint)?;
    let reserved_bytes = checkpoint_future_reserve_bytes(checkpoint)?;
    let reserved_checkpoint_bytes = bytes
        .len()
        .checked_add(reserved_bytes)
        .ok_or(MusubiProviderAttestationJournalErrorV1::CapacityExceeded)?;
    if bytes.is_empty() || reserved_checkpoint_bytes > policy.checkpoint_max_bytes {
        return Err(MusubiProviderAttestationJournalErrorV1::CapacityExceeded);
    }
    let decoded: StoredJournalCheckpointV1 =
        norito::decode_canonical_with_limits(&bytes, JOURNAL_CHECKPOINT_DECODE_LIMITS_V1)
            .map_err(|_| MusubiProviderAttestationJournalErrorV1::CapacityExceeded)?;
    if decoded != *checkpoint {
        return Err(MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint);
    }
    Ok(bytes)
}
fn encode_checkpoint_pruning_delivered(
    checkpoint: &mut StoredJournalCheckpointV1,
    policy: MusubiProviderAttestationJournalPolicyV1,
    pruneable_delivered: &BTreeSet<MusubiProviderAttestationApprovalIdV1>,
) -> Result<Vec<u8>, MusubiProviderAttestationJournalErrorV1> {
    loop {
        match encode_checkpoint(checkpoint, policy) {
            Ok(bytes) => return Ok(bytes),
            Err(MusubiProviderAttestationJournalErrorV1::CapacityExceeded) => {
                let Some((oldest_delivered_index, _)) = checkpoint
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| {
                        pruneable_delivered.contains(&entry.intent.approval_id)
                            && matches!(&entry.state, StoredJournalStateV1::Delivered { .. })
                    })
                    .min_by_key(|(_, entry)| entry.intent.sequence)
                else {
                    return Err(MusubiProviderAttestationJournalErrorV1::CapacityExceeded);
                };
                checkpoint.entries.remove(oldest_delivered_index);
            }
            Err(error) => return Err(error),
        }
    }
}
// Reserve the same conservative envelope and alignment budget for nested payloads
// without making those field-only records standalone frame owners.
fn canonical_reserve_footprint<T: norito::SerializePayload>(
    value: &T,
) -> Result<usize, MusubiProviderAttestationJournalErrorV1> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let payload_len = norito::core::encoded_payload_len(value)
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint)?;
    let alignment = norito::core::archived_payload_align::<T>();
    let padding = (alignment - norito::core::Header::SIZE % alignment) % alignment;
    norito::core::Header::SIZE
        .checked_add(padding)
        .and_then(|overhead| overhead.checked_add(payload_len))
        .ok_or(MusubiProviderAttestationJournalErrorV1::CapacityExceeded)
}
fn checkpoint_future_reserve_bytes(
    checkpoint: &StoredJournalCheckpointV1,
) -> Result<usize, MusubiProviderAttestationJournalErrorV1> {
    let encoded_header_len = norito::encode_canonical(&StoredJournalCheckpointV1 {
        version: checkpoint.version,
        checkpoint_sequence: checkpoint.checkpoint_sequence,
        next_intent_sequence: checkpoint.next_intent_sequence,
        last_observed_unix_ms: checkpoint.last_observed_unix_ms,
        entries: Vec::new(),
    })
    .map_err(|_| MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint)?
    .len();
    let header_reserve = JOURNAL_CHECKPOINT_HEADER_FOOTPRINT_BYTES_V1
        .checked_sub(encoded_header_len)
        .ok_or(MusubiProviderAttestationJournalErrorV1::CapacityExceeded)?;
    checkpoint
        .entries
        .iter()
        .try_fold(header_reserve, |total, entry| {
            let encoded_entry_len = canonical_reserve_footprint(entry)?;
            let encoded_intent_len = canonical_reserve_footprint(&entry.intent)?;
            let target_footprint = match &entry.state {
                StoredJournalStateV1::AwaitingApproval { .. }
                | StoredJournalStateV1::ApprovalClaimed { .. } => encoded_intent_len
                    .checked_add(MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1)
                    .and_then(|value| {
                        value.checked_add(JOURNAL_ACTIVE_ENTRY_WRAPPER_MARGIN_BYTES_V1)
                    })
                    .ok_or(MusubiProviderAttestationJournalErrorV1::CapacityExceeded)?,
                StoredJournalStateV1::ApprovedPendingHandoff { .. }
                | StoredJournalStateV1::HandoffClaimed { .. } => {
                    let attestation = match &entry.state {
                        StoredJournalStateV1::ApprovedPendingHandoff { attestation, .. }
                        | StoredJournalStateV1::HandoffClaimed { attestation, .. } => attestation,
                        _ => unreachable!("matched approved attestation state"),
                    };
                    let encoded_attestation_len = norito::encode_canonical(attestation.as_ref())
                        .map_err(|_| MusubiProviderAttestationJournalErrorV1::CorruptCheckpoint)?
                        .len();
                    encoded_intent_len
                        .checked_add(encoded_attestation_len)
                        .and_then(|value| {
                            value.checked_add(JOURNAL_ACTIVE_ENTRY_WRAPPER_MARGIN_BYTES_V1)
                        })
                        .ok_or(MusubiProviderAttestationJournalErrorV1::CapacityExceeded)?
                }
                StoredJournalStateV1::Delivered { .. }
                | StoredJournalStateV1::DeadLetter { .. } => encoded_entry_len,
            };
            let reserve = target_footprint.saturating_sub(encoded_entry_len);
            total
                .checked_add(reserve)
                .ok_or(MusubiProviderAttestationJournalErrorV1::CapacityExceeded)
        })
}
// The daemon leaves the sealed two-slot file adapter inactive until qualified
// signer, combined time/head/blob durability, and coordinator-inventory
// bindings are configured. A receipt remains an acknowledgement record, not
// independently authenticated evidence.
#[cfg(test)]
pub(crate) mod tests;
