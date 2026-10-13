//! Fail-closed online-auditor coordination for atomic private settlement.

use eyre::{Result, eyre};
use iroha::client::{Client, IdentityRequestSignerV1};
use iroha_core::private_settlement::{
    PrivateSettlementAuditPolicyEvaluatorV1, PrivateSettlementAuditorCredentialProviderV1,
    PrivateSettlementAuditorSidecarViewV1, PrivateSettlementSidecarLifecycleV1,
    approve_private_settlement_leg_with_provider_v1,
};
use iroha_crypto::{Algorithm, HybridSecretKey, PublicKey};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PRIVATE_SETTLEMENT_MAX_AUDIT_MEMO_BYTES_V1,
        PRIVATE_SETTLEMENT_MAX_AUDIT_POLICY_REFERENCES_V1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementCommitteeAuthorityV1, PrivateSettlementPoolGovernanceV1,
        PrivateSettlementRouteV1,
    },
    privacy::PrivacyPoolIdV1,
};
use iroha_torii_shared::private_settlement_api::{
    PrivateSettlementAuditApprovalRequestV1, PrivateSettlementAuditApprovalResponseV1,
    PrivateSettlementAuditorCapsuleRequestV1, PrivateSettlementAuditorCapsuleResponseV1,
    PrivateSettlementLifecycleDtoV1,
};
use std::{collections::BTreeSet, path::Path};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

const PRIVATE_SETTLEMENT_AUDITOR_COMMITTEE_SIZE_V1: usize = 4;
const PRIVATE_SETTLEMENT_AUDITOR_SECRET_FILE_VERSION_V1: u8 = 1;
const PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_MAX_IDENTITIES_V1: usize = 256;
const PRIVATE_SETTLEMENT_AUDITOR_SECRET_FILE_MAX_BYTES_V1: u64 = 16 * 1024;
const PRIVATE_SETTLEMENT_AUDIT_POLICY_FILE_MAX_BYTES_V1: u64 = 256 * 1024;
const PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_FILE_MAX_BYTES_V1: u64 = 256 * 1024;

/// Strict local business policy applied to one decrypted settlement leg.
///
/// The record deliberately contains exact allowlists rather than wildcard
/// switches. It is restricted operator material and must be loaded from an
/// owner-only runtime file, never from an environment variable or public
/// governance state.
#[derive(PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[cfg_attr(test, derive(Clone))]
#[norito(deny_unknown_fields)]
pub struct PrivateSettlementAuditorBusinessPolicyV1 {
    version: u8,
    exact_network_id: NetworkId,
    exact_route: PrivateSettlementRouteV1,
    exact_pool_id: PrivacyPoolIdV1,
    exact_audit_policy_id: iroha_crypto::Hash,
    exact_audit_policy_revision: u64,
    exact_audit_key_epoch: u64,
    allowed_payers: Vec<AccountId>,
    allowed_recipients: Vec<AccountId>,
    allowed_sponsors: Vec<AccountId>,
    allowed_asset_definition_ids: Vec<AssetDefinitionId>,
    minimum_amount: u128,
    maximum_amount: u128,
    maximum_sponsor_reimbursement_amount: u128,
    maximum_memo_bytes: u32,
    allowed_policy_references: Vec<iroha_crypto::Hash>,
    required_policy_references: Vec<iroha_crypto::Hash>,
    maximum_remaining_blocks: u64,
}

impl Drop for PrivateSettlementAuditorBusinessPolicyV1 {
    fn drop(&mut self) {
        for account in self
            .allowed_payers
            .iter_mut()
            .chain(&mut self.allowed_recipients)
            .chain(&mut self.allowed_sponsors)
        {
            account.zeroize_for_confidential_discard();
        }
        for asset in &mut self.allowed_asset_definition_ids {
            asset.aid_bytes.zeroize();
        }
        for reference in self
            .allowed_policy_references
            .iter_mut()
            .chain(&mut self.required_policy_references)
        {
            *reference = iroha_crypto::Hash::prehashed([0; iroha_crypto::Hash::LENGTH]);
        }
        self.minimum_amount.zeroize();
        self.maximum_amount.zeroize();
        self.maximum_sponsor_reimbursement_amount.zeroize();
        self.maximum_memo_bytes.zeroize();
        self.maximum_remaining_blocks.zeroize();
    }
}

struct PrivateSettlementAuditorBusinessPolicyInputV1<'a> {
    network_id: NetworkId,
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
    audit_policy_id: iroha_crypto::Hash,
    audit_policy_revision: u64,
    audit_key_epoch: u64,
    payer: &'a AccountId,
    recipient: &'a AccountId,
    sponsor: &'a AccountId,
    asset_definition_id: &'a AssetDefinitionId,
    amount: u128,
    sponsor_reimbursement_amount: u128,
    memo: &'a [u8],
    policy_references: &'a [iroha_crypto::Hash],
    settlement_expiry_height: u64,
    authoritative_height: u64,
}

fn is_strictly_ordered_non_empty_v1<T: Ord>(values: &[T], maximum: usize) -> bool {
    !values.is_empty() && values.len() <= maximum && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_strictly_ordered_v1<T: Ord>(values: &[T], maximum: usize) -> bool {
    values.len() <= maximum && values.windows(2).all(|pair| pair[0] < pair[1])
}

impl PrivateSettlementAuditorBusinessPolicyV1 {
    fn validate(&self) -> Result<()> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || self.exact_route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
            || self.exact_route.lane_incarnation
                == iroha_crypto::Hash::prehashed([0; iroha_crypto::Hash::LENGTH])
            || self.exact_pool_id.is_zero()
            || self.exact_audit_policy_id
                == iroha_crypto::Hash::prehashed([0; iroha_crypto::Hash::LENGTH])
            || self.exact_audit_policy_revision == 0
            || self.exact_audit_key_epoch == 0
            || !is_strictly_ordered_non_empty_v1(
                &self.allowed_payers,
                PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_MAX_IDENTITIES_V1,
            )
            || !is_strictly_ordered_non_empty_v1(
                &self.allowed_recipients,
                PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_MAX_IDENTITIES_V1,
            )
            || !is_strictly_ordered_non_empty_v1(
                &self.allowed_sponsors,
                PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_MAX_IDENTITIES_V1,
            )
            || !is_strictly_ordered_non_empty_v1(
                &self.allowed_asset_definition_ids,
                PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_MAX_IDENTITIES_V1,
            )
            || self.minimum_amount == 0
            || self.minimum_amount > self.maximum_amount
            || usize::try_from(self.maximum_memo_bytes).map_or(true, |maximum| {
                maximum > PRIVATE_SETTLEMENT_MAX_AUDIT_MEMO_BYTES_V1
            })
            || !is_strictly_ordered_v1(
                &self.allowed_policy_references,
                PRIVATE_SETTLEMENT_MAX_AUDIT_POLICY_REFERENCES_V1,
            )
            || !is_strictly_ordered_v1(
                &self.required_policy_references,
                PRIVATE_SETTLEMENT_MAX_AUDIT_POLICY_REFERENCES_V1,
            )
            || !self.required_policy_references.iter().all(|required| {
                self.allowed_policy_references
                    .binary_search(required)
                    .is_ok()
            })
            || self.maximum_remaining_blocks == 0
        {
            return Err(eyre!(
                "private-settlement auditor business policy is invalid"
            ));
        }
        Ok(())
    }

    fn approves_input_v1(&self, input: &PrivateSettlementAuditorBusinessPolicyInputV1<'_>) -> bool {
        self.validate().is_ok()
            && input.network_id == self.exact_network_id
            && input.route == self.exact_route
            && input.pool_id == self.exact_pool_id
            && input.audit_policy_id == self.exact_audit_policy_id
            && input.audit_policy_revision == self.exact_audit_policy_revision
            && input.audit_key_epoch == self.exact_audit_key_epoch
            && self.allowed_payers.binary_search(input.payer).is_ok()
            && self
                .allowed_recipients
                .binary_search(input.recipient)
                .is_ok()
            && self.allowed_sponsors.binary_search(input.sponsor).is_ok()
            && self
                .allowed_asset_definition_ids
                .binary_search(input.asset_definition_id)
                .is_ok()
            && (self.minimum_amount..=self.maximum_amount).contains(&input.amount)
            && input.sponsor_reimbursement_amount <= self.maximum_sponsor_reimbursement_amount
            && usize::try_from(self.maximum_memo_bytes)
                .is_ok_and(|maximum| input.memo.len() <= maximum)
            && input.policy_references.iter().all(|reference| {
                self.allowed_policy_references
                    .binary_search(reference)
                    .is_ok()
            })
            && self
                .required_policy_references
                .iter()
                .all(|required| input.policy_references.binary_search(required).is_ok())
            && input
                .settlement_expiry_height
                .checked_sub(input.authoritative_height)
                .is_some_and(|remaining| {
                    remaining > 0 && remaining <= self.maximum_remaining_blocks
                })
    }
}

impl PrivateSettlementAuditPolicyEvaluatorV1 for PrivateSettlementAuditorBusinessPolicyV1 {
    fn approves(
        &self,
        context: iroha_core::private_settlement::PrivateSettlementAuditEvaluationV1<'_>,
    ) -> bool {
        self.approves_input_v1(&PrivateSettlementAuditorBusinessPolicyInputV1 {
            network_id: context.plaintext.network_id,
            route: context.plaintext.route,
            pool_id: context.plaintext.pool_id,
            audit_policy_id: context.audit_policy.body.policy_id,
            audit_policy_revision: context.audit_policy.body.revision,
            audit_key_epoch: context.audit_policy.body.key_epoch,
            payer: &context.plaintext.payer,
            recipient: &context.plaintext.recipient,
            sponsor: &context.plaintext.sponsor,
            asset_definition_id: &context.plaintext.asset_definition_id,
            amount: context.plaintext.amount,
            sponsor_reimbursement_amount: context.plaintext.sponsor_reimbursement_amount,
            memo: &context.plaintext.memo,
            policy_references: &context.plaintext.policy_references,
            settlement_expiry_height: context.plaintext.settlement_expiry_height,
            authoritative_height: context.authoritative_height,
        })
    }
}

struct PrivateSettlementOnlineAuditorQuorumViewV1<T> {
    response: T,
    authoritative_height: u64,
    authority_context_height: u64,
    expiry_height: u64,
}

trait PrivateSettlementOnlineAuditorTransportV1 {
    type View;
    type Approval;
    type Acknowledgement;

    fn fetch_quorum(
        &self,
        endpoints: &[Url],
        expected_authority: &PrivateSettlementCommitteeAuthorityV1,
        payload_digest: iroha_crypto::Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        signer: &dyn IdentityRequestSignerV1,
    ) -> Result<PrivateSettlementOnlineAuditorQuorumViewV1<Self::View>>;

    fn submit_quorum(
        &self,
        endpoints: &[Url],
        expected_authority: &PrivateSettlementCommitteeAuthorityV1,
        payload_digest: iroha_crypto::Hash,
        signer: &dyn IdentityRequestSignerV1,
        approval: &Self::Approval,
    ) -> Result<Self::Acknowledgement>;
}

impl PrivateSettlementOnlineAuditorTransportV1 for Client {
    type View = PrivateSettlementAuditorCapsuleResponseV1;
    type Approval = PrivateSettlementAuditApprovalRequestV1;
    type Acknowledgement = PrivateSettlementAuditApprovalResponseV1;

    fn fetch_quorum(
        &self,
        endpoints: &[Url],
        expected_authority: &PrivateSettlementCommitteeAuthorityV1,
        payload_digest: iroha_crypto::Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        signer: &dyn IdentityRequestSignerV1,
    ) -> Result<PrivateSettlementOnlineAuditorQuorumViewV1<Self::View>> {
        let response = self.private_settlement_auditor_capsule_quorum_for_authority_v1(
            endpoints,
            expected_authority,
            payload_digest,
            request,
            signer,
        )?;
        Ok(PrivateSettlementOnlineAuditorQuorumViewV1 {
            authoritative_height: response.authoritative_height,
            authority_context_height: response.manifest.authority_context_height,
            expiry_height: response.manifest.expiry_height,
            response,
        })
    }

    fn submit_quorum(
        &self,
        endpoints: &[Url],
        expected_authority: &PrivateSettlementCommitteeAuthorityV1,
        payload_digest: iroha_crypto::Hash,
        signer: &dyn IdentityRequestSignerV1,
        approval: &Self::Approval,
    ) -> Result<Self::Acknowledgement> {
        self.submit_private_settlement_audit_approval_quorum_for_authority_v1(
            endpoints,
            expected_authority,
            payload_digest,
            signer,
            approval,
        )
    }
}

fn validate_committee_endpoints_v1(endpoints: &[Url]) -> Result<()> {
    let unique = endpoints
        .iter()
        .map(url::Url::as_str)
        .collect::<BTreeSet<_>>();
    if endpoints.len() != PRIVATE_SETTLEMENT_AUDITOR_COMMITTEE_SIZE_V1
        || unique.len() != PRIVATE_SETTLEMENT_AUDITOR_COMMITTEE_SIZE_V1
    {
        return Err(eyre!(
            "private-settlement online auditor requires four distinct committee endpoints"
        ));
    }
    Ok(())
}

/// Validate the separately governed four-validator authority and every BLS
/// proof of possession.
///
/// # Errors
///
/// Returns a redacted error when the authority shape, key algorithms, or proofs
/// of possession are invalid.
pub fn validate_private_settlement_expected_authority_v1(
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<()> {
    authority
        .validate()
        .map_err(|_| eyre!("private-settlement expected committee authority is invalid"))?;
    if authority
        .validators
        .iter()
        .zip(&authority.validator_pops)
        .any(|(validator, pop)| {
            validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
                || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
        })
    {
        return Err(eyre!(
            "private-settlement expected committee authority is invalid"
        ));
    }
    Ok(())
}

fn validate_authoritative_height_v1(
    authoritative_height: u64,
    authority_context_height: u64,
    expiry_height: u64,
) -> Result<()> {
    if authoritative_height == 0
        || authoritative_height < authority_context_height
        || authoritative_height > expiry_height
    {
        return Err(eyre!("private-settlement online auditor height is stale"));
    }
    Ok(())
}

fn coordinate_with_transport_v1<T, BuildApproval>(
    transport: &T,
    endpoints: &[Url],
    expected_authority: &PrivateSettlementCommitteeAuthorityV1,
    payload_digest: iroha_crypto::Hash,
    capsule_request: &PrivateSettlementAuditorCapsuleRequestV1,
    signer: &dyn IdentityRequestSignerV1,
    build_approval: BuildApproval,
) -> Result<T::Acknowledgement>
where
    T: PrivateSettlementOnlineAuditorTransportV1,
    BuildApproval: FnOnce(T::View) -> Result<T::Approval>,
{
    validate_committee_endpoints_v1(endpoints)?;
    validate_private_settlement_expected_authority_v1(expected_authority)?;
    let quorum = transport
        .fetch_quorum(
            endpoints,
            expected_authority,
            payload_digest,
            capsule_request,
            signer,
        )
        .map_err(|_| eyre!("private-settlement online auditor quorum fetch failed"))?;
    validate_authoritative_height_v1(
        quorum.authoritative_height,
        quorum.authority_context_height,
        quorum.expiry_height,
    )?;
    let approval = build_approval(quorum.response).map_err(|_| {
        eyre!("private-settlement online auditor credential or policy operation failed")
    })?;
    transport
        .submit_quorum(
            endpoints,
            expected_authority,
            payload_digest,
            signer,
            &approval,
        )
        .map_err(|_| eyre!("private-settlement online auditor acknowledgement quorum failed"))
}

/// Exact settlement request and its authenticated audit policy context.
#[derive(Debug)]
pub struct PrivateSettlementOnlineAuditorOperationV1<'a> {
    /// Committee identity required of every endpoint response.
    pub expected_authority: &'a PrivateSettlementCommitteeAuthorityV1,
    /// Exact encrypted settlement payload being audited.
    pub payload_digest: iroha_crypto::Hash,
    /// Committed audit policy and key epoch for this operation.
    pub audit_policy: &'a PrivateSettlementAuditPolicyV1,
    /// Pool governance binding the operation to that audit policy.
    pub pool_governance: &'a PrivateSettlementPoolGovernanceV1,
}

/// Fetch, decrypt, evaluate, sign, and submit one approval as a fail-closed CLI operation.
///
/// The client transport supplies exact three-of-four views and acknowledgement
/// quorums. `credentials` may be supplied by a deployment-owned provider;
/// `request_signer` authenticates the four HTTP requests and must advertise
/// that provider's exact purpose-separated approval key.
///
/// # Errors
///
/// Returns only redacted endpoint-quorum, stale-height, credential/policy, or
/// acknowledgement-quorum failures. Decrypted plaintext and provider details
/// never cross this boundary.
pub fn coordinate_private_settlement_online_auditor_v1<P, E>(
    client: &Client,
    endpoints: &[Url],
    operation: &PrivateSettlementOnlineAuditorOperationV1<'_>,
    credentials: &P,
    request_signer: &dyn IdentityRequestSignerV1,
    evaluator: &E,
) -> Result<PrivateSettlementAuditApprovalResponseV1>
where
    P: PrivateSettlementAuditorCredentialProviderV1 + ?Sized,
    E: PrivateSettlementAuditPolicyEvaluatorV1 + ?Sized,
{
    let expected_authority = operation.expected_authority;
    let payload_digest = operation.payload_digest;
    let audit_policy = operation.audit_policy;
    let pool_governance = operation.pool_governance;
    if credentials.approval_public_key() != request_signer.public_key()
        || audit_policy.validate().is_err()
        || pool_governance.body.audit_policy_digest != audit_policy.policy_digest
        || pool_governance.body.audit_key_epoch != audit_policy.body.key_epoch
        || pool_governance.body.route.dataspace_id != audit_policy.body.dataspace_id
        || !audit_policy
            .body
            .auditors
            .iter()
            .any(|auditor| &auditor.signing_key == request_signer.public_key())
    {
        return Err(eyre!(
            "private-settlement online auditor credential or policy operation failed"
        ));
    }
    let capsule_request = PrivateSettlementAuditorCapsuleRequestV1 {
        audit_policy: audit_policy.clone(),
    };
    coordinate_with_transport_v1(
        client,
        endpoints,
        expected_authority,
        payload_digest,
        &capsule_request,
        request_signer,
        |response| {
            build_approval_request_v1(
                response,
                audit_policy,
                pool_governance,
                credentials,
                request_signer.public_key(),
                evaluator,
            )
        },
    )
}

fn build_approval_request_v1<P, E>(
    response: PrivateSettlementAuditorCapsuleResponseV1,
    audit_policy: &PrivateSettlementAuditPolicyV1,
    pool_governance: &PrivateSettlementPoolGovernanceV1,
    credentials: &P,
    transport_public_key: &PublicKey,
    evaluator: &E,
) -> Result<PrivateSettlementAuditApprovalRequestV1>
where
    P: PrivateSettlementAuditorCredentialProviderV1 + ?Sized,
    E: PrivateSettlementAuditPolicyEvaluatorV1 + ?Sized,
{
    if credentials.approval_public_key() != transport_public_key
        || response.access_audit_policy != *audit_policy
        || response.audit_policy != *audit_policy
        || !response
            .audit_policy
            .is_active_at(response.authoritative_height)
        || !pool_governance.is_active_at(response.authoritative_height)
    {
        return Err(eyre!(
            "private-settlement online auditor credential or policy operation failed"
        ));
    }
    let auditor_id = response
        .audit_policy
        .body
        .auditors
        .iter()
        .find(|auditor| &auditor.signing_key == credentials.approval_public_key())
        .map(|auditor| auditor.auditor_id.clone())
        .ok_or_else(|| {
            eyre!("private-settlement online auditor credential or policy operation failed")
        })?;
    let authoritative_height = response.authoritative_height;
    let view = PrivateSettlementAuditorSidecarViewV1 {
        manifest: response.manifest,
        policy: response.audit_policy,
        authority: response.committee_authority,
        statement: response.statement,
        delta: response.delta,
        audit_capsule: response.audit_capsule,
        availability: response.availability,
        lifecycle: sidecar_lifecycle_v1(response.lifecycle),
    };
    let approval = approve_private_settlement_leg_with_provider_v1(
        &view,
        pool_governance,
        authoritative_height,
        &auditor_id,
        credentials,
        evaluator,
    )
    .map_err(|_| {
        eyre!("private-settlement online auditor credential or policy operation failed")
    })?;
    Ok(PrivateSettlementAuditApprovalRequestV1 {
        audit_policy: audit_policy.clone(),
        approval,
    })
}

fn sidecar_lifecycle_v1(
    lifecycle: PrivateSettlementLifecycleDtoV1,
) -> PrivateSettlementSidecarLifecycleV1 {
    match lifecycle {
        PrivateSettlementLifecycleDtoV1::Collecting => {
            PrivateSettlementSidecarLifecycleV1::Collecting
        }
        PrivateSettlementLifecycleDtoV1::Audited => PrivateSettlementSidecarLifecycleV1::Audited,
        PrivateSettlementLifecycleDtoV1::Prepared => PrivateSettlementSidecarLifecycleV1::Prepared,
        PrivateSettlementLifecycleDtoV1::CommitCertified => {
            PrivateSettlementSidecarLifecycleV1::CommitCertified
        }
        PrivateSettlementLifecycleDtoV1::Finalized => {
            PrivateSettlementSidecarLifecycleV1::Finalized
        }
        PrivateSettlementLifecycleDtoV1::Aborted => PrivateSettlementSidecarLifecycleV1::Aborted,
        PrivateSettlementLifecycleDtoV1::Expired => PrivateSettlementSidecarLifecycleV1::Expired,
    }
}

#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PrivateSettlementAuditorSecretFileV1 {
    version: u8,
    x25519_secret_hex: String,
    ml_kem_768_secret_hex: String,
}

impl Drop for PrivateSettlementAuditorSecretFileV1 {
    fn drop(&mut self) {
        self.x25519_secret_hex.zeroize();
        self.ml_kem_768_secret_hex.zeroize();
    }
}

/// Runtime-only restricted pool mapping that clears its asset-binding opening on drop.
pub struct ZeroizingPrivateSettlementPoolGovernanceV1(PrivateSettlementPoolGovernanceV1);

impl core::ops::Deref for ZeroizingPrivateSettlementPoolGovernanceV1 {
    type Target = PrivateSettlementPoolGovernanceV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingPrivateSettlementPoolGovernanceV1 {
    fn drop(&mut self) {
        self.0.body.asset_definition_id.aid_bytes.zeroize();
        self.0.body.asset_binding_salt.zeroize();
    }
}

/// Load one owner-only runtime hybrid capsule-decryption secret.
///
/// The file is strict Norito JSON with `version`, `x25519_secret_hex`, and
/// `ml_kem_768_secret_hex` fields. It must be absolute, owner-only mode `0600`,
/// singly linked, with a non-symlink final path component. File and decoded
/// component buffers are zeroized after checked key construction.
pub fn load_private_settlement_auditor_secret_v1(path: &Path) -> Result<HybridSecretKey> {
    let bytes = read_owner_only_auditor_secret_file_v1(path)?;
    let encoded: PrivateSettlementAuditorSecretFileV1 = norito::json::from_slice(bytes.as_slice())
        .map_err(|_| eyre!("private-settlement auditor decryption-key file is invalid"))?;
    if encoded.version != PRIVATE_SETTLEMENT_AUDITOR_SECRET_FILE_VERSION_V1 {
        return Err(eyre!(
            "private-settlement auditor decryption-key file is invalid"
        ));
    }
    let x25519 = decode_canonical_secret_hex_v1(&encoded.x25519_secret_hex)?;
    let ml_kem = decode_canonical_secret_hex_v1(&encoded.ml_kem_768_secret_hex)?;
    HybridSecretKey::from_bytes(x25519.as_slice(), ml_kem.as_slice())
        .map_err(|_| eyre!("private-settlement auditor decryption-key file is invalid"))
}

/// Load one integrity-protected, separately governed committee trust anchor.
///
/// The file must satisfy the same absolute, owner-only, non-symlink,
/// single-link, stable-read rules as the restricted auditor inputs. The
/// authority and every BLS proof of possession are validated before return.
///
/// # Errors
///
/// Returns a redacted error when secure file admission, strict Norito JSON
/// decoding, authority shape, key algorithms, or proofs of possession fail.
pub fn load_private_settlement_committee_authority_v1(
    path: &Path,
) -> Result<PrivateSettlementCommitteeAuthorityV1> {
    let bytes = read_owner_only_auditor_secret_file_v1(path)
        .map_err(|_| eyre!("private-settlement committee authority file is unavailable"))?;
    let authority: PrivateSettlementCommitteeAuthorityV1 =
        norito::json::from_slice(bytes.as_slice())
            .map_err(|_| eyre!("private-settlement committee authority is invalid"))?;
    validate_private_settlement_expected_authority_v1(&authority)?;
    Ok(authority)
}

/// Load and validate one restricted pool-governance record without echoing its contents.
pub fn load_private_settlement_pool_governance_v1(
    path: &Path,
) -> Result<ZeroizingPrivateSettlementPoolGovernanceV1> {
    let bytes = read_owner_only_auditor_secret_file_v1(path)
        .map_err(|_| eyre!("private-settlement restricted pool governance file is unavailable"))?;
    let governance: PrivateSettlementPoolGovernanceV1 = norito::json::from_slice(bytes.as_slice())
        .map_err(|_| eyre!("private-settlement restricted pool governance is invalid"))?;
    governance
        .validate()
        .map_err(|_| eyre!("private-settlement restricted pool governance is invalid"))?;
    Ok(ZeroizingPrivateSettlementPoolGovernanceV1(governance))
}

/// Load and validate the complete current governed auditor policy.
///
/// This owner-only input is sent as signed request evidence and is accepted by
/// a validator only when its self-digest, epoch, lifecycle, and dataspace match
/// the exact policy revision active in that validator's WSV.
pub fn load_private_settlement_audit_policy_v1(
    path: &Path,
) -> Result<PrivateSettlementAuditPolicyV1> {
    let bytes = read_owner_only_auditor_restricted_file_v1(
        path,
        PRIVATE_SETTLEMENT_AUDIT_POLICY_FILE_MAX_BYTES_V1,
    )
    .map_err(|_| eyre!("private-settlement auditor policy file is unavailable"))?;
    let policy: PrivateSettlementAuditPolicyV1 = norito::json::from_slice(bytes.as_slice())
        .map_err(|_| eyre!("private-settlement auditor policy is invalid"))?;
    policy
        .validate()
        .map_err(|_| eyre!("private-settlement auditor policy is invalid"))?;
    Ok(policy)
}

/// Load and validate one strict owner-only local business policy.
pub fn load_private_settlement_auditor_business_policy_v1(
    path: &Path,
) -> Result<PrivateSettlementAuditorBusinessPolicyV1> {
    let bytes = read_owner_only_auditor_business_policy_file_v1(path)
        .map_err(|_| eyre!("private-settlement auditor business policy file is unavailable"))?;
    let policy: PrivateSettlementAuditorBusinessPolicyV1 =
        norito::json::from_slice(bytes.as_slice())
            .map_err(|_| eyre!("private-settlement auditor business policy is invalid"))?;
    policy.validate()?;
    Ok(policy)
}

fn decode_canonical_secret_hex_v1(encoded: &str) -> Result<Zeroizing<Vec<u8>>> {
    if encoded.is_empty()
        || !encoded.len().is_multiple_of(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(eyre!(
            "private-settlement auditor decryption-key file is invalid"
        ));
    }
    let decoded = Zeroizing::new(
        hex::decode(encoded)
            .map_err(|_| eyre!("private-settlement auditor decryption-key file is invalid"))?,
    );
    let canonical = Zeroizing::new(hex::encode(decoded.as_slice()));
    if canonical.as_str() != encoded {
        return Err(eyre!(
            "private-settlement auditor decryption-key file is invalid"
        ));
    }
    Ok(decoded)
}

fn read_owner_only_auditor_secret_file_v1(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_owner_only_auditor_restricted_file_v1(
        path,
        PRIVATE_SETTLEMENT_AUDITOR_SECRET_FILE_MAX_BYTES_V1,
    )
}

fn read_owner_only_auditor_business_policy_file_v1(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_owner_only_auditor_restricted_file_v1(
        path,
        PRIVATE_SETTLEMENT_AUDITOR_BUSINESS_POLICY_FILE_MAX_BYTES_V1,
    )
}

fn read_owner_only_auditor_restricted_file_v1(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() {
        return Err(eyre!(
            "private-settlement auditor decryption-key file path must be absolute"
        ));
    }
    #[cfg(unix)]
    {
        read_owner_only_auditor_secret_file_unix_v1(path, maximum_bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = maximum_bytes;
        Err(eyre!(
            "private-settlement auditor decryption-key loading requires secure local file support"
        ))
    }
}

#[cfg(unix)]
fn private_settlement_restricted_file_open_flags_v1() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const PRIVATE_SETTLEMENT_RESTRICTED_FILE_XATTR_NAME_LIST_MAX_BYTES_V1: usize = 64 * 1024;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_restricted_file_xattr_names_v1(names: &[u8]) -> Result<()> {
    if names.len() > PRIVATE_SETTLEMENT_RESTRICTED_FILE_XATTR_NAME_LIST_MAX_BYTES_V1 {
        return Err(eyre!(
            "private-settlement auditor restricted file xattr list exceeds its bound"
        ));
    }
    if names.is_empty() {
        return Ok(());
    }
    if names.last() != Some(&0) {
        return Err(eyre!(
            "private-settlement auditor restricted file xattr list is malformed"
        ));
    }
    for name in names[..names.len() - 1].split(|byte| *byte == 0) {
        if name.is_empty() {
            return Err(eyre!(
                "private-settlement auditor restricted file xattr list is malformed"
            ));
        }
        #[cfg(target_os = "macos")]
        let permitted = name == b"com.apple.provenance";
        #[cfg(target_os = "linux")]
        let permitted = false;
        if !permitted {
            return Err(eyre!(
                "private-settlement auditor restricted file has an unapproved extended attribute"
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_no_restricted_file_acl_xattrs_v1(file: &std::fs::File) -> Result<()> {
    let mut names = vec![0_u8; PRIVATE_SETTLEMENT_RESTRICTED_FILE_XATTR_NAME_LIST_MAX_BYTES_V1];
    let count = rustix::fs::flistxattr(file, &mut names)
        .map_err(|_| eyre!("private-settlement auditor restricted file xattr inspection failed"))?;
    if count > names.len() {
        return Err(eyre!(
            "private-settlement auditor restricted file xattr inspection failed"
        ));
    }
    names.truncate(count);
    validate_restricted_file_xattr_names_v1(&names)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn validate_no_restricted_file_acl_xattrs_v1(_file: &std::fs::File) -> Result<()> {
    Err(eyre!(
        "private-settlement auditor restricted file xattr inspection is unavailable"
    ))
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "descriptor-bound macOS extended-ACL inspection requires libc"
)]
unsafe extern "C" {
    fn acl_get_fd_np(
        descriptor: std::os::raw::c_int,
        acl_type: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    fn acl_get_entry(
        acl: *mut std::ffi::c_void,
        entry_id: std::os::raw::c_int,
        entry: *mut *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;
    fn acl_free(object: *mut std::ffi::c_void) -> std::os::raw::c_int;
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "descriptor-bound macOS extended-ACL inspection requires libc"
)]
fn validate_no_restricted_file_acl_v1(file: &std::fs::File) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_EXTENDED: std::os::raw::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: std::os::raw::c_int = 0;
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return if std::io::Error::last_os_error().raw_os_error() == Some(2) {
            Ok(())
        } else {
            Err(eyre!(
                "private-settlement auditor restricted file ACL inspection failed"
            ))
        };
    }
    let mut entry = std::ptr::null_mut();
    let status = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
    let freed = unsafe { acl_free(acl) };
    if status == 0 && freed == 0 {
        return Err(eyre!(
            "private-settlement auditor restricted file has an extended ACL"
        ));
    }
    Err(eyre!(
        "private-settlement auditor restricted file ACL inspection failed"
    ))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn validate_no_restricted_file_acl_v1(_file: &std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn read_owner_only_auditor_secret_file_unix_v1(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    use eyre::WrapErr as _;
    use std::{
        fs,
        io::{Read as _, Take},
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    fn validate_metadata(metadata: &fs::Metadata, maximum_bytes: u64) -> Result<()> {
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum_bytes
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(eyre!(
                "private-settlement auditor decryption-key file is not an owner-only regular file"
            ));
        }
        Ok(())
    }

    fn unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.nlink() == 1
            && after.nlink() == 1
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }

    let path_metadata = std::fs::symlink_metadata(path)
        .wrap_err("failed to inspect private-settlement auditor decryption-key file")?;
    validate_metadata(&path_metadata, maximum_bytes)?;
    let descriptor = rustix::fs::open(
        path,
        private_settlement_restricted_file_open_flags_v1(),
        rustix::fs::Mode::empty(),
    )
    .wrap_err("failed to securely open private-settlement auditor decryption-key file")?;
    let mut file = std::fs::File::from(descriptor);
    let before = file
        .metadata()
        .wrap_err("failed to inspect opened private-settlement auditor decryption-key file")?;
    validate_metadata(&before, maximum_bytes)?;
    if !unchanged(&path_metadata, &before) {
        return Err(eyre!(
            "private-settlement auditor decryption-key file changed during secure open"
        ));
    }
    validate_no_restricted_file_acl_xattrs_v1(&file)?;
    validate_no_restricted_file_acl_v1(&file)?;
    let capacity = usize::try_from(before.len())
        .map_err(|_| eyre!("private-settlement auditor decryption-key file is invalid"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| eyre!("private-settlement auditor decryption-key allocation failed"))?;
    let mut bounded: Take<&mut std::fs::File> = (&mut file).take(maximum_bytes.saturating_add(1));
    bounded
        .read_to_end(&mut bytes)
        .wrap_err("failed to read private-settlement auditor decryption-key file")?;
    let after = file
        .metadata()
        .wrap_err("failed to re-inspect private-settlement auditor decryption-key file")?;
    validate_metadata(&after, maximum_bytes)?;
    if !unchanged(&before, &after)
        || u64::try_from(bytes.len()).ok() != Some(before.len())
        || bytes.len() > usize::try_from(maximum_bytes).unwrap_or(usize::MAX)
    {
        return Err(eyre!(
            "private-settlement auditor decryption-key file changed during bounded read"
        ));
    }
    validate_no_restricted_file_acl_xattrs_v1(&file)?;
    validate_no_restricted_file_acl_v1(&file)?;
    let after_policy = file.metadata().wrap_err(
        "failed to re-inspect private-settlement auditor decryption-key file after access-control validation",
    )?;
    validate_metadata(&after_policy, maximum_bytes)?;
    if !unchanged(&after, &after_policy) {
        return Err(eyre!(
            "private-settlement auditor decryption-key file changed during access-control validation"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::client::BorrowedKeyPairIdentityRequestSignerV1;
    use iroha_crypto::{Algorithm, HashOf, HybridKeyPair, KeyPair};
    use iroha_data_model::{
        block::BlockHeader,
        nexus::{
            PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditorV1,
            PrivateSettlementHybridPublicKeyV1,
        },
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use std::cell::Cell;

    struct MockTransportV1 {
        fetch: core::result::Result<PrivateSettlementOnlineAuditorQuorumViewV1<u8>, &'static str>,
        submit: core::result::Result<u8, &'static str>,
        fetch_failures: usize,
        submit_failures: usize,
        fetch_endpoint_attempts: Cell<usize>,
        submit_endpoint_attempts: Cell<usize>,
    }

    impl PrivateSettlementOnlineAuditorTransportV1 for MockTransportV1 {
        type View = u8;
        type Approval = u8;
        type Acknowledgement = u8;

        fn fetch_quorum(
            &self,
            endpoints: &[Url],
            _expected_authority: &PrivateSettlementCommitteeAuthorityV1,
            _payload_digest: iroha_crypto::Hash,
            _request: &PrivateSettlementAuditorCapsuleRequestV1,
            _signer: &dyn IdentityRequestSignerV1,
        ) -> Result<PrivateSettlementOnlineAuditorQuorumViewV1<Self::View>> {
            self.fetch_endpoint_attempts.set(endpoints.len());
            if endpoints.len().saturating_sub(self.fetch_failures) < 3 {
                return Err(eyre!("insufficient mock fetch responses"));
            }
            self.fetch
                .as_ref()
                .map(|view| PrivateSettlementOnlineAuditorQuorumViewV1 {
                    response: view.response,
                    authoritative_height: view.authoritative_height,
                    authority_context_height: view.authority_context_height,
                    expiry_height: view.expiry_height,
                })
                .map_err(|error| eyre!(*error))
        }

        fn submit_quorum(
            &self,
            endpoints: &[Url],
            _expected_authority: &PrivateSettlementCommitteeAuthorityV1,
            _payload_digest: iroha_crypto::Hash,
            _signer: &dyn IdentityRequestSignerV1,
            _approval: &Self::Approval,
        ) -> Result<Self::Acknowledgement> {
            self.submit_endpoint_attempts.set(endpoints.len());
            if endpoints.len().saturating_sub(self.submit_failures) < 3 {
                return Err(eyre!("insufficient mock approval acknowledgements"));
            }
            self.submit.map_err(|error| eyre!(error))
        }
    }

    fn endpoints_v1() -> Vec<Url> {
        (0_u16..4)
            .map(|index| {
                Url::parse(&format!("http://127.0.0.1:{}/", 25_000 + index))
                    .expect("endpoint fixture")
            })
            .collect()
    }

    fn authority_v1() -> PrivateSettlementCommitteeAuthorityV1 {
        let validator_keys = (0_u8..4)
            .map(|index| {
                KeyPair::from_seed(
                    vec![0xD0_u8.saturating_add(index); 32],
                    Algorithm::BlsNormal,
                )
            })
            .collect::<Vec<_>>();
        let validators = validator_keys
            .iter()
            .map(|key| iroha_model_base::peer::PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let validator_pops = validator_keys
            .iter()
            .map(|key| {
                iroha_crypto::bls_normal_pop_prove(key.private_key())
                    .expect("validator proof-of-possession fixture")
            })
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(41),
                lane_id: LaneId::new(7),
                lane_incarnation: iroha_crypto::Hash::prehashed([0xD8; 32]),
            },
            validator_set_hash: HashOf::new(&validators),
            validators,
            validator_pops,
        };
        authority.validate().expect("committee authority fixture");
        authority
    }

    fn signer_v1() -> KeyPair {
        KeyPair::try_from_seed(vec![0xB9; 32], Algorithm::Ed25519).expect("checked signer fixture")
    }

    fn capsule_request_v1() -> PrivateSettlementAuditorCapsuleRequestV1 {
        let signing = signer_v1();
        let mut hybrid_rng = iroha_crypto::rng_from_seed_slice(b"online auditor request fixture");
        let hybrid = HybridKeyPair::generate(&mut hybrid_rng).expect("hybrid fixture");
        PrivateSettlementAuditorCapsuleRequestV1 {
            audit_policy: PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
                version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                dataspace_id: authority_v1().route.dataspace_id,
                policy_id: iroha_crypto::Hash::new(b"online auditor policy fixture"),
                revision: 1,
                key_epoch: 1,
                activation_height: 1,
                retirement_height: None,
                min_approvals: 1,
                auditors: vec![PrivateSettlementAuditorV1 {
                    auditor_id: AccountId::new(signing.public_key().clone()),
                    signing_key: signing.public_key().clone(),
                    encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(
                        hybrid.public(),
                    ),
                }],
            })
            .expect("audit policy fixture"),
        }
    }

    fn account_v1(seed: u8) -> AccountId {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("checked account fixture")
                .public_key()
                .clone(),
        )
    }

    fn asset_definition_v1(seed: u8) -> AssetDefinitionId {
        let mut bytes = [seed; 16];
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        AssetDefinitionId::from_uuid_bytes(bytes).expect("checked asset fixture")
    }

    fn network_id_v1(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([seed; 32]),
        ))
    }

    struct BusinessPolicyFixtureV1 {
        policy: PrivateSettlementAuditorBusinessPolicyV1,
        network_id: NetworkId,
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
        payer: AccountId,
        recipient: AccountId,
        sponsor: AccountId,
        asset_definition_id: AssetDefinitionId,
        policy_reference: iroha_crypto::Hash,
    }

    fn business_policy_fixture_v1() -> BusinessPolicyFixtureV1 {
        let network_id = network_id_v1(0x21);
        let route = PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(23),
            lane_id: LaneId::new(5),
            lane_incarnation: iroha_crypto::Hash::prehashed([0x22; 32]),
        };
        let pool_id = PrivacyPoolIdV1::new([0x23; 32]);
        let payer = account_v1(0x24);
        let recipient = account_v1(0x25);
        let sponsor = account_v1(0x26);
        let asset_definition_id = asset_definition_v1(0x27);
        let policy_reference = iroha_crypto::Hash::prehashed([0x28; 32]);
        let policy = PrivateSettlementAuditorBusinessPolicyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            exact_network_id: network_id,
            exact_route: route,
            exact_pool_id: pool_id,
            exact_audit_policy_id: iroha_crypto::Hash::prehashed([0x29; 32]),
            exact_audit_policy_revision: 4,
            exact_audit_key_epoch: 7,
            allowed_payers: vec![payer.clone()],
            allowed_recipients: vec![recipient.clone()],
            allowed_sponsors: vec![sponsor.clone()],
            allowed_asset_definition_ids: vec![asset_definition_id.clone()],
            minimum_amount: 10,
            maximum_amount: 1_000,
            maximum_sponsor_reimbursement_amount: 25,
            maximum_memo_bytes: 64,
            allowed_policy_references: vec![policy_reference],
            required_policy_references: vec![policy_reference],
            maximum_remaining_blocks: 20,
        };
        BusinessPolicyFixtureV1 {
            policy,
            network_id,
            route,
            pool_id,
            payer,
            recipient,
            sponsor,
            asset_definition_id,
            policy_reference,
        }
    }

    fn business_policy_input_v1<'a>(
        fixture: &'a BusinessPolicyFixtureV1,
        amount: u128,
        policy_references: &'a [iroha_crypto::Hash],
    ) -> PrivateSettlementAuditorBusinessPolicyInputV1<'a> {
        PrivateSettlementAuditorBusinessPolicyInputV1 {
            network_id: fixture.network_id,
            route: fixture.route,
            pool_id: fixture.pool_id,
            audit_policy_id: fixture.policy.exact_audit_policy_id,
            audit_policy_revision: fixture.policy.exact_audit_policy_revision,
            audit_key_epoch: fixture.policy.exact_audit_key_epoch,
            payer: &fixture.payer,
            recipient: &fixture.recipient,
            sponsor: &fixture.sponsor,
            asset_definition_id: &fixture.asset_definition_id,
            amount,
            sponsor_reimbursement_amount: 10,
            memo: b"invoice-42",
            policy_references,
            settlement_expiry_height: 115,
            authoritative_height: 100,
        }
    }

    fn successful_transport_v1() -> MockTransportV1 {
        MockTransportV1 {
            fetch: Ok(PrivateSettlementOnlineAuditorQuorumViewV1 {
                response: 7,
                authoritative_height: 19,
                authority_context_height: 10,
                expiry_height: 30,
            }),
            submit: Ok(9),
            fetch_failures: 1,
            submit_failures: 1,
            fetch_endpoint_attempts: Cell::new(0),
            submit_endpoint_attempts: Cell::new(0),
        }
    }

    #[test]
    fn coordinator_accepts_validated_fetch_quorum_with_one_endpoint_failure() {
        let transport = successful_transport_v1();
        let signer = signer_v1();
        let result = coordinate_with_transport_v1(
            &transport,
            &endpoints_v1(),
            &authority_v1(),
            iroha_crypto::Hash::new(b"online-auditor-one-failure"),
            &capsule_request_v1(),
            &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
            |view| Ok(view.saturating_add(1)),
        )
        .expect("the transport's validated three-of-four quorum succeeds");
        assert_eq!(result, 9);
        assert_eq!(transport.fetch_endpoint_attempts.get(), 4);
        assert_eq!(transport.submit_endpoint_attempts.get(), 4);
    }

    #[test]
    fn coordinator_rejects_split_or_substituted_fetch_view_without_approval() {
        let transport = MockTransportV1 {
            fetch: Err("SPLIT_VIEW_SECRET_CANARY"),
            ..successful_transport_v1()
        };
        let signer = signer_v1();
        let approval_called = Cell::new(false);
        let error = coordinate_with_transport_v1(
            &transport,
            &endpoints_v1(),
            &authority_v1(),
            iroha_crypto::Hash::new(b"online-auditor-split-view"),
            &capsule_request_v1(),
            &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
            |_| {
                approval_called.set(true);
                Ok(1)
            },
        )
        .expect_err("split view must fail closed");
        assert_eq!(
            error.to_string(),
            "private-settlement online auditor quorum fetch failed"
        );
        assert!(!format!("{error:#}").contains("SPLIT_VIEW_SECRET_CANARY"));
        assert!(!approval_called.get());
        assert_eq!(transport.submit_endpoint_attempts.get(), 0);
    }

    #[test]
    fn coordinator_rejects_stale_quorum_height_before_provider_use() {
        let transport = MockTransportV1 {
            fetch: Ok(PrivateSettlementOnlineAuditorQuorumViewV1 {
                response: 7,
                authoritative_height: 31,
                authority_context_height: 10,
                expiry_height: 30,
            }),
            ..successful_transport_v1()
        };
        let signer = signer_v1();
        let approval_called = Cell::new(false);
        let error = coordinate_with_transport_v1(
            &transport,
            &endpoints_v1(),
            &authority_v1(),
            iroha_crypto::Hash::new(b"online-auditor-stale-height"),
            &capsule_request_v1(),
            &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
            |_| {
                approval_called.set(true);
                Ok(1)
            },
        )
        .expect_err("stale quorum height must fail closed");
        assert_eq!(
            error.to_string(),
            "private-settlement online auditor height is stale"
        );
        assert!(!approval_called.get());
        assert_eq!(transport.submit_endpoint_attempts.get(), 0);
    }

    #[test]
    fn coordinator_redacts_provider_failure_and_skips_submission() {
        let transport = successful_transport_v1();
        let signer = signer_v1();
        let error = coordinate_with_transport_v1(
            &transport,
            &endpoints_v1(),
            &authority_v1(),
            iroha_crypto::Hash::new(b"online-auditor-provider-failure"),
            &capsule_request_v1(),
            &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
            |_| Err(eyre!("PROVIDER_BACKEND_SECRET_CANARY")),
        )
        .expect_err("provider failure must fail closed");
        assert_eq!(
            error.to_string(),
            "private-settlement online auditor credential or policy operation failed"
        );
        assert!(!format!("{error:#}").contains("PROVIDER_BACKEND_SECRET_CANARY"));
        assert_eq!(transport.submit_endpoint_attempts.get(), 0);
    }

    #[test]
    fn coordinator_accepts_exact_three_of_four_approval_acknowledgements() {
        let transport = successful_transport_v1();
        let signer = signer_v1();
        let acknowledgement = coordinate_with_transport_v1(
            &transport,
            &endpoints_v1(),
            &authority_v1(),
            iroha_crypto::Hash::new(b"online-auditor-three-acks"),
            &capsule_request_v1(),
            &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
            |_| Ok(11),
        )
        .expect("transport-validated exact acknowledgement quorum succeeds");
        assert_eq!(acknowledgement, 9);
        assert_eq!(transport.fetch_endpoint_attempts.get(), 4);
        assert_eq!(transport.submit_endpoint_attempts.get(), 4);
    }

    #[test]
    fn coordinator_rejects_duplicate_endpoints_before_transport() {
        let transport = successful_transport_v1();
        let signer = signer_v1();
        let mut endpoints = endpoints_v1();
        endpoints[3] = endpoints[0].clone();
        assert!(
            coordinate_with_transport_v1(
                &transport,
                &endpoints,
                &authority_v1(),
                iroha_crypto::Hash::new(b"online-auditor-duplicate-endpoint"),
                &capsule_request_v1(),
                &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
                |_| Ok(11),
            )
            .is_err()
        );
        assert_eq!(transport.fetch_endpoint_attempts.get(), 0);
        assert_eq!(transport.submit_endpoint_attempts.get(), 0);
    }

    #[test]
    fn coordinator_rejects_invalid_governed_authority_before_transport() {
        let transport = successful_transport_v1();
        let signer = signer_v1();
        let mut authority = authority_v1();
        authority.validator_pops[0][0] ^= 1;
        let error = coordinate_with_transport_v1(
            &transport,
            &endpoints_v1(),
            &authority,
            iroha_crypto::Hash::new(b"online-auditor-invalid-authority"),
            &capsule_request_v1(),
            &BorrowedKeyPairIdentityRequestSignerV1::new(&signer),
            |_| Ok(11),
        )
        .expect_err("invalid governed authority must fail before network access");
        assert_eq!(
            error.to_string(),
            "private-settlement expected committee authority is invalid"
        );
        assert_eq!(transport.fetch_endpoint_attempts.get(), 0);
        assert_eq!(transport.submit_endpoint_attempts.get(), 0);
    }

    #[test]
    fn business_policy_requires_every_exact_private_constraint() {
        let fixture = business_policy_fixture_v1();
        fixture
            .policy
            .validate()
            .expect("strict business policy fixture validates");
        let references = [fixture.policy_reference];
        assert!(fixture.policy.approves_input_v1(&business_policy_input_v1(
            &fixture,
            500,
            &references
        )));
        assert!(!fixture.policy.approves_input_v1(&business_policy_input_v1(
            &fixture,
            1_001,
            &references
        )));
        let unexpected = [iroha_crypto::Hash::prehashed([0xFF; 32])];
        assert!(!fixture.policy.approves_input_v1(&business_policy_input_v1(
            &fixture,
            500,
            &unexpected
        )));
    }

    #[test]
    fn business_policy_rejects_wildcard_or_noncanonical_allowlists() {
        let fixture = business_policy_fixture_v1();
        let mut empty = fixture.policy.clone();
        empty.allowed_payers.clear();
        assert!(empty.validate().is_err());

        let mut noncanonical = fixture.policy;
        noncanonical
            .allowed_recipients
            .push(noncanonical.allowed_recipients[0].clone());
        assert!(noncanonical.validate().is_err());
    }

    #[cfg(unix)]
    fn write_owner_only_secret_v1(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, bytes).expect("write auditor secret fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set auditor secret fixture permissions");
    }

    #[cfg(unix)]
    #[test]
    fn auditor_secret_loader_accepts_exact_owner_only_norito_json() {
        let directory = tempfile::tempdir().expect("auditor secret directory");
        let path = directory.path().join("auditor-hybrid-secret.json");
        let mut rng = iroha_crypto::rng_from_seed_slice(b"CLI online auditor hybrid key fixture");
        let expected =
            iroha_crypto::HybridKeyPair::generate(&mut rng).expect("generate hybrid key fixture");
        let (x25519, ml_kem) = expected.secret().to_bytes();
        let document = norito::json!({
            "version": (PRIVATE_SETTLEMENT_AUDITOR_SECRET_FILE_VERSION_V1),
            "x25519_secret_hex": (hex::encode(x25519)),
            "ml_kem_768_secret_hex": (hex::encode(ml_kem)),
        });
        let bytes = norito::json::to_vec(&document).expect("encode secret fixture");
        write_owner_only_secret_v1(&path, &bytes);

        let actual =
            load_private_settlement_auditor_secret_v1(&path).expect("load exact owner-only secret");
        assert_eq!(
            actual.public().x25519_bytes(),
            expected.public().x25519_bytes()
        );
        assert_eq!(
            actual.public().kyber_bytes(),
            expected.public().kyber_bytes()
        );
    }

    #[cfg(unix)]
    #[test]
    fn auditor_secret_loader_redacts_invalid_secret_material() {
        let directory = tempfile::tempdir().expect("auditor secret directory");
        let path = directory.path().join("invalid-auditor-hybrid-secret.json");
        let canary = "AUDITOR_DECRYPTION_SECRET_CANARY_MUST_NOT_ESCAPE";
        write_owner_only_secret_v1(&path, canary.as_bytes());

        let error = load_private_settlement_auditor_secret_v1(&path)
            .expect_err("invalid secret material must fail");
        assert!(!format!("{error:#}").contains(canary));
    }

    #[cfg(unix)]
    #[test]
    fn business_policy_loader_accepts_only_valid_owner_only_policy() {
        let directory = tempfile::tempdir().expect("auditor policy directory");
        let path = directory.path().join("auditor-business-policy.json");
        let expected = business_policy_fixture_v1().policy;
        let bytes = norito::json::to_vec(&expected).expect("encode business policy fixture");
        write_owner_only_secret_v1(&path, &bytes);

        let loaded = load_private_settlement_auditor_business_policy_v1(&path)
            .expect("load strict owner-only business policy");
        assert!(loaded == expected);
    }

    #[cfg(unix)]
    #[test]
    fn committee_authority_loader_requires_owner_only_absolute_trust_anchor() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().expect("committee authority directory");
        let authority = authority_v1();
        let bytes = norito::json::to_vec(&authority).expect("encode committee authority fixture");

        let valid = directory.path().join("committee-authority.json");
        write_owner_only_secret_v1(&valid, &bytes);
        assert_eq!(
            load_private_settlement_committee_authority_v1(&valid)
                .expect("load owner-only committee trust anchor"),
            authority
        );

        assert!(
            load_private_settlement_committee_authority_v1(Path::new(
                "relative-committee-authority.json"
            ))
            .is_err(),
            "relative trust-anchor paths must fail closed"
        );

        let permissive = directory.path().join("permissive-authority.json");
        std::fs::write(&permissive, &bytes).expect("write permissive authority fixture");
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive authority fixture mode");
        assert!(
            load_private_settlement_committee_authority_v1(&permissive).is_err(),
            "group/world-readable trust anchors must fail closed"
        );

        let linked = directory.path().join("linked-authority.json");
        symlink(&valid, &linked).expect("create authority symlink fixture");
        assert!(
            load_private_settlement_committee_authority_v1(&linked).is_err(),
            "symlink trust anchors must fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restricted_file_open_is_nonblocking_and_nofollow() {
        let flags = private_settlement_restricted_file_open_flags_v1();
        assert!(flags.contains(rustix::fs::OFlags::NONBLOCK));
        assert!(flags.contains(rustix::fs::OFlags::NOFOLLOW));
        assert!(flags.contains(rustix::fs::OFlags::CLOEXEC));
        assert!(flags.contains(rustix::fs::OFlags::RDONLY));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn restricted_file_xattr_names_reject_acl_authority_and_malformed_lists() {
        assert!(validate_restricted_file_xattr_names_v1(b"").is_ok());
        #[cfg(target_os = "macos")]
        assert!(
            validate_restricted_file_xattr_names_v1(b"com.apple.provenance\0").is_ok(),
            "the exact benign macOS provenance xattr must remain usable"
        );
        for names in [
            b"system.posix_acl_access\0".as_slice(),
            b"system.posix_acl_default\0".as_slice(),
            b"system.nfs4_acl\0".as_slice(),
            b"system.richacl\0".as_slice(),
            b"security.NTACL\0".as_slice(),
            b"system.cifs_acl\0".as_slice(),
            b"trusted.SGI_ACL_FILE\0".as_slice(),
            b"com.apple.system.Security\0".as_slice(),
            b"com.apple.macl\0".as_slice(),
            b"user.oracle.metadata\0".as_slice(),
        ] {
            assert!(
                validate_restricted_file_xattr_names_v1(names).is_err(),
                "every non-allowlisted xattr must fail closed"
            );
        }
        #[cfg(target_os = "macos")]
        assert!(
            validate_restricted_file_xattr_names_v1(
                b"com.apple.provenance\0user.second-attribute\0"
            )
            .is_err(),
            "a permitted provenance attribute cannot hide a second attribute"
        );
        assert!(validate_restricted_file_xattr_names_v1(b"not-terminated").is_err());
        assert!(validate_restricted_file_xattr_names_v1(b"first\0\0second\0").is_err());
        assert!(
            validate_restricted_file_xattr_names_v1(&vec![
                b'x';
                PRIVATE_SETTLEMENT_RESTRICTED_FILE_XATTR_NAME_LIST_MAX_BYTES_V1
                    + 1
            ])
            .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn committee_authority_loader_accepts_exact_macos_provenance_attribute() {
        let directory = tempfile::tempdir().expect("committee authority directory");
        let authority = authority_v1();
        let bytes = norito::json::to_vec(&authority).expect("encode committee authority fixture");
        let path = directory.path().join("xattr-committee-authority.json");
        write_owner_only_secret_v1(&path, &bytes);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open xattr authority fixture");
        rustix::fs::fsetxattr(
            &file,
            "com.apple.provenance",
            b"\x01\x02",
            rustix::fs::XattrFlags::empty(),
        )
        .expect("set macOS provenance fixture");
        assert_eq!(
            load_private_settlement_committee_authority_v1(&path)
                .expect("load trust anchor carrying exact macOS provenance metadata"),
            authority,
            "exact macOS provenance metadata must not disable the restricted-file loader"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn committee_authority_loader_rejects_unapproved_descriptor_xattr() {
        let directory = tempfile::tempdir().expect("committee authority directory");
        let authority = authority_v1();
        let bytes = norito::json::to_vec(&authority).expect("encode committee authority fixture");
        let path = directory
            .path()
            .join("unapproved-xattr-committee-authority.json");
        write_owner_only_secret_v1(&path, &bytes);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open unapproved-xattr authority fixture");
        #[cfg(target_os = "linux")]
        let xattr_name = "user.iroha-private-settlement-test";
        #[cfg(target_os = "macos")]
        let xattr_name = "com.hyperledger.iroha.private-settlement-test";
        rustix::fs::fsetxattr(
            &file,
            xattr_name,
            b"untrusted-metadata",
            rustix::fs::XattrFlags::empty(),
        )
        .expect("set unapproved extended attribute fixture");
        assert!(
            load_private_settlement_committee_authority_v1(&path).is_err(),
            "an unapproved descriptor-bound xattr must fail closed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn committee_authority_loader_rejects_extended_acl() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("committee authority directory");
        let authority = authority_v1();
        let bytes = norito::json::to_vec(&authority).expect("encode committee authority fixture");
        let path = directory.path().join("acl-committee-authority.json");
        write_owner_only_secret_v1(&path, &bytes);
        let output = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(&path)
            .output()
            .expect("run macOS chmod");
        assert!(
            output.status.success(),
            "chmod +a failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("ACL authority metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the ACL fixture must retain owner-only POSIX mode bits"
        );
        assert!(
            load_private_settlement_committee_authority_v1(&path).is_err(),
            "restricted trust anchors with an extended ACL must fail closed"
        );
        let _ = std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&path)
            .status();
    }
}
