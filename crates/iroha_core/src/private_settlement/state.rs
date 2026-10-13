//! Validator-derived private-settlement pool transitions and staging evidence.
//!
//! No caller-supplied successor root crosses this module.  A verified leg is
//! minted only after the exact proof, approvals, durable sidecar evidence,
//! authoritative pool head, and replay sets all agree.  The token retains the
//! compact successor frontier needed for deterministic crash recovery and
//! atomic global application.

use super::{
    global_state::PrivateSettlementPoolKeyV1,
    sidecar_store::{
        PrivateSettlementAuditorSidecarViewV1, PrivateSettlementAuthenticatedAuditorViewV1,
        PrivateSettlementFileSidecarStoreV1, PrivateSettlementSidecarStoreErrorV1,
    },
};
use crate::{
    privacy_engines::{
        atomic_private_settlement::{
            atomic_private_settlement_program_id_v1, verify_atomic_private_settlement_v1,
        },
        proof_managed_accumulator::{
            append_proof_managed_commitments_v1, build_proof_managed_frontier_v1,
            validate_proof_managed_frontier_v1,
        },
    },
    state::StateView,
};
use iroha_crypto::{Hash, PublicKey};
#[cfg(test)]
use iroha_data_model::nexus::PrivateSettlementPoolGovernanceV1;
use iroha_data_model::{
    nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1,
        PRIVATE_SETTLEMENT_INPUT_SLOTS_V1, PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1,
        PrivateSettlementAuditApprovalV1, PrivateSettlementAuditPolicyV1, PrivateSettlementDeltaV1,
        PrivateSettlementLegPayloadV1, PrivateSettlementPoolGovernanceLifecycleV1,
        PrivateSettlementRouteV1, validate_private_settlement_audit_approvals_v1,
    },
    privacy::{
        PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyCommitmentV1,
        PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyNullifierV1, PrivacyPoolIdV1,
        PrivacyPoolProgramNamespaceV1, PrivacyProtocolIdV1, PrivacyRootV1,
    },
};
use norito::codec::{Decode, Encode};
use norito::derive::{JsonDeserialize, JsonSerialize};
use std::{collections::BTreeSet, convert::TryFrom as _};
use thiserror::Error;

const VERIFIED_LEG_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:verified-leg:v1\0";
const APPROVALS_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:approvals:v1\0";
const DURABLE_AVAILABILITY_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:durable-availability:v1\0";

fn zero_hash_v1() -> Hash {
    Hash::prehashed([0; Hash::LENGTH])
}

fn canonical_digest_v1<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<Hash, norito::Error> {
    let encoded = norito::encode_canonical(value)?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| norito::Error::Io(std::io::Error::other("canonical value is too large")))?;
    Ok(Hash::new_from_chunks(&[
        domain,
        &encoded_len.to_le_bytes(),
        encoded.as_slice(),
    ]))
}

pub(super) fn private_settlement_approvals_digest_v1(
    approvals: &[PrivateSettlementAuditApprovalV1],
) -> Result<Hash, PrivateSettlementStateErrorV1> {
    canonical_digest_v1(APPROVALS_DIGEST_DOMAIN_V1, &approvals.to_vec())
        .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)
}

fn settlement_namespace_v1(
    pool_id: PrivacyPoolIdV1,
) -> Result<PrivacyNamespaceV1, PrivateSettlementStateErrorV1> {
    let program_id = atomic_private_settlement_program_id_v1()
        .map_err(|_| PrivateSettlementStateErrorV1::PoolInvariant)?;
    Ok(PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
            pool_id,
            program_id,
        }),
    ))
}

/// One superseded public governance revision retained for snapshot validation.
///
/// The immutable route, pool, and asset-binding commitment live on the owning
/// [`PrivateSettlementPoolGovernanceProjectionV1`]. Retaining the policy and
/// lifecycle fields of every superseded revision lets recovery validate old
/// finalized receipts against the policy that was effective when they committed.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::state::PrivateSettlementPoolGovernanceRevisionV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, JsonDeserialize, JsonSerialize)]
pub(crate) struct PrivateSettlementPoolGovernanceRevisionV1 {
    pub(crate) audit_policy_digest: Hash,
    pub(crate) audit_key_epoch: u64,
    pub(crate) lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
    pub(crate) governance_digest: Hash,
}

impl PrivateSettlementPoolGovernanceRevisionV1 {
    fn validate_fields(&self) -> Result<(), PrivateSettlementStateErrorV1> {
        if self.audit_policy_digest == zero_hash_v1()
            || self.audit_key_epoch == 0
            || self.lifecycle.governance_revision == 0
            || self.lifecycle.activation_height == 0
            || self
                .lifecycle
                .retirement_height
                .is_some_and(|retirement| retirement <= self.lifecycle.activation_height)
            || self.governance_digest == zero_hash_v1()
        {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        Ok(())
    }
}

/// Public governance projection retained in globally replicated settlement state.
///
/// The restricted asset identifier and asset-binding opening salt are deliberately
/// absent. They remain in access-controlled governance/auditor material supplied
/// when the pool is bootstrapped.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::private_settlement::state::PrivateSettlementPoolGovernanceProjectionV1"
)]
pub(crate) struct PrivateSettlementPoolGovernanceProjectionV1 {
    pub(crate) version: u8,
    pub(crate) route: PrivateSettlementRouteV1,
    pub(crate) pool_id: PrivacyPoolIdV1,
    pub(crate) asset_binding_commitment: Hash,
    pub(crate) audit_policy_digest: Hash,
    pub(crate) audit_key_epoch: u64,
    pub(crate) lifecycle: PrivateSettlementPoolGovernanceLifecycleV1,
    pub(crate) governance_digest: Hash,
    /// Superseded revisions in exact ascending revision order.
    pub(crate) prior_revisions: Vec<PrivateSettlementPoolGovernanceRevisionV1>,
}

impl PrivateSettlementPoolGovernanceProjectionV1 {
    /// Derive the public projection only after validating the complete restricted record.
    #[cfg(test)]
    pub(crate) fn from_restricted(
        governance: &PrivateSettlementPoolGovernanceV1,
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        governance
            .validate()
            .map_err(|_| PrivateSettlementStateErrorV1::PoolGovernance)?;
        let projection = Self {
            version: governance.body.version,
            route: governance.body.route,
            pool_id: governance.body.pool_id,
            asset_binding_commitment: governance.body.asset_binding_commitment,
            audit_policy_digest: governance.body.audit_policy_digest,
            audit_key_epoch: governance.body.audit_key_epoch,
            lifecycle: governance.body.lifecycle,
            governance_digest: governance.governance_digest,
            prior_revisions: Vec::new(),
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Validate the complete public projection after snapshot recovery.
    pub(crate) fn validate_current_fields(&self) -> Result<(), PrivateSettlementStateErrorV1> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || self.route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
            || self.route.lane_incarnation == zero_hash_v1()
            || self.pool_id.is_zero()
            || self.asset_binding_commitment == zero_hash_v1()
            || self.audit_policy_digest == zero_hash_v1()
            || self.audit_key_epoch == 0
            || self.lifecycle.governance_revision == 0
            || self.lifecycle.activation_height == 0
            || self
                .lifecycle
                .retirement_height
                .is_some_and(|retirement| retirement <= self.lifecycle.activation_height)
            || self.governance_digest == zero_hash_v1()
        {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        Ok(())
    }

    /// Validate the current projection and its complete, gap-free revision lineage.
    pub(crate) fn validate(&self) -> Result<(), PrivateSettlementStateErrorV1> {
        self.validate_current_fields()?;
        let expected_prior_count = usize::try_from(
            self.lifecycle
                .governance_revision
                .checked_sub(1)
                .ok_or(PrivateSettlementStateErrorV1::PoolGovernance)?,
        )
        .map_err(|_| PrivateSettlementStateErrorV1::PoolGovernance)?;
        if self.prior_revisions.len() != expected_prior_count {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }

        let mut previous: Option<PrivateSettlementPoolGovernanceRevisionV1> = None;
        for (index, revision) in self.prior_revisions.iter().copied().enumerate() {
            revision.validate_fields()?;
            let expected_revision = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(PrivateSettlementStateErrorV1::PoolGovernance)?;
            if revision.lifecycle.governance_revision != expected_revision
                || previous.is_some_and(|prior| {
                    prior.audit_policy_digest == revision.audit_policy_digest
                        || prior.audit_key_epoch >= revision.audit_key_epoch
                        || prior.governance_digest == revision.governance_digest
                        || prior.lifecycle.activation_height >= revision.lifecycle.activation_height
                        || !prior
                            .lifecycle
                            .is_active_at(revision.lifecycle.activation_height.saturating_sub(1))
                })
            {
                return Err(PrivateSettlementStateErrorV1::PoolGovernance);
            }
            previous = Some(revision);
        }

        if let Some(previous) = previous {
            if previous.audit_policy_digest == self.audit_policy_digest
                || previous.audit_key_epoch >= self.audit_key_epoch
                || previous.governance_digest == self.governance_digest
                || previous.lifecycle.activation_height >= self.lifecycle.activation_height
                || !previous
                    .lifecycle
                    .is_active_at(self.lifecycle.activation_height.saturating_sub(1))
            {
                return Err(PrivateSettlementStateErrorV1::PoolGovernance);
            }
        } else if self.lifecycle.governance_revision != 1 {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        Ok(())
    }

    /// Return the compact current revision without duplicating immutable pool fields.
    pub(crate) fn current_revision(&self) -> PrivateSettlementPoolGovernanceRevisionV1 {
        PrivateSettlementPoolGovernanceRevisionV1 {
            audit_policy_digest: self.audit_policy_digest,
            audit_key_epoch: self.audit_key_epoch,
            lifecycle: self.lifecycle,
            governance_digest: self.governance_digest,
        }
    }

    /// Return the exact effective revision at a height, respecting later activations.
    pub(crate) fn revision_at(
        &self,
        height: u64,
    ) -> Option<PrivateSettlementPoolGovernanceRevisionV1> {
        if self.validate().is_err() {
            return None;
        }
        for (index, revision) in self.prior_revisions.iter().copied().enumerate() {
            let next_activation = self
                .prior_revisions
                .get(index + 1)
                .map_or(self.lifecycle.activation_height, |next| {
                    next.lifecycle.activation_height
                });
            if revision.lifecycle.is_active_at(height) && height < next_activation {
                return Some(revision);
            }
        }
        let current = self.current_revision();
        current.lifecycle.is_active_at(height).then_some(current)
    }

    /// Bind one complete restricted policy to the exact governance revision
    /// effective at `height`.
    ///
    /// Unlike [`Self::validate_against_policy_at`], this also accepts a
    /// superseded revision retained in the public lineage. It is used only for
    /// authorized retention reads, where the historical sidecar policy must be
    /// proven against the revision that governed its authority context while a
    /// separately supplied current policy controls present-day access.
    fn policy_revision_at(
        &self,
        policy: &PrivateSettlementAuditPolicyV1,
        height: u64,
    ) -> Result<PrivateSettlementPoolGovernanceRevisionV1, PrivateSettlementStateErrorV1> {
        policy
            .validate()
            .map_err(|_| PrivateSettlementStateErrorV1::PoolGovernance)?;
        let policy_digest = policy
            .computed_policy_digest()
            .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
        let revision = self
            .revision_at(height)
            .ok_or(PrivateSettlementStateErrorV1::PoolGovernance)?;
        if self.route.dataspace_id != policy.body.dataspace_id
            || revision.audit_policy_digest != policy.policy_digest
            || revision.audit_policy_digest != policy_digest
            || revision.audit_key_epoch != policy.body.key_epoch
            || revision.lifecycle.activation_height < policy.body.activation_height
            || !policy.is_active_at(height)
        {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        Ok(revision)
    }

    /// Materialize a replacement while preserving the complete prior lineage.
    pub(crate) fn with_replacement(
        &self,
        mut replacement: Self,
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        self.validate()?;
        replacement.validate_current_fields()?;
        if !replacement.prior_revisions.is_empty() {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        replacement
            .prior_revisions
            .clone_from(&self.prior_revisions);
        replacement.prior_revisions.push(self.current_revision());
        replacement.validate()?;
        Ok(replacement)
    }

    /// Compare only the externally supplied current revision fields.
    pub(crate) fn current_fields_equal(&self, other: &Self) -> bool {
        self.version == other.version
            && self.route == other.route
            && self.pool_id == other.pool_id
            && self.asset_binding_commitment == other.asset_binding_commitment
            && self.audit_policy_digest == other.audit_policy_digest
            && self.audit_key_epoch == other.audit_key_epoch
            && self.lifecycle == other.lifecycle
            && self.governance_digest == other.governance_digest
    }

    /// Validate the public projection against the exact restricted auditor policy.
    ///
    /// Committee validators need policy signing keys to verify approvals, but
    /// must never receive the literal asset mapping or its opening salt. This
    /// check therefore enforces every policy/lifecycle binding using only the
    /// globally replicated projection.
    pub(crate) fn validate_against_policy_at(
        &self,
        policy: &PrivateSettlementAuditPolicyV1,
        height: u64,
    ) -> Result<(), PrivateSettlementStateErrorV1> {
        self.validate()?;
        policy
            .validate()
            .map_err(|_| PrivateSettlementStateErrorV1::PoolGovernance)?;
        let policy_digest = policy
            .computed_policy_digest()
            .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
        if self.route.dataspace_id != policy.body.dataspace_id
            || self.audit_policy_digest != policy.policy_digest
            || self.audit_policy_digest != policy_digest
            || self.audit_key_epoch != policy.body.key_epoch
            || self.lifecycle.activation_height < policy.body.activation_height
            || match policy.body.retirement_height {
                Some(policy_retirement) => self
                    .lifecycle
                    .retirement_height
                    .is_none_or(|retirement| retirement > policy_retirement),
                None => false,
            }
            || !self.lifecycle.is_active_at(height)
            || !policy.is_active_at(height)
        {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        Ok(())
    }
}

/// Authorize one retained capsule against an exact governance projection.
pub(super) fn authorize_private_settlement_auditor_view_against_governance_v1(
    governance: &PrivateSettlementPoolGovernanceProjectionV1,
    network_id: &iroha_data_model::NetworkId,
    access_policy: &PrivateSettlementAuditPolicyV1,
    signing_key: &PublicKey,
    authoritative_height: u64,
    view: PrivateSettlementAuditorSidecarViewV1,
) -> Result<PrivateSettlementAuthenticatedAuditorViewV1, PrivateSettlementSidecarStoreErrorV1> {
    let unavailable = || PrivateSettlementSidecarStoreErrorV1::Unavailable;
    if &view.manifest.network_id != network_id
        || view.statement.network_id != *network_id
        || governance.route != view.statement.route
        || governance.pool_id != view.statement.pool_id
    {
        return Err(unavailable());
    }
    let historical_revision = governance
        .policy_revision_at(&view.policy, view.manifest.authority_context_height)
        .map_err(|_| unavailable())?;
    let access_revision = governance
        .policy_revision_at(access_policy, authoritative_height)
        .map_err(|_| unavailable())?;
    let same_revision = access_revision.lifecycle.governance_revision
        == historical_revision.lifecycle.governance_revision
        && access_policy == &view.policy;
    let successor_revision = access_revision.lifecycle.governance_revision
        > historical_revision.lifecycle.governance_revision
        && access_policy.body.policy_id == view.policy.body.policy_id
        && access_policy.body.revision > view.policy.body.revision
        && access_policy.body.key_epoch > view.policy.body.key_epoch;
    if !same_revision && !successor_revision {
        return Err(unavailable());
    }
    let auditor = access_policy
        .body
        .auditors
        .iter()
        .find(|auditor| &auditor.signing_key == signing_key)
        .ok_or_else(unavailable)?;
    if view
        .authority
        .validators
        .iter()
        .any(|validator| validator.public_key() == signing_key)
        || !view
            .policy
            .body
            .auditors
            .iter()
            .any(|historical| historical.auditor_id == auditor.auditor_id)
        || !view
            .audit_capsule
            .wrapped_deks
            .iter()
            .any(|wrapped| wrapped.auditor_id == auditor.auditor_id)
    {
        return Err(unavailable());
    }
    Ok(PrivateSettlementAuthenticatedAuditorViewV1 {
        auditor_id: auditor.auditor_id.clone(),
        access_policy: access_policy.clone(),
        view,
    })
}

/// Fetch one encrypted auditor capsule using only state-bound authorization.
///
/// The caller supplies the complete restricted policy as evidence, never as
/// authority. This operation derives height and network from one committed
/// [`StateView`], reads exactly one content-addressed sidecar, binds both its
/// historical policy and the supplied current policy to the same WSV
/// governance lineage, and maps the authenticated signing key to one stable
/// auditor identity. Missing and unauthorized records intentionally share the
/// same unavailable result.
///
/// # Errors
///
/// Returns unavailable for every authorization denial, or a redacted local
/// sidecar corruption/backend error.
pub fn fetch_private_settlement_auditor_view_v1(
    state: &StateView<'_>,
    store: &PrivateSettlementFileSidecarStoreV1,
    digest: Hash,
    access_policy: &PrivateSettlementAuditPolicyV1,
    signing_key: &PublicKey,
) -> Result<PrivateSettlementAuthenticatedAuditorViewV1, PrivateSettlementSidecarStoreErrorV1> {
    let authoritative_height = u64::try_from(state.block_hashes.len())
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
    let view = store.auditor_material_v1(digest, authoritative_height)?;
    let key = PrivateSettlementPoolKeyV1::new(view.statement.route, view.statement.pool_id)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
    let governance = state
        .world
        .private_settlement_governance
        .get(&key)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
    authorize_private_settlement_auditor_view_against_governance_v1(
        governance,
        &state.network_id,
        access_policy,
        signing_key,
        authoritative_height,
        view,
    )
}

/// Persisted compact frontier for one explicitly governed settlement pool.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    JsonDeserialize,
    JsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::private_settlement::state::PrivateSettlementPoolStateV1")]
pub(crate) struct PrivateSettlementPoolStateV1 {
    version: u8,
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
    restricted_pool_policy_digest: Hash,
    epoch: u64,
    root: PrivacyRootV1,
    tree_size: u64,
    leaf: Option<[u8; 32]>,
    ommers: Vec<[u8; 32]>,
}

impl PrivateSettlementPoolStateV1 {
    /// Bootstrap one pool from the exact governed origin commitments.
    pub(crate) fn bootstrap(
        route: PrivateSettlementRouteV1,
        pool_id: PrivacyPoolIdV1,
        restricted_pool_policy_digest: Hash,
        initial_commitments: &[PrivacyCommitmentV1],
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        if pool_id.is_zero()
            || route.lane_incarnation == zero_hash_v1()
            || restricted_pool_policy_digest == zero_hash_v1()
        {
            return Err(PrivateSettlementStateErrorV1::PoolInvariant);
        }
        let namespace = settlement_namespace_v1(pool_id)?;
        let frontier = build_proof_managed_frontier_v1(namespace, initial_commitments)
            .map_err(|_| PrivateSettlementStateErrorV1::PoolInvariant)?;
        let state = Self {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            route,
            pool_id,
            restricted_pool_policy_digest,
            epoch: 1,
            root: frontier.root,
            tree_size: frontier.tree_size,
            leaf: frontier.leaf,
            ommers: frontier.ommers,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validate the complete persisted frontier after load or restart.
    pub(crate) fn validate(&self) -> Result<(), PrivateSettlementStateErrorV1> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || self.pool_id.is_zero()
            || self.route.lane_incarnation == zero_hash_v1()
            || self.restricted_pool_policy_digest == zero_hash_v1()
            || self.epoch == 0
            || self.root.is_zero()
            || self.tree_size == 0
        {
            return Err(PrivateSettlementStateErrorV1::PoolInvariant);
        }
        validate_proof_managed_frontier_v1(
            settlement_namespace_v1(self.pool_id)?,
            self.tree_size,
            self.leaf,
            &self.ommers,
            self.root,
        )
        .map_err(|_| PrivateSettlementStateErrorV1::PoolInvariant)
    }

    /// Opaque pool identifier.
    #[must_use]
    pub(crate) const fn pool_id(&self) -> PrivacyPoolIdV1 {
        self.pool_id
    }

    /// Canonical participant route.
    #[must_use]
    pub(crate) const fn route(&self) -> PrivateSettlementRouteV1 {
        self.route
    }

    /// Digest of the restricted one-pool-to-one-asset governance record.
    #[must_use]
    pub(crate) const fn restricted_pool_policy_digest(&self) -> Hash {
        self.restricted_pool_policy_digest
    }

    /// Rebind this unchanged frontier to an exact replacement governance record.
    pub(crate) fn rotate_governance_digest(
        &self,
        expected_current_digest: Hash,
        replacement_digest: Hash,
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        self.validate()?;
        if self.restricted_pool_policy_digest != expected_current_digest
            || replacement_digest == zero_hash_v1()
            || replacement_digest == expected_current_digest
        {
            return Err(PrivateSettlementStateErrorV1::PoolGovernance);
        }
        let mut rotated = self.clone();
        rotated.restricted_pool_policy_digest = replacement_digest;
        rotated.validate()?;
        Ok(rotated)
    }

    /// Current root epoch.
    #[must_use]
    pub(crate) const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Current authoritative root.
    #[must_use]
    pub(crate) const fn root(&self) -> PrivacyRootV1 {
        self.root
    }

    pub(super) fn successor(
        &self,
        output_commitments: &[PrivacyCommitmentV1],
    ) -> Result<PrivateSettlementSuccessorFrontierV1, PrivateSettlementStateErrorV1> {
        self.validate()?;
        let frontier = append_proof_managed_commitments_v1(
            settlement_namespace_v1(self.pool_id)?,
            self.tree_size,
            self.leaf,
            &self.ommers,
            self.root,
            output_commitments,
        )
        .map_err(|_| PrivateSettlementStateErrorV1::SuccessorDerivation)?;
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(PrivateSettlementStateErrorV1::SuccessorDerivation)?;
        if frontier.root == self.root {
            return Err(PrivateSettlementStateErrorV1::SuccessorDerivation);
        }
        Ok(PrivateSettlementSuccessorFrontierV1 {
            epoch,
            root: frontier.root,
            tree_size: frontier.tree_size,
            leaf: frontier.leaf,
            ommers: frontier.ommers,
        })
    }

    /// Apply a globally certified delta after every participant QC is verified.
    ///
    /// The global carrier deliberately omits proofs and audit plaintext. This
    /// method therefore rechecks every public state binding and independently
    /// derives the successor frontier instead of trusting the certificate's
    /// caller-supplied `new_root`.
    pub(super) fn apply_certified_delta(
        &self,
        delta: &PrivateSettlementDeltaV1,
        governance: &PrivateSettlementPoolGovernanceProjectionV1,
        authority_context_height: u64,
        expiry_height: u64,
        finalized_height: u64,
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        self.validate()?;
        governance.validate()?;
        if !governance.lifecycle.is_active_at(authority_context_height)
            || !governance.lifecycle.is_active_at(finalized_height)
            || governance
                .lifecycle
                .retirement_height
                .is_some_and(|retirement| expiry_height >= retirement)
            || (
                &governance.governance_digest,
                &governance.route,
                &governance.pool_id,
            ) != (
                &self.restricted_pool_policy_digest,
                &self.route,
                &self.pool_id,
            )
            || delta.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || delta.route != self.route
            || delta.pool_id != self.pool_id
            || delta.asset_binding_commitment != governance.asset_binding_commitment
            || delta.audit_policy_digest != governance.audit_policy_digest
            || delta.audit_key_epoch != governance.audit_key_epoch
            || delta.old_root != self.root
            || delta.old_epoch != self.epoch
            || delta.old_epoch.checked_add(1) != Some(delta.new_epoch)
            || delta.nullifiers.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
            || delta.output_commitments.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
            || delta.encrypted_outputs.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1
            || delta.nullifiers.iter().any(PrivacyNullifierV1::is_zero)
            || delta
                .output_commitments
                .iter()
                .any(PrivacyCommitmentV1::is_zero)
            || delta
                .nullifiers
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != delta.nullifiers.len()
            || delta
                .output_commitments
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != delta.output_commitments.len()
        {
            return Err(PrivateSettlementStateErrorV1::ParentHeadMismatch);
        }
        for (index, encrypted) in delta.encrypted_outputs.iter().enumerate() {
            if encrypted.recipient.is_zero()
                || encrypted.ephemeral_public_key.is_zero()
                || encrypted.commitment != delta.output_commitments[index]
                || encrypted.ciphertext.len() != PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1
                || encrypted.ciphertext.get(..4) != Some(b"IPNE".as_slice())
                || encrypted.ciphertext[4..].iter().all(|byte| *byte == 0)
            {
                return Err(PrivateSettlementStateErrorV1::ParentHeadMismatch);
            }
        }
        let successor = self.successor(&delta.output_commitments)?;
        if delta.new_root != successor.root || delta.new_epoch != successor.epoch {
            return Err(PrivateSettlementStateErrorV1::CallerSelectedSuccessor);
        }
        let next = Self {
            version: self.version,
            route: self.route,
            pool_id: self.pool_id,
            restricted_pool_policy_digest: self.restricted_pool_policy_digest,
            epoch: successor.epoch,
            root: successor.root,
            tree_size: successor.tree_size,
            leaf: successor.leaf,
            ommers: successor.ommers,
        };
        next.validate()?;
        Ok(next)
    }

    /// Apply one previously verified token to this exact parent head.
    #[cfg(test)]
    pub(crate) fn apply_verified(
        &self,
        verified: &ValidatedPrivateSettlementLegV1,
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        self.validate()?;
        verified.validate_digest()?;
        if verified.route != self.route
            || verified.pool_id != self.pool_id
            || verified.restricted_pool_policy_digest != self.restricted_pool_policy_digest
            || verified.delta.old_root != self.root
            || verified.delta.old_epoch != self.epoch
            || verified.delta.new_root != verified.successor.root
            || verified.delta.new_epoch != verified.successor.epoch
        {
            return Err(PrivateSettlementStateErrorV1::ParentHeadMismatch);
        }
        let next = Self {
            version: self.version,
            route: self.route,
            pool_id: self.pool_id,
            restricted_pool_policy_digest: self.restricted_pool_policy_digest,
            epoch: verified.successor.epoch,
            root: verified.successor.root,
            tree_size: verified.successor.tree_size,
            leaf: verified.successor.leaf,
            ommers: verified.successor.ommers.clone(),
        };
        next.validate()?;
        Ok(next)
    }
}

/// Fsync-backed availability evidence minted by the restricted sidecar store.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::state::PrivateSettlementDurableAvailabilityV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
pub(crate) struct PrivateSettlementDurableAvailabilityV1 {
    payload_digest: Hash,
    persisted_record_digest: Hash,
    payload_bytes: u64,
    fsync_generation: u64,
    evidence_digest: Hash,
}

impl PrivateSettlementDurableAvailabilityV1 {
    /// Mint evidence only after the sidecar record and parent directory are durable.
    pub(super) fn new(
        payload_digest: Hash,
        persisted_record_digest: Hash,
        payload_bytes: u64,
        fsync_generation: u64,
    ) -> Result<Self, PrivateSettlementStateErrorV1> {
        if payload_digest == zero_hash_v1()
            || persisted_record_digest == zero_hash_v1()
            || payload_bytes == 0
            || fsync_generation == 0
        {
            return Err(PrivateSettlementStateErrorV1::Availability);
        }
        let mut evidence = Self {
            payload_digest,
            persisted_record_digest,
            payload_bytes,
            fsync_generation,
            evidence_digest: zero_hash_v1(),
        };
        evidence.evidence_digest = evidence.computed_digest()?;
        Ok(evidence)
    }

    fn computed_digest(&self) -> Result<Hash, PrivateSettlementStateErrorV1> {
        canonical_digest_v1(
            DURABLE_AVAILABILITY_DIGEST_DOMAIN_V1,
            &(
                self.payload_digest,
                self.persisted_record_digest,
                self.payload_bytes,
                self.fsync_generation,
            ),
        )
        .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)
    }

    fn validate_for(
        &self,
        payload: &PrivateSettlementLegPayloadV1,
    ) -> Result<(), PrivateSettlementStateErrorV1> {
        let expected_payload_digest = payload
            .payload_digest()
            .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
        let expected_bytes = u64::try_from(
            payload
                .canonical_bytes_len()
                .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?,
        )
        .map_err(|_| PrivateSettlementStateErrorV1::Availability)?;
        if self.payload_digest != expected_payload_digest
            || self.payload_bytes != expected_bytes
            || self.persisted_record_digest == zero_hash_v1()
            || self.fsync_generation == 0
            || self.evidence_digest != self.computed_digest()?
        {
            return Err(PrivateSettlementStateErrorV1::Availability);
        }
        Ok(())
    }

    /// Self-authenticating digest persisted in verified-leg tokens.
    #[must_use]
    pub(super) const fn evidence_digest(&self) -> Hash {
        self.evidence_digest
    }
}

#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::state::PrivateSettlementSuccessorFrontierV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
pub(super) struct PrivateSettlementSuccessorFrontierV1 {
    pub(super) epoch: u64,
    pub(super) root: PrivacyRootV1,
    pub(super) tree_size: u64,
    pub(super) leaf: Option<[u8; 32]>,
    pub(super) ommers: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::state::PrivateSettlementVerifiedLegDigestMaterialV1"
)]
struct PrivateSettlementVerifiedLegDigestMaterialV1 {
    manifest_digest: Hash,
    statement_digest: Hash,
    approvals_digest: Hash,
    durable_availability_digest: Hash,
    restricted_pool_policy_digest: Hash,
    verified_at_height: u64,
    delta: PrivateSettlementDeltaV1,
    successor: PrivateSettlementSuccessorFrontierV1,
}

/// Unforgeable-in-API token proving that one leg passed every Prepare gate.
///
/// The fields remain private and the token is revalidated after decode.  It is
/// deliberately persisted with staged locks so a restart can reconstruct and
/// reject conflicting pool/nullifier/output reservations.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::private_settlement::state::ValidatedPrivateSettlementLegV1")]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
pub(crate) struct ValidatedPrivateSettlementLegV1 {
    route: PrivateSettlementRouteV1,
    pool_id: PrivacyPoolIdV1,
    restricted_pool_policy_digest: Hash,
    manifest_digest: Hash,
    statement_digest: Hash,
    approvals_digest: Hash,
    durable_availability_digest: Hash,
    verified_at_height: u64,
    delta: PrivateSettlementDeltaV1,
    successor: PrivateSettlementSuccessorFrontierV1,
    verification_digest: Hash,
}

impl ValidatedPrivateSettlementLegV1 {
    fn digest_material(&self) -> PrivateSettlementVerifiedLegDigestMaterialV1 {
        PrivateSettlementVerifiedLegDigestMaterialV1 {
            manifest_digest: self.manifest_digest,
            statement_digest: self.statement_digest,
            approvals_digest: self.approvals_digest,
            durable_availability_digest: self.durable_availability_digest,
            restricted_pool_policy_digest: self.restricted_pool_policy_digest,
            verified_at_height: self.verified_at_height,
            delta: self.delta.clone(),
            successor: self.successor.clone(),
        }
    }

    pub(super) fn validate_digest(&self) -> Result<(), PrivateSettlementStateErrorV1> {
        if self.route != self.delta.route
            || self.pool_id != self.delta.pool_id
            || self.restricted_pool_policy_digest == zero_hash_v1()
            || self.manifest_digest == zero_hash_v1()
            || self.statement_digest == zero_hash_v1()
            || self.approvals_digest == zero_hash_v1()
            || self.durable_availability_digest == zero_hash_v1()
            || self.verified_at_height == 0
            || self.verification_digest
                != canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &self.digest_material())
                    .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?
        {
            return Err(PrivateSettlementStateErrorV1::VerifiedToken);
        }
        Ok(())
    }

    /// Rebind a decoded token to the exact immutable sidecar material.
    pub(super) fn validate_against_payload(
        &self,
        manifest: &AtomicPrivateSettlementV1,
        payload: &PrivateSettlementLegPayloadV1,
        durable_availability_digest: Hash,
    ) -> Result<(), PrivateSettlementStateErrorV1> {
        self.validate_digest()?;
        let manifest_digest = manifest
            .manifest_digest()
            .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
        let statement_digest = payload
            .statement
            .digest()
            .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
        if self.manifest_digest != manifest_digest
            || self.statement_digest != statement_digest
            || self.durable_availability_digest != durable_availability_digest
            || self.delta != payload.delta
            || self.route != payload.statement.route
            || self.pool_id != payload.statement.pool_id
        {
            return Err(PrivateSettlementStateErrorV1::VerifiedToken);
        }
        Ok(())
    }

    /// Rebind a decoded token to the exact canonical approval set.
    pub(super) fn validate_against_approvals(
        &self,
        approvals: &[PrivateSettlementAuditApprovalV1],
    ) -> Result<(), PrivateSettlementStateErrorV1> {
        self.validate_digest()?;
        if self.approvals_digest != private_settlement_approvals_digest_v1(approvals)? {
            return Err(PrivateSettlementStateErrorV1::VerifiedToken);
        }
        Ok(())
    }

    /// Fixed validator-derived delta authorized for global atomic application.
    #[must_use]
    pub(crate) const fn delta(&self) -> &PrivateSettlementDeltaV1 {
        &self.delta
    }

    /// Digest persisted in the sidecar journal and Prepare vote.
    #[must_use]
    pub(crate) const fn verification_digest(&self) -> Hash {
        self.verification_digest
    }

    /// Opaque pool locked by this verified leg.
    #[must_use]
    pub(super) const fn pool_id(&self) -> PrivacyPoolIdV1 {
        self.pool_id
    }

    /// Exact parent head reserved by this verified leg.
    #[must_use]
    pub(super) const fn parent_head(&self) -> (u64, PrivacyRootV1) {
        (self.delta.old_epoch, self.delta.old_root)
    }

    /// Fixed nullifiers reserved until global commit or terminal release.
    #[must_use]
    pub(super) fn nullifiers(&self) -> &[PrivacyNullifierV1] {
        &self.delta.nullifiers
    }

    /// Fixed output commitments reserved until global commit or terminal release.
    #[must_use]
    pub(super) fn output_commitments(&self) -> &[PrivacyCommitmentV1] {
        &self.delta.output_commitments
    }

    /// Authoritative height at which the complete verification finished.
    #[must_use]
    pub(super) const fn verified_at_height(&self) -> u64 {
        self.verified_at_height
    }

    /// Compare the immutable transition evidence while ignoring retry height.
    ///
    /// A committee may re-run verification after restart at a later height.
    /// The freshly minted token then has a different verification digest only
    /// because `verified_at_height` changed. Durable staging is idempotent when
    /// every semantic input and reserved state transition is otherwise exact.
    pub(super) fn same_transition_as(
        &self,
        other: &Self,
    ) -> Result<bool, PrivateSettlementStateErrorV1> {
        self.validate_digest()?;
        other.validate_digest()?;
        Ok(self.route == other.route
            && self.pool_id == other.pool_id
            && self.restricted_pool_policy_digest == other.restricted_pool_policy_digest
            && self.manifest_digest == other.manifest_digest
            && self.statement_digest == other.statement_digest
            && self.approvals_digest == other.approvals_digest
            && self.durable_availability_digest == other.durable_availability_digest
            && self.delta == other.delta
            && self.successor == other.successor)
    }
}

/// Verify one complete leg and derive its sole admissible successor token.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_private_settlement_leg_v1(
    manifest: &AtomicPrivateSettlementV1,
    payload: &PrivateSettlementLegPayloadV1,
    policy: &PrivateSettlementAuditPolicyV1,
    approvals: &[PrivateSettlementAuditApprovalV1],
    availability: &PrivateSettlementDurableAvailabilityV1,
    pool_state: &PrivateSettlementPoolStateV1,
    pool_governance: &PrivateSettlementPoolGovernanceProjectionV1,
    existing_nullifiers: &BTreeSet<PrivacyNullifierV1>,
    existing_commitments: &BTreeSet<PrivacyCommitmentV1>,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
) -> Result<ValidatedPrivateSettlementLegV1, PrivateSettlementStateErrorV1> {
    validate_private_settlement_leg_with_proof_verifier_v1(
        manifest,
        payload,
        policy,
        approvals,
        availability,
        pool_state,
        pool_governance,
        existing_nullifiers,
        existing_commitments,
        current_height,
        || {
            verify_atomic_private_settlement_v1(
                manifest,
                &payload.statement,
                canonical_genesis_hash,
                current_height,
                &payload.proof,
            )
            .map_err(|_| PrivateSettlementStateErrorV1::Proof)
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_private_settlement_leg_with_proof_verifier_v1<F>(
    manifest: &AtomicPrivateSettlementV1,
    payload: &PrivateSettlementLegPayloadV1,
    policy: &PrivateSettlementAuditPolicyV1,
    approvals: &[PrivateSettlementAuditApprovalV1],
    availability: &PrivateSettlementDurableAvailabilityV1,
    pool_state: &PrivateSettlementPoolStateV1,
    pool_governance: &PrivateSettlementPoolGovernanceProjectionV1,
    existing_nullifiers: &BTreeSet<PrivacyNullifierV1>,
    existing_commitments: &BTreeSet<PrivacyCommitmentV1>,
    current_height: u64,
    verify_proof: F,
) -> Result<ValidatedPrivateSettlementLegV1, PrivateSettlementStateErrorV1>
where
    F: FnOnce() -> Result<(), PrivateSettlementStateErrorV1>,
{
    pool_state.validate()?;
    pool_governance.validate_against_policy_at(policy, manifest.authority_context_height)?;
    payload
        .validate_against(manifest, policy)
        .map_err(|_| PrivateSettlementStateErrorV1::Payload)?;
    availability.validate_for(payload)?;
    validate_private_settlement_audit_approvals_v1(approvals, policy, payload, current_height)
        .map_err(|_| PrivateSettlementStateErrorV1::Approvals)?;
    verify_proof()?;

    if pool_governance.governance_digest == zero_hash_v1()
        || pool_governance.governance_digest != pool_state.restricted_pool_policy_digest
        || pool_governance.route != payload.statement.route
        || pool_governance.pool_id != payload.statement.pool_id
        || pool_governance.asset_binding_commitment != payload.statement.asset_binding_commitment
        || pool_governance
            .lifecycle
            .retirement_height
            .is_some_and(|retirement| manifest.expiry_height >= retirement)
        || payload.statement.route != pool_state.route
        || payload.statement.pool_id != pool_state.pool_id
        || payload.statement.old_epoch != pool_state.epoch
        || payload.statement.old_root != pool_state.root
    {
        return Err(PrivateSettlementStateErrorV1::ParentHeadMismatch);
    }
    if payload
        .statement
        .nullifiers
        .iter()
        .any(|nullifier| existing_nullifiers.contains(nullifier))
        || payload
            .statement
            .output_commitments
            .iter()
            .any(|commitment| existing_commitments.contains(commitment))
    {
        return Err(PrivateSettlementStateErrorV1::ReplayConflict);
    }

    let successor = pool_state.successor(&payload.statement.output_commitments)?;
    if payload.statement.new_root != successor.root
        || payload.statement.new_epoch != successor.epoch
        || payload.delta.new_root != successor.root
        || payload.delta.new_epoch != successor.epoch
    {
        return Err(PrivateSettlementStateErrorV1::CallerSelectedSuccessor);
    }
    let manifest_digest = manifest
        .manifest_digest()
        .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
    let statement_digest = payload
        .statement
        .digest()
        .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
    let approvals_digest = private_settlement_approvals_digest_v1(approvals)?;
    let mut verified = ValidatedPrivateSettlementLegV1 {
        route: pool_state.route,
        pool_id: pool_state.pool_id,
        restricted_pool_policy_digest: pool_governance.governance_digest,
        manifest_digest,
        statement_digest,
        approvals_digest,
        durable_availability_digest: availability.evidence_digest,
        verified_at_height: current_height,
        delta: payload.delta.clone(),
        successor,
        verification_digest: zero_hash_v1(),
    };
    verified.verification_digest =
        canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &verified.digest_material())
            .map_err(|_| PrivateSettlementStateErrorV1::CanonicalEncoding)?;
    verified.validate_digest()?;
    Ok(verified)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
/// Exercise every committee state gate except the independently tested STARK verifier.
///
/// This test-only seam keeps the large state-gate matrix fast and diagnostic;
/// the real proof-bearing owner bundle and committee path are covered by the
/// private-settlement proof and sidecar integration tests.
pub(crate) fn validate_private_settlement_leg_without_proof_for_test_v1(
    manifest: &AtomicPrivateSettlementV1,
    payload: &PrivateSettlementLegPayloadV1,
    policy: &PrivateSettlementAuditPolicyV1,
    approvals: &[PrivateSettlementAuditApprovalV1],
    availability: &PrivateSettlementDurableAvailabilityV1,
    pool_state: &PrivateSettlementPoolStateV1,
    pool_governance: &PrivateSettlementPoolGovernanceProjectionV1,
    existing_nullifiers: &BTreeSet<PrivacyNullifierV1>,
    existing_commitments: &BTreeSet<PrivacyCommitmentV1>,
    current_height: u64,
) -> Result<ValidatedPrivateSettlementLegV1, PrivateSettlementStateErrorV1> {
    validate_private_settlement_leg_with_proof_verifier_v1(
        manifest,
        payload,
        policy,
        approvals,
        availability,
        pool_state,
        pool_governance,
        existing_nullifiers,
        existing_commitments,
        current_height,
        || Ok(()),
    )
}

#[cfg(test)]
pub(crate) fn validated_private_settlement_leg_for_sidecar_test_v1(
    manifest: &AtomicPrivateSettlementV1,
    payload: &PrivateSettlementLegPayloadV1,
    approvals: &[PrivateSettlementAuditApprovalV1],
    durable_availability_digest: Hash,
    verified_at_height: u64,
) -> ValidatedPrivateSettlementLegV1 {
    let restricted_pool_policy_digest = Hash::new(b"private-settlement-test-pool-policy");
    let mut verified = ValidatedPrivateSettlementLegV1 {
        route: payload.statement.route,
        pool_id: payload.statement.pool_id,
        restricted_pool_policy_digest,
        manifest_digest: manifest.manifest_digest().expect("test manifest digest"),
        statement_digest: payload.statement.digest().expect("test statement digest"),
        approvals_digest: private_settlement_approvals_digest_v1(approvals)
            .expect("test approvals digest"),
        durable_availability_digest,
        verified_at_height,
        delta: payload.delta.clone(),
        successor: PrivateSettlementSuccessorFrontierV1 {
            epoch: payload.delta.new_epoch,
            root: payload.delta.new_root,
            tree_size: 1,
            leaf: Some([0xA7; 32]),
            ommers: Vec::new(),
        },
        verification_digest: zero_hash_v1(),
    };
    verified.verification_digest =
        canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &verified.digest_material())
            .expect("test verified-leg digest");
    verified.validate_digest().expect("test verified-leg token");
    verified
}

/// Redacted state-validation failure before Prepare or atomic application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum PrivateSettlementStateErrorV1 {
    /// Persisted pool governance or compact frontier is invalid.
    #[error("private-settlement pool state is invalid")]
    PoolInvariant,
    /// Restricted one-pool-to-one-asset governance is invalid or stale.
    #[error("private-settlement restricted pool governance is invalid")]
    PoolGovernance,
    /// Public payload objects or availability metadata are invalid.
    #[error("private-settlement leg payload is invalid")]
    Payload,
    /// Sidecar bytes are not proven durable and exact.
    #[error("private-settlement durable availability evidence is invalid")]
    Availability,
    /// Auditor approvals are insufficient, invalid, or mismatched.
    #[error("private-settlement auditor approvals are invalid")]
    Approvals,
    /// Settlement-only proof verification failed.
    #[error("private-settlement proof verification failed")]
    Proof,
    /// The supplied parent root or route differs from authoritative pool state.
    #[error("private-settlement parent pool head is stale")]
    ParentHeadMismatch,
    /// A nullifier or output commitment is already visible or reserved.
    #[error("private-settlement state item conflicts with an existing reservation")]
    ReplayConflict,
    /// The delta contains a root other than the validator-derived successor.
    #[error("private-settlement caller-selected successor is rejected")]
    CallerSelectedSuccessor,
    /// The compact successor frontier could not be derived.
    #[error("private-settlement successor frontier derivation failed")]
    SuccessorDerivation,
    /// Persisted verified-leg evidence was malformed or substituted.
    #[error("private-settlement verified-leg token is invalid")]
    VerifiedToken,
    /// Canonical Norito encoding unexpectedly failed.
    #[error("private-settlement canonical encoding failed")]
    CanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_settlement::sidecar_store::tests::sidecar_fixture;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};

    #[test]
    fn pool_state_and_governance_frames_keep_their_declared_owner_roots() {
        use crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1;

        let fixture = sidecar_fixture();
        let projection =
            PrivateSettlementPoolGovernanceProjectionV1::from_restricted(&fixture.pool_governance)
                .expect("governance projection");
        assert_private_settlement_frame_v1(
            &projection,
            "iroha_core::private_settlement::state::PrivateSettlementPoolGovernanceProjectionV1",
        );
        let pool = PrivateSettlementPoolStateV1::bootstrap(
            projection.route,
            projection.pool_id,
            projection.governance_digest,
            &[commitment(0x21)],
        )
        .expect("governed pool");
        assert_private_settlement_frame_v1(
            &pool,
            "iroha_core::private_settlement::state::PrivateSettlementPoolStateV1",
        );
    }

    #[test]
    fn verified_leg_digest_material_retains_its_encode_only_frame_root() {
        use norito::NoritoSchema as _;

        let pool = PrivateSettlementPoolStateV1::bootstrap(
            route(1),
            PrivacyPoolIdV1::new([0x11; 32]),
            Hash::new(b"restricted pool policy"),
            &[commitment(0x21)],
        )
        .expect("governed pool");
        let verified = verified_for(
            &pool,
            vec![commitment(0x41), commitment(0x42), commitment(0x43)],
        );
        let material = verified.digest_material();
        let expected =
            "iroha_core::private_settlement::state::PrivateSettlementVerifiedLegDigestMaterialV1";
        assert_eq!(
            PrivateSettlementVerifiedLegDigestMaterialV1::nominal_name(),
            expected
        );
        assert_eq!(
            PrivateSettlementVerifiedLegDigestMaterialV1::frame_name(),
            expected
        );
        let frame = norito::encode_canonical(&material).expect("encode-only digest frame");
        assert_eq!(
            frame[6..22],
            norito::schema::identity::frame_hash::<PrivateSettlementVerifiedLegDigestMaterialV1>()
        );
        assert_ne!(
            frame[6..22],
            norito::schema::identity::frame_hash::<PrivateSettlementPoolStateV1>()
        );
        let mut changed = material.clone();
        changed.verified_at_height += 1;
        assert_ne!(
            canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &material).expect("digest"),
            canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &changed).expect("changed digest"),
        );
        // This signing/digest carrier intentionally has no decoding or typed-frame reader.
    }

    fn route(byte: u8) -> PrivateSettlementRouteV1 {
        PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(u64::from(byte)),
            lane_id: LaneId::new(u32::from(byte)),
            lane_incarnation: Hash::new([byte]),
        }
    }

    fn commitment(byte: u8) -> PrivacyCommitmentV1 {
        PrivacyCommitmentV1::new([byte; 32])
    }

    fn nullifier(byte: u8) -> PrivacyNullifierV1 {
        PrivacyNullifierV1::new([byte; 32])
    }

    #[test]
    fn committee_governance_projection_binds_policy_without_restricted_asset_opening() {
        let fixture = sidecar_fixture();
        let projection =
            PrivateSettlementPoolGovernanceProjectionV1::from_restricted(&fixture.pool_governance)
                .expect("restricted governance projects");
        projection
            .validate_against_policy_at(
                &fixture.sidecar.policy,
                fixture.sidecar.manifest.authority_context_height,
            )
            .expect("public projection binds the governed auditor policy");

        let encoded = norito::encode_canonical(&projection).expect("projection encodes");
        let literal_asset = fixture.pool_governance.body.asset_definition_id.to_string();
        assert!(
            !encoded
                .windows(literal_asset.len())
                .any(|window| window == literal_asset.as_bytes()),
            "committee projection must not contain the literal asset identifier"
        );
        assert!(
            !encoded.windows(32).any(|window| {
                window == fixture.pool_governance.body.asset_binding_salt.as_slice()
            }),
            "committee projection must not contain the asset-binding salt"
        );

        let mut substituted_policy = fixture.sidecar.policy;
        substituted_policy.body.key_epoch += 1;
        substituted_policy.policy_digest = substituted_policy
            .body
            .computed_policy_digest()
            .expect("substituted policy hashes");
        assert_eq!(
            projection.validate_against_policy_at(
                &substituted_policy,
                fixture.sidecar.manifest.authority_context_height,
            ),
            Err(PrivateSettlementStateErrorV1::PoolGovernance)
        );
    }

    fn verified_for(
        state: &PrivateSettlementPoolStateV1,
        outputs: Vec<PrivacyCommitmentV1>,
    ) -> ValidatedPrivateSettlementLegV1 {
        let successor = state.successor(&outputs).expect("successor frontier");
        let mut verified = ValidatedPrivateSettlementLegV1 {
            route: state.route,
            pool_id: state.pool_id,
            restricted_pool_policy_digest: state.restricted_pool_policy_digest,
            manifest_digest: Hash::new(b"manifest"),
            statement_digest: Hash::new(b"statement"),
            approvals_digest: Hash::new(b"approvals"),
            durable_availability_digest: Hash::new(b"availability"),
            verified_at_height: 10,
            delta: PrivateSettlementDeltaV1 {
                version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                bundle_id: Hash::new(b"bundle"),
                leg_ordinal: 0,
                route: state.route,
                pool_id: state.pool_id,
                asset_binding_commitment: Hash::new(b"asset binding"),
                old_root: state.root,
                new_root: successor.root,
                old_epoch: state.epoch,
                new_epoch: successor.epoch,
                nullifiers: vec![nullifier(0x31), nullifier(0x32)],
                output_commitments: outputs,
                encrypted_outputs: Vec::new(),
                statement_digest: Hash::new(b"statement"),
                proof_digest: Hash::new(b"proof"),
                capsule_digest: Hash::new(b"capsule"),
                audit_policy_digest: Hash::new(b"audit policy"),
                audit_key_epoch: 1,
            },
            successor,
            verification_digest: zero_hash_v1(),
        };
        verified.verification_digest =
            canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &verified.digest_material())
                .expect("verified-leg digest");
        verified.validate_digest().expect("verified-leg token");
        verified
    }

    #[test]
    fn pool_bootstrap_and_verified_application_derive_the_only_successor() {
        let origin = PrivateSettlementPoolStateV1::bootstrap(
            route(1),
            PrivacyPoolIdV1::new([0x11; 32]),
            Hash::new(b"restricted pool policy"),
            &[commitment(0x21)],
        )
        .expect("pool bootstrap");
        let verified = verified_for(
            &origin,
            vec![commitment(0x41), commitment(0x42), commitment(0x43)],
        );

        let successor = origin.apply_verified(&verified).expect("atomic apply");
        assert_eq!(successor.epoch(), origin.epoch() + 1);
        assert_eq!(successor.root(), verified.delta().new_root);
        assert_ne!(successor.root(), origin.root());
        assert_eq!(successor.tree_size, origin.tree_size + 3);
        assert_eq!(
            successor.apply_verified(&verified),
            Err(PrivateSettlementStateErrorV1::ParentHeadMismatch),
            "a finalized leg cannot advance the pool twice"
        );
    }

    #[test]
    fn application_rejects_a_digest_valid_token_with_a_substituted_successor() {
        let origin = PrivateSettlementPoolStateV1::bootstrap(
            route(2),
            PrivacyPoolIdV1::new([0x12; 32]),
            Hash::new(b"restricted pool policy"),
            &[commitment(0x22)],
        )
        .expect("pool bootstrap");
        let mut verified = verified_for(
            &origin,
            vec![commitment(0x51), commitment(0x52), commitment(0x53)],
        );
        verified.delta.new_root = PrivacyRootV1::new([0x99; 32]);
        verified.verification_digest =
            canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &verified.digest_material())
                .expect("substituted token digest");
        verified
            .validate_digest()
            .expect("digest is internally consistent");

        assert_eq!(
            origin.apply_verified(&verified),
            Err(PrivateSettlementStateErrorV1::ParentHeadMismatch)
        );
    }

    #[test]
    fn verified_transition_identity_ignores_only_retry_height() {
        let origin = PrivateSettlementPoolStateV1::bootstrap(
            route(4),
            PrivacyPoolIdV1::new([0x14; 32]),
            Hash::new(b"restricted pool policy"),
            &[commitment(0x24)],
        )
        .expect("pool bootstrap");
        let first = verified_for(
            &origin,
            vec![commitment(0x61), commitment(0x62), commitment(0x63)],
        );
        let mut retry = first.clone();
        retry.verified_at_height += 1;
        retry.verification_digest =
            canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &retry.digest_material())
                .expect("retry token digest");
        assert!(
            first
                .same_transition_as(&retry)
                .expect("valid retry tokens compare")
        );

        retry.delta.nullifiers[0] = nullifier(0x64);
        retry.verification_digest =
            canonical_digest_v1(VERIFIED_LEG_DIGEST_DOMAIN_V1, &retry.digest_material())
                .expect("substituted token digest");
        assert!(
            !first
                .same_transition_as(&retry)
                .expect("digest-valid substitution compares")
        );
    }

    #[test]
    fn pool_bootstrap_rejects_ungoverned_or_zero_origins() {
        let pool_id = PrivacyPoolIdV1::new([0x13; 32]);
        assert_eq!(
            PrivateSettlementPoolStateV1::bootstrap(
                route(3),
                pool_id,
                zero_hash_v1(),
                &[commitment(0x23)],
            ),
            Err(PrivateSettlementStateErrorV1::PoolInvariant)
        );
        assert_eq!(
            PrivateSettlementPoolStateV1::bootstrap(
                route(3),
                pool_id,
                Hash::new(b"restricted pool policy"),
                &[PrivacyCommitmentV1::new([0; 32])],
            ),
            Err(PrivateSettlementStateErrorV1::PoolInvariant)
        );
    }
}
