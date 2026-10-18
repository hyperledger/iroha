//! Sole portable validator for canonical public governance lineage.
use super::*;
use crate::nexus::{ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PrivateSettlementValidationError};
impl PrivateSettlementPoolGovernanceRevisionV1 {
    /// Validate the fixed public revision fields without granting execution authority.
    /// # Errors
    /// Reserved values or malformed activation/retirement bounds.
    pub fn validate_public_fields(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.audit_policy_digest == Hash::prehashed([0; Hash::LENGTH])
            || self.audit_key_epoch == 0
            || self.lifecycle.governance_revision == 0
            || self.lifecycle.activation_height == 0
            || self
                .lifecycle
                .retirement_height
                .is_some_and(|retirement| retirement <= self.lifecycle.activation_height)
            || self.governance_digest == Hash::prehashed([0; Hash::LENGTH])
        {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
        }
        Ok(())
    }
}
impl PrivateSettlementPoolGovernanceProjectionV1 {
    /// Validate or select canonical public governance lineage using the native rule.
    /// # Errors
    /// Malformed public fields, gaps or nonmonotonic revision/lifecycle bindings.
    pub fn validate_public_fields(&self) -> Result<(), PrivateSettlementValidationError> {
        if self.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
            || self.route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
            || self.route.lane_incarnation == Hash::prehashed([0; Hash::LENGTH])
            || self.pool_id.is_zero()
            || self.asset_binding_commitment == Hash::prehashed([0; Hash::LENGTH])
            || self.audit_policy_digest == Hash::prehashed([0; Hash::LENGTH])
            || self.audit_key_epoch == 0
            || self.lifecycle.governance_revision == 0
            || self.lifecycle.activation_height == 0
            || self
                .lifecycle
                .retirement_height
                .is_some_and(|retirement| retirement <= self.lifecycle.activation_height)
            || self.governance_digest == Hash::prehashed([0; Hash::LENGTH])
        {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
        }
        Ok(())
    }
    /// Validate or select canonical public governance lineage using the native rule.
    /// # Errors
    /// Malformed public fields, gaps or nonmonotonic revision/lifecycle bindings.
    pub fn validate_public_lineage(&self) -> Result<(), PrivateSettlementValidationError> {
        self.validate_public_fields()?;
        let expected_prior_count = usize::try_from(
            self.lifecycle
                .governance_revision
                .checked_sub(1)
                .ok_or(PrivateSettlementValidationError::InvalidPoolGovernanceBinding)?,
        )
        .map_err(|_| PrivateSettlementValidationError::InvalidPoolGovernanceBinding)?;
        if self.prior_revisions.len() != expected_prior_count {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
        }

        let mut previous: Option<PrivateSettlementPoolGovernanceRevisionV1> = None;
        for (index, revision) in self.prior_revisions.iter().copied().enumerate() {
            revision.validate_public_fields()?;
            let expected_revision = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(PrivateSettlementValidationError::InvalidPoolGovernanceBinding)?;
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
                return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
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
                return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
            }
        } else if self.lifecycle.governance_revision != 1 {
            return Err(PrivateSettlementValidationError::InvalidPoolGovernanceBinding);
        }
        Ok(())
    }
    /// Validate or select canonical public governance lineage using the native rule.
    /// # Errors
    /// Malformed public fields, gaps or nonmonotonic revision/lifecycle bindings.
    pub fn current_public_revision(&self) -> PrivateSettlementPoolGovernanceRevisionV1 {
        PrivateSettlementPoolGovernanceRevisionV1 {
            audit_policy_digest: self.audit_policy_digest,
            audit_key_epoch: self.audit_key_epoch,
            lifecycle: self.lifecycle,
            governance_digest: self.governance_digest,
        }
    }
    /// Validate or select canonical public governance lineage using the native rule.
    /// # Errors
    /// Malformed public fields, gaps or nonmonotonic revision/lifecycle bindings.
    pub fn effective_revision_at(
        &self,
        height: u64,
    ) -> Option<PrivateSettlementPoolGovernanceRevisionV1> {
        if self.validate_public_lineage().is_err() {
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
        let current = self.current_public_revision();
        current.lifecycle.is_active_at(height).then_some(current)
    }
}
