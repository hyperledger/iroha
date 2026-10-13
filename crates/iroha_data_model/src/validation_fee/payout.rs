//! Independent Parliament conversion policy and immutable validator custody identity.
use super::*;

/// Immutable ownership and earning-lane coordinates shared by pricing and conversion.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::validation_fee::payout::ValidationFeeRewardCustodyV1")]
pub struct ValidationFeeRewardCustodyV1 {
    /// Non-signable treasury wrapper identity.
    pub contract_address: ContractAddress,
    /// Protected SBD fee treasury.
    pub treasury_account_id: AccountId,
    /// Exact SBD fee asset.
    pub ds_asset_id: AssetDefinitionId,
    /// Exact XOR reward asset.
    pub xor_asset_id: AssetDefinitionId,
    /// Protected funded validator reward custody.
    pub reward_pool_account_id: AccountId,
    /// Authenticated Nexus lane earning validator rewards.
    pub validator_lane_id: iroha_model_base::topology::LaneId,
}
impl ValidationFeeRewardCustodyV1 {
    /// Return a deterministic custody invariant violation, if any.
    pub fn invariant_error(&self) -> Option<&'static str> {
        if self.contract_address.subject_id() != self.treasury_account_id {
            return Some("reward custody treasury must be its non-signable contract subject");
        }
        if self.treasury_account_id == self.reward_pool_account_id
            || self.ds_asset_id == self.xor_asset_id
        {
            return Some("fee and reward custody/assets must remain distinct");
        }
        None
    }
}
impl ValidationFeeTreasuryPayoutBindingV1 {
    /// Extract immutable custody coordinates, excluding mutable conversion settings.
    pub fn custody(&self) -> ValidationFeeRewardCustodyV1 {
        ValidationFeeRewardCustodyV1 {
            contract_address: self.contract_address.clone(),
            treasury_account_id: self.treasury_account_id.clone(),
            ds_asset_id: self.ds_asset_id.clone(),
            xor_asset_id: self.xor_asset_id.clone(),
            reward_pool_account_id: self.reward_pool_account_id.clone(),
            validator_lane_id: self.validator_lane_id,
        }
    }
}
/// One independently enacted conversion policy; pricing does not copy this binding.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::validation_fee::payout::ValidationFeePayoutPolicyEntryV1"
)]
pub struct ValidationFeePayoutPolicyEntryV1 {
    /// Contiguous conversion revision, assigned at finalized enactment.
    pub revision: u64,
    /// Exact authorized Parliament proposal fingerprint.
    pub proposal_id: [u8; 32],
    /// Hash of the complete independent conversion binding.
    pub lifecycle_seal: [u8; 32],
    /// Current contract, pool, oracle, limits and claim settings.
    pub payout_binding: ValidationFeeTreasuryPayoutBindingV1,
    /// Complete independent finalized Parliament authority.
    pub parliament_authorization: ValidationFeeParliamentAuthorizationV1,
}
impl ValidationFeePayoutPolicyEntryV1 {
    /// Validate this exact binding and the Parliament proposal that authorized it.
    pub fn invariant_error(&self) -> Option<&'static str> {
        if self.revision == 0
            || self.payout_binding.invariant_error().is_some()
            || self.parliament_authorization.invariant_error().is_some()
        {
            return Some(
                "invalid independent conversion revision, binding or Parliament authority",
            );
        }
        if self.payout_binding.lifecycle_seal().ok() != Some(self.lifecycle_seal) {
            return Some("independent conversion lifecycle seal differs from its binding");
        }
        let fingerprint = super::validation_fee_payout_lifecycle_proposal_fingerprint(
            &self.parliament_authorization.proposal_operator,
            &self.payout_binding,
        );
        if self.proposal_id != fingerprint
            || self.parliament_authorization.proposal_fingerprint != fingerprint
        {
            return Some("independent conversion policy differs from its authorized proposal");
        }
        None
    }
}
/// Independently revised conversion history under the shared protected policy commitment.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::validation_fee::payout::ValidationFeePayoutPolicyRegistryV1"
)]
pub struct ValidationFeePayoutPolicyRegistryV1 {
    /// Contiguous retained conversion enactments in revision order.
    pub entries: Vec<ValidationFeePayoutPolicyEntryV1>,
}
impl ValidationFeePayoutPolicyRegistryV1 {
    /// Check authority, revision order and permanent custody identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty registry, invalid authority, noncontiguous
    /// revisions, changed custody, decreasing enactment heights, or duplicate proposals.
    pub(crate) fn validate(&self, retired_revision: u64) -> Result<(), String> {
        let first = self
            .entries
            .first()
            .ok_or("independent conversion policy is unconfigured")?;
        let custody = first.payout_binding.custody();
        let mut previous_height = 0;
        let mut proposals = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|index| retired_revision.checked_add(index))
                .and_then(|revision| revision.checked_add(1))
                .ok_or("independent conversion revision overflow")?;
            if entry.revision != expected
                || entry.invariant_error().is_some()
                || entry.payout_binding.custody() != custody
                || entry.parliament_authorization.enacted_at_height < previous_height
                || !proposals.insert(entry.proposal_id)
            {
                return Err(
                    "invalid independent conversion policy history or changed custody identity"
                        .into(),
                );
            }
            previous_height = entry.parliament_authorization.enacted_at_height;
        }
        Ok(())
    }
    /// Return the latest retained conversion enactment.
    pub fn head(&self) -> Option<&ValidationFeePayoutPolicyEntryV1> {
        self.entries.last()
    }
    /// Select the conversion revision finalized before this block, independently of retail months.
    pub fn effective_entry_at_height(
        &self,
        height: u64,
    ) -> Option<&ValidationFeePayoutPolicyEntryV1> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.parliament_authorization.enacted_at_height < height)
    }
}
