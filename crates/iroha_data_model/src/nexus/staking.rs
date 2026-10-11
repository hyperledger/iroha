//! Public lane staking records and reward metadata.
use crate::{account::AccountId, asset::AssetId};
use iroha_crypto::Hash;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::BTreeMap;
/// Signature scope for exact staking effects, including network-independent genesis templates.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetaryScopeV1")]
#[norito(tag = "scope", content = "value", deny_unknown_fields)]
pub enum PublicLaneMonetaryScopeV1 {
    /// Only the authenticated genesis bootstrap may execute this template.
    Genesis,
    /// Ordinary execution on exactly this genesis-derived network.
    Network(crate::NetworkId),
}

/// Exact eligibility boundary for a new validator registration.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetaryRegistrationV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneMonetaryRegistrationV1 {
    /// Inclusive first height of the new validator tenure.
    pub activation_height: u64,
}

/// Exact validator tenure and peer binding authorized for additional stake.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetaryBondV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneMonetaryBondV1 {
    /// Inclusive first height of the validator tenure.
    pub activation_height: u64,
    /// Peer binding observed by the staker.
    pub peer_id: PeerId,
}

/// Exact retained withdrawal request authorized for release.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetaryUnbondV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneMonetaryUnbondV1 {
    /// Inclusive first height of the validator tenure.
    pub activation_height: u64,
    /// Domain-separated commitment to the exact pending withdrawal record.
    pub request_hash: Hash,
}

/// Exact validator tenure and eligible exposure authorized for a privileged slash.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetarySlashV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneMonetarySlashV1 {
    /// Inclusive first height of the validator tenure.
    pub activation_height: u64,
    /// Complete eligible custody exposure before this slash.
    pub slashable_exposure: Quantity,
}

/// Exact state identity to which a monetary staking instruction is restricted.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetaryPreconditionV1")]
#[norito(tag = "operation", content = "value", deny_unknown_fields)]
pub enum PublicLaneMonetaryPreconditionV1 {
    /// A new registration at this exact eligibility boundary.
    Registration(PublicLaneMonetaryRegistrationV1),
    /// Additional stake for the currently bound validator tenure.
    Bond(PublicLaneMonetaryBondV1),
    /// One retained withdrawal request, including its amount and liability window.
    Unbond(PublicLaneMonetaryUnbondV1),
    /// One privileged slash against an exact tenure and slashable exposure.
    Slash(PublicLaneMonetarySlashV1),
}

/// Signed exact transfer and operation-specific custody change for a staking action.
///
/// Registration and bonding reserve `amount` at `destination_asset`; withdrawal
/// and slashing release `amount` at `source_asset`. The instruction determines
/// this direction, so the caller cannot select additional reserve effects.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneMonetaryPlanV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneMonetaryPlanV1 {
    /// Genesis-derived network identity covered by the submitting signature.
    pub network_scope: PublicLaneMonetaryScopeV1,
    /// Last block height at which this plan may execute, inclusive.
    pub valid_until_height: u64,
    /// Exact source asset, including its dataspace scope.
    pub source_asset: AssetId,
    /// Exact destination asset, including its dataspace scope.
    pub destination_asset: AssetId,
    /// Exact quantity moved and added to or removed from protocol custody.
    pub amount: Quantity,
    /// Exact operation and retained state being authorized.
    pub precondition: PublicLaneMonetaryPreconditionV1,
}
impl PublicLaneMonetaryPlanV1 {
    /// Build the exact prefunded registration template authenticated by genesis.
    ///
    /// Both assets and the amount remain explicit. Core accepts this scope only
    /// while applying initial genesis, where the first eligibility height is one.
    #[must_use]
    pub fn genesis_registration(
        source_asset: AssetId,
        destination_asset: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            network_scope: PublicLaneMonetaryScopeV1::Genesis,
            valid_until_height: 1,
            source_asset,
            destination_asset,
            amount,
            precondition: PublicLaneMonetaryPreconditionV1::Registration(
                PublicLaneMonetaryRegistrationV1 {
                    activation_height: 1,
                },
            ),
        }
    }

    /// Check state-independent invariants before collecting signed monetary effects.
    #[must_use]
    pub fn has_canonical_shape(&self) -> bool {
        self.valid_until_height > 0
            && !self.amount.is_zero()
            && self.source_asset.definition() == self.destination_asset.definition()
            && self.source_asset.scope() == self.destination_asset.scope()
            && match &self.precondition {
                PublicLaneMonetaryPreconditionV1::Registration(value) => {
                    value.activation_height > 0
                }
                PublicLaneMonetaryPreconditionV1::Bond(value) => value.activation_height > 0,
                PublicLaneMonetaryPreconditionV1::Unbond(value) => value.activation_height > 0,
                PublicLaneMonetaryPreconditionV1::Slash(value) => {
                    value.activation_height > 0 && value.slashable_exposure >= self.amount
                }
            }
    }
}

/// Exact funded validation-fee reward payment authorized by the current beneficiary.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneFeeRewardClaimV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneFeeRewardClaimV1 {
    /// Commitment to the complete currently enacted conversion lifecycle.
    pub lifecycle_seal: [u8; 32],
    /// Original earning account retained through authenticated account recovery.
    pub beneficiary_id: AccountId,
    /// Exact current beneficiary ownership revision.
    pub beneficiary_revision: u64,
    /// Global network-XOR custody asset held by the reward pool.
    pub source_asset: AssetId,
    /// Exact global network-XOR asset of the signing recipient.
    pub destination_asset: AssetId,
    /// Complete positive reserved credit observed before signing.
    pub amount: Quantity,
    /// Exact next receipt sequence observed before signing.
    pub expected_claim_sequence: u64,
}

impl PublicLaneFeeRewardClaimV1 {
    /// Check a positive payment between exact global assets of the same definition.
    #[must_use]
    pub fn has_canonical_shape(&self, recipient: &AccountId) -> bool {
        self.lifecycle_seal != [0; 32]
            && !self.amount.is_zero()
            && self.source_asset
                == AssetId::new(
                    self.source_asset.definition().clone(),
                    self.source_asset.account().clone(),
                )
            && self.destination_asset
                == AssetId::new(self.source_asset.definition().clone(), recipient.clone())
    }
}

/// Bounded signed reward processing and payment plan.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneRewardClaimPlanV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneRewardClaimPlanV1 {
    /// Exact network or authenticated genesis template scope.
    pub network_scope: PublicLaneMonetaryScopeV1,
    /// Last block height at which this plan may execute, inclusive.
    pub valid_until_height: u64,
    /// Exact positive funded reward payment; absence and no-op claims are rejected.
    pub fee_claim: PublicLaneFeeRewardClaimV1,
}
impl PublicLaneRewardClaimPlanV1 {
    /// Check the exact funded global-XOR payment and nonzero expiry.
    #[must_use]
    pub fn has_canonical_shape(&self, recipient: &AccountId) -> bool {
        self.valid_until_height > 0 && self.fee_claim.has_canonical_shape(recipient)
    }
}

/// Commit to every field of a retained withdrawal request in a distinct protocol domain.
///
/// # Errors
/// Returns an error if the canonical Norito encoding cannot be produced.
pub fn public_lane_unbonding_commitment(
    request: &PublicLaneUnbonding,
) -> Result<Hash, norito::Error> {
    let mut bytes = b"iroha.staking.pending_unbond.v1\0".to_vec();
    bytes.extend_from_slice(&norito::encode_canonical(request)?);
    Ok(Hash::new(bytes))
}

/// Snapshot of a validator registered for a public Nexus lane.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneValidatorRecord")]
pub struct PublicLaneValidatorRecord {
    /// Lane that the validator services.
    pub lane_id: LaneId,
    /// Account that owns validator authority for the lane.
    pub validator: AccountId,
    /// Peer identity that participates in consensus and receives routed traffic.
    pub peer_id: PeerId,
    /// Canonical self-stake account; must equal `validator`.
    pub stake_account: AccountId,
    /// Total bonded stake attributed to the validator (self + nominators).
    pub total_stake: Quantity,
    /// Portion of stake supplied by the validator.
    pub self_stake: Quantity,
    /// Descriptive metadata such as endpoints and jurisdiction flags.
    /// Commission is zero; metadata cannot change reward allocation.
    pub metadata: Metadata,
    /// Current lifecycle state of the validator.
    pub status: PublicLaneValidatorStatus,
    /// Inclusive first height at which this validator may be elected.
    ///
    /// Pending validators carry this scheduled boundary before their lifecycle
    /// status is promoted, so a finalized boundary snapshot can project them
    /// without depending on block-local execution order.
    pub activation_height: u64,
    /// Requested exclusive end for selection into a new, unfrozen committee.
    ///
    /// This does not revoke a current or already frozen seat. Certified retention
    /// may extend voting and slashing obligations beyond the requested height.
    pub election_exit_height: Option<u64>,
    /// Authenticated exclusive first height no longer covered by this binding.
    ///
    /// Retained custody records preserve this boundary after exit or slash so
    /// evidence can be matched to the exact historical tenure.
    pub deactivation_height: Option<u64>,
}
/// Lifecycle state for a validator entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneValidatorStatus")]
pub enum PublicLaneValidatorStatus {
    /// Validator is scheduled for election eligibility at the exact payload height.
    PendingActivation(u64),
    /// Validator participates in consensus for the target lane.
    Active,
    /// Exit requested at the payload release time; certified replacement is still required.
    Exiting(u64),
    /// Validator exit processing is complete.
    ///
    /// Historical authority and stake custody remain governed by the exact
    /// retained `[activation_height, deactivation_height)` tenure and their
    /// independent release boundaries.
    Exited,
    /// Validator was slashed; slash ids help correlate telemetry/audits.
    Slashed(Hash),
}
/// Per-staker bonded stake record.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneStakeShare")]
pub struct PublicLaneStakeShare {
    /// Lane serviced by the validator.
    pub lane_id: LaneId,
    /// Validator the stake is delegated to.
    pub validator: AccountId,
    /// Account that provided the stake.
    pub staker: AccountId,
    /// Amount of stake currently bonded.
    pub bonded: Quantity,
    /// Pending unbonding requests keyed by client-supplied identifier.
    pub pending_unbonds: BTreeMap<Hash, PublicLaneUnbonding>,
    /// Optional metadata for dashboards or wallet hints.
    pub metadata: Metadata,
}
/// Pending unbond request tracked on-ledger.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLaneUnbonding")]
pub struct PublicLaneUnbonding {
    /// Deterministic identifier supplied by the submitter.
    pub request_id: Hash,
    /// Amount scheduled for release.
    pub amount: Quantity,
    /// Unix timestamp (ms) when the withdrawal can be finalised.
    pub release_at_ms: u64,
    /// Inclusive final offence height underwritten by this retained custody.
    pub slashable_through_height: u64,
    /// Earliest block whose post-finality transaction phase may release the funds.
    ///
    /// Consensus penalties run before ordinary transactions at this height, so
    /// evidence for `slashable_through_height` admitted at the end of the
    /// configured horizon still has its complete slashing-delay window.
    pub liability_release_height: u64,
}
/// Pending reward summary for an account and lane.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::staking::PublicLanePendingReward")]
pub struct PublicLanePendingReward {
    /// Lane identifier.
    pub lane_id: LaneId,
    /// Account that will receive the payout.
    pub account: AccountId,
    /// Exact funded XOR custody source asset.
    pub asset: AssetId,
    /// Unpaid funded XOR, including dust below the payout threshold.
    pub amount: Quantity,
    /// Immutable reward identity retained through beneficiary recovery.
    pub beneficiary_id: AccountId,
    /// Authenticated recovery revision of the current owner.
    pub beneficiary_revision: u64,
    /// Exact next claim receipt sequence.
    pub expected_claim_sequence: u64,
    /// Commitment to the governed funding and custody lifecycle.
    pub lifecycle_seal: [u8; 32],
    /// Whether this amount reaches the governed minimum claim threshold.
    pub claimable: bool,
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_primitives::numeric::Numeric;
    #[derive(Encode)]
    struct ForgedPublicLaneStakeShare {
        lane_id: LaneId,
        validator: AccountId,
        staker: AccountId,
        bonded: Numeric,
        pending_unbonds: BTreeMap<Hash, PublicLaneUnbonding>,
        metadata: Metadata,
    }
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked durable staking fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    #[test]
    fn negative_numeric_payloads_cannot_decode_as_durable_staking_quantities() {
        let stake = ForgedPublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: account(0x41),
            staker: account(0x42),
            bonded: Numeric::new(-1_i32, 0),
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        };
        let encoded = stake.encode();
        assert!(
            PublicLaneStakeShare::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as durable bonded stake"
        );
    }
}

#[cfg(test)]
mod captured_staking_schema_tests;

#[cfg(test)]
mod monetary_codec_tests;
