//! Bounded staking plan observations. These reads are not finality or execution proofs.

use super::{PublicLaneMonetaryPlanV1, PublicLaneRewardClaimPlanV1};
use crate::{
    NetworkId,
    asset::{AssetDefinitionId, AssetId},
    prelude::AccountId,
};
use iroha_crypto::Hash;
use iroha_model_base::{peer::PeerId, topology::LaneId};
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Maximum exact source and destination assets in one preparation response.
pub const PUBLIC_LANE_PREPARATION_BALANCE_LIMIT: usize = 2;
/// Maximum canonical request body accepted by the preparation endpoint.
pub const PUBLIC_LANE_PREPARATION_REQUEST_MAX_BYTES: usize = 64 * 1024;
/// Maximum canonical response body accepted by operator clients.
pub const PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES: usize = 256 * 1024;
/// Prepare an initial self-bond for the next unfrozen election.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::nexus::staking_preparation::PublicLanePrepareRegistrationV1"
)]
#[norito(deny_unknown_fields)]
pub struct PublicLanePrepareRegistrationV1 {
    /// Canonical validator and self-stake account.
    pub validator: AccountId,
    /// Exact consensus peer identity.
    pub peer_id: PeerId,
    /// Explicit amount selected by the operator.
    pub amount: Quantity,
    /// Include fresh-peer key activation lead for `RegisterPublicLaneCandidate`.
    pub candidate: bool,
}

/// Prepare additional self stake or delegation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking_preparation::PublicLanePrepareBondV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLanePrepareBondV1 {
    /// Registered validator.
    pub validator: AccountId,
    /// Account depositing the explicit quantity.
    pub staker: AccountId,
    /// Explicit amount selected by the operator.
    pub amount: Quantity,
}

/// Prepare withdrawal of one exact retained request.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking_preparation::PublicLanePrepareUnbondV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLanePrepareUnbondV1 {
    /// Registered validator.
    pub validator: AccountId,
    /// Owner of the retained stake position.
    pub staker: AccountId,
    /// Exact retained unbond request identifier.
    pub request_id: Hash,
}

/// Prepare the current exact positive funded reward entitlement.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking_preparation::PublicLanePrepareClaimV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLanePrepareClaimV1 {
    /// Canonical reward recipient.
    pub recipient: AccountId,
}

/// Exact operator intent; preparation never chooses an amount or recipient.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::nexus::staking_preparation::PublicLanePreparationOperationV1"
)]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
pub enum PublicLanePreparationOperationV1 {
    /// Initial self-bond.
    Registration(PublicLanePrepareRegistrationV1),
    /// Additional self stake or delegation.
    Bond(PublicLanePrepareBondV1),
    /// Withdrawal of an existing request.
    FinalizeUnbond(PublicLanePrepareUnbondV1),
    /// Bounded reward processing and payout.
    ClaimRewards(PublicLanePrepareClaimV1),
}

/// Bounded read-only plan request; no transaction is signed or submitted.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::nexus::staking_preparation::PublicLanePreparationRequestV1"
)]
#[norito(deny_unknown_fields)]
pub struct PublicLanePreparationRequestV1 {
    /// Exact public lane.
    pub lane_id: LaneId,
    /// Expiry offset from the observed height, from one through one committed epoch.
    pub valid_for_blocks: u64,
    /// Exact operator-selected intent.
    pub operation: PublicLanePreparationOperationV1,
}

/// Canonical file content consumed by the corresponding signing command.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking_preparation::PublicLanePreparedPlanV1")]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
pub enum PublicLanePreparedPlanV1 {
    /// One exact movement and operation-specific preconditions.
    Monetary(PublicLaneMonetaryPlanV1),
    /// Exact bounded record commitments, cursor, accruals and payouts.
    Claim(PublicLaneRewardClaimPlanV1),
}

/// Observed balance and independently reserved obligations for one exact asset.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::nexus::staking_preparation::PublicLanePreparationBalanceV1"
)]
#[norito(deny_unknown_fields)]
pub struct PublicLanePreparationBalanceV1 {
    /// Exact asset definition, scope and owner.
    pub asset: AssetId,
    /// Observed asset balance; zero if absent.
    pub balance: Quantity,
    /// Bonded and pending-unbond custody reserve.
    pub stake_reserved: Quantity,
    /// Sum of unpaid public-lane and validation-fee reward reserves for this exact asset.
    pub rewards_reserved: Quantity,
}

/// One coherent server observation; block identity is not a cryptographic state proof.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::staking_preparation::PublicLanePreparationV1")]
#[norito(deny_unknown_fields)]
pub struct PublicLanePreparationV1 {
    /// Exact request echoed for response binding.
    pub request: PublicLanePreparationRequestV1,
    /// Genesis-derived observed network.
    pub network_id: NetworkId,
    /// Committed observation height.
    pub observed_height: u64,
    /// Committed block hash reported by the server, not independently verified here.
    pub observed_block_hash: Hash,
    /// Authenticated ledger time within the server state snapshot.
    pub observed_ledger_time_ms: u64,
    /// The next block after observation; election eligibility may change if inclusion is delayed.
    pub assumed_execution_height: u64,
    /// Immutable genesis-pinned XOR definition; never inferred from an alias.
    pub xor_asset_definition_id: AssetDefinitionId,
    /// Exact canonical signing input; execution recomputes all monetary preconditions.
    pub plan: PublicLanePreparedPlanV1,
    /// Strictly ordered unique exact source and destination assets, at most two.
    pub balances: Vec<PublicLanePreparationBalanceV1>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};

    #[test]
    fn preparation_request_and_response_roundtrip_with_required_nullable_fields() {
        let recipient = AccountId::new(
            KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 10,
            operation: PublicLanePreparationOperationV1::ClaimRewards(PublicLanePrepareClaimV1 {
                recipient: recipient.clone(),
            }),
        };
        let network_id =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"preparation")));
        let response = PublicLanePreparationV1 {
            request: request.clone(),
            network_id,
            observed_height: 1,
            observed_block_hash: Hash::new(b"block"),
            observed_ledger_time_ms: 0,
            assumed_execution_height: 2,
            xor_asset_definition_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
            plan: PublicLanePreparedPlanV1::Claim(PublicLaneRewardClaimPlanV1 {
                network_scope: super::super::PublicLaneMonetaryScopeV1::Network(network_id),
                valid_until_height: 11,
                fee_claim: super::super::PublicLaneFeeRewardClaimV1 {
                    lifecycle_seal: [7; 32],
                    beneficiary_id: recipient.clone(),
                    beneficiary_revision: 0,
                    source_asset: AssetId::new(
                        "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
                        recipient.clone(),
                    ),
                    destination_asset: AssetId::new(
                        "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
                        recipient.clone(),
                    ),
                    amount: Quantity::one(),
                    expected_claim_sequence: 0,
                },
            }),
            balances: vec![],
        };
        let wire = norito::encode_canonical(&response).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<PublicLanePreparationV1>(&wire).unwrap(),
            response
        );
        let json = norito::json::to_json(&request).unwrap();
        assert_eq!(
            norito::json::from_str::<PublicLanePreparationRequestV1>(&json).unwrap(),
            request
        );
        let recipient_field = format!(
            "\"recipient\":{}",
            norito::json::to_json(&recipient).expect("recipient JSON")
        );
        let absent = json.replace(&recipient_field, "");
        assert_ne!(absent, json, "remove the required recipient field");
        assert!(norito::json::from_str::<PublicLanePreparationRequestV1>(&absent).is_err());
        let unknown = json.replacen('{', "{\"unexpected\":true,", 1);
        assert!(norito::json::from_str::<PublicLanePreparationRequestV1>(&unknown).is_err());
    }
}
