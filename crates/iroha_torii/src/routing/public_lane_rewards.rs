//! Pending automatic rewards projected from authenticated funded XOR entitlements.

use super::*;
use iroha_data_model::nexus::PublicLanePendingReward;

pub(super) fn collect_pending_public_lane_rewards(
    world: &impl iroha_core::state::WorldReadOnly,
    height: u64,
    lane_id: LaneId,
    account_id: &AccountId,
    asset_filter: Option<&AssetId>,
) -> Result<Vec<PublicLanePendingReward>, Error> {
    let pending =
        iroha_core::validation_fee_rewards::pending_fee_reward(world, height, account_id, lane_id)
            .map_err(|error| match error {
                iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
                    Error::AppServiceUnavailable {
                        code: "reward_projection_resources_unavailable",
                        message:
                            "Local reward projection did not complete; retry the original request"
                                .into(),
                    }
                }
                iroha_core::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                    conversion_error(error.to_string())
                }
            })?;
    Ok(pending
        .into_iter()
        .filter(|reward| asset_filter.is_none_or(|asset| asset == &reward.asset))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_json_exposes_exact_automatic_entitlement_and_dust() {
        let recipient = AccountId::new(
            checked_routing_fixture_keypair(
                0x77,
                Algorithm::Ed25519,
                "automatic pending reward fixture",
            )
            .public_key()
            .clone(),
        );
        let asset = AssetId::new(
            test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400bb"),
            recipient.clone(),
        );
        let (_, value) = pending_reward_to_json(PublicLanePendingReward {
            lane_id: LaneId::SINGLE,
            account: recipient.clone(),
            asset: asset.clone(),
            amount: "0.000000001".parse().unwrap(),
            beneficiary_id: recipient.clone(),
            beneficiary_revision: 3,
            expected_claim_sequence: 7,
            lifecycle_seal: [0xA5; 32],
            claimable: false,
        });
        assert_eq!(value["asset"], Value::from(asset.to_string()));
        assert_eq!(value["amount"], Value::from("0.000000001"));
        assert_eq!(value["beneficiary_id"], Value::from(recipient.to_string()));
        assert_eq!(value["beneficiary_revision"], Value::from(3_u64));
        assert_eq!(value["expected_claim_sequence"], Value::from(7_u64));
        assert_eq!(value["lifecycle_seal"], Value::from("a5".repeat(32)));
        assert_eq!(value["claimable"], Value::from(false));
        assert!(
            !value
                .as_object()
                .unwrap()
                .contains_key("processed_through_epoch")
        );
    }
}
