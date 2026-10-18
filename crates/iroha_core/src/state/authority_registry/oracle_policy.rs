//! Exact deterministic oracle economics, governance and binding policy.
//!
//! These are the State-owned fields in `execution_policy_digest_v1` that can
//! change oracle state transitions. No service endpoint, worker or filesystem
//! setting is retained in this projection.

use iroha_config::parameters::actual::Oracle;
use iroha_data_model::{account::AccountId, asset::id::AssetDefinitionId};
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:oracle-economics:v1")]
struct OracleEconomicsV1 {
    reward_asset: AssetDefinitionId,
    reward_pool: AccountId,
    reward_amount: Quantity,
    slash_asset: AssetDefinitionId,
    slash_receiver: AccountId,
    slash_outlier_amount: Quantity,
    slash_error_amount: Quantity,
    slash_no_show_amount: Quantity,
    dispute_bond_asset: AssetDefinitionId,
    dispute_bond_amount: Quantity,
    dispute_reward_amount: Quantity,
    frivolous_slash_amount: Quantity,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:oracle-vote-thresholds:v1")]
struct OracleVoteThresholdsV1 {
    low: u64,
    medium: u64,
    high: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:oracle-governance:v1")]
struct OracleGovernanceV1 {
    intake_sla_blocks: u64,
    rules_sla_blocks: u64,
    cop_sla_blocks: u64,
    technical_sla_blocks: u64,
    policy_jury_sla_blocks: u64,
    enact_sla_blocks: u64,
    intake_min_votes: u64,
    rules_min_votes: u64,
    cop_min_votes: OracleVoteThresholdsV1,
    technical_min_votes: u64,
    policy_jury_min_votes: OracleVoteThresholdsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:oracle-twitter-binding:v1")]
struct OracleTwitterBindingV1 {
    feed_id: Name,
    pepper_id: String,
    max_ttl_ms: u64,
    min_ttl_ms: u64,
    min_update_spacing_ms: u64,
}

/// Canonical first-release oracle state-transition policy.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:oracle:v1")]
pub(super) struct OraclePolicyV1 {
    history_depth: u64,
    economics: OracleEconomicsV1,
    governance: OracleGovernanceV1,
    twitter_binding: OracleTwitterBindingV1,
}

fn count(value: usize) -> u64 {
    u64::try_from(value).expect("Iroha oracle policy requires a pointer width of at most 64 bits")
}

impl OraclePolicyV1 {
    /// Borrow and project every oracle field used by deterministic execution.
    pub(super) fn from_actual(config: &Oracle) -> Self {
        let economics = &config.economics;
        let governance = &config.governance;
        let twitter = &config.twitter_binding;
        Self {
            history_depth: count(config.history_depth.get()),
            economics: OracleEconomicsV1 {
                reward_asset: economics.reward_asset.clone(),
                reward_pool: economics.reward_pool.clone(),
                reward_amount: economics.reward_amount.clone(),
                slash_asset: economics.slash_asset.clone(),
                slash_receiver: economics.slash_receiver.clone(),
                slash_outlier_amount: economics.slash_outlier_amount.clone(),
                slash_error_amount: economics.slash_error_amount.clone(),
                slash_no_show_amount: economics.slash_no_show_amount.clone(),
                dispute_bond_asset: economics.dispute_bond_asset.clone(),
                dispute_bond_amount: economics.dispute_bond_amount.clone(),
                dispute_reward_amount: economics.dispute_reward_amount.clone(),
                frivolous_slash_amount: economics.frivolous_slash_amount.clone(),
            },
            governance: OracleGovernanceV1 {
                intake_sla_blocks: governance.intake_sla_blocks,
                rules_sla_blocks: governance.rules_sla_blocks,
                cop_sla_blocks: governance.cop_sla_blocks,
                technical_sla_blocks: governance.technical_sla_blocks,
                policy_jury_sla_blocks: governance.policy_jury_sla_blocks,
                enact_sla_blocks: governance.enact_sla_blocks,
                intake_min_votes: count(governance.intake_min_votes.get()),
                rules_min_votes: count(governance.rules_min_votes.get()),
                cop_min_votes: OracleVoteThresholdsV1 {
                    low: count(governance.cop_min_votes.low.get()),
                    medium: count(governance.cop_min_votes.medium.get()),
                    high: count(governance.cop_min_votes.high.get()),
                },
                technical_min_votes: count(governance.technical_min_votes.get()),
                policy_jury_min_votes: OracleVoteThresholdsV1 {
                    low: count(governance.policy_jury_min_votes.low.get()),
                    medium: count(governance.policy_jury_min_votes.medium.get()),
                    high: count(governance.policy_jury_min_votes.high.get()),
                },
            },
            twitter_binding: OracleTwitterBindingV1 {
                feed_id: twitter.feed_id.clone(),
                pepper_id: twitter.pepper_id.clone(),
                max_ttl_ms: twitter.max_ttl_ms,
                min_ttl_ms: twitter.min_ttl_ms,
                min_update_spacing_ms: twitter.min_update_spacing_ms,
            },
        }
    }
}

/// Stream the complete original oracle policy without cloning its variable leaves.
pub(super) fn borrowed(config: &Oracle) -> impl norito::SerializePayload + '_ {
    use super::policy_borrowed::{Ref, record};

    let economics = &config.economics;
    let governance = &config.governance;
    let twitter = &config.twitter_binding;
    record!(
        count(config.history_depth.get()),
        record!(
            Ref(&economics.reward_asset),
            Ref(&economics.reward_pool),
            Ref(&economics.reward_amount),
            Ref(&economics.slash_asset),
            Ref(&economics.slash_receiver),
            Ref(&economics.slash_outlier_amount),
            Ref(&economics.slash_error_amount),
            Ref(&economics.slash_no_show_amount),
            Ref(&economics.dispute_bond_asset),
            Ref(&economics.dispute_bond_amount),
            Ref(&economics.dispute_reward_amount),
            Ref(&economics.frivolous_slash_amount)
        ),
        record!(
            governance.intake_sla_blocks,
            governance.rules_sla_blocks,
            governance.cop_sla_blocks,
            governance.technical_sla_blocks,
            governance.policy_jury_sla_blocks,
            governance.enact_sla_blocks,
            count(governance.intake_min_votes.get()),
            count(governance.rules_min_votes.get()),
            record!(
                count(governance.cop_min_votes.low.get()),
                count(governance.cop_min_votes.medium.get()),
                count(governance.cop_min_votes.high.get())
            ),
            count(governance.technical_min_votes.get()),
            record!(
                count(governance.policy_jury_min_votes.low.get()),
                count(governance.policy_jury_min_votes.medium.get()),
                count(governance.policy_jury_min_votes.high.get())
            )
        ),
        record!(
            Ref(&twitter.feed_id),
            Ref(&twitter.pepper_id),
            twitter.max_ttl_ms,
            twitter.min_ttl_ms,
            twitter.min_update_spacing_ms
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use std::num::NonZeroUsize;

    fn policy() -> Oracle {
        crate::state::default_oracle()
    }

    fn frame(config: &Oracle) -> Vec<u8> {
        super::super::policy_borrowed::assert_same_payload(
            &borrowed(config),
            &OraclePolicyV1::from_actual(config),
        );
        norito::encode_canonical(&OraclePolicyV1::from_actual(config)).unwrap()
    }

    fn other_quantity(current: &Quantity) -> Quantity {
        let one = Quantity::from(1_u64);
        if current == &one {
            Quantity::from(2_u64)
        } else {
            one
        }
    }

    fn other_asset(current: &AssetDefinitionId) -> AssetDefinitionId {
        let mut bytes = [0_u8; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        bytes[0] = 1;
        let candidate = AssetDefinitionId::from_uuid_bytes(bytes).unwrap();
        if current == &candidate {
            bytes[0] = 2;
            AssetDefinitionId::from_uuid_bytes(bytes).unwrap()
        } else {
            candidate
        }
    }

    fn other_account(current: &AccountId) -> AccountId {
        let candidate = AccountId::new(
            KeyPair::from_seed(b"oracle-policy-other-account".to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        if current == &candidate {
            AccountId::new(
                KeyPair::from_seed(b"oracle-policy-alternative".to_vec(), Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        } else {
            candidate
        }
    }

    fn other_feed(current: &Name) -> Name {
        let candidate: Name = "altered".parse().unwrap();
        if current == &candidate {
            "alternative".parse().unwrap()
        } else {
            candidate
        }
    }

    fn increment(value: NonZeroUsize) -> NonZeroUsize {
        NonZeroUsize::new(value.get().checked_add(1).unwrap()).unwrap()
    }

    #[test]
    fn oracle_policy_roundtrips_with_explicit_v1_identity() {
        let projected = OraclePolicyV1::from_actual(&policy());
        assert_eq!(OraclePolicyV1::nominal_name(), "iroha:state:oracle:v1");
        let encoded = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<OraclePolicyV1>(&encoded).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), encoded);
    }

    fn assert_mutations_change_projection(mutations: &[(&str, fn(&mut Oracle))]) {
        let baseline = policy();
        let expected = frame(&baseline);
        for &(name, mutate) in mutations {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(frame(&changed), expected, "{name}");
        }
    }

    #[test]
    fn every_oracle_economics_field_changes_the_projection() {
        let mutations: &[(&str, fn(&mut Oracle))] = &[
            ("history depth", |c| {
                c.history_depth = increment(c.history_depth)
            }),
            ("reward asset", |c| {
                c.economics.reward_asset = other_asset(&c.economics.reward_asset)
            }),
            ("reward pool", |c| {
                c.economics.reward_pool = other_account(&c.economics.reward_pool)
            }),
            ("reward amount", |c| {
                c.economics.reward_amount = other_quantity(&c.economics.reward_amount)
            }),
            ("slash asset", |c| {
                c.economics.slash_asset = other_asset(&c.economics.slash_asset)
            }),
            ("slash receiver", |c| {
                c.economics.slash_receiver = other_account(&c.economics.slash_receiver)
            }),
            ("slash outlier", |c| {
                c.economics.slash_outlier_amount = other_quantity(&c.economics.slash_outlier_amount)
            }),
            ("slash error", |c| {
                c.economics.slash_error_amount = other_quantity(&c.economics.slash_error_amount)
            }),
            ("slash no show", |c| {
                c.economics.slash_no_show_amount = other_quantity(&c.economics.slash_no_show_amount)
            }),
            ("dispute bond asset", |c| {
                c.economics.dispute_bond_asset = other_asset(&c.economics.dispute_bond_asset)
            }),
            ("dispute bond amount", |c| {
                c.economics.dispute_bond_amount = other_quantity(&c.economics.dispute_bond_amount)
            }),
            ("dispute reward", |c| {
                c.economics.dispute_reward_amount =
                    other_quantity(&c.economics.dispute_reward_amount)
            }),
            ("frivolous slash", |c| {
                c.economics.frivolous_slash_amount =
                    other_quantity(&c.economics.frivolous_slash_amount)
            }),
        ];
        assert_eq!(mutations.len(), 13);
        assert_mutations_change_projection(mutations);
    }

    #[test]
    fn every_oracle_governance_field_changes_the_projection() {
        let mutations: &[(&str, fn(&mut Oracle))] = &[
            ("intake SLA", |c| c.governance.intake_sla_blocks += 1),
            ("rules SLA", |c| c.governance.rules_sla_blocks += 1),
            ("COP SLA", |c| c.governance.cop_sla_blocks += 1),
            ("technical SLA", |c| c.governance.technical_sla_blocks += 1),
            ("policy jury SLA", |c| {
                c.governance.policy_jury_sla_blocks += 1
            }),
            ("enact SLA", |c| c.governance.enact_sla_blocks += 1),
            ("intake votes", |c| {
                c.governance.intake_min_votes = increment(c.governance.intake_min_votes)
            }),
            ("rules votes", |c| {
                c.governance.rules_min_votes = increment(c.governance.rules_min_votes)
            }),
            ("COP low votes", |c| {
                c.governance.cop_min_votes.low = increment(c.governance.cop_min_votes.low)
            }),
            ("COP medium votes", |c| {
                c.governance.cop_min_votes.medium = increment(c.governance.cop_min_votes.medium)
            }),
            ("COP high votes", |c| {
                c.governance.cop_min_votes.high = increment(c.governance.cop_min_votes.high)
            }),
            ("technical votes", |c| {
                c.governance.technical_min_votes = increment(c.governance.technical_min_votes)
            }),
            ("jury low votes", |c| {
                c.governance.policy_jury_min_votes.low =
                    increment(c.governance.policy_jury_min_votes.low)
            }),
            ("jury medium votes", |c| {
                c.governance.policy_jury_min_votes.medium =
                    increment(c.governance.policy_jury_min_votes.medium)
            }),
            ("jury high votes", |c| {
                c.governance.policy_jury_min_votes.high =
                    increment(c.governance.policy_jury_min_votes.high)
            }),
        ];
        assert_eq!(mutations.len(), 15);
        assert_mutations_change_projection(mutations);
    }

    #[test]
    fn every_oracle_twitter_binding_field_changes_the_projection() {
        let mutations: &[(&str, fn(&mut Oracle))] = &[
            ("Twitter feed", |c| {
                c.twitter_binding.feed_id = other_feed(&c.twitter_binding.feed_id)
            }),
            ("Twitter pepper", |c| c.twitter_binding.pepper_id.push('x')),
            ("Twitter max TTL", |c| c.twitter_binding.max_ttl_ms += 1),
            ("Twitter min TTL", |c| c.twitter_binding.min_ttl_ms += 1),
            ("Twitter spacing", |c| {
                c.twitter_binding.min_update_spacing_ms += 1
            }),
        ];
        assert_eq!(mutations.len(), 5);
        assert_mutations_change_projection(mutations);
    }
}
