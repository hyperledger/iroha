//! Bounded authenticated policy-history suffix and first-release wire regressions.
use super::parliament_tests::{authorization, entry, payout_binding, policy, proposal_operator};
use super::*;

fn revised_payout(revision: u64) -> ValidationFeePayoutPolicyEntryV1 {
    let mut binding = payout_binding();
    binding.min_reward_claim_xor_minor = revision;
    let proposal_id =
        validation_fee_payout_lifecycle_proposal_fingerprint(&proposal_operator(), &binding);
    ValidationFeePayoutPolicyEntryV1 {
        revision,
        proposal_id,
        lifecycle_seal: binding.lifecycle_seal().unwrap(),
        payout_binding: binding,
        parliament_authorization: authorization(proposal_id, 1),
    }
}

fn source_registry() -> ValidationFeePolicyRegistryV1 {
    let first = entry(policy(1, None), 1);
    let second = entry(policy(2, Some(first.policy_hash)), 2);
    ValidationFeePolicyRegistryV1 {
        history: None,
        registered_policies: vec![first, second],
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![revised_payout(1), revised_payout(2)],
        },
    }
}

#[test]
fn settled_registry_appends_beyond_former_lifetime_byte_limit_with_bounded_hot_suffix() {
    let mut registry = ValidationFeePolicyRegistryV1 {
        history: None,
        registered_policies: Vec::new(),
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![revised_payout(1)],
        },
    };
    let mut admitted = norito::to_bytes(&registry.payout_policies.entries[0])
        .unwrap()
        .len();
    let mut revision = 1;
    while admitted <= 2 * MAX_VALIDATION_FEE_REGISTRY_BYTES {
        revision += 1;
        let next = revised_payout(revision);
        admitted += norito::to_bytes(&next).unwrap().len();
        registry.payout_policies.entries.push(next);
        registry.validate().unwrap();
        let height = 100_000 + revision;
        let compacted = registry
            .compacted_suffix(height, u64::MAX, height)
            .unwrap()
            .unwrap();
        compacted
            .validate_history_source(height, &registry)
            .unwrap();
        assert_eq!(compacted.payout_policies.entries.len(), 1);
        assert!(
            norito::to_bytes(&compacted).unwrap().len() < MAX_VALIDATION_FEE_REGISTRY_BYTES / 8
        );
        assert_eq!(
            compacted.history.as_ref().unwrap().retired_payout_revision,
            revision - 1
        );
        registry = compacted;
    }
    assert!(revision > 2);
    assert!(admitted > 2 * MAX_VALIDATION_FEE_REGISTRY_BYTES);
}

#[test]
fn old_wallet_frontier_keeps_earning_policy_until_settlement_and_preserves_service_predecessor() {
    let source = source_registry();
    let first_month = source.registered_policies[0].policy.effective_from_ms;
    let next_month = source.registered_policies[1].policy.effective_from_ms;
    let payout_height = source.payout_policies.entries[1]
        .parliament_authorization
        .enacted_at_height;
    assert!(
        source
            .compacted_suffix(payout_height, first_month, payout_height)
            .unwrap()
            .is_none()
    );
    let old_wallet = source
        .compacted_suffix(100_000, first_month, 100_000)
        .unwrap()
        .unwrap();
    assert_eq!(old_wallet.registered_policies.len(), 2);
    assert_eq!(old_wallet.payout_policies.entries.len(), 1);
    old_wallet
        .validate_history_source(100_000, &source)
        .unwrap();
    let settled = old_wallet
        .compacted_suffix(100_001, next_month, 100_001)
        .unwrap()
        .unwrap();
    assert_eq!(
        old_wallet.genesis_policy_hash(),
        Some(source.registered_policies[0].policy_hash)
    );
    assert_eq!(
        settled.genesis_policy_hash(),
        old_wallet.genesis_policy_hash()
    );
    assert_eq!(settled.registered_policies.len(), 1);
    assert_eq!(settled.registered_policies[0].policy.policy_version, 2);
    settled
        .validate_history_source(100_001, &old_wallet)
        .unwrap();
    assert_eq!(
        settled.history.as_ref().unwrap().retired_policy_hash,
        Some(source.registered_policies[0].policy_hash)
    );
}

#[test]
fn checkpoint_rejects_changed_source_arbitrary_floors_gaps_and_rewritten_overlap() {
    let source = source_registry();
    let next = source
        .compacted_suffix(100_000, u64::MAX, 100_000)
        .unwrap()
        .unwrap();
    next.validate_history_source(100_000, &source).unwrap();
    assert!(next.validate_history_source(99_999, &source).is_err());
    let mut cases = Vec::new();
    let mut changed = next.clone();
    changed.history.as_mut().unwrap().genesis_policy_hash = Some([8; 32]);
    cases.push(changed);
    let mut changed = next.clone();
    changed.history.as_mut().unwrap().genesis_policy_hash = None;
    cases.push(changed);
    let mut changed = next.clone();
    changed.history.as_mut().unwrap().registry_hash[0] ^= 1;
    cases.push(changed);
    let mut changed = next.clone();
    changed.history.as_mut().unwrap().retired_policy_hash = Some([7; 32]);
    cases.push(changed);
    let mut changed = next.clone();
    changed.history.as_mut().unwrap().retired_policy_version += 1;
    cases.push(changed);
    let mut changed = next.clone();
    changed.history.as_mut().unwrap().retired_payout_revision += 1;
    cases.push(changed);
    let mut changed = next.clone();
    changed.payout_policies.entries[0] = revised_payout(3);
    cases.push(changed);
    let mut changed = next.clone();
    changed.registered_policies.clear();
    cases.push(changed);
    for changed in cases {
        assert!(changed.validate_history_source(100_000, &source).is_err());
    }
    let mut substituted = source.clone();
    substituted.payout_policies.entries[1] = revised_payout(3);
    assert!(next.validate_history_source(100_000, &substituted).is_err());
    assert!(next.compacted_suffix(100_000, u64::MAX, 100_000).is_err());
}

#[test]
fn registry_checkpoint_roundtrips_canonical_norito_json_and_requires_new_field() {
    let source = source_registry();
    let next = source
        .compacted_suffix(100_000, u64::MAX, 100_000)
        .unwrap()
        .unwrap();
    for registry in [source, next] {
        let bytes = norito::encode_canonical(&registry).unwrap();
        let decoded: ValidationFeePolicyRegistryV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, registry);
        let json = norito::json::to_json(&registry).unwrap();
        let decoded: ValidationFeePolicyRegistryV1 = norito::json::from_str(&json).unwrap();
        assert_eq!(decoded, registry);
        let mut value: norito::json::Value = norito::json::from_str(&json).unwrap();
        if registry.history.is_some() {
            let mut missing_anchor = value.clone();
            missing_anchor
                .as_object_mut()
                .unwrap()
                .get_mut("history")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("genesis_policy_hash");
            assert!(
                norito::json::from_value::<ValidationFeePolicyRegistryV1>(missing_anchor).is_err()
            );
        }
        value.as_object_mut().unwrap().remove("history");
        assert!(norito::json::from_value::<ValidationFeePolicyRegistryV1>(value).is_err());
    }
}

#[test]
fn payout_only_checkpoint_accepts_first_pricing_and_preserves_genesis_after_retirement() {
    let mut source = source_registry();
    source.registered_policies.clear();
    let mut next = source
        .compacted_suffix(100_000, u64::MAX, 100_000)
        .unwrap()
        .unwrap();
    assert_eq!(source.genesis_policy_hash(), None);
    assert_eq!(next.genesis_policy_hash(), None);
    let commitment = ValidationFeePolicySnapshotCommitmentV1::from_registry(
        100_000,
        1_793_451_600_000,
        Some(&next),
    );
    assert!(matches!(
        commitment.status,
        ValidationFeePolicySnapshotStatusV1::Available(_)
    ));
    let first = entry(policy(1, None), 1);
    next.registered_policies.push(first.clone());
    next.validate_history_source(100_000, &source).unwrap();
    assert_eq!(next.genesis_policy_hash(), Some(first.policy_hash));
    let second = entry(policy(2, Some(first.policy_hash)), 2);
    next.registered_policies.push(second);
    let compacted = next
        .compacted_suffix(100_001, u64::MAX, 100_001)
        .unwrap()
        .unwrap();
    compacted.validate_history_source(100_001, &next).unwrap();
    assert_eq!(compacted.genesis_policy_hash(), Some(first.policy_hash));
    assert_eq!(
        compacted.history.as_ref().unwrap().genesis_policy_hash,
        Some(first.policy_hash)
    );
    let mut changed = next;
    changed.history.as_mut().unwrap().genesis_policy_hash = Some([9; 32]);
    assert!(changed.validate().is_err());
}
