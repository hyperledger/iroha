//! Original parameter-version ownership of the canonical staking monetary policy.

use super::*;
use core::num::NonZeroU32;
use iroha_data_model::parameter::Parameter;
use iroha_primitives::numeric::Quantity;

fn policy() -> PublicLaneStakingPolicy {
    let account = AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap(),
    );
    PublicLaneStakingPolicy {
        min_validator_stake: "2000.25".parse().unwrap(),
        max_stake_shares_per_validator: NonZeroU32::new(7).unwrap(),
        max_pending_unbonds_per_share: NonZeroU32::new(3).unwrap(),
        unbonding_delay_ms: 43_210,
        max_slash_bps: 1_001,
        stake_asset_id: AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::parse_fully_qualified("app.acme").unwrap(),
            "stake".parse().unwrap(),
        ),
        stake_escrow_account_id: account.clone(),
        slash_sink_account_id: account,
    }
}

fn parameter(policy: PublicLaneStakingPolicy) -> Parameter {
    Parameter::Custom(policy.into_custom_parameter().unwrap())
}

#[test]
fn initialized_staking_owner_never_removes_or_replaces_with_absence() {
    let mut owner = StateParameters::default();
    assert!(owner.staking_policy().is_none());
    assert!(matches!(
        owner.require_staking_policy(),
        Err(PublicLaneStakingPolicyError::MissingParameter)
    ));
    let selected = policy();
    owner.set_parameter(parameter(selected.clone())).unwrap();
    let original = owner.clone();
    assert_eq!(owner.staking_policy(), Some(&selected));
    assert_eq!(owner.require_staking_policy().unwrap(), &selected);
    assert!(
        owner
            .remove_custom_parameter(&PublicLaneStakingPolicy::parameter_id())
            .is_err()
    );
    assert_eq!(owner, original);
    assert!(owner.replace(Parameters::default()).is_err());
    assert_eq!(owner, original);
    let unrelated = "unrelated_policy".parse().unwrap();
    assert!(owner.remove_custom_parameter(&unrelated).unwrap().is_none());
    assert_eq!(owner, original);
}

#[test]
fn staking_projection_restores_from_only_the_canonical_parameter_bytes() {
    use norito::codec::Encode as _;
    let selected = policy();
    let mut canonical = Parameters::default();
    canonical.set_parameter(parameter(selected.clone()));
    let owner = StateParameters::try_from(canonical.clone()).unwrap();
    assert_eq!(owner.encode(), canonical.encode());
    let json = norito::json::to_json(&owner).unwrap();
    assert_eq!(json, norito::json::to_json(&canonical).unwrap());
    let restored: StateParameters = norito::json::from_str(&json).unwrap();
    assert_eq!(restored, owner);
    assert_eq!(restored.require_staking_policy().unwrap(), &selected);
    let mut replacement = canonical;
    let mut next = selected;
    next.min_validator_stake = Quantity::from(3_000_u32);
    replacement.set_parameter(parameter(next.clone()));
    let mut updated = owner;
    updated.replace(replacement).unwrap();
    assert_eq!(updated.require_staking_policy().unwrap(), &next);
    assert_ne!(updated, restored);
}

#[test]
fn staking_original_decoder_refusal_and_invalid_update_leave_both_values_unchanged() {
    use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, classify_decode_attempt};
    let mut owner = StateParameters::default();
    owner.set_parameter(parameter(policy())).unwrap();
    let original = owner.clone();
    let mut next = policy();
    next.unbonding_delay_ms += 1;
    let next_parameter = parameter(next.clone());
    let zero = DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let error = zero
        .with(|| classify_decode_attempt(|| owner.set_parameter(next_parameter.clone())))
        .unwrap_err();
    assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(error.local_refusal().is_some());
    assert!(matches!(
        error.error(),
        norito::Error::ScopedDecodeResource(_)
    ));
    assert_eq!(owner, original);
    owner.set_parameter(next_parameter).unwrap();
    assert_eq!(owner.require_staking_policy().unwrap(), &next);
    let committed = owner.clone();
    let mut invalid = next;
    invalid.max_slash_bps = 10_001;
    let malformed = Parameter::Custom(CustomParameter::new(
        PublicLaneStakingPolicy::parameter_id(),
        Json::try_new(invalid).unwrap(),
    ));
    let error = classify_decode_attempt(|| owner.set_parameter(malformed)).unwrap_err();
    assert!(error.local_refusal().is_none());
    assert_eq!(owner, committed);
}

#[test]
fn staking_frozen_predecessor_survives_update_and_rollback_without_reader_decode() {
    let initial = policy();
    let mut next = initial.clone();
    next.unbonding_delay_ms += 1;
    let mut parameters = StateParameters::default();
    parameters
        .set_parameter(parameter(initial.clone()))
        .unwrap();
    let owner = mv::cell::Cell::new(parameters);
    let predecessor = owner.view();
    let original_pointer: *const PublicLaneStakingPolicy =
        predecessor.require_staking_policy().unwrap();
    let mut block = owner.block();
    block.set_parameter(parameter(next.clone())).unwrap();
    assert_eq!(predecessor.require_staking_policy().unwrap(), &initial);
    block.commit();
    let current = owner.view();
    norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
        assert_eq!(predecessor.require_staking_policy().unwrap(), &initial);
        assert_eq!(current.require_staking_policy().unwrap(), &next);
        assert!(core::ptr::eq(
            predecessor.require_staking_policy().unwrap(),
            original_pointer
        ));
    });
    let rollback = owner.block_and_revert();
    assert_eq!(rollback.require_staking_policy().unwrap(), &initial);
    rollback.commit();
    assert_eq!(owner.view().require_staking_policy().unwrap(), &initial);
}
