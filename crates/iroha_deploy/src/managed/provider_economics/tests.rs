//! Arithmetic-only claim controls. These inputs are not authenticated World or finality fixtures.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    sorafs::{
        capacity::ProviderId,
        pin_registry::StorageClass,
        reserve::{
            RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveDuration, ReserveLifecycleStage,
            ReservePolicyV1, ReserveTier,
        },
    },
};

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
fn claims() -> (
    ReserveAuthorityPolicyV1,
    ReserveProviderAccountV1,
    PricingScheduleRecord,
) {
    let policy = ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .unwrap(),
        custody_account: account(1),
        treasury_account: account(2),
        operations_authority: account(3),
        decision_authority: account(4),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: "1000".parse().unwrap(),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    };
    let partition = ReserveProviderAccountV1 {
        terms: ReserveProviderTermsV1 {
            provider_id: ProviderId::new([8; 32]),
            provider_account: account(3),
            tier: ReserveTier::TierA,
            storage_class: StorageClass::Hot,
            duration: ReserveDuration::Monthly,
            capacity_gib: 1,
        },
        policy_digest: policy.digest().unwrap(),
        revision: 1,
        reserve_balance: XorQuantity::zero(),
        debt_principal: XorQuantity::zero(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::zero(),
        lifecycle_stage: ReserveLifecycleStage::Warning,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    };
    (policy, partition, PricingScheduleRecord::launch_default())
}
fn amount(value: &str) -> XorQuantity {
    value.parse().unwrap()
}

#[test]
fn underwriting_and_exact_pricing_derive_distinct_principal_and_nominal_credit() {
    let (policy, partition, pricing) = claims();
    let amounts = calculate(
        &partition.terms,
        &amount("0.75"),
        &policy,
        &partition,
        None,
        &pricing,
        1_000_000,
    )
    .unwrap();
    assert_eq!(
        amounts.price_bond,
        pricing
            .required_collateral(StorageClass::Hot, 1, 1000, 1000)
            .unwrap()
    );
    assert_eq!(amounts.reserve_requirement, amount("24"));
    assert_eq!(amounts.target_reserve, amount("24"));
    assert_eq!(amounts.top_up, amount("24"));
    assert_eq!(amounts.available_credit, amounts.expected_settlement);
    assert_eq!(
        amounts.expected_settlement,
        pricing
            .expected_settlement_storage_charge(StorageClass::Hot, 1)
            .unwrap()
    );
    assert!(amounts.price_bond < *amounts.target_reserve.as_quantity());
}

#[test]
fn exact_admitted_stake_debt_and_slash_bound_target_without_borrowing_or_epoch_renewal() {
    let (policy, mut partition, pricing) = claims();
    partition.reserve_balance = amount("32");
    partition.debt_principal = amount("3");
    partition.credit_cap = amount("3");
    let mut credit = ProviderCreditRecord::new(
        partition.terms.provider_id,
        Quantity::zero(),
        Quantity::from(27_u32),
        Quantity::zero(),
        Quantity::zero(),
        1,
        1,
        iroha_model_base::metadata::Metadata::default(),
    );
    credit.slashed = Quantity::from(2_u32);
    let amounts = calculate(
        &partition.terms,
        &amount("30"),
        &policy,
        &partition,
        Some(&credit),
        &pricing,
        40 * 86400 * 1000,
    )
    .unwrap();
    assert_eq!(amounts.onboarding_epoch, 1);
    assert_eq!(
        amounts.price_bond,
        pricing
            .required_collateral(StorageClass::Hot, 1, 1, 40 * 86400)
            .unwrap()
    );
    assert_eq!(amounts.target_reserve, amount("35"));
    assert_eq!(amounts.top_up, amount("3"));
    partition.reserve_balance = amount("35");
    assert!(
        calculate(
            &partition.terms,
            &amount("30"),
            &policy,
            &partition,
            Some(&credit),
            &pricing,
            40 * 86400 * 1000
        )
        .unwrap()
        .top_up
        .is_zero()
    );
    partition.reserve_balance = amount("40");
    assert!(
        calculate(
            &partition.terms,
            &amount("30"),
            &policy,
            &partition,
            Some(&credit),
            &pricing,
            40 * 86400 * 1000
        )
        .unwrap()
        .top_up
        .is_zero()
    );
}

#[test]
fn quantity_overflow_invalid_schedule_time_and_provider_refuse_before_derivation() {
    let (policy, mut partition, mut pricing) = claims();
    let stake = amount("1");
    assert!(
        calculate(
            &partition.terms,
            &stake,
            &policy,
            &partition,
            None,
            &pricing,
            999
        )
        .is_err()
    );
    pricing.currency_code = "usd".into();
    assert!(
        calculate(
            &partition.terms,
            &stake,
            &policy,
            &partition,
            None,
            &pricing,
            1000
        )
        .is_err()
    );
    pricing = PricingScheduleRecord::launch_default();
    let mut credit = ProviderCreditRecord::new(
        ProviderId::new([9; 32]),
        Quantity::zero(),
        Quantity::zero(),
        Quantity::zero(),
        Quantity::zero(),
        2,
        2,
        iroha_model_base::metadata::Metadata::default(),
    );
    assert!(
        calculate(
            &partition.terms,
            &stake,
            &policy,
            &partition,
            Some(&credit),
            &pricing,
            1000
        )
        .is_err()
    );
    credit.provider_id = partition.terms.provider_id;
    assert!(
        calculate(
            &partition.terms,
            &stake,
            &policy,
            &partition,
            Some(&credit),
            &pricing,
            1000
        )
        .is_err()
    );
    // Each operand fits the signed 512-bit mantissa, while their sum does not.
    // Parsing an out-of-range operand would fail before the economic owner is exercised.
    let large = amount(&"4".repeat(154));
    assert!(large.checked_add(&large).is_err());
    partition.reserve_balance = large.clone();
    partition.debt_principal = large.clone();
    partition.credit_cap = large.clone();
    assert!(
        calculate(
            &partition.terms,
            &large,
            &policy,
            &partition,
            None,
            &pricing,
            1000
        )
        .is_err()
    );
}

#[test]
fn economic_graph_bounds_precede_clones() {
    let (policy, partition, mut pricing) = claims();
    pricing.notes = Some("x".repeat(MAX_PRICING_BYTES));
    assert!(
        calculate(
            &partition.terms,
            &amount("1"),
            &policy,
            &partition,
            None,
            &pricing,
            1000
        )
        .unwrap_err()
        .to_string()
        .contains("byte bound")
    );
}
