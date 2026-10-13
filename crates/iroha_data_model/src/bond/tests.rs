//! Bond terms validation, arithmetic and schedule tests.
use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::domain::DomainId;

pub(crate) fn account(seed: u8) -> AccountId {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("seeded key");
    AccountId::new(key_pair.public_key().clone())
}

pub(crate) fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("bonds", "universal").expect("domain"),
        name.parse().expect("asset name"),
    )
}

fn q(text: &str) -> Quantity {
    text.parse().expect("quantity literal")
}

const DAY: u64 = 86_400_000;
// 2026-01-15T00:00:00Z and 2029-01-15T00:00:00Z.
const ISSUE: u64 = 1_768_435_200_000;
const MATURITY: u64 = 1_863_129_600_000;

/// Annual 6.50 % bond, denomination 50, three coupons and par redemption.
pub(crate) fn annual_terms() -> BondTerms {
    let cashflows = fixed_rate_bullet_schedule(&BondScheduleRequest {
        denomination: q("50"),
        coupon_rate_bps: 650,
        coupon_frequency: 1,
        issue_date_ms: ISSUE,
        maturity_date_ms: MATURITY,
        redemption_price_bps: 10_000,
        record_offset_ms: DAY,
    })
    .expect("regular schedule");
    BondTerms {
        issuer: account(1),
        paying_agent: account(2),
        payment_asset: definition("eur"),
        denomination: q("50"),
        coupon_rate_bps: 650,
        coupon_frequency: 1,
        day_count: BondDayCount::ActActIcma,
        issue_date_ms: ISSUE,
        maturity_date_ms: MATURITY,
        redemption_price_bps: 10_000,
        call: Some(BondCallTerms {
            first_call_date_ms: ISSUE + 365 * DAY,
            price_bps: 10_100,
            notice_ms: 30 * DAY,
        }),
        cashflows,
        identifiers: BondIdentifiers {
            isin: Some("SI0031234567".to_owned()),
            cfi: Some("DBFTFB".to_owned()),
            issuer_lei: Some("5299000DI3047E2LIV03".to_owned()),
            bdt_version: "bdt-1.0".to_owned(),
            bdt_document_sha256: Some([7; 32]),
        },
        terms_sha256: [9; 32],
    }
}

fn rejected(terms: &BondTerms, fragment: &str) {
    let error = terms.validate().expect_err("terms must be rejected");
    assert!(
        matches!(error, BondError::InvalidTerms(_)),
        "unexpected error class: {error:?}"
    );
    assert!(error.to_string().contains(fragment), "{error}");
    assert!(error.to_string().starts_with("bond.invalid_terms: "));
}

#[test]
fn regular_schedule_is_valid_and_bullet_shaped() {
    let terms = annual_terms();
    terms.validate().expect("valid terms");
    let kinds: Vec<_> = terms.cashflows.iter().map(|cf| cf.kind).collect();
    assert_eq!(
        kinds,
        [
            BondCashflowKind::Coupon,
            BondCashflowKind::Coupon,
            BondCashflowKind::Coupon,
            BondCashflowKind::Redemption
        ]
    );
    assert_eq!(terms.cashflows[0].amount_per_unit, q("3.25"));
    assert_eq!(terms.cashflows[3].amount_per_unit, q("50"));
    // The final coupon shares the maturity payment date with the redemption.
    assert_eq!(terms.cashflows[2].payment_date_ms, MATURITY);
    assert_eq!(terms.cashflows[3].payment_date_ms, MATURITY);
    assert_eq!(terms.cashflows[0].payment_date_ms, ISSUE + 365 * DAY);
    assert_eq!(terms.cashflows[0].record_date_ms, ISSUE + 364 * DAY);
}

#[test]
fn coupon_and_redemption_amounts_are_exact() {
    assert_eq!(regular_coupon_amount(&q("50"), 650, 1).unwrap(), q("3.25"));
    assert_eq!(regular_coupon_amount(&q("50"), 650, 2).unwrap(), q("1.625"));
    assert_eq!(
        regular_coupon_amount(&q("1000"), 500, 4).unwrap(),
        q("12.5")
    );
    assert!(regular_coupon_amount(&q("50"), 650, 0).is_err());
    // 50 x 6.5 % / 12 = 0.2708333... is not a terminating decimal.
    assert!(regular_coupon_amount(&q("50"), 650, 12).is_err());
    assert_eq!(redemption_amount(&q("50"), 10_000).unwrap(), q("50"));
    assert_eq!(redemption_amount(&q("50"), 10_100).unwrap(), q("50.5"));
}

#[test]
fn holder_payments_round_down_to_the_payment_scale() {
    let two = NumericSpec::fractional(2);
    assert_eq!(
        holder_payment(&q("3"), &q("1.625"), two).unwrap(),
        q("4.87")
    );
    assert_eq!(
        holder_payment(&q("3"), &q("1.625"), NumericSpec::unconstrained()).unwrap(),
        q("4.875")
    );
    let snapshot = BTreeMap::from([(account(10), q("3")), (account(11), q("1"))]);
    assert_eq!(
        snapshot_amount_due(&snapshot, &q("1.625"), two).unwrap(),
        q("6.49")
    );
}

#[test]
fn vault_account_is_deterministic_and_bond_specific() {
    let a = bond_vault_account_id(&definition("bond_a"));
    assert_eq!(a, bond_vault_account_id(&definition("bond_a")));
    assert_ne!(a, bond_vault_account_id(&definition("bond_b")));
}

#[test]
fn registration_rules_reject_each_violation() {
    let mut terms = annual_terms();
    terms.cashflows.clear();
    rejected(&terms, "1..=400");

    let mut terms = annual_terms();
    terms.cashflows.swap(0, 1);
    rejected(&terms, "contiguous");

    let mut terms = annual_terms();
    terms.cashflows[1].payment_date_ms = terms.cashflows[0].payment_date_ms;
    terms.cashflows[1].record_date_ms = terms.cashflows[0].record_date_ms;
    rejected(&terms, "strictly increase");

    let mut terms = annual_terms();
    terms.cashflows[0].record_date_ms = terms.cashflows[0].payment_date_ms + 1;
    rejected(&terms, "record date follows");

    let mut terms = annual_terms();
    terms.cashflows[0].record_date_ms = ISSUE - 1;
    rejected(&terms, "outside [issue, maturity]");

    let mut terms = annual_terms();
    terms.cashflows[3].payment_date_ms = MATURITY - DAY;
    terms.cashflows[3].record_date_ms = MATURITY - 2 * DAY;
    rejected(&terms, "must equal maturity");

    let mut terms = annual_terms();
    terms.cashflows[1].kind = BondCashflowKind::Redemption;
    terms.cashflows[1].amount_per_unit = q("50");
    rejected(&terms, "must be last");

    let mut terms = annual_terms();
    terms.cashflows[3].kind = BondCashflowKind::Coupon;
    terms.cashflows[3].amount_per_unit = q("3.25");
    rejected(&terms, "must end with its redemption");

    let mut terms = annual_terms();
    terms.cashflows[1].amount_per_unit = q("3.26");
    rejected(&terms, "coupon 1 amount per unit must be 3.25");

    let mut terms = annual_terms();
    terms.cashflows[3].amount_per_unit = q("49");
    rejected(&terms, "redemption amount per unit must be 50");

    let mut terms = annual_terms();
    terms.coupon_frequency = 3;
    rejected(&terms, "frequency must be 0, 1, 2, 4 or 12");

    let mut terms = annual_terms();
    terms.coupon_rate_bps = 0;
    rejected(&terms, "zero coupon rate requires frequency 0");

    let mut terms = annual_terms();
    terms.coupon_frequency = 12;
    rejected(&terms, "not an exact decimal");

    let mut terms = annual_terms();
    terms.denomination = Quantity::zero();
    rejected(&terms, "denomination must be positive");

    let mut terms = annual_terms();
    terms.redemption_price_bps = 0;
    rejected(&terms, "redemption price must be positive");

    let mut terms = annual_terms();
    terms.maturity_date_ms = ISSUE;
    rejected(&terms, "issue date must precede maturity");

    let mut terms = annual_terms();
    terms.call.as_mut().unwrap().first_call_date_ms = MATURITY;
    rejected(&terms, "first call date");

    let mut terms = annual_terms();
    terms.call.as_mut().unwrap().price_bps = 0;
    rejected(&terms, "call price must be positive");

    let mut terms = annual_terms();
    terms.cashflows[1].record_date_ms = terms.cashflows[0].record_date_ms - 1;
    terms.cashflows[0].record_date_ms = terms.cashflows[0].payment_date_ms;
    rejected(&terms, "record dates must not decrease");
}

#[test]
fn identifier_bounds_are_enforced() {
    let cases: [(fn(&mut BondIdentifiers), &str); 6] = [
        (|ids| ids.isin = Some("SI00312345678".to_owned()), "isin"),
        (|ids| ids.cfi = Some("DBFTFBX".to_owned()), "cfi"),
        (|ids| ids.issuer_lei = Some("5".repeat(21)), "issuer_lei"),
        (|ids| ids.bdt_version = "v".repeat(33), "bdt_version"),
        (|ids| ids.bdt_version = String::new(), "bdt_version"),
        (|ids| ids.isin = Some("SI 0031".to_owned()), "isin"),
    ];
    for (mutate, label) in cases {
        let mut terms = annual_terms();
        mutate(&mut terms.identifiers);
        rejected(&terms, label);
    }
}

#[test]
fn zero_coupon_bond_has_only_its_redemption() {
    let cashflows = fixed_rate_bullet_schedule(&BondScheduleRequest {
        denomination: q("100"),
        coupon_rate_bps: 0,
        coupon_frequency: 0,
        issue_date_ms: ISSUE,
        maturity_date_ms: MATURITY,
        redemption_price_bps: 10_000,
        record_offset_ms: DAY,
    })
    .expect("zero-coupon schedule");
    assert_eq!(cashflows.len(), 1);
    let mut terms = annual_terms();
    terms.coupon_rate_bps = 0;
    terms.coupon_frequency = 0;
    terms.denomination = q("100");
    terms.call = None;
    terms.cashflows = cashflows;
    terms.validate().expect("zero-coupon terms");
    let mut with_coupon = annual_terms();
    with_coupon.coupon_rate_bps = 0;
    with_coupon.coupon_frequency = 0;
    rejected(&with_coupon, "zero-coupon bonds cannot schedule coupons");
}

#[test]
fn schedule_builder_handles_semiannual_end_of_month_and_irregular_periods() {
    // 2026-08-31 to 2028-08-31, semi-annual: end-of-month clamps to 28/29 February.
    let issue = 1_788_134_400_000;
    let maturity = 1_851_292_800_000;
    let cashflows = fixed_rate_bullet_schedule(&BondScheduleRequest {
        denomination: q("1000"),
        coupon_rate_bps: 500,
        coupon_frequency: 2,
        issue_date_ms: issue,
        maturity_date_ms: maturity,
        redemption_price_bps: 10_000,
        record_offset_ms: 0,
    })
    .expect("semi-annual schedule");
    let payments: Vec<_> = cashflows.iter().map(|cf| cf.payment_date_ms).collect();
    assert_eq!(
        payments,
        [
            1_803_772_800_000, // 2027-02-28
            1_819_670_400_000, // 2027-08-31
            1_835_395_200_000, // 2028-02-29
            maturity,
            maturity
        ]
    );
    assert!(
        cashflows[..4]
            .iter()
            .all(|cf| cf.amount_per_unit == q("25"))
    );
    let irregular = fixed_rate_bullet_schedule(&BondScheduleRequest {
        denomination: q("1000"),
        coupon_rate_bps: 500,
        coupon_frequency: 2,
        issue_date_ms: issue + DAY,
        maturity_date_ms: maturity,
        redemption_price_bps: 10_000,
        record_offset_ms: 0,
    });
    assert!(irregular.is_err());
}

#[test]
fn record_json_and_codec_roundtrip() {
    let terms = annual_terms();
    let mut record = BondRecord::registered(definition("bond"), terms, q("1000"));
    let cashflow = record.cashflow_mut(0).unwrap();
    cashflow.status = BondCashflowStatus::Recorded;
    cashflow.snapshot.insert(account(10), q("3"));
    cashflow.claimed.insert(account(10));
    cashflow.evidence_sha256 = Some([3; 32]);
    let json = norito::json::to_json(&record).expect("record JSON");
    assert!(json.contains(&"09".repeat(32)), "{json}");
    let decoded: BondRecord = norito::json::from_str(&json).expect("record from JSON");
    assert_eq!(decoded, record);
    let bytes = record.encode();
    let decoded = BondRecord::decode(&mut bytes.as_slice()).expect("record decode");
    assert_eq!(decoded, record);
    assert!(decoded.cashflow(0).unwrap().all_claimed());
    assert!(
        !decoded
            .cashflow(1)
            .unwrap()
            .snapshot
            .contains_key(&account(10))
    );
}
