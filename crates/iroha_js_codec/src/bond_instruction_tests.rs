//! Strict JSON coverage and the shared JavaScript vectors of the boxed bond kernel.
//!
//! `javascript/iroha_js/test/fixtures/bond-v1-codec.json` is produced by this module from
//! the native data model: instruction envelopes with their exact archive and frame bytes,
//! vault accounts, `fixed_rate_bullet_schedule` outputs, `BondTerms::validate` verdicts and
//! rounded holder payments. The JavaScript SDK tests replay the same vectors.

use base64::Engine as _;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetId,
    bond::{
        BondCallTerms, BondCashflowKind, BondDayCount, BondIdentifiers, BondScheduleRequest,
        BondTerms, bond_vault_account_id, fixed_rate_bullet_schedule, holder_payment,
    },
    isi::{
        bond::{
            CallBond, ClaimBondCashflow, CloseBondCashflow, DeclareBondDefault, FundBondCashflow,
            RecordBondCashflow, RegisterBond,
        },
        instruction_wire_id,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::{NumericSpec, Quantity};

use super::*;
use crate::{
    decode_instruction_archive, decode_instruction_frame, encode_instruction_archive,
    encode_instruction_frame, instruction_from_json, instruction_to_json_value,
};

const PREFIX: u16 = 369;
const FIXTURE_FILE: &str = "javascript/iroha_js/test/fixtures/bond-v1-codec.json";
const FIXTURE: &str = include_str!("../../../javascript/iroha_js/test/fixtures/bond-v1-codec.json");
const DAY: u64 = 86_400_000;
/// 2026-01-15T00:00:00Z.
const ISSUE: u64 = 1_768_435_200_000;
/// 2029-01-15T00:00:00Z.
const MATURITY: u64 = 1_863_129_600_000;

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("bond test-only key")
            .public_key()
            .clone(),
    )
}

fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("bondpoc", "universal").expect("bond test domain"),
        name.parse().expect("bond test asset name"),
    )
}

fn q(text: &str) -> Quantity {
    text.parse().expect("quantity literal")
}

fn bond() -> AssetDefinitionId {
    definition("si_bond_2030")
}

fn issuer() -> AccountId {
    account(0x11)
}

fn paying_agent() -> AccountId {
    account(0x12)
}

fn holder() -> AccountId {
    account(0x21)
}

fn annual_request() -> BondScheduleRequest {
    BondScheduleRequest {
        denomination: q("50"),
        coupon_rate_bps: 650,
        coupon_frequency: 1,
        issue_date_ms: ISSUE,
        maturity_date_ms: MATURITY,
        redemption_price_bps: 10_000,
        record_offset_ms: DAY,
    }
}

/// Annual 6.50 % bond on a 50 EUR denomination with a call and every identifier.
fn annual_terms() -> BondTerms {
    BondTerms {
        issuer: issuer(),
        paying_agent: paying_agent(),
        payment_asset: definition("eur_cash"),
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
        cashflows: fixed_rate_bullet_schedule(&annual_request()).expect("annual schedule"),
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

/// Zero-coupon bond without a call or optional identifiers.
fn zero_coupon_terms() -> BondTerms {
    let request = BondScheduleRequest {
        denomination: q("100"),
        coupon_rate_bps: 0,
        coupon_frequency: 0,
        redemption_price_bps: 10_000,
        ..annual_request()
    };
    BondTerms {
        denomination: q("100"),
        coupon_rate_bps: 0,
        coupon_frequency: 0,
        day_count: BondDayCount::Act365Fixed,
        call: None,
        cashflows: fixed_rate_bullet_schedule(&request).expect("zero-coupon schedule"),
        identifiers: BondIdentifiers {
            isin: None,
            cfi: None,
            issuer_lei: None,
            bdt_version: "bdt-1.0".to_owned(),
            bdt_document_sha256: None,
        },
        ..annual_terms()
    }
}

fn native_instructions() -> Vec<(&'static str, InstructionBox)> {
    let payment_date = annual_terms().cashflows[1].payment_date_ms;
    vec![
        (
            "Register",
            BondInstructionBox::from(RegisterBond::new(bond(), annual_terms())).into(),
        ),
        (
            "RegisterZeroCoupon",
            BondInstructionBox::from(RegisterBond::new(
                definition("si_zero_2029"),
                zero_coupon_terms(),
            ))
            .into(),
        ),
        (
            "RecordCashflow",
            BondInstructionBox::from(RecordBondCashflow::new(bond(), 0)).into(),
        ),
        (
            "FundCashflow",
            BondInstructionBox::from(FundBondCashflow::new(
                bond(),
                0,
                AssetId::new(definition("eur_cash"), paying_agent()),
            ))
            .into(),
        ),
        (
            "ClaimCashflow",
            BondInstructionBox::from(ClaimBondCashflow::new(bond(), 0, holder())).into(),
        ),
        (
            "CloseCashflow",
            BondInstructionBox::from(CloseBondCashflow::new(bond(), 0)).into(),
        ),
        (
            "Call",
            BondInstructionBox::from(CallBond::new(bond(), payment_date)).into(),
        ),
        (
            "DeclareDefault",
            BondInstructionBox::from(DeclareBondDefault::new(bond(), 1, [0xab; 32])).into(),
        ),
    ]
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    let mut map = json::Map::new();
    for (key, value) in fields {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

fn value<T: json::JsonSerialize + ?Sized>(item: &T) -> Value {
    json::to_value(item).expect("fixture JSON value")
}

fn text(value: &Value) -> String {
    json::to_json(value).expect("fixture JSON text")
}

fn instruction_vectors() -> Value {
    Value::Array(
        native_instructions()
            .into_iter()
            .map(|(name, native)| {
                let rendered = {
                    let _network = ChainDiscriminantGuard::enter(PREFIX);
                    instruction_to_json_value(&native).expect("canonical bond JSON")
                };
                let source = text(&rendered);
                let archive = encode_instruction_archive(&source, PREFIX).expect("archive");
                let frame = encode_instruction_frame(&source, PREFIX).expect("frame");
                object([
                    ("name", Value::String(name.to_owned())),
                    ("json", rendered),
                    ("archive_hex", Value::String(hex::encode(archive))),
                    ("frame_hex", Value::String(hex::encode(frame))),
                ])
            })
            .collect(),
    )
}

fn schedule_request_json(request: &BondScheduleRequest) -> Value {
    object([
        ("denomination", value(&request.denomination)),
        ("couponRateBps", value(&request.coupon_rate_bps)),
        ("couponFrequency", value(&request.coupon_frequency)),
        ("issueDateMs", value(&request.issue_date_ms)),
        ("maturityDateMs", value(&request.maturity_date_ms)),
        ("redemptionPriceBps", value(&request.redemption_price_bps)),
        ("recordOffsetMs", value(&request.record_offset_ms)),
    ])
}

fn schedule_cases() -> Vec<(&'static str, BondScheduleRequest)> {
    // 2026-08-31 and 2029-08-31: end-of-month clamping into 28/29 February.
    let eom_issue = 1_788_134_400_000;
    let eom_maturity = 1_882_828_800_000;
    // 2026-01-15T12:00:00Z keeps its time of day on every generated date.
    let noon = ISSUE + DAY / 2;
    let base = annual_request();
    vec![
        ("annual_650bps_par", base.clone()),
        (
            "semiannual_650bps_premium_redemption",
            BondScheduleRequest {
                coupon_frequency: 2,
                redemption_price_bps: 10_100,
                ..base.clone()
            },
        ),
        (
            "quarterly_500bps_on_1000",
            BondScheduleRequest {
                denomination: q("1000"),
                coupon_rate_bps: 500,
                coupon_frequency: 4,
                ..base.clone()
            },
        ),
        (
            "monthly_600bps_on_1200",
            BondScheduleRequest {
                denomination: q("1200"),
                coupon_rate_bps: 600,
                coupon_frequency: 12,
                maturity_date_ms: 1_831_507_200_000, // 2028-01-15
                ..base.clone()
            },
        ),
        (
            "zero_coupon",
            BondScheduleRequest {
                denomination: q("100"),
                coupon_rate_bps: 0,
                coupon_frequency: 0,
                ..base.clone()
            },
        ),
        (
            "semiannual_end_of_month",
            BondScheduleRequest {
                denomination: q("1000"),
                coupon_rate_bps: 500,
                coupon_frequency: 2,
                issue_date_ms: eom_issue,
                maturity_date_ms: eom_maturity,
                record_offset_ms: 7 * DAY,
                ..base.clone()
            },
        ),
        (
            "record_offset_clamped_to_issue",
            BondScheduleRequest {
                coupon_frequency: 4,
                coupon_rate_bps: 800,
                record_offset_ms: 120 * DAY,
                ..base.clone()
            },
        ),
        (
            "fractional_denomination_noon",
            BondScheduleRequest {
                denomination: q("0.5"),
                coupon_rate_bps: 125,
                coupon_frequency: 2,
                issue_date_ms: noon,
                maturity_date_ms: MATURITY + DAY / 2,
                redemption_price_bps: 9_950,
                record_offset_ms: 0,
            },
        ),
        (
            "rate_without_frequency_is_redemption_only",
            BondScheduleRequest {
                coupon_rate_bps: 650,
                coupon_frequency: 0,
                ..base.clone()
            },
        ),
        (
            "monthly_650bps_on_50_repeats",
            BondScheduleRequest {
                coupon_frequency: 12,
                ..base.clone()
            },
        ),
        (
            "irregular_first_period",
            BondScheduleRequest {
                issue_date_ms: ISSUE + DAY,
                ..base.clone()
            },
        ),
        (
            "issue_not_before_maturity",
            BondScheduleRequest {
                maturity_date_ms: ISSUE,
                ..base.clone()
            },
        ),
        (
            "unsupported_frequency",
            BondScheduleRequest {
                coupon_frequency: 3,
                ..base.clone()
            },
        ),
        (
            "monthly_400_coupons_exceed_limit",
            BondScheduleRequest {
                denomination: q("1200"),
                coupon_rate_bps: 600,
                coupon_frequency: 12,
                maturity_date_ms: 2_820_182_400_000, // 2059-05-15
                ..base
            },
        ),
    ]
}

fn schedule_vectors() -> Value {
    Value::Array(
        schedule_cases()
            .into_iter()
            .map(|(name, request)| {
                let result = match fixed_rate_bullet_schedule(&request) {
                    Ok(cashflows) => {
                        // A generated schedule must register: complete the terms
                        // around it and run the shared Core validation.
                        let frequency = request.coupon_frequency;
                        let terms = BondTerms {
                            denomination: request.denomination.clone(),
                            coupon_rate_bps: if frequency == 0 {
                                0
                            } else {
                                request.coupon_rate_bps
                            },
                            coupon_frequency: frequency,
                            issue_date_ms: request.issue_date_ms,
                            maturity_date_ms: request.maturity_date_ms,
                            redemption_price_bps: request.redemption_price_bps,
                            call: None,
                            cashflows: cashflows.clone(),
                            ..annual_terms()
                        };
                        terms
                            .validate()
                            .unwrap_or_else(|error| panic!("{name} must register: {error}"));
                        ("cashflows", value(&cashflows))
                    }
                    Err(error) => ("error", Value::String(error.to_string())),
                };
                object([
                    ("name", Value::String(name.to_owned())),
                    ("request", schedule_request_json(&request)),
                    result,
                ])
            })
            .collect(),
    )
}

type TermsMutation = fn(&mut BondTerms);

fn validation_cases() -> Vec<(&'static str, TermsMutation)> {
    vec![
        ("valid_annual", |_| {}),
        ("valid_zero_coupon", |terms| *terms = zero_coupon_terms()),
        ("valid_without_call", |terms| terms.call = None),
        ("isin_too_long", |terms| {
            terms.identifiers.isin = Some("SI00312345678".to_owned());
        }),
        ("cfi_empty", |terms| {
            terms.identifiers.cfi = Some(String::new())
        }),
        ("lei_not_printable", |terms| {
            terms.identifiers.issuer_lei = Some("5299 000DI".to_owned());
        }),
        ("lei_non_ascii", |terms| {
            terms.identifiers.issuer_lei = Some("5299\u{e9}".to_owned());
        }),
        ("bdt_version_too_long", |terms| {
            terms.identifiers.bdt_version = "v".repeat(33);
        }),
        ("zero_denomination", |terms| {
            terms.denomination = Quantity::zero();
        }),
        ("zero_redemption_price", |terms| {
            terms.redemption_price_bps = 0;
        }),
        ("unsupported_frequency", |terms| terms.coupon_frequency = 3),
        ("zero_rate_with_frequency", |terms| {
            terms.coupon_rate_bps = 0
        }),
        ("rate_without_frequency", |terms| terms.coupon_frequency = 0),
        ("issue_not_before_maturity", |terms| {
            terms.maturity_date_ms = terms.issue_date_ms;
        }),
        ("zero_call_price", |terms| {
            terms.call.as_mut().expect("call").price_bps = 0;
        }),
        ("call_on_issue_date", |terms| {
            terms.call.as_mut().expect("call").first_call_date_ms = ISSUE;
        }),
        ("call_on_maturity", |terms| {
            terms.call.as_mut().expect("call").first_call_date_ms = MATURITY;
        }),
        ("call_price_scale_overflow", |terms| {
            terms.denomination = q("0.0000000000000000000000001");
            terms.call.as_mut().expect("call").price_bps = 3;
        }),
        ("empty_schedule", |terms| terms.cashflows.clear()),
        ("indices_not_contiguous", |terms| {
            terms.cashflows[1].index = 2;
        }),
        ("record_after_payment", |terms| {
            terms.cashflows[0].record_date_ms = terms.cashflows[0].payment_date_ms + 1;
        }),
        ("record_before_issue", |terms| {
            terms.cashflows[0].record_date_ms = ISSUE - 1;
        }),
        ("payment_after_maturity", |terms| {
            terms.cashflows[3].payment_date_ms = MATURITY + 1;
        }),
        ("redemption_not_last", |terms| {
            terms.cashflows[1].kind = BondCashflowKind::Redemption;
            terms.cashflows[1].amount_per_unit = q("50");
        }),
        ("redemption_before_maturity", |terms| {
            terms.cashflows[3].payment_date_ms = MATURITY - DAY;
            terms.cashflows[3].record_date_ms = MATURITY - 2 * DAY;
        }),
        ("wrong_redemption_amount", |terms| {
            terms.cashflows[3].amount_per_unit = q("49");
        }),
        ("schedule_without_redemption", |terms| {
            terms.cashflows[3].kind = BondCashflowKind::Coupon;
            terms.cashflows[3].amount_per_unit = q("3.25");
        }),
        ("wrong_coupon_amount", |terms| {
            terms.cashflows[1].amount_per_unit = q("3.26");
        }),
        ("monthly_coupon_repeats", |terms| {
            terms.coupon_frequency = 12;
        }),
        ("coupons_on_zero_coupon_bond", |terms| {
            terms.coupon_rate_bps = 0;
            terms.coupon_frequency = 0;
        }),
        ("payment_dates_repeat", |terms| {
            terms.cashflows[1].payment_date_ms = terms.cashflows[0].payment_date_ms;
            terms.cashflows[1].record_date_ms = terms.cashflows[0].record_date_ms;
        }),
        ("record_dates_decrease", |terms| {
            terms.cashflows[1].record_date_ms = terms.cashflows[0].record_date_ms - 1;
            terms.cashflows[0].record_date_ms = terms.cashflows[0].payment_date_ms;
        }),
        ("valid_final_coupon_before_maturity", |terms| {
            terms.cashflows[2].payment_date_ms = MATURITY - DAY;
            terms.cashflows[2].record_date_ms = MATURITY - 2 * DAY;
        }),
    ]
}

fn validation_vectors() -> Value {
    Value::Array(
        validation_cases()
            .into_iter()
            .map(|(name, mutate)| {
                let mut terms = annual_terms();
                mutate(&mut terms);
                let error = terms
                    .validate()
                    .err()
                    .map_or(Value::Null, |error| Value::String(error.to_string()));
                object([
                    ("name", Value::String(name.to_owned())),
                    ("terms", {
                        let _network = ChainDiscriminantGuard::enter(PREFIX);
                        value(&terms)
                    }),
                    ("error", error),
                ])
            })
            .collect(),
    )
}

fn holder_payment_vectors() -> Value {
    let cases: [(&str, &str, Option<u32>); 7] = [
        ("3", "1.625", Some(2)),
        ("3", "1.625", None),
        ("1", "1.625", Some(0)),
        ("1000", "3.25", Some(2)),
        ("7", "0.0001", Some(2)),
        ("123456789", "50.5", Some(6)),
        ("2", "0.003125", Some(4)),
    ];
    Value::Array(
        cases
            .into_iter()
            .map(|(units, amount, scale)| {
                let spec = scale.map_or_else(NumericSpec::unconstrained, NumericSpec::fractional);
                let payment = holder_payment(&q(units), &q(amount), spec).expect("holder payment");
                object([
                    ("units", Value::String(units.to_owned())),
                    ("amountPerUnit", Value::String(amount.to_owned())),
                    (
                        "paymentScale",
                        scale.map_or(Value::Null, |scale| value(&scale)),
                    ),
                    ("payment", value(&payment)),
                ])
            })
            .collect(),
    )
}

fn vault_vectors() -> Value {
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    Value::Array(
        [bond(), definition("si_zero_2029"), definition("eur_cash")]
            .into_iter()
            .map(|id| {
                let vault = bond_vault_account_id(&id);
                object([
                    ("bond", value(&id)),
                    ("account", value(&vault)),
                    (
                        "public_key_hex",
                        Value::String(hex::encode(vault.expect_single_signatory().to_bytes().1)),
                    ),
                ])
            })
            .collect(),
    )
}

/// Generate the complete shared fixture from the native data model.
fn generate_fixture() -> Value {
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    object([
        ("version", Value::from(1_u64)),
        ("network_prefix", value(&PREFIX)),
        ("bond", value(&bond())),
        ("payment_asset", value(&definition("eur_cash"))),
        (
            "accounts",
            object([
                ("issuer", value(&issuer())),
                ("paying_agent", value(&paying_agent())),
                ("holder", value(&holder())),
            ]),
        ),
        ("instructions", instruction_vectors()),
        ("vaults", vault_vectors()),
        ("schedules", schedule_vectors()),
        ("terms_validation", validation_vectors()),
        ("holder_payments", holder_payment_vectors()),
    ])
}

fn repository_fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(FIXTURE_FILE)
}

#[test]
#[ignore = "writes javascript/iroha_js/test/fixtures/bond-v1-codec.json; run it to accept an intended change"]
fn regenerate_bond_js_fixture() {
    let generated = format!(
        "{}\n",
        json::to_json_pretty(&generate_fixture()).expect("pretty fixture")
    );
    let path = repository_fixture_path();
    if std::fs::read(&path).ok().as_deref() != Some(generated.as_bytes()) {
        std::fs::write(path, generated).expect("write the shared bond fixture");
    }
}

#[test]
fn shared_bond_fixture_matches_native_generation() {
    let checked_in: Value = json::from_json(FIXTURE).expect("shared bond fixture JSON");
    assert_eq!(
        checked_in,
        generate_fixture(),
        "regenerate with `cargo test -p iroha_js_codec --lib -- --ignored regenerate_bond_js_fixture`"
    );
}

#[test]
fn bond_envelopes_roundtrip_through_json_archive_and_frame() {
    for (name, native) in native_instructions() {
        assert!(is_bond_instruction(&native), "{name}");
        assert_eq!(
            instruction_wire_id(&native),
            Some(BondInstructionBox::WIRE_ID),
            "{name}"
        );
        let value = {
            let _network = ChainDiscriminantGuard::enter(PREFIX);
            instruction_to_json_value(&native).expect("render bond JSON")
        };
        let source = text(&value);
        let parsed = {
            let _network = ChainDiscriminantGuard::enter(PREFIX);
            instruction_from_json(&source).expect("bond JSON parses")
        };
        assert_eq!(parsed, native, "{name}");
        let archive = encode_instruction_archive(&source, PREFIX).expect("archive");
        let decoded: Value =
            json::from_json(&decode_instruction_archive(&archive, PREFIX).expect("decode"))
                .expect("decoded archive JSON");
        assert_eq!(decoded, value, "{name}");
        let frame = encode_instruction_frame(&source, PREFIX).expect("frame");
        let decoded: Value =
            json::from_json(&decode_instruction_frame(&frame, PREFIX).expect("decode frame"))
                .expect("decoded frame JSON");
        assert_eq!(decoded, value, "{name}");
    }
}

#[test]
fn bond_envelope_shape_is_exact() {
    let fixture: Value = json::from_json(FIXTURE).expect("shared bond fixture JSON");
    let register = fixture["instructions"][0]["json"].clone();
    let declare = fixture["instructions"][7]["json"].clone();
    assert!(
        register
            .get("Bond")
            .and_then(|bond| bond.get("Register"))
            .is_some()
    );
    let rendered = text(&declare);
    assert!(
        rendered.contains(&format!(r#""evidence_sha256":"{}""#, "ab".repeat(32))),
        "{rendered}"
    );
    assert!(
        rendered.starts_with(r#"{"Bond":{"DeclareDefault":{"#),
        "{rendered}"
    );
}

fn edited(source: &Value, edit: impl FnOnce(&mut json::Map)) -> String {
    let mut value = source.clone();
    let Value::Object(envelope) = &mut value else {
        panic!("bond envelope object");
    };
    let Some(Value::Object(variants)) = envelope.get_mut("Bond") else {
        panic!("bond variants");
    };
    let Some(Value::Object(payload)) = variants.values_mut().next() else {
        panic!("bond payload");
    };
    edit(payload);
    text(&value)
}

#[test]
fn bond_json_rejects_noncanonical_missing_extra_and_ambiguous_payloads() {
    let fixture: Value = json::from_json(FIXTURE).expect("shared bond fixture JSON");
    let register = fixture["instructions"][0]["json"].clone();
    let fund = fixture["instructions"][3]["json"].clone();
    let declare = fixture["instructions"][7]["json"].clone();
    let mut cases = vec![
        edited(&register, |payload| {
            payload.insert("legacy".to_owned(), Value::Null);
        }),
        edited(&register, |payload| {
            payload.remove("terms");
        }),
        edited(&register, |payload| {
            let Some(Value::Object(terms)) = payload.get_mut("terms") else {
                panic!("terms");
            };
            terms.insert("denomination".to_owned(), Value::String("50.0".to_owned()));
        }),
        edited(&register, |payload| {
            let Some(Value::Object(terms)) = payload.get_mut("terms") else {
                panic!("terms");
            };
            terms.insert(
                "day_count".to_owned(),
                Value::String("actacticma".to_owned()),
            );
        }),
        edited(&register, |payload| {
            let Some(Value::Object(terms)) = payload.get_mut("terms") else {
                panic!("terms");
            };
            terms.remove("call");
        }),
        edited(&fund, |payload| {
            payload.insert("index".to_owned(), Value::String("0".to_owned()));
        }),
        edited(&fund, |payload| {
            payload.insert("index".to_owned(), Value::from(65_536_u64));
        }),
        edited(&declare, |payload| {
            payload.insert("evidence_sha256".to_owned(), Value::String("AB".repeat(32)));
        }),
        edited(&declare, |payload| {
            payload.insert(
                "evidence_sha256".to_owned(),
                Value::String(format!("0x{}", "ab".repeat(32))),
            );
        }),
    ];
    let mut envelope_extra = register.clone();
    envelope_extra
        .as_object_mut()
        .expect("envelope")
        .insert("legacy".to_owned(), Value::Null);
    cases.push(text(&envelope_extra));
    let payload = register["Bond"]["Register"].clone();
    for variants in [
        object([("Issue", payload.clone())]),
        object([
            ("Register", payload.clone()),
            (
                "CloseCashflow",
                fixture["instructions"][5]["json"]["Bond"]["CloseCashflow"].clone(),
            ),
        ]),
        object([]),
    ] {
        cases.push(text(&object([("Bond", variants)])));
    }
    cases.push(r#"{"Bond":[]}"#.to_owned());
    cases.push(text(&object([("RegisterBond", payload)])));
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    for malformed in cases {
        assert!(
            instruction_from_json(&malformed).is_err(),
            "malformed bond JSON must be rejected: {malformed}"
        );
    }
}

#[test]
fn bond_requires_its_envelope_instead_of_generic_base64() {
    let native: InstructionBox =
        BondInstructionBox::from(RecordBondCashflow::new(bond(), 0)).into();
    let bytes = norito::encode_canonical(&native).expect("canonical instruction");
    let base64 = json::to_json(&Value::String(
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ))
    .expect("base64 JSON");
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    assert!(instruction_from_json(&base64).is_err());
}

#[test]
fn vault_literal_matches_the_data_model_and_requires_a_canonical_bond() {
    let expected = {
        let _network = ChainDiscriminantGuard::enter(PREFIX);
        bond_vault_account_id(&bond()).to_string()
    };
    let literal = bond_vault_account_literal(&bond().to_string(), PREFIX).expect("vault");
    assert_eq!(literal, expected);
    let other = bond_vault_account_literal(&bond().to_string(), 753).expect("vault 753");
    assert_ne!(other, literal);
    let parsed = crate::account_address_parse_encoded(&other, Some(753)).expect("i105 vault");
    let original = crate::account_address_parse_encoded(&literal, Some(PREFIX)).expect("vault");
    assert_eq!(parsed.canonical_bytes, original.canonical_bytes);
    for malformed in ["", " x", "si_bond_2030#bondpoc.universal", "abc"] {
        assert!(
            bond_vault_account_literal(malformed, PREFIX).is_err(),
            "{malformed}"
        );
    }
    let padded = format!(" {}", bond());
    assert!(bond_vault_account_literal(&padded, PREFIX).is_err());
}

#[test]
fn schedule_builder_admits_exactly_399_coupons() {
    let fits = fixed_rate_bullet_schedule(&BondScheduleRequest {
        denomination: q("1200"),
        coupon_rate_bps: 600,
        coupon_frequency: 12,
        maturity_date_ms: 2_817_590_400_000, // 2059-04-15: 399 monthly periods
        ..annual_request()
    })
    .expect("399 coupons and the redemption fit the 400 cash-flow bound");
    assert_eq!(fits.len(), 400);
}

#[test]
fn bond_schedule_vectors_cover_success_and_every_builder_refusal() {
    let fixture: Value = json::from_json(FIXTURE).expect("shared bond fixture JSON");
    let schedules = fixture["schedules"].as_array().expect("schedule vectors");
    let errors: Vec<&str> = schedules
        .iter()
        .filter_map(|vector| vector.get("error").and_then(Value::as_str))
        .collect();
    for fragment in [
        "not an exact decimal",
        "irregular",
        "precede maturity",
        "frequency must be",
        "cash-flow limit",
    ] {
        assert!(
            errors.iter().any(|error| error.contains(fragment)),
            "missing schedule refusal {fragment}"
        );
    }
    let annual = &schedules[0]["cashflows"];
    assert_eq!(annual.as_array().map(Vec::len), Some(4));
    assert_eq!(
        annual[0]["amount_per_unit"],
        Value::String("3.25".to_owned())
    );
    assert_eq!(annual[3]["kind"], Value::String("Redemption".to_owned()));
}
