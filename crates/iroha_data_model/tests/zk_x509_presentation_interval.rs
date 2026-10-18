//! Public-boundary tests for the canonical zk-X509 presentation-interval
//! definition and its shared cross-language vectors.
//!
//! Covers `specs/zk_delivery_plan.md` X.1: the presentation window is bounded by
//! the latest `notBefore` and the earliest `notAfter` of every certificate in the
//! path and ends strictly before the CRL `nextUpdate`.

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    privacy::{
        IrohaZkX509StarkP256StatementV1, PrivacyAttributeDigestV1, PrivacyCertificateKeyDigestV1,
        PrivacyChallengeV1, PrivacyEngineManifestDigestV1, PrivacyIssuerIdV1, PrivacyNullifierV1,
        PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPolicyIdV1, PrivacyRootV1,
        PrivacyStatementContextV1, PrivacyStatementSchemaDigestV1,
        PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1, PrivacyX509CrlDerDigestV1,
        PrivacyX509CrlIssuerSpkiDigestV1, PrivacyX509ExtendedKeyUsageV1,
        PrivacyX509KeyUsageRequirementV1, PrivacyX509KeyUsageV1,
        PrivacyZkX509CertificatePolicyRecordDigestV1, PrivacyZkX509CertificateValidityV1,
        PrivacyZkX509CrlRecordDigestV1, PrivacyZkX509CrlRecordV1, PrivacyZkX509CrlUpdateIntervalV1,
        PrivacyZkX509DisclosedAttributeV1, PrivacyZkX509PresentationBoundsV1,
        PrivacyZkX509PresentationIntervalErrorV1, PrivacyZkX509PresentationWindowV1,
        PrivacyZkX509RecordLifecycleV1, PrivacyZkX509TrustAnchorRecordDigestV1,
        ZK_X509_MAX_CHAIN_DEPTH_V1, ZK_X509_MAX_CRL_AGE_SECONDS_V1,
        ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1, ZK_X509_MAX_UNIX_SECONDS_V1,
        ZK_X509_MIN_CHAIN_DEPTH_V1, validate_zk_x509_presentation_interval_v1,
    },
};
use norito::json::{self, Value};

/// Shared cross-language vectors; regenerate with
/// `python3 scripts/check_zk_x509_presentation_interval.py --write`.
const VECTORS: &str = include_str!("../../../fixtures/zk/x509/interval_vectors_v1.json");

/// 2023-01-01T00:00:00Z.
const T: u64 = 1_672_531_200;
/// 2022-01-01T00:00:00Z and 2030-01-01T00:00:00Z.
const WIDE: PrivacyZkX509CertificateValidityV1 =
    PrivacyZkX509CertificateValidityV1::new(1_640_995_200, 1_893_456_000);

fn validity(not_before: u64, not_after: u64) -> PrivacyZkX509CertificateValidityV1 {
    PrivacyZkX509CertificateValidityV1::new(not_before, not_after)
}

fn crl(this_update: u64, next_update: u64) -> PrivacyZkX509CrlUpdateIntervalV1 {
    PrivacyZkX509CrlUpdateIntervalV1::new(this_update, next_update)
}

fn window(start: u64, end: u64) -> PrivacyZkX509PresentationWindowV1 {
    PrivacyZkX509PresentationWindowV1::new(start, end)
}

/// Independent formulation: every signed interval is checked on its own, with
/// no earliest/latest reduction. A bound computed from the latest expiry
/// disagrees with this oracle on any path whose CA expires before the leaf.
fn per_interval_oracle(
    certificates: &[PrivacyZkX509CertificateValidityV1],
    crl: PrivacyZkX509CrlUpdateIntervalV1,
    start: u64,
    end: u64,
) -> bool {
    (2..=3).contains(&certificates.len())
        && start < end
        && end - start <= 300
        && certificates.iter().all(|certificate| {
            certificate.not_before_unix_seconds() <= certificate.not_after_unix_seconds()
                && certificate.not_before_unix_seconds() <= start
                && end <= certificate.not_after_unix_seconds()
        })
        && crl.this_update_unix_seconds < crl.next_update_unix_seconds
        && crl.this_update_unix_seconds <= start
        && end < crl.next_update_unix_seconds
        && end - crl.this_update_unix_seconds <= 300
        && end <= 253_402_300_799
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .get(name)
        .unwrap_or_else(|| panic!("vector field `{name}` is missing"))
}

fn number(value: &Value, name: &str) -> u64 {
    field(value, name)
        .as_u64()
        .unwrap_or_else(|| panic!("vector field `{name}` is not an unsigned integer"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name)
        .as_str()
        .unwrap_or_else(|| panic!("vector field `{name}` is not a string"))
}

fn rows<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    field(value, name)
        .as_array()
        .unwrap_or_else(|| panic!("vector field `{name}` is not an array"))
}

struct VectorCase<'a> {
    name: &'a str,
    certificates: Vec<PrivacyZkX509CertificateValidityV1>,
    crl: PrivacyZkX509CrlUpdateIntervalV1,
    value: &'a Value,
}

fn vector_cases(document: &Value) -> Vec<VectorCase<'_>> {
    rows(document, "cases")
        .iter()
        .map(|value| VectorCase {
            name: text(value, "name"),
            certificates: rows(value, "certificates")
                .iter()
                .map(|row| validity(number(row, "not_before"), number(row, "not_after")))
                .collect(),
            crl: crl(
                number(field(value, "crl"), "this_update"),
                number(field(value, "crl"), "next_update"),
            ),
            value,
        })
        .collect()
}

fn result_code(result: Result<(), PrivacyZkX509PresentationIntervalErrorV1>) -> &'static str {
    result.map_or_else(
        PrivacyZkX509PresentationIntervalErrorV1::code,
        |()| "admitted",
    )
}

#[test]
fn shared_vectors_match_the_canonical_definition() {
    let document: Value = json::from_str(VECTORS).expect("tracked interval vectors");
    assert_eq!(
        text(&document, "schema"),
        "iroha.zk-x509.presentation-interval-vectors.v1"
    );
    assert_eq!(
        number(&document, "max_crl_age_seconds"),
        ZK_X509_MAX_CRL_AGE_SECONDS_V1
    );
    assert_eq!(
        number(&document, "max_presentation_window_seconds"),
        ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1
    );
    assert_eq!(
        number(&document, "max_unix_seconds"),
        ZK_X509_MAX_UNIX_SECONDS_V1
    );
    assert_eq!(
        number(&document, "min_chain_depth"),
        u64::from(ZK_X509_MIN_CHAIN_DEPTH_V1)
    );
    assert_eq!(
        number(&document, "max_chain_depth"),
        u64::from(ZK_X509_MAX_CHAIN_DEPTH_V1)
    );
    let cases = vector_cases(&document);
    assert!(cases.len() >= 21, "tracked vectors lost a case");
    let mut windows = 0_usize;
    let mut deadlines = 0_usize;
    let mut blocks = 0_usize;
    for case in &cases {
        let bounds =
            PrivacyZkX509PresentationBoundsV1::from_signed_intervals(&case.certificates, case.crl);
        match (case.value.get("bounds"), case.value.get("bounds_error")) {
            (Some(expected), None) => {
                let bounds = bounds.unwrap_or_else(|error| panic!("{}: {error}", case.name));
                assert_eq!(
                    bounds.earliest_start_unix_seconds(),
                    number(expected, "earliest_start"),
                    "{}: earliest admissible start",
                    case.name
                );
                assert_eq!(
                    bounds.latest_end_unix_seconds(),
                    number(expected, "latest_end"),
                    "{}: latest admissible end",
                    case.name
                );
            }
            (None, Some(expected)) => assert_eq!(
                bounds
                    .map(|_| ())
                    .map_err(PrivacyZkX509PresentationIntervalErrorV1::code),
                Err(expected.as_str().expect("bounds error code")),
                "{}: bounds error",
                case.name
            ),
            _ => panic!("{}: exactly one of bounds/bounds_error", case.name),
        }
        for row in rows(case.value, "windows") {
            let start = number(row, "not_before");
            let end = number(row, "not_after");
            let expected = text(row, "result");
            assert_eq!(
                result_code(validate_zk_x509_presentation_interval_v1(
                    &case.certificates,
                    case.crl,
                    window(start, end),
                )),
                expected,
                "{}: window [{start}, {end}]",
                case.name
            );
            assert_eq!(
                expected == "admitted",
                per_interval_oracle(&case.certificates, case.crl, start, end),
                "{}: window [{start}, {end}] differs from the per-interval oracle",
                case.name
            );
            windows += 1;
        }
        for row in rows(case.value, "deadlines") {
            let bounds = bounds.expect("deadline vectors carry bounds");
            assert_eq!(
                bounds.presentation_deadline_unix_ms(number(row, "presentation_not_after")),
                Ok(number(row, "deadline_unix_ms")),
                "{}: holder deadline",
                case.name
            );
            deadlines += 1;
        }
        for row in rows(case.value, "blocks") {
            let window = window(number(row, "not_before"), number(row, "not_after"));
            assert_eq!(
                window.admits_block_timestamp_ms(number(row, "timestamp_ms")),
                field(row, "admitted").as_bool().expect("admitted flag"),
                "{}: block timestamp {}",
                case.name,
                number(row, "timestamp_ms")
            );
            blocks += 1;
        }
    }
    assert!(windows >= 70 && deadlines >= 25 && blocks >= 18);
}

#[test]
fn shared_vectors_cover_every_required_boundary_class() {
    let document: Value = json::from_str(VECTORS).expect("tracked interval vectors");
    let cases = vector_cases(&document);
    let window_results = |case: &VectorCase<'_>| -> Vec<(u64, u64, bool)> {
        rows(case.value, "windows")
            .iter()
            .map(|row| {
                (
                    number(row, "not_before"),
                    number(row, "not_after"),
                    text(row, "result") == "admitted",
                )
            })
            .collect()
    };
    // Earliest expiry at each path position, with boundary equality admitted
    // and the one-second overflow rejected.
    for position in 0..3 {
        assert!(
            cases.iter().any(|case| {
                let expiries: Vec<u64> = case
                    .certificates
                    .iter()
                    .map(|certificate| certificate.not_after_unix_seconds())
                    .collect();
                let Some(&earliest) = expiries.iter().min() else {
                    return false;
                };
                let unique_at_position = expiries.len() == 3
                    && expiries[position] == earliest
                    && expiries
                        .iter()
                        .filter(|expiry| **expiry == earliest)
                        .count()
                        == 1;
                let results = window_results(case);
                unique_at_position
                    && results
                        .iter()
                        .any(|(_, end, admitted)| *end == earliest && *admitted)
                    && results
                        .iter()
                        .any(|(_, end, admitted)| *end == earliest + 1 && !*admitted)
            }),
            "no vector places the unique earliest expiry at path position {position}"
        );
        // Latest notBefore at each path position, with equality admitted and
        // the one-second underflow rejected.
        assert!(
            cases.iter().any(|case| {
                let starts: Vec<u64> = case
                    .certificates
                    .iter()
                    .map(|certificate| certificate.not_before_unix_seconds())
                    .collect();
                let Some(&latest) = starts.iter().max() else {
                    return false;
                };
                let unique_at_position = starts.len() == 3
                    && starts[position] == latest
                    && starts.iter().filter(|start| **start == latest).count() == 1
                    && latest > case.crl.this_update_unix_seconds;
                let results = window_results(case);
                unique_at_position
                    && results
                        .iter()
                        .any(|(start, _, admitted)| *start == latest && *admitted)
                    && results
                        .iter()
                        .any(|(start, _, admitted)| *start + 1 == latest && !*admitted)
            }),
            "no vector places the unique latest notBefore at path position {position}"
        );
    }
    // CRL nextUpdate exclusion: equality rejects, the preceding second admits.
    assert!(cases.iter().any(|case| {
        let next_update = case.crl.next_update_unix_seconds;
        let results = window_results(case);
        results
            .iter()
            .any(|(_, end, admitted)| *end == next_update && !*admitted)
            && results
                .iter()
                .any(|(_, end, admitted)| *end + 1 == next_update && *admitted)
    }));
    // CRL age: exactly 300 seconds admits, 301 rejects with a well-shaped window.
    assert!(cases.iter().any(|case| {
        let this_update = case.crl.this_update_unix_seconds;
        let results = window_results(case);
        results
            .iter()
            .any(|(_, end, admitted)| *end == this_update + 300 && *admitted)
            && results.iter().any(|(start, end, admitted)| {
                *end == this_update + 301 && *end - *start <= 300 && !*admitted
            })
    }));
    // The RFC 5280 calendar ceiling: a window may end at the last calendar
    // second and never after it, and nextUpdate stays exclusive there.
    assert!(cases.iter().any(|case| {
        let results = window_results(case);
        results
            .iter()
            .any(|(_, end, admitted)| *end == ZK_X509_MAX_UNIX_SECONDS_V1 && *admitted)
            && results
                .iter()
                .any(|(_, end, admitted)| *end == ZK_X509_MAX_UNIX_SECONDS_V1 + 1 && !*admitted)
    }));
    assert!(cases.iter().any(|case| {
        case.crl.next_update_unix_seconds == ZK_X509_MAX_UNIX_SECONDS_V1
            && field(case.value, "signable").as_bool() == Some(true)
            && window_results(case)
                .iter()
                .any(|(_, end, admitted)| *end == ZK_X509_MAX_UNIX_SECONDS_V1 && !*admitted)
    }));
    // An already expired credential and a path with no common second.
    for name in ["certificate-expired-before-crl", "disjoint-certificates"] {
        let case = cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("vector `{name}` is missing"));
        assert!(
            window_results(case)
                .iter()
                .all(|(_, _, admitted)| !*admitted)
        );
    }
}

/// Regression for the revision-6 latest-expiry formula.
///
/// The intermediate CA expires 150 seconds after the CRL `thisUpdate`, the leaf
/// a day later and the root years later. `min(TU + 301, NU, Cmax + 1, PA + 1)`
/// budgets a deadline of `TU + 300`; the path is only valid through `TU + 150`.
#[test]
fn earliest_expiry_binds_where_the_latest_expiry_formula_admits_an_expired_path() {
    let intermediate_expiry = T + 150;
    for (name, certificates) in [
        (
            "intermediate",
            vec![
                validity(WIDE.not_before_unix_seconds(), T + 86_400),
                validity(WIDE.not_before_unix_seconds(), intermediate_expiry),
                WIDE,
            ],
        ),
        (
            "root",
            vec![
                validity(WIDE.not_before_unix_seconds(), T + 86_400),
                WIDE,
                validity(WIDE.not_before_unix_seconds(), intermediate_expiry),
            ],
        ),
        (
            "leaf",
            vec![
                validity(WIDE.not_before_unix_seconds(), intermediate_expiry),
                validity(WIDE.not_before_unix_seconds(), T + 86_400),
                WIDE,
            ],
        ),
    ] {
        let fresh_crl = crl(T, T + 301);
        let bounds =
            PrivacyZkX509PresentationBoundsV1::from_signed_intervals(&certificates, fresh_crl)
                .expect("overlapping signed intervals");
        assert_eq!(
            bounds.latest_end_unix_seconds(),
            intermediate_expiry,
            "{name}: the bound is the earliest expiry"
        );
        // Boundary equality is admitted; one second later is not.
        assert_eq!(bounds.admit(window(T, intermediate_expiry)), Ok(()));
        assert_eq!(
            bounds.admit(window(T, intermediate_expiry + 1)),
            Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds)
        );
        // The retired formula: latest expiry in the path.
        let latest_expiry = certificates
            .iter()
            .map(|certificate| certificate.not_after_unix_seconds())
            .max()
            .expect("non-empty path");
        let retired_window = window(T, T + 300);
        let retired_deadline_ms = (T + 301)
            .min(fresh_crl.next_update_unix_seconds)
            .min(latest_expiry + 1)
            .min(retired_window.not_after_unix_seconds + 1)
            * 1_000
            - 1;
        assert_eq!(retired_deadline_ms, (T + 301) * 1_000 - 1);
        assert_eq!(
            bounds.admit(retired_window),
            Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds),
            "{name}: the latest-expiry window covers an expired certificate"
        );
        let deadline_ms = bounds
            .presentation_deadline_unix_ms(retired_window.not_after_unix_seconds)
            .expect("deadline fits");
        assert_eq!(deadline_ms, (intermediate_expiry + 1) * 1_000 - 1);
        assert!(deadline_ms < retired_deadline_ms);
        // The builder never emits a window past the earliest expiry, and the
        // block second after it is outside every window the builder emits.
        let built = bounds
            .widest_window_from(T)
            .expect("admissible builder window");
        assert_eq!(built, window(T, intermediate_expiry));
        assert!(built.admits_block_timestamp_ms(deadline_ms));
        assert!(!built.admits_block_timestamp_ms(deadline_ms + 1));
        assert!(!built.admits_block_timestamp_ms(retired_deadline_ms));
    }
}

#[test]
fn bounds_equal_the_per_interval_oracle_on_an_exhaustive_boundary_grid() {
    let not_befores = [T - 2, T, T + 2];
    let not_afters = [T + 297, T + 299, T + 300, T + 302];
    let mut validities = Vec::new();
    for not_before in not_befores {
        for not_after in not_afters {
            validities.push(validity(not_before, not_after));
        }
    }
    let crls = [
        crl(T - 1, T + 299),
        crl(T, T + 300),
        crl(T, T + 301),
        crl(T, T + 305),
        crl(T + 1, T + 303),
    ];
    let starts = (T - 3)..=(T + 3);
    let ends = (T + 295)..=(T + 304);
    let mut admitted = 0_u64;
    let mut rejected = 0_u64;
    let mut check = |certificates: &[PrivacyZkX509CertificateValidityV1]| {
        for crl in crls {
            let bounds =
                PrivacyZkX509PresentationBoundsV1::from_signed_intervals(certificates, crl);
            for start in starts.clone() {
                for end in ends.clone() {
                    let canonical = bounds
                        .and_then(|bounds| bounds.admit(window(start, end)))
                        .is_ok();
                    assert_eq!(
                        canonical,
                        per_interval_oracle(certificates, crl, start, end),
                        "window [{start}, {end}] under {crl:?}"
                    );
                    assert_eq!(
                        canonical,
                        validate_zk_x509_presentation_interval_v1(
                            certificates,
                            crl,
                            window(start, end)
                        )
                        .is_ok()
                    );
                    if canonical {
                        admitted += 1;
                    } else {
                        rejected += 1;
                    }
                }
            }
        }
    };
    for leaf in &validities {
        for root in &validities {
            check(&[*leaf, *root]);
            for intermediate in &validities {
                check(&[*leaf, *intermediate, *root]);
            }
        }
    }
    assert!(admitted > 10_000 && rejected > 100_000);
}

#[test]
fn builder_windows_are_admitted_maximal_and_never_outlive_any_signed_interval() {
    let paths: [&[PrivacyZkX509CertificateValidityV1]; 4] = [
        &[WIDE, WIDE],
        &[validity(T + 5, T + 120), WIDE, WIDE],
        &[WIDE, validity(T + 7, T + 150), WIDE],
        &[WIDE, WIDE, validity(T + 9, T + 90)],
    ];
    for certificates in paths {
        for crl in [crl(T, T + 301), crl(T, T + 200), crl(T, T + 3_600)] {
            let bounds =
                PrivacyZkX509PresentationBoundsV1::from_signed_intervals(certificates, crl)
                    .expect("overlapping signed intervals");
            let earliest = bounds.earliest_start_unix_seconds();
            let latest = bounds.latest_end_unix_seconds();
            assert_eq!(
                bounds.widest_window_from(earliest - 1),
                Err(PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds)
            );
            assert_eq!(
                bounds.widest_window_from(latest),
                Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds)
            );
            for start in earliest..latest {
                let built = bounds.widest_window_from(start).expect("admissible start");
                assert_eq!(built.not_before_unix_seconds, start);
                assert_eq!(bounds.admit(built), Ok(()));
                assert!(per_interval_oracle(
                    certificates,
                    crl,
                    built.not_before_unix_seconds,
                    built.not_after_unix_seconds
                ));
                // Maximal: one more second leaves the bounds or the width cap.
                assert!(
                    bounds
                        .admit(window(start, built.not_after_unix_seconds + 1))
                        .is_err()
                );
                assert_eq!(
                    built.not_after_unix_seconds,
                    latest.min(start + ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1)
                );
                assert_eq!(
                    bounds.presentation_deadline_unix_ms(built.not_after_unix_seconds),
                    built.last_admissible_block_timestamp_ms()
                );
            }
        }
    }
}

#[test]
fn crl_bounds_exclude_next_update_cap_age_and_reject_reversed_intervals() {
    // nextUpdate binds: the last covered second is nextUpdate - 1.
    let bounds = PrivacyZkX509PresentationBoundsV1::from_crl(crl(T, T + 200)).expect("CRL bounds");
    assert_eq!(bounds.earliest_start_unix_seconds(), T);
    assert_eq!(bounds.latest_end_unix_seconds(), T + 199);
    assert_eq!(bounds.admit(window(T, T + 199)), Ok(()));
    assert_eq!(
        bounds.admit(window(T, T + 200)),
        Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds)
    );
    assert_eq!(
        bounds.admit(window(T - 1, T + 199)),
        Err(PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds)
    );
    // The age cap binds: nextUpdate - 1 == thisUpdate + 300 is the last second.
    for next_update in [T + 301, T + 302, T + 86_400] {
        let bounds =
            PrivacyZkX509PresentationBoundsV1::from_crl(crl(T, next_update)).expect("CRL bounds");
        assert_eq!(
            bounds.latest_end_unix_seconds(),
            T + ZK_X509_MAX_CRL_AGE_SECONDS_V1
        );
    }
    for (this_update, next_update) in [(T, T), (T + 1, T), (u64::MAX, u64::MAX)] {
        assert_eq!(
            PrivacyZkX509PresentationBoundsV1::from_crl(crl(this_update, next_update)),
            Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidCrlUpdateInterval)
        );
    }
    // The minimal CRL covers its single second, which admits no window.
    let single = PrivacyZkX509PresentationBoundsV1::from_crl(crl(T, T + 1)).expect("CRL bounds");
    assert_eq!(single.latest_end_unix_seconds(), T);
    assert_eq!(
        single.widest_window_from(T),
        Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds)
    );
    // Saturating age arithmetic never wraps, and the calendar ceiling applies.
    assert_eq!(
        PrivacyZkX509PresentationBoundsV1::from_crl(crl(u64::MAX - 1, u64::MAX)),
        Err(PrivacyZkX509PresentationIntervalErrorV1::DisjointIntervals)
    );
    let last_calendar_crl = PrivacyZkX509PresentationBoundsV1::from_crl(crl(
        ZK_X509_MAX_UNIX_SECONDS_V1 - 10,
        u64::MAX,
    ))
    .expect("CRL bounds");
    assert_eq!(
        last_calendar_crl.latest_end_unix_seconds(),
        ZK_X509_MAX_UNIX_SECONDS_V1
    );
}

#[test]
fn certificate_path_bounds_reject_malformed_paths_and_cap_at_the_calendar() {
    assert_eq!(
        PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[]),
        Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidChainDepth)
    );
    assert_eq!(
        PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[WIDE]),
        Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidChainDepth)
    );
    assert_eq!(
        PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[WIDE; 4]),
        Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidChainDepth)
    );
    assert_eq!(
        PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[
            WIDE,
            validity(T + 1, T),
            validity(T + 3, T + 2),
        ]),
        Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidCertificateValidity { index: 1 })
    );
    assert_eq!(
        PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[
            validity(T + 200, T + 400),
            validity(T, T + 100),
        ]),
        Err(PrivacyZkX509PresentationIntervalErrorV1::DisjointIntervals)
    );
    let single_second = PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[
        validity(T, T + 100),
        validity(T + 100, T + 200),
    ])
    .expect("one shared second");
    assert_eq!(single_second.earliest_start_unix_seconds(), T + 100);
    assert_eq!(single_second.latest_end_unix_seconds(), T + 100);
    let beyond_calendar = PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[
        validity(T, u64::MAX),
        validity(T, u64::MAX),
    ])
    .expect("path bounds");
    assert_eq!(
        beyond_calendar.latest_end_unix_seconds(),
        ZK_X509_MAX_UNIX_SECONDS_V1
    );
    // Intersection is commutative and never widens either operand.
    let path = PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[
        validity(T + 20, T + 95),
        validity(T + 5, T + 90),
    ])
    .expect("path bounds");
    let crl_bounds =
        PrivacyZkX509PresentationBoundsV1::from_crl(crl(T + 30, T + 80)).expect("CRL bounds");
    let both = path.intersect(crl_bounds).expect("overlap");
    assert_eq!(crl_bounds.intersect(path), Ok(both));
    assert_eq!(both.earliest_start_unix_seconds(), T + 30);
    assert_eq!(both.latest_end_unix_seconds(), T + 79);
    assert_eq!(
        path.intersect(
            PrivacyZkX509PresentationBoundsV1::from_crl(crl(T + 91, T + 300)).expect("CRL bounds")
        ),
        Err(PrivacyZkX509PresentationIntervalErrorV1::DisjointIntervals)
    );
}

#[test]
fn window_shape_and_block_timestamp_admission_use_inclusive_seconds() {
    assert_eq!(window(T, T + 1).validate(), Ok(()));
    assert_eq!(window(T, T + 300).validate(), Ok(()));
    for (start, end) in [(T, T), (T, T - 1), (T, T + 301), (u64::MAX, 0)] {
        assert_eq!(
            window(start, end).validate(),
            Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidWindow {
                start,
                end,
                max_seconds: ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
            })
        );
    }
    let presentation = window(T, T + 60);
    assert!(!presentation.contains_unix_seconds(T - 1));
    assert!(presentation.contains_unix_seconds(T));
    assert!(presentation.contains_unix_seconds(T + 60));
    assert!(!presentation.contains_unix_seconds(T + 61));
    let first = presentation
        .first_admissible_block_timestamp_ms()
        .expect("start fits");
    let last = presentation
        .last_admissible_block_timestamp_ms()
        .expect("end fits");
    assert_eq!(first, T * 1_000);
    assert_eq!(last, (T + 61) * 1_000 - 1);
    assert!(!presentation.admits_block_timestamp_ms(first - 1));
    assert!(presentation.admits_block_timestamp_ms(first));
    assert!(presentation.admits_block_timestamp_ms(last));
    assert!(!presentation.admits_block_timestamp_ms(last + 1));
    for overflowing in [u64::MAX, u64::MAX / 1_000, u64::MAX / 1_000 + 1] {
        assert_eq!(
            window(0, overflowing).last_admissible_block_timestamp_ms(),
            Err(PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow)
        );
    }
    assert_eq!(
        window(u64::MAX / 1_000 + 1, u64::MAX).first_admissible_block_timestamp_ms(),
        Err(PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow)
    );
    assert_eq!(
        window(0, u64::MAX / 1_000 - 1).last_admissible_block_timestamp_ms(),
        Ok(u64::MAX / 1_000 * 1_000 - 1)
    );
}

#[test]
fn holder_deadline_is_the_minimum_of_every_signed_bound_and_the_public_end() {
    let certificates = [validity(T - 100, T + 250), WIDE, validity(T - 50, T + 240)];
    for (crl, earliest_bound) in [
        // CRL age binds: TU + 301.
        (crl(T - 100, T + 3_600), T - 100 + 301),
        // CRL nextUpdate binds.
        (crl(T, T + 220), T + 220),
        // Earliest certificate expiry binds: Cmin + 1.
        (crl(T, T + 301), T + 241),
    ] {
        let bounds = PrivacyZkX509PresentationBoundsV1::from_signed_intervals(&certificates, crl)
            .expect("overlapping signed intervals");
        for presentation_not_after in [T + 1, T + 150, T + 239, T + 240, T + 241, T + 300] {
            let expected_second = (crl.this_update_unix_seconds + 301)
                .min(crl.next_update_unix_seconds)
                .min(T + 241)
                .min(presentation_not_after + 1);
            assert_eq!(
                bounds.presentation_deadline_unix_ms(presentation_not_after),
                Ok(expected_second * 1_000 - 1)
            );
            assert!(expected_second <= earliest_bound);
        }
        assert_eq!(
            bounds.presentation_deadline_unix_ms(u64::MAX),
            Ok(earliest_bound * 1_000 - 1)
        );
    }
}

#[test]
fn private_interval_types_redact_debug_and_error_codes_are_distinct() {
    let bounds = PrivacyZkX509PresentationBoundsV1::from_certificate_path(&[WIDE, WIDE])
        .expect("path bounds");
    for rendered in [format!("{WIDE:?}"), format!("{bounds:?}")] {
        assert!(rendered.ends_with("{ <private material redacted> }"));
        assert!(!rendered.contains("1640995200") && !rendered.contains("1893456000"));
    }
    let errors = [
        PrivacyZkX509PresentationIntervalErrorV1::InvalidWindow {
            start: 2,
            end: 1,
            max_seconds: 300,
        },
        PrivacyZkX509PresentationIntervalErrorV1::InvalidChainDepth,
        PrivacyZkX509PresentationIntervalErrorV1::InvalidCertificateValidity { index: 2 },
        PrivacyZkX509PresentationIntervalErrorV1::InvalidCrlUpdateInterval,
        PrivacyZkX509PresentationIntervalErrorV1::DisjointIntervals,
        PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds,
        PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds,
        PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow,
    ];
    let codes: std::collections::BTreeSet<_> = errors.iter().map(|error| error.code()).collect();
    assert_eq!(codes.len(), errors.len());
    assert!(!codes.contains("admitted"));
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}

fn statement(start: u64, end: u64) -> IrohaZkX509StarkP256StatementV1 {
    let wallet = KeyPair::try_from_seed(vec![0x61; 32], Algorithm::Ed25519).expect("wallet key");
    IrohaZkX509StarkP256StatementV1 {
        context: PrivacyStatementContextV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x91; 32])),
            ),
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0x62; 32]),
            parameter_id: PrivacyParameterIdV1::new([0x63; 32]),
            parameter_digest: PrivacyParameterDigestV1::new([0x64; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new([0x65; 32]),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new([0x66; 32]),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new([0x67; 32]),
        },
        trust_anchor_id: PrivacyIssuerIdV1::new([0x51; 32]),
        certificate_policy_id: PrivacyPolicyIdV1::new([0x52; 32]),
        trust_anchor_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1::new([0x53; 32]),
        trust_anchor_record_epoch: 1,
        certificate_policy_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1::new(
            [0x54; 32],
        ),
        certificate_policy_record_epoch: 1,
        crl_record_digest: PrivacyZkX509CrlRecordDigestV1::new([0x55; 32]),
        crl_record_epoch: 1,
        subject_public_key_digest: PrivacyCertificateKeyDigestV1::new([0x56; 32]),
        ca_membership_root: PrivacyRootV1::new([0x57; 32]),
        ca_membership_root_epoch: 1,
        key_usage: PrivacyX509KeyUsageV1 {
            digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
            content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
            key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
            key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
        },
        extended_key_usages: vec![PrivacyX509ExtendedKeyUsageV1::ClientAuthentication],
        disclosed_attributes: vec![PrivacyZkX509DisclosedAttributeV1 {
            index: 3,
            attribute_digest: PrivacyAttributeDigestV1::new([0x58; 32]),
        }],
        presentation_not_before_unix_seconds: start,
        presentation_not_after_unix_seconds: end,
        wallet_account: AccountId::new(wallet.public_key().clone()),
        wallet_challenge: PrivacyChallengeV1::new([0x68; 32]),
        certificate_nullifier: PrivacyNullifierV1::new([0x59; 32]),
    }
}

#[test]
fn statement_and_crl_record_expose_the_canonical_interval_views() {
    use iroha_data_model::privacy::{
        PrivacyConsensusLimitsV1, PrivacyStatementV1, PrivacyStatementValidationError,
    };
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let admitted = statement(T, T + 300);
    assert_eq!(admitted.presentation_window(), window(T, T + 300));
    assert_eq!(admitted.presentation_window().validate(), Ok(()));
    PrivacyStatementV1::IrohaZkX509StarkP256V1(admitted)
        .validate(&limits)
        .expect("the exact presentation-window ceiling is admitted");
    // Statement validation is the canonical window shape, with its own error
    // identity preserved.
    for (start, end) in [(T, T), (T, T - 1), (T, T + 301)] {
        let rejected = statement(start, end);
        assert!(rejected.presentation_window().validate().is_err());
        assert_eq!(
            PrivacyStatementV1::IrohaZkX509StarkP256V1(rejected).validate(&limits),
            Err(
                PrivacyStatementValidationError::InvalidX509PresentationWindow {
                    start,
                    end,
                    max_seconds: ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
                }
            )
        );
    }
    let record = PrivacyZkX509CrlRecordV1::new(
        PrivacyIssuerIdV1::new([0x51; 32]),
        PrivacyPolicyIdV1::new([0x52; 32]),
        1,
        7,
        PrivacyX509CrlDerDigestV1::new([0x5a; 32]),
        PrivacyX509CrlIssuerSpkiDigestV1::new([0x5b; 32]),
        T,
        T + 300,
        None,
        PrivacyZkX509RecordLifecycleV1::Active,
    )
    .expect("canonical signed-CRL record");
    assert_eq!(record.update_interval(), crl(T, T + 300));
    let bounds =
        PrivacyZkX509PresentationBoundsV1::from_crl(record.update_interval()).expect("CRL bounds");
    assert_eq!(bounds.earliest_start_unix_seconds(), T);
    assert_eq!(bounds.latest_end_unix_seconds(), T + 299);
}

#[test]
fn bounds_containment_is_inclusive_and_is_the_crl_freshness_predicate_at_one_second() {
    let bounds = PrivacyZkX509PresentationBoundsV1::from_signed_intervals(
        &[validity(T + 10, T + 120), WIDE],
        crl(T, T + 301),
    )
    .expect("overlapping signed intervals");
    assert_eq!(bounds.earliest_start_unix_seconds(), T + 10);
    assert_eq!(bounds.latest_end_unix_seconds(), T + 120);
    for (second, inside) in [
        (T + 9, false),
        (T + 10, true),
        (T + 11, true),
        (T + 119, true),
        (T + 120, true),
        (T + 121, false),
        (0, false),
        (u64::MAX, false),
    ] {
        assert_eq!(
            bounds.contains_unix_seconds(second),
            inside,
            "second {second}"
        );
    }
    // Every second of every admitted window is contained, and both endpoints
    // of the bounds are admissible window endpoints.
    for start in (T + 10)..(T + 120) {
        let built = bounds.widest_window_from(start).expect("admissible start");
        assert!(bounds.contains_unix_seconds(built.not_before_unix_seconds));
        assert!(bounds.contains_unix_seconds(built.not_after_unix_seconds));
    }
    // CRL-only bounds: thisUpdate inclusive, nextUpdate exclusive, age capped.
    let short = PrivacyZkX509PresentationBoundsV1::from_crl(crl(T, T + 200)).expect("CRL bounds");
    assert!(!short.contains_unix_seconds(T - 1));
    assert!(short.contains_unix_seconds(T));
    assert!(short.contains_unix_seconds(T + 199));
    assert!(!short.contains_unix_seconds(T + 200));
    let long = PrivacyZkX509PresentationBoundsV1::from_crl(crl(T, T + 3_600)).expect("CRL bounds");
    assert!(long.contains_unix_seconds(T + 300));
    assert!(!long.contains_unix_seconds(T + 301));
}

/// A window endpoint that equals a bound only the private path imposes
/// publishes an exact certificate date; an endpoint the public CRL bounds
/// explain equally does not.
#[test]
fn window_publishes_private_bound_flags_exact_certificate_dates_only() {
    let fresh_crl = crl(T, T + 301);
    let public = PrivacyZkX509PresentationBoundsV1::from_crl(fresh_crl).expect("public CRL bounds");
    assert_eq!(public.earliest_start_unix_seconds(), T);
    assert_eq!(public.latest_end_unix_seconds(), T + 300);
    let combined = |certificates: &[PrivacyZkX509CertificateValidityV1]| {
        PrivacyZkX509PresentationBoundsV1::from_signed_intervals(certificates, fresh_crl)
            .expect("overlapping signed intervals")
    };
    // Private upper bound at each path position: the earliest notAfter binds.
    for position in 0..3 {
        let mut certificates = [WIDE; 3];
        certificates[position] = validity(WIDE.not_before_unix_seconds(), T + 150);
        let bounds = combined(&certificates);
        let widest = bounds.widest_window_from(T).expect("admissible start");
        assert_eq!(widest, window(T, T + 150));
        assert!(
            bounds.window_publishes_private_bound(public, widest),
            "position {position}: the widest window ends at the private expiry"
        );
        assert!(bounds.window_publishes_private_bound(public, window(T + 149, T + 150)));
        // Interior endpoints publish no exact date.
        for presentation in [window(T, T + 149), window(T + 1, T + 100), window(T, T + 1)] {
            assert_eq!(bounds.admit(presentation), Ok(()));
            assert!(
                !bounds.window_publishes_private_bound(public, presentation),
                "position {position}: [{}, {}]",
                presentation.not_before_unix_seconds,
                presentation.not_after_unix_seconds
            );
        }
    }
    // Private lower bound at each path position: the latest notBefore binds.
    for position in 0..3 {
        let mut certificates = [WIDE; 3];
        certificates[position] = validity(T + 40, WIDE.not_after_unix_seconds());
        let bounds = combined(&certificates);
        assert_eq!(bounds.earliest_start_unix_seconds(), T + 40);
        let clamped = bounds
            .widest_window_from(bounds.earliest_start_unix_seconds())
            .expect("admissible start");
        assert_eq!(clamped, window(T + 40, T + 300));
        assert!(
            bounds.window_publishes_private_bound(public, clamped),
            "position {position}: the clamped start is the private notBefore"
        );
        // The end of that window is the public CRL bound, so a later start
        // publishes nothing.
        assert!(!bounds.window_publishes_private_bound(public, window(T + 41, T + 300)));
    }
    // Both private bounds bind, on different certificates.
    let both = combined(&[validity(T + 20, T + 400), validity(T - 5, T + 90)]);
    assert!(both.window_publishes_private_bound(public, window(T + 20, T + 60)));
    assert!(both.window_publishes_private_bound(public, window(T + 30, T + 90)));
    assert!(both.window_publishes_private_bound(public, window(T + 20, T + 90)));
    assert!(!both.window_publishes_private_bound(public, window(T + 21, T + 89)));
    // Public ties: the certificate dates coincide with the public CRL bounds,
    // which already explain the endpoints.
    let tied = combined(&[validity(T, T + 300), WIDE]);
    assert_eq!(tied, public.intersect(tied).expect("overlap"));
    assert!(!tied.window_publishes_private_bound(public, window(T, T + 300)));
    // No certificate binds: the widest window carries only public bounds.
    let unbound = combined(&[WIDE, WIDE]);
    let widest = unbound.widest_window_from(T).expect("admissible start");
    assert_eq!(widest, window(T, T + 300));
    assert!(!unbound.window_publishes_private_bound(public, widest));
    // nextUpdate, not a certificate, binds a short CRL.
    let short_crl = crl(T, T + 200);
    let short_public =
        PrivacyZkX509PresentationBoundsV1::from_crl(short_crl).expect("public CRL bounds");
    let short = PrivacyZkX509PresentationBoundsV1::from_signed_intervals(&[WIDE, WIDE], short_crl)
        .expect("overlapping signed intervals");
    assert!(!short.window_publishes_private_bound(short_public, window(T, T + 199)));
}

/// Hand-written CRL registration freshness of
/// `iroha_core::smartcontracts::isi::privacy::validate_zk_x509_crl_freshness_v1`,
/// transcribed from the source lines pinned under `deferred` in
/// `specs/zk_x509_presentation_interval_sites.json`.
fn isi_crl_registration_freshness(
    record: PrivacyZkX509CrlUpdateIntervalV1,
    block_timestamp_ms: u64,
) -> bool {
    let block_unix_seconds = block_timestamp_ms / 1_000;
    if block_unix_seconds < record.this_update_unix_seconds
        || block_unix_seconds >= record.next_update_unix_seconds
    {
        return false;
    }
    let Some(age) = block_unix_seconds.checked_sub(record.this_update_unix_seconds) else {
        return false;
    };
    age <= ZK_X509_MAX_CRL_AGE_SECONDS_V1
}

/// Hand-written exclusive submission deadline of the two pinned
/// `(PA + 1) * 1000` sites.
fn hand_written_deadline_exclusive_millis(presentation_not_after: u64) -> Option<u64> {
    presentation_not_after
        .checked_add(1)
        .and_then(|seconds| seconds.checked_mul(1_000))
}

/// The sites that do not call the definition yet compute exactly what it
/// computes. X.6 migrates them; until then this grid and the source pins in
/// the site inventory keep them from drifting apart.
#[test]
fn deferred_sites_equal_the_canonical_definition_on_a_boundary_grid() {
    let max_second = u64::MAX / 1_000;
    let this_updates = [
        0,
        1,
        T,
        ZK_X509_MAX_UNIX_SECONDS_V1 - 301,
        ZK_X509_MAX_UNIX_SECONDS_V1 - 300,
        ZK_X509_MAX_UNIX_SECONDS_V1 - 1,
        ZK_X509_MAX_UNIX_SECONDS_V1,
        ZK_X509_MAX_UNIX_SECONDS_V1 + 1,
        max_second - 301,
        max_second,
        u64::MAX - 301,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut compared = 0_u64;
    let mut admitted = 0_u64;
    let mut beyond_calendar = 0_u64;
    for this_update in this_updates {
        let mut next_updates = vec![0, this_update.saturating_sub(1), u64::MAX];
        for offset in [0, 1, 2, 200, 299, 300, 301, 302, 3_600] {
            next_updates.extend(this_update.checked_add(offset));
        }
        for next_update in next_updates {
            let record = crl(this_update, next_update);
            let bounds = PrivacyZkX509PresentationBoundsV1::from_crl(record);
            let mut seconds = vec![
                0,
                ZK_X509_MAX_UNIX_SECONDS_V1 - 1,
                ZK_X509_MAX_UNIX_SECONDS_V1,
                ZK_X509_MAX_UNIX_SECONDS_V1 + 1,
                max_second,
            ];
            for anchor in [this_update, next_update] {
                seconds.extend(anchor.checked_sub(1));
                seconds.push(anchor);
                for offset in [1, 199, 299, 300, 301] {
                    seconds.extend(anchor.checked_add(offset));
                }
            }
            for second in seconds {
                // Every consensus timestamp is a `u64` millisecond count.
                if second > max_second {
                    continue;
                }
                for millisecond in [0, 1, 999] {
                    let Some(block_timestamp_ms) = (second * 1_000).checked_add(millisecond) else {
                        continue;
                    };
                    let hand_written = isi_crl_registration_freshness(record, block_timestamp_ms);
                    let canonical = bounds.is_ok_and(|bounds| {
                        bounds.contains_unix_seconds(block_timestamp_ms / 1_000)
                    });
                    if second <= ZK_X509_MAX_UNIX_SECONDS_V1 {
                        assert_eq!(
                            hand_written, canonical,
                            "CRL [{this_update}, {next_update}) at {block_timestamp_ms} ms"
                        );
                    } else {
                        // The one difference: the definition never admits a
                        // second after 9999-12-31T23:59:59Z, while the
                        // hand-written predicate has no calendar ceiling.
                        assert!(!canonical, "block second {second} is past the calendar");
                        beyond_calendar += u64::from(hand_written);
                    }
                    compared += 1;
                    admitted += u64::from(canonical);
                }
            }
        }
    }
    assert!(compared > 5_000, "compared {compared} grid points");
    assert!(admitted > 200, "admitted {admitted} grid points");
    assert!(
        beyond_calendar > 0,
        "the grid must reach the calendar ceiling difference"
    );
    // The two pinned `(PA + 1) * 1000` sites and the canonical accessor agree,
    // including on both overflow edges.
    for presentation_not_after in [
        0,
        1,
        T,
        ZK_X509_MAX_UNIX_SECONDS_V1,
        ZK_X509_MAX_UNIX_SECONDS_V1 + 1,
        max_second - 1,
        max_second,
        max_second + 1,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let canonical = window(0, presentation_not_after)
            .last_admissible_block_timestamp_ms()
            .ok()
            .map(|last| last + 1);
        assert_eq!(
            hand_written_deadline_exclusive_millis(presentation_not_after),
            canonical,
            "presentation end {presentation_not_after}"
        );
    }
    assert_eq!(hand_written_deadline_exclusive_millis(max_second), None);
    assert_eq!(
        hand_written_deadline_exclusive_millis(max_second - 1),
        Some(max_second * 1_000)
    );
    // The pinned network-test literal `trusted second + 300` is the end of the
    // widest builder window for a CRL signed at the trusted second.
    assert_eq!(ZK_X509_MAX_CRL_AGE_SECONDS_V1, 300);
    assert_eq!(ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1, 300);
    for trusted_second in [T, 1_785_024_000] {
        let bounds = PrivacyZkX509PresentationBoundsV1::from_signed_intervals(
            &[WIDE, WIDE],
            crl(trusted_second, trusted_second + 301),
        )
        .expect("overlapping signed intervals");
        assert_eq!(
            bounds.widest_window_from(trusted_second),
            Ok(window(
                trusted_second,
                trusted_second.checked_add(300).expect("fits")
            ))
        );
    }
}

use iroha_data_model::privacy::{
    PrivacyZkX509HolderBudgetV1, PrivacyZkX509HolderScheduleErrorV1,
    PrivacyZkX509HolderScheduleOutcomeV1, PrivacyZkX509HolderScheduleV1,
};

fn holder_budget(terms: [u64; 6]) -> PrivacyZkX509HolderBudgetV1 {
    PrivacyZkX509HolderBudgetV1 {
        observation_ms: terms[0],
        preparation_ms: terms[1],
        proving_ms: terms[2],
        publication_jitter_ms: terms[3],
        submission_ms: terms[4],
        clock_margin_ms: terms[5],
    }
}

#[test]
fn holder_budget_counts_every_named_term_and_rejects_aggregate_overflow() {
    assert_eq!(holder_budget([1, 2, 4, 8, 16, 32]).total_millis(), Ok(63));
    assert_eq!(holder_budget([0; 6]).total_millis(), Ok(0));
    for index in 0..6 {
        let mut terms = [0; 6];
        terms[index] = u64::MAX;
        assert_eq!(holder_budget(terms).total_millis(), Ok(u64::MAX));
        terms[(index + 1) % 6] = 1;
        assert_eq!(
            holder_budget(terms).total_millis(),
            Err(PrivacyZkX509HolderScheduleErrorV1::BudgetOverflow)
        );
    }
}

#[test]
fn holder_schedule_every_phase_can_exhaust_the_last_admissible_millisecond() {
    let original = statement(T, T + 200);
    let deadline = (T + 201) * 1_000 - 1;
    let schedule_start = deadline - 63;
    let schedule = PrivacyZkX509HolderScheduleV1::new(
        &original,
        &[WIDE, WIDE],
        crl(T, T + 301),
        holder_budget([1, 2, 4, 8, 16, 32]),
    )
    .expect("original intervals admit this public window");
    assert!(std::ptr::eq(schedule.original(), &original));
    assert_eq!(
        schedule.assess(&original.clone(), schedule_start),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
    );
    assert_eq!(
        schedule.assess(&original, schedule_start + 1),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
    );
    for index in 0..6 {
        let mut terms = [1, 2, 4, 8, 16, 32];
        terms[index] += 1;
        let over = PrivacyZkX509HolderScheduleV1::new(
            &original,
            &[WIDE, WIDE],
            crl(T, T + 301),
            holder_budget(terms),
        )
        .expect("one more budget millisecond is representable");
        assert_eq!(
            over.assess(&original, schedule_start),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
        );
    }
    let zero = PrivacyZkX509HolderScheduleV1::new(
        &original,
        &[WIDE, WIDE],
        crl(T, T + 301),
        holder_budget([0; 6]),
    )
    .expect("explicit zero estimates");
    assert_eq!(
        zero.assess(&original, deadline),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
    );
    assert_eq!(
        zero.assess(&original, deadline + 1),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
    );
}

#[test]
fn holder_schedule_uses_the_original_earliest_expiry_crl_and_public_window() {
    for (certificates, selected_crl, end) in [
        // Signed CRL age, exclusive nextUpdate, private intermediate expiry,
        // and a deliberately shorter public window each bind in turn.
        ([WIDE, WIDE, WIDE], crl(T, T + 3_600), T + 300),
        ([WIDE, WIDE, WIDE], crl(T, T + 220), T + 219),
        (
            [WIDE, validity(T - 10, T + 150), WIDE],
            crl(T, T + 301),
            T + 150,
        ),
        ([WIDE, WIDE, WIDE], crl(T, T + 301), T + 20),
    ] {
        let original = statement(T, end);
        let before = original.clone();
        let deadline = (end + 1) * 1_000 - 1;
        let schedule = PrivacyZkX509HolderScheduleV1::new(
            &original,
            &certificates,
            selected_crl,
            holder_budget([11, 13, 17, 19, 23, 29]),
        )
        .expect("the original signed intervals admit exactly this window");
        assert_eq!(
            schedule.assess(&original, deadline - 112),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
        );
        assert_eq!(
            schedule.assess(&original, deadline - 111),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
        );
        assert!(
            original
                .presentation_window()
                .admits_block_timestamp_ms(deadline)
        );
        assert!(
            !original
                .presentation_window()
                .admits_block_timestamp_ms(deadline + 1)
        );
        assert_eq!(schedule.original(), &before);
    }
}

#[test]
fn holder_schedule_rejects_invalid_original_intervals_without_clamping_or_defaults() {
    let valid = statement(T, T + 200);
    for (certificates, selected_crl, expected) in [
        (
            vec![WIDE],
            crl(T, T + 301),
            PrivacyZkX509PresentationIntervalErrorV1::InvalidChainDepth,
        ),
        (
            vec![WIDE, validity(T, T - 1)],
            crl(T, T + 301),
            PrivacyZkX509PresentationIntervalErrorV1::InvalidCertificateValidity { index: 1 },
        ),
        (
            vec![WIDE, WIDE],
            crl(T, T),
            PrivacyZkX509PresentationIntervalErrorV1::InvalidCrlUpdateInterval,
        ),
        (
            vec![WIDE, WIDE],
            crl(T + 1, T + 301),
            PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds,
        ),
        (
            vec![WIDE, WIDE],
            crl(T, T + 200),
            PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds,
        ),
        (
            vec![WIDE, validity(T - 1, T + 199)],
            crl(T, T + 301),
            PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds,
        ),
    ] {
        let error = PrivacyZkX509HolderScheduleV1::new(
            &valid,
            &certificates,
            selected_crl,
            holder_budget([0; 6]),
        )
        .expect_err("the original signed bounds are not replaceable local estimates");
        assert_eq!(
            error,
            PrivacyZkX509HolderScheduleErrorV1::Interval(expected)
        );
    }
    let invalid = statement(T, T);
    let error = PrivacyZkX509HolderScheduleV1::new(
        &invalid,
        &[WIDE, WIDE],
        crl(T, T + 301),
        holder_budget([0; 6]),
    )
    .expect_err("non-empty public window remains mandatory");
    assert_eq!(
        error,
        PrivacyZkX509HolderScheduleErrorV1::Interval(
            PrivacyZkX509PresentationIntervalErrorV1::InvalidWindow {
                start: T,
                end: T,
                max_seconds: 300,
            }
        )
    );
    assert_eq!(
        PrivacyZkX509HolderScheduleV1::new(
            &valid,
            &[WIDE, WIDE],
            crl(T, T + 301),
            holder_budget([u64::MAX, 0, 0, 0, 0, 1]),
        )
        .expect_err("no saturating budget"),
        PrivacyZkX509HolderScheduleErrorV1::BudgetOverflow
    );
}

#[test]
fn holder_schedule_supersession_compares_exact_identities_not_epoch_order_or_time() {
    let original = statement(T, T + 200);
    let schedule = PrivacyZkX509HolderScheduleV1::new(
        &original,
        &[WIDE, WIDE],
        crl(T, T + 301),
        holder_budget([1; 6]),
    )
    .expect("admitted original");
    let changes: [fn(&mut IrohaZkX509StarkP256StatementV1); 15] = [
        |value| value.trust_anchor_id = PrivacyIssuerIdV1::new([0xa1; 32]),
        |value| value.certificate_policy_id = PrivacyPolicyIdV1::new([0xa2; 32]),
        |value| {
            value.trust_anchor_record_digest =
                PrivacyZkX509TrustAnchorRecordDigestV1::new([0xa3; 32])
        },
        |value| {
            value.certificate_policy_record_digest =
                PrivacyZkX509CertificatePolicyRecordDigestV1::new([0xa4; 32])
        },
        |value| value.crl_record_digest = PrivacyZkX509CrlRecordDigestV1::new([0xa5; 32]),
        |value| value.trust_anchor_record_epoch = 0,
        |value| value.certificate_policy_record_epoch = 0,
        |value| value.crl_record_epoch = 0,
        |value| value.trust_anchor_record_epoch = 2,
        |value| value.certificate_policy_record_epoch = 2,
        |value| value.crl_record_epoch = 2,
        |value| value.ca_membership_root = PrivacyRootV1::new([0xa6; 32]),
        |value| value.ca_membership_root_epoch = 2,
        |value| value.wallet_challenge = PrivacyChallengeV1::new([0xa7; 32]),
        |value| value.context.parameter_digest = PrivacyParameterDigestV1::new([0xa8; 32]),
    ];
    for change in changes {
        let mut current = original.clone();
        change(&mut current);
        assert_eq!(
            current.presentation_window(),
            original.presentation_window()
        );
        assert_eq!(
            schedule.assess(&current, T * 1_000),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::Superseded)
        );
        // Supersession wins even when evaluating the old timing would overflow.
        assert_eq!(
            schedule.assess(&current, u64::MAX),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::Superseded)
        );
        assert!(std::ptr::eq(schedule.original(), &original));
    }
    let mut changed_window = original.clone();
    changed_window.presentation_not_after_unix_seconds += 1;
    assert_eq!(
        schedule.assess(&changed_window, T * 1_000),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::Superseded)
    );
    assert_eq!(
        schedule.assess(&original, T * 1_000),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
    );
}

#[test]
fn holder_schedule_completion_overflow_is_distinct_from_insufficient_time() {
    let original = statement(T, T + 200);
    let schedule = PrivacyZkX509HolderScheduleV1::new(
        &original,
        &[WIDE, WIDE],
        crl(T, T + 301),
        holder_budget([0, 0, 0, 0, 0, 1]),
    )
    .expect("one millisecond estimate");
    assert_eq!(
        schedule.assess(&original, u64::MAX),
        Err(PrivacyZkX509HolderScheduleErrorV1::CompletionOverflow)
    );
    assert_eq!(
        schedule.assess(&original, u64::MAX - 1),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
    );
}

#[test]
fn holder_schedule_redacts_private_bounds_and_does_not_authorize_block_time() {
    let original = statement(T, T + 200);
    let schedule = PrivacyZkX509HolderScheduleV1::new(
        &original,
        &[WIDE, validity(T - 17, T + 233)],
        crl(T, T + 301),
        holder_budget([1; 6]),
    )
    .expect("interior public window");
    assert_eq!(
        format!("{schedule:?}"),
        "PrivacyZkX509HolderScheduleV1 { <private material redacted> }"
    );
    for error in [
        PrivacyZkX509HolderScheduleErrorV1::Interval(
            PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds,
        ),
        PrivacyZkX509HolderScheduleErrorV1::Interval(
            PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds,
        ),
        PrivacyZkX509HolderScheduleErrorV1::BudgetOverflow,
        PrivacyZkX509HolderScheduleErrorV1::CompletionOverflow,
    ] {
        for rendered in [format!("{error:?}"), error.to_string()] {
            for private in [T - 17, T + 233, 1_640_995_200, 1_893_456_000] {
                assert!(!rendered.contains(&private.to_string()));
            }
        }
    }
    let early = (T - 1) * 1_000;
    assert_eq!(
        schedule.assess(&original, early),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
    );
    assert!(
        !original
            .presentation_window()
            .admits_block_timestamp_ms(early)
    );
    // A later observation does not mutate or advance an implicit clock owner.
    assert_eq!(
        schedule.assess(&original, (T + 201) * 1_000),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
    );
    assert_eq!(
        schedule.assess(&original, early),
        Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
    );
}

#[test]
fn holder_schedule_copy_preserves_the_original_borrow_and_budget() {
    let original = statement(T, T + 200);
    let schedule = PrivacyZkX509HolderScheduleV1::new(
        &original,
        &[WIDE, WIDE],
        crl(T, T + 301),
        holder_budget([1, 2, 3, 4, 5, 6]),
    )
    .expect("immutable borrowed scheduling estimate");
    let copied = schedule;
    let deadline = (T + 201) * 1_000 - 1;
    for value in [schedule, copied] {
        assert!(std::ptr::eq(value.original(), &original));
        assert_eq!(
            value.assess(&original, deadline - 21),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::WithinBudget)
        );
        assert_eq!(
            value.assess(&original, deadline - 20),
            Ok(PrivacyZkX509HolderScheduleOutcomeV1::Reprepare)
        );
        assert_eq!(
            format!("{value:?}"),
            "PrivacyZkX509HolderScheduleV1 { <private material redacted> }"
        );
    }
}
