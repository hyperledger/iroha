//! Deterministic epoch-seed fixtures through actual typed contract invocations.

use super::*;

const SOURCE: &str = r#"seiyaku SeedFixture {
    view fn seed(int epoch) authorize(anyone) -> Option<bytes> {
        crypto::vrf::epoch_seed(epoch: epoch)
    }
    fixture seeded {
        vrf_epoch_seed(7, b"01234567890123456789012345678901");
    }
    #[test(fixture = "seeded")]
    fn exact_seed_and_missing_epoch() {
        let found = test::invoke_kotoage(kotoage: "seed", arguments: { epoch: 7 });
        match found {
            Option::some(seed_bytes) => { test::assert_eq(actual: seed_bytes, expected: b"01234567890123456789012345678901"); },
            Option::none => { test::assert(false); }
        }
        let missing = test::invoke_kotoage(kotoage: "seed", arguments: { epoch: 8 });
        match missing {
            Option::some(_) => { test::assert(false); },
            Option::none => {}
        }
    }
    #[test]
    fn seed_fixture_is_isolated_from_other_tests() {
        let missing = test::invoke_kotoage(kotoage: "seed", arguments: { epoch: 7 });
        match missing {
            Option::some(_) => { test::assert(false); },
            Option::none => {}
        }
    }
}"#;

fn run(source: &str) -> KotoTestRunReportV1 {
    let root = SourceModuleUnit {
        source_name: "seed.ko".into(),
        source: source.into(),
    };
    run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new(&root.source_name, 753),
        &root,
        &KotoTestModuleGraphV1::default(),
    )
    .expect("compile and run VRF fixture suite")
}

#[test]
fn vrf_fixture_supplies_exact_seed_and_keeps_test_cases_isolated() {
    let report = run(SOURCE);
    assert_eq!(report.cases.len(), 2);
    assert!(report.is_success(), "{report:#?}");
}

#[test]
fn vrf_fixture_rejects_invalid_epoch_or_seed_before_test_execution() {
    for (action, expected) in [
        (
            "vrf_epoch_seed(-1, b\"01234567890123456789012345678901\");",
            "unsigned 64-bit integer",
        ),
        (
            "vrf_epoch_seed(18446744073709551616, b\"01234567890123456789012345678901\");",
            "unsigned 64-bit integer",
        ),
        ("vrf_epoch_seed(7, b\"short\");", "exactly 32 bytes"),
        ("vrf_epoch_seed(7);", "expects 2 arguments"),
    ] {
        let source = SOURCE.replace(
            "vrf_epoch_seed(7, b\"01234567890123456789012345678901\");",
            action,
        );
        let report = run(&source);
        assert_eq!(report.failed(), 1, "{report:#?}");
        assert!(
            report.cases.iter().any(|case| case
                .failure
                .as_deref()
                .is_some_and(|failure| failure.contains(expected))),
            "{report:#?}"
        );
    }
}
