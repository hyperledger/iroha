//! Immutable compiler-captured identities for this source owner’s existing codecs.

const CASES: &[crate::captured_schema_tests::Case] = &[
    crate::captured_schema_tests::Case::bidirectional::<super::RiskOperation>(
        "iroha_data_model::fraud::types::RiskOperation",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::RiskContext>(
        "iroha_data_model::fraud::types::RiskContext",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::FeatureInput>(
        "iroha_data_model::fraud::types::FeatureInput",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::RiskQuery>(
        "iroha_data_model::fraud::types::RiskQuery",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::AssessmentDecision>(
        "iroha_data_model::fraud::types::AssessmentDecision",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::RuleOutcome>(
        "iroha_data_model::fraud::types::RuleOutcome",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::FraudAssessment>(
        "iroha_data_model::fraud::types::FraudAssessment",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::GovernanceExport>(
        "iroha_data_model::fraud::types::GovernanceExport",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::DecisionAggregate>(
        "iroha_data_model::fraud::types::DecisionAggregate",
    ),
];

#[test]
fn captured_codec_schema_identities() {
    for case in CASES {
        case.check();
    }
}

crate::captured_schema_tests::native_capture::owner_printer!(CASES);
