//! Immutable compiler-captured identities for this source owner’s existing codecs.

const CASES: &[crate::captured_schema_tests::Case] = &[
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeeChargingMode>(
        "iroha_data_model::validation_fee::ValidationFeeChargingMode",
    ),
    crate::captured_schema_tests::Case::bidirectional::<
        super::ValidationFeeParliamentAuthorizationV1,
    >("iroha_data_model::validation_fee::ValidationFeeParliamentAuthorizationV1"),
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeePolicyRegistryEntryV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicyRegistryEntryV1",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeePolicyRegistryV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1",
    ),
    crate::captured_schema_tests::Case::paired_bidirectional::<super::ValidationFeePolicyHistoryV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicyHistoryV1",
    ),
    crate::captured_schema_tests::Case::bidirectional::<
        super::ValidationFeePolicySnapshotAvailableV1,
    >("iroha_data_model::validation_fee::ValidationFeePolicySnapshotAvailableV1"),
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeePolicySnapshotStatusV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicySnapshotStatusV1",
    ),
    crate::captured_schema_tests::Case::bidirectional::<
        super::ValidationFeePolicySnapshotCommitmentV1,
    >("iroha_data_model::validation_fee::ValidationFeePolicySnapshotCommitmentV1"),
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeePolicyWitnessProofV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicyWitnessProofV1",
    ),
    crate::captured_schema_tests::Case::serialize::<
        super::ValidationFeePolicyProposalFingerprintEnvelopeV1,
    >("iroha_data_model::validation_fee::ValidationFeePolicyProposalFingerprintEnvelopeV1"),
    crate::captured_schema_tests::Case::serialize::<
        super::ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1,
    >(
        "iroha_data_model::validation_fee::ValidationFeePayoutLifecycleProposalFingerprintEnvelopeV1",
    ),
    crate::captured_schema_tests::Case::serialize::<super::ValidationFeePolicyFingerprintPayloadV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicyFingerprintPayloadV1",
    ),
    crate::captured_schema_tests::Case::serialize::<
        super::ValidationFeePayoutLifecycleFingerprintPayloadV1,
    >("iroha_data_model::validation_fee::ValidationFeePayoutLifecycleFingerprintPayloadV1"),
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeeTreasuryPayoutBindingV1>(
        "iroha_data_model::validation_fee::ValidationFeeTreasuryPayoutBindingV1",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::ValidationFeePolicyV1>(
        "iroha_data_model::validation_fee::ValidationFeePolicyV1",
    ),
];

#[test]
fn captured_codec_schema_identities() {
    for case in CASES {
        case.check();
    }
}

crate::captured_schema_tests::native_capture::owner_printer!(CASES);
