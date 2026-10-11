//! Immutable compiler-captured identities for this source owner’s existing codecs.

const CASES: &[crate::captured_schema_tests::Case] = &[
    crate::captured_schema_tests::Case::paired_bidirectional::<super::PublicLaneValidatorRecord>(
        "iroha_data_model::nexus::staking::PublicLaneValidatorRecord",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::PublicLaneValidatorStatus>(
        "iroha_data_model::nexus::staking::PublicLaneValidatorStatus",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::PublicLaneStakeShare>(
        "iroha_data_model::nexus::staking::PublicLaneStakeShare",
    ),
    crate::captured_schema_tests::Case::bidirectional::<super::PublicLaneUnbonding>(
        "iroha_data_model::nexus::staking::PublicLaneUnbonding",
    ),
    crate::captured_schema_tests::Case::paired_bidirectional::<super::PublicLanePendingReward>(
        "iroha_data_model::nexus::staking::PublicLanePendingReward",
    ),
];

#[test]
fn captured_codec_schema_identities() {
    for case in CASES {
        case.check();
    }
}

crate::captured_schema_tests::native_capture::owner_printer!(CASES);
