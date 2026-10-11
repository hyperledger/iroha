//! Exact network binding and archive rejection at the privacy JNI boundary.

use super::*;

#[test]
fn deployment_and_raw_genesis_must_match_the_exact_expected_network() {
    let expected = [0xA5; 32];
    let other = [0xA7; 32];
    let network = network_id_from_raw_bytes(&expected).expect("canonical network");
    let other_network = network_id_from_raw_bytes(&other).expect("other canonical network");
    assert!(java_privacy_deployment_network_matches(
        &network, &expected, &expected
    ));
    assert!(!java_privacy_deployment_network_matches(
        &network, &expected, &other
    ));
    assert!(!java_privacy_deployment_network_matches(
        &other_network,
        &other,
        &expected
    ));
    assert!(!java_privacy_deployment_network_matches(
        &network, &other, &expected
    ));
    assert!(!java_privacy_deployment_network_matches(
        &network,
        &expected,
        &[0xA4; 32]
    ));
}

#[test]
fn tuple_and_construction_reject_malformed_archives_before_admission() {
    assert!(!java_privacy_exact12_capability_tuple_admitted(
        b"archived-shell",
        0,
        &[0xA5; 32]
    ));
    assert!(!java_privacy_exact12_submit_proof_admitted(
        b"archived-shell",
        0,
        b"instruction",
        &[0xA5; 32],
    ));
}
