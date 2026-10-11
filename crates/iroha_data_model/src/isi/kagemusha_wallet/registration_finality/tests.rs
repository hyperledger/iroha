//! Semantic DATA projection deliberately cannot manufacture finalized registration.
use super::*;
use crate::{
    block::output_test_support,
    kagemusha::{KagemushaDevicePublicKeyV1, kagemusha_wallet_provider_contract_v1},
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
};

#[test]
fn non_register_and_invalid_selected_originals_are_not_registration_data() {
    let fixture = NativeFinalityFixture::new();
    let verified = fixture
        .verifier()
        .verify_retained_decision(fixture.latest())
        .unwrap();
    let committed = output_test_support::committed(verified.block(), 0);
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *fixture.network_id().as_bytes(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    assert!(
        project_kagemusha_wallet_registration_v1(
            &committed,
            fixture.network_id(),
            &scheme,
            [1; 32],
            0
        )
        .is_err()
    );
}
