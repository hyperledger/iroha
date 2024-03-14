//! The verifiable random function used by sumeragi.
use ::vrf::{
    openssl::{CipherSuite, ECVRF},
    VRF,
};
use iroha_crypto::{KeyPair, PublicKey};

/// Perform the verifiable random function
pub fn perform_vrf(old_state: &Vec<u8>, kp: &KeyPair) -> Vec<u8> {
    assert!(kp.algorithm() == iroha_crypto::Algorithm::Secp256k1);
    let mut ctx = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).expect("Cannot fail");
    ctx.prove(&kp.private_key().to_bytes().1, old_state.as_ref())
        .expect("Is not allowed to fail")
}
/// Verify the verifiable random function
pub fn verify_vrf(old_state: &Vec<u8>, new_state: &Vec<u8>, pk: &PublicKey) -> bool {
    assert!(pk.algorithm() == iroha_crypto::Algorithm::Secp256k1);

    let mut ctx = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).expect("Cannot fail");
    ctx.verify(&pk.to_bytes().1, new_state.as_ref(), old_state.as_ref())
        .is_ok()
}
