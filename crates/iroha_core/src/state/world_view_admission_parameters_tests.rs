//! Admission projections borrow one original World view across later publications.

use super::*;
use iroha_data_model::{
    crypto_admission_policy::CryptoAdmissionPolicyV1,
    parameter::{Parameter, system::TransactionParameter},
};
use std::num::NonZeroU64;

fn publish_policy(world: &World, algorithm: Algorithm, max_bytes: u64) {
    let mut block = world.block();
    block
        .parameters
        .set_parameter(
            CryptoAdmissionPolicyV1::new(vec![algorithm])
                .unwrap()
                .into_parameter()
                .unwrap(),
        )
        .unwrap();
    block
        .parameters
        .set_parameter(Parameter::Transaction(TransactionParameter::MaxTxBytes(
            NonZeroU64::new(max_bytes).unwrap(),
        )))
        .unwrap();
    block.commit();
}

#[test]
fn admission_parameters_keep_the_original_view_across_policy_publication() {
    let world = World::new();
    publish_policy(&world, Algorithm::Ed25519, 131_072);
    let original_view = world.view();
    let original = original_view.transaction_admission_parameters();
    assert!(std::ptr::eq(original, original_view.parameters.get()));
    publish_policy(&world, Algorithm::Secp256k1, 262_144);
    let current_view = world.view();
    let current = current_view.transaction_admission_parameters();
    assert!(!std::ptr::eq(original, current));

    // This is a borrow of already validated source, so even a zero-byte decoder
    // allowance cannot cause a second parse or replace the retained view.
    norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 128), || {
        let retained = original_view.transaction_admission_parameters();
        assert!(std::ptr::eq(original, retained));
        assert_eq!(retained.transaction().max_tx_bytes.get(), 131_072);
        assert_eq!(
            retained
                .require_crypto_policy()
                .unwrap()
                .allowed_algorithms(),
            &[Algorithm::Ed25519]
        );
        assert_eq!(current.transaction().max_tx_bytes.get(), 262_144);
        assert_eq!(
            current
                .require_crypto_policy()
                .unwrap()
                .allowed_algorithms(),
            &[Algorithm::Secp256k1]
        );
    });
}

#[test]
fn admission_parameters_do_not_substitute_an_absent_original_policy() {
    let world = World::new();
    let view = world.view();
    norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 128), || {
        let original = view.transaction_admission_parameters();
        assert!(std::ptr::eq(original, view.parameters.get()));
        assert!(original.crypto_policy().is_none());
        assert_eq!(
            original.require_crypto_policy().unwrap_err(),
            "ordinary crypto policy has not been initialized by authenticated genesis"
        );
    });
}
