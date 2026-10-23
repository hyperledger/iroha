//! Structural policy validation over original restored parameter cuts.

use super::*;
use iroha_crypto::Algorithm;
use iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1;

fn commit_policy(world: &World, algorithm: Algorithm) {
    let policy = CryptoAdmissionPolicyV1::new(vec![algorithm]).unwrap();
    let mut original = world.parameters.block();
    original
        .get_mut()
        .set_parameter(policy.into_parameter().unwrap())
        .unwrap();
    original.commit();
}

#[test]
fn restored_history_requires_policy_in_each_initialized_original_cut() {
    // These are structural parameter cuts, not fabricated native block authority.
    let world = World::default();
    validate_restored_crypto_policy(&world, 0).unwrap();
    let before = norito::json::to_json(&world).unwrap();
    assert!(validate_restored_crypto_policy(&world, 1).is_err());
    assert_eq!(norito::json::to_json(&world).unwrap(), before);
    commit_policy(&world, Algorithm::Ed25519);
    validate_restored_crypto_policy(&world, 1).unwrap();
    let before = norito::json::to_json(&world).unwrap();
    assert!(validate_restored_crypto_policy(&world, 2).is_err());
    assert_eq!(norito::json::to_json(&world).unwrap(), before);
    commit_policy(&world, Algorithm::Secp256k1);
    validate_restored_crypto_policy(&world, 2).unwrap();
    assert_eq!(
        world
            .parameters
            .view()
            .get()
            .require_crypto_policy()
            .unwrap()
            .allowed_algorithms(),
        &[Algorithm::Secp256k1]
    );
    assert_eq!(
        world
            .parameters
            .predecessor_view()
            .get()
            .as_ref()
            .unwrap()
            .require_crypto_policy()
            .unwrap()
            .allowed_algorithms(),
        &[Algorithm::Ed25519]
    );
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(0, 0, 0, 0, 0));
    zero.with(|| validate_restored_crypto_policy(&world, 2))
        .unwrap();
}

#[test]
fn unchanged_parameter_commit_restores_the_same_initialized_current_and_predecessor_cut() {
    let world = World::default();
    // An absent undo does not make an uninitialized current value acceptable.
    world.parameters.block().commit();
    assert!(world.parameters.predecessor_view().get().is_none());
    for height in [1, 2, 3] {
        assert!(validate_restored_crypto_policy(&world, height).is_err());
    }

    commit_policy(&world, Algorithm::Ed25519);
    validate_restored_crypto_policy(&world, 1).unwrap();
    // A real unchanged block removes the undo payload. Canonical MV replacement
    // then reads the unchanged current value as its original predecessor.
    world.parameters.block().commit();
    assert!(world.parameters.predecessor_view().get().is_none());
    let before = norito::json::to_json(&world).unwrap();
    for height in [2, 3] {
        validate_restored_crypto_policy(&world, height).unwrap();
        let replacement = world.parameters.block_and_revert();
        assert_eq!(
            replacement
                .get_before_block()
                .require_crypto_policy()
                .unwrap()
                .allowed_algorithms(),
            &[Algorithm::Ed25519]
        );
        assert_eq!(replacement.get(), replacement.get_before_block());
        drop(replacement);
        assert_eq!(norito::json::to_json(&world).unwrap(), before);
    }
}
