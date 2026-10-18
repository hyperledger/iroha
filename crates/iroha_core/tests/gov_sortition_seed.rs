//! Deterministic sortition seed computation for governance draws.

use iroha_core::governance::sortition::compute_seed;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{NetworkId, block::BlockHeader};
fn test_network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([seed; Hash::LENGTH]),
    ))
}
#[test]
fn sortition_seed_is_deterministic_and_domain_separated() {
    let network_id = test_network_id(0x11);
    let beacon = [0xAB; 32];
    let epoch = 42u64;
    let seed_a = compute_seed(&network_id, epoch, &beacon, b"gov:draw:v1");
    let seed_b = compute_seed(&network_id, epoch, &beacon, b"gov:draw:v1");
    assert_eq!(seed_a, seed_b);
    let seed_other_domain = compute_seed(&network_id, epoch, &beacon, b"gov:draw:v2");
    assert_ne!(seed_a, seed_other_domain);
    let seed_other_network = compute_seed(&test_network_id(0x22), epoch, &beacon, b"gov:draw:v1");
    assert_ne!(seed_a, seed_other_network);
}
