//! Nexus asset-selector configuration parsing tests.

use super::*;
fn checked_nexus_contract_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked Nexus contract Ed25519 account key fixture")
}
#[test]
fn nexus_contract_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_nexus_contract_ed25519_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("Nexus contract fixture account key advertises a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[test]
fn nexus_staking_parse_accepts_asset_alias_selector() {
    let cfg = NexusStaking {
        stake_asset_id: "xor#universal".to_owned(),
        ..NexusStaking::default()
    };
    let mut emitter = Emitter::new();
    let parsed = cfg
        .parse(&mut emitter)
        .expect("staking config should parse");
    assert_eq!(parsed.stake_asset_id, "xor#universal");
    assert!(emitter.into_result().is_ok());
}
