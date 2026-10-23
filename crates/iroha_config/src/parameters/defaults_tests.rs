//! Tests for the built-in parameter defaults.
use super::{governance, network, nexus::fees, oracle, pipeline, queue, torii};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::AccountId;
#[test]
fn gas_technical_account_matches_default_bootstrap_identity() {
    let _chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        super::common::chain_discriminant(),
    );
    let parsed = AccountId::parse_encoded(pipeline::GAS_TECH_ACCOUNT_ID)
        .expect("default gas technical account must be canonical I105");
    assert_eq!(parsed, governance::bond_escrow_account_id());
}
#[test]
fn sponsor_vault_custody_account_is_canonical_and_dedicated() {
    let _chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        super::common::chain_discriminant(),
    );
    let parsed = AccountId::parse_encoded(fees::SPONSOR_VAULT_CUSTODY_ACCOUNT_ID)
        .expect("default sponsor vault custody account must be canonical I105");
    assert_eq!(parsed, fees::sponsor_vault_custody_account_id());
    assert_ne!(parsed.to_string(), pipeline::GAS_TECH_ACCOUNT_ID);
}
#[test]
fn jdg_signature_schemes_includes_simple_threshold() {
    let schemes = governance::jdg_signature_schemes();
    assert!(schemes.contains(&"simple_threshold".to_string()));
}
#[test]
fn soracloud_public_runtime_defaults_are_non_zero() {
    assert_eq!(torii::SORACLOUD_PUBLIC_RATE_PER_IP_PER_SEC, Some(1_000_000));
    assert_eq!(torii::SORACLOUD_PUBLIC_BURST_PER_IP, Some(10_000_000));
    assert_eq!(torii::SORACLOUD_PUBLIC_MAX_INFLIGHT.get(), 32);
    assert_eq!(
        torii::SORACLOUD_PUBLIC_MAX_RESPONSE_BYTES.get(),
        64 * 1024 * 1024
    );
    assert_eq!(
        torii::SORACLOUD_MUTATION_RATE_PER_ACCOUNT_ORIGIN_PER_SEC,
        Some(1_000_000)
    );
    assert_eq!(
        torii::SORACLOUD_MUTATION_BURST_PER_ACCOUNT_ORIGIN,
        Some(10_000_000)
    );
    assert_eq!(torii::SORACLOUD_MUTATION_MAX_INFLIGHT.get(), 64);
}

#[test]
fn queue_defaults_allow_two_times_legacy_soak_capacity() {
    assert_eq!(queue::CAPACITY.get(), 262_144);
    assert_eq!(queue::CAPACITY_PER_USER.get(), 16_384);
    assert!(queue::CAPACITY_PER_USER < queue::CAPACITY);
    assert_eq!(queue::MAX_RETAINED_BYTES.get(), 128 * 1024 * 1024);
}
#[test]
fn quic_datagrams_default_fail_closed() {
    const {
        assert!(!network::QUIC_DATAGRAMS_ENABLED);
    };
}
#[test]
fn oracle_custody_defaults_are_public_only_and_not_legacy_seeded() {
    let legacy_reward_pool_keypair =
        KeyPair::try_from_seed(b"oracle-reward-pool".to_vec(), Algorithm::Ed25519)
            .expect("legacy reward-pool seed derives");
    let legacy_slash_receiver_keypair =
        KeyPair::try_from_seed(b"oracle-slash-receiver".to_vec(), Algorithm::Ed25519)
            .expect("legacy slash-receiver seed derives");
    let reward_pool = oracle::reward_pool();
    let slash_receiver = oracle::slash_receiver();
    assert_eq!(
        reward_pool,
        AccountId::new(
            oracle::REWARD_POOL_PUBLIC_KEY
                .parse()
                .expect("reward-pool public key")
        )
    );
    assert_eq!(
        slash_receiver,
        AccountId::new(
            oracle::SLASH_RECEIVER_PUBLIC_KEY
                .parse()
                .expect("slash-receiver public key")
        )
    );
    assert_ne!(reward_pool, slash_receiver);
    assert_ne!(
        reward_pool,
        AccountId::new(legacy_reward_pool_keypair.public_key().clone())
    );
    assert_ne!(
        slash_receiver,
        AccountId::new(legacy_slash_receiver_keypair.public_key().clone())
    );
}

#[test]
fn genesis_fee_defaults_do_not_consume_input_decode_quota() {
    let chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        super::common::chain_discriminant(),
    );
    let expected_fee_sink = AccountId::parse_encoded(fees::FEE_SINK_ACCOUNT_ID).unwrap();
    let expected_sponsor =
        AccountId::parse_encoded(fees::SPONSOR_VAULT_CUSTODY_ACCOUNT_ID).unwrap();
    drop(chain);
    let quota = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let policy = norito::with_decode_limits_scope(quota, fees::genesis_policy);
    assert!(policy.successful_claim_fee_exempt_authorities.is_empty());
    assert_eq!(policy.fee_sink_account_id, expected_fee_sink);
    assert_eq!(policy.sponsor_vault_custody_account_id, expected_sponsor);
    // Runtime input parsing must still enforce the same caller-owned limit.
    norito::with_decode_limits_scope(quota, || {
        assert!(
            AccountId::parse_encoded(fees::FEE_SINK_ACCOUNT_ID)
                .unwrap_err()
                .is_decode_resource_limit()
        );
    });
}
