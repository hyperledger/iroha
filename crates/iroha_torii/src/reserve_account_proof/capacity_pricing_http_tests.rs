//! Same-cut capacity/pricing over the real signed route and SDK before service activation.

use super::*;
use iroha_data_model::{
    isi::sorafs::{
        DecideSorafsReserveMovement, RegisterCapacityDeclaration, RequestSorafsReserveMovement,
    },
    sorafs::{
        capacity::CapacityDeclarationRecord, pricing::PricingScheduleRecord,
        reserve::ReserveMovementKindV1,
    },
};
use sorafs_manifest::{
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CapacityDeclarationV1, CapacityMetadataEntry,
        ChunkerCommitmentV1,
    },
    provider_advert::{CapabilityType, StakePointer},
};
use std::time::{Duration, Instant};

fn register_native_capacity(f: &mut Fixture) -> (CapacityDeclarationRecord, ProviderCreditRecord) {
    let digest = f.policy.digest().unwrap();
    let signed = f.chain.sign(
        &f.outsider_key,
        [RequestSorafsReserveMovement::new(
            [0x74; 32],
            f.provider,
            ReserveMovementKindV1::TopUp,
            "1".parse().unwrap(),
            1,
            digest,
        )
        .into()],
        5_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let signed = f.chain.sign(
        &f.manager_key,
        [DecideSorafsReserveMovement::new(
            [0x74; 32],
            2,
            digest,
            true,
            "Native HTTP capacity funding".into(),
        )
        .into()],
        6_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let credit = ProviderCreditRecord::new(
        f.provider,
        0_u32.into(),
        1_u32.into(),
        1_u32.into(),
        0_u32.into(),
        6,
        6,
        iroha_model_base::metadata::Metadata::default(),
    );
    let signed = f.chain.sign(
        &f.manager_key,
        [UpsertProviderCredit::new(None, credit.clone()).into()],
        7_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let declaration = CapacityDeclarationV1 {
        version: CAPACITY_DECLARATION_VERSION_V1,
        provider_id: *f.provider.as_bytes(),
        stake: StakePointer {
            pool_id: [0x75; 32],
            stake_amount: "1".parse().unwrap(),
        },
        committed_capacity_gib: 1,
        chunker_commitments: vec![ChunkerCommitmentV1 {
            profile_id: "sorafs.sf1@1.0.0".into(),
            profile_aliases: None,
            committed_gib: 1,
            capability_refs: vec![CapabilityType::ToriiGateway],
        }],
        lane_commitments: Vec::new(),
        pricing: None,
        valid_from: 100,
        valid_until: 2_000_000_000,
        metadata: vec![
            CapacityMetadataEntry {
                key: "sorafs.owner_account_id".into(),
                value: f.outsider.to_string(),
            },
            CapacityMetadataEntry {
                key: "sorafs.storage_class".into(),
                value: "hot".into(),
            },
            CapacityMetadataEntry {
                key: "note_a".into(),
                value: "a".repeat(3_000),
            },
            CapacityMetadataEntry {
                key: "note_b".into(),
                value: "b".repeat(3_000),
            },
        ],
    };
    declaration.validate().unwrap();
    let payload = norito::encode_canonical(&declaration).unwrap();
    assert!(payload.len() > 4_096);
    let signed = f.chain.sign(
        &f.outsider_key,
        [RegisterCapacityDeclaration::new(payload.clone()).into()],
        8_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let view = f.chain.state().view();
    let record = view
        .world()
        .capacity_declarations()
        .get(&f.provider)
        .unwrap()
        .clone();
    assert_eq!(record.declaration, payload);
    assert_eq!(record.provider_id, f.provider);
    assert_eq!(
        record.registered_epoch,
        f.chain.committed(f.chain.height()).block_time_ms() / 1_000
    );
    (record, credit)
}

#[test]
fn signed_sdk_capacity_and_pricing_are_exact_native_facts_before_service_activation() {
    let _auth = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let mut f = Fixture::new_with_owner_funds(true);
    f.publish_policy();
    f.register();
    let app = f.app(WORKING_BYTES);
    let mut server = LoopbackServer::start(app.clone());
    let client = iroha::client::Client::builder(iroha::config::Config {
        chain: f.chain.state().chain_id_ref().clone(),
        network_id: f.chain.network_id(),
        account: f.manager.clone(),
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        key_pair: f.manager_key.clone(),
        basic_auth: None,
        api_token: None,
        http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
        torii_api_url: format!("http://{}/", server.address).parse().unwrap(),
        torii_request_timeout: Duration::from_secs(10),
        transaction_ttl: Duration::from_secs(30),
        transaction_status_timeout: Duration::from_secs(30),
        transaction_add_nonce: true,
        sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
        sorafs_anonymity_policy: Default::default(),
        sorafs_rollout_phase: Default::default(),
    })
    .build()
    .unwrap();
    let schema = CoreState::native_world_schema_hash_v1().unwrap();
    let before_tip = f.verified_tip();
    let before = client
        .with_request_deadline(Instant::now() + Duration::from_secs(30))
        .get_reserve_account_state(
            &f.manager,
            f.provider,
            &f.outsider,
            &f.policy,
            schema,
            &before_tip,
        )
        .unwrap();
    assert!(before.capacity().is_none() && before.credit().is_none());
    assert_eq!(before.pricing(), &PricingScheduleRecord::launch_default());
    let (capacity, credit) = register_native_capacity(&mut f);
    let tip = f.verified_tip();
    let current = client
        .with_request_deadline(Instant::now() + Duration::from_secs(30))
        .get_reserve_account_state(&f.manager, f.provider, &f.outsider, &f.policy, schema, &tip)
        .unwrap();
    assert_eq!(current.capacity(), Some(&capacity));
    assert_eq!(current.credit(), Some(&credit));
    assert_eq!(current.pricing(), before.pricing());
    assert_eq!(current.height(), 8);
    assert_eq!(current.context_id(), tip.context_id());
    assert_eq!(
        current.current().unwrap().reserve_balance,
        "1".parse().unwrap()
    );
    assert!(current.current().unwrap().debt_principal.is_zero());
    assert!(current.capacity().unwrap().valid_from_epoch > current.block_time_ms() / 1_000);
    assert!(!app.sorafs_node.is_enabled());
    assert!(app.sorafs_reserve_transaction_signer.is_none());
    assert!(
        client
            .with_request_deadline(Instant::now() + Duration::from_secs(30))
            .get_reserve_account_state(
                &f.manager,
                f.provider,
                &f.outsider,
                &f.policy,
                schema,
                &before_tip
            )
            .is_err()
    );
    drop(client);
    server.stop().unwrap();
}
