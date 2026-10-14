//! Torii account faucet tests.
#![cfg(feature = "app_api")]
use axum::{body::to_bytes, http::Request, response::Response};
use http::StatusCode;
use iroha_core::{
    governance::manifest::LaneManifestRegistry,
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{LaneAuthorityRoute, State, World, WorldReadOnly},
    tx::TransactionBuilder,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::AccountId,
    asset::{AssetDefinitionAlias, AssetDefinitionId, AssetId},
    isi::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    level::Level,
    nexus::PublicLaneMonetaryPlanV1,
    parameter::{Parameter, system::SumeragiNposParameters},
    prelude::{
        Account, Asset, AssetDefinition, Domain, InstructionBox, Log, Mint, SignedTransaction,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::numeric::Quantity;
use iroha_torii::{Torii, json_entry, json_object};
use iroha_version::codec::DecodeVersioned as _;
use scrypt::{Params as ScryptParams, scrypt as derive_scrypt};
use sha2::{Digest as _, Sha256};
use std::{
    num::{NonZeroU8, NonZeroU64},
    sync::Arc,
};
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
#[path = "accounts_faucet_policy_tests.rs"]
mod policy_tests;
struct FaucetTestContext {
    native_chain: parking_lot::Mutex<iroha_core::sumeragi::test_chain::CertifiedTestChain>,
    app: iroha_torii::TestApiRouterRuntime,
    state: Arc<State>,
    queue: Arc<Queue>,
    asset_definition_id: AssetDefinitionId,
    authority_id: AccountId,
    authority_key_pair: KeyPair,
    user_id: AccountId,
    other_user_id: AccountId,
    pow_difficulty_bits: u8,
    pow_scrypt_log_n: u8,
    pow_scrypt_r: u32,
    pow_scrypt_p: u32,
    pow_max_anchor_age_blocks: u64,
    _data_dir: tempfile::TempDir,
}
fn checked_faucet_account_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked faucet account fixture keypair")
}
fn checked_faucet_block_leader_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
        .expect("generate checked faucet block leader fixture keypair")
}
fn signed_faucet_beacon_fixture(
    network_id: iroha_data_model::NetworkId,
    budget: &iroha_allocation::AllocationBudget,
) -> (
    iroha_core::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1,
    iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1,
) {
    // Each original signed genesis has its own network identity; a process-wide
    // singleton would substitute the first test's authenticated beacon binding.
    iroha_core::beacon::signed_persisted_pulse_fixture_for_world(network_id, 5, budget)
}
#[test]
fn faucet_account_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_faucet_account_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture faucet account public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[test]
fn faucet_block_leader_fixture_uses_checked_bls_key_generation() {
    let key_pair = checked_faucet_block_leader_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture faucet block leader public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::BlsNormal);
}
fn build_faucet_test_context(prefund_user: bool) -> FaucetTestContext {
    build_faucet_test_context_with_registration(prefund_user, None, true)
}
fn build_faucet_test_context_with_selector(
    prefund_user: bool,
    faucet_selector: Option<&str>,
) -> FaucetTestContext {
    build_faucet_test_context_with_registration(prefund_user, faucet_selector, true)
}
fn build_faucet_test_context_with_registration(
    prefund_user: bool,
    faucet_selector: Option<&str>,
    register_user: bool,
) -> FaucetTestContext {
    build_faucet_test_context_with_enabled(prefund_user, faucet_selector, register_user, true)
}
fn build_faucet_test_context_with_enabled(
    prefund_user: bool,
    faucet_selector: Option<&str>,
    register_user: bool,
    faucet_enabled: bool,
) -> FaucetTestContext {
    build_faucet_test_context_with_authority(
        prefund_user,
        faucet_selector,
        register_user,
        faucet_enabled,
        false,
    )
}
fn build_faucet_test_context_with_authority(
    prefund_user: bool,
    faucet_selector: Option<&str>,
    register_user: bool,
    faucet_enabled: bool,
    authoritative: bool,
) -> FaucetTestContext {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let data_dir = tempfile::tempdir().expect("isolated faucet Torii persistence");
    cfg.torii.data_dir = data_dir
        .path()
        .canonicalize()
        .expect("canonical fixture directory");
    cfg.torii.sorafs_storage.data_dir = cfg.torii.data_dir.join("sorafs");
    cfg.torii.sorafs_discovery.replay_checkpoint_path =
        cfg.torii.data_dir.join("provider-replay.to");
    cfg.torii.da_ingest.replay_cache_store_dir = cfg.torii.data_dir.join("da-replay");
    cfg.torii.da_ingest.manifest_store_dir = cfg.torii.data_dir.join("da-manifests");
    cfg.torii.sorafs_gc.state_dir = Some(cfg.torii.sorafs_storage.data_dir.join("gc"));
    cfg.torii.sorafs_por.state_dir = cfg.torii.sorafs_storage.data_dir.join("por");
    cfg.torii.sorafs_por.drand.state_path = cfg
        .torii
        .sorafs_por
        .state_dir
        .join(iroha_config::parameters::defaults::sorafs::por::DRAND_STATE_FILE);
    cfg.torii.sorafs_por.vrf_state_path = cfg
        .torii
        .sorafs_por
        .state_dir
        .join(iroha_config::parameters::defaults::sorafs::por::VRF_STATE_FILE);
    let _kura = Kura::blank_kura_for_testing();
    let _query = LiveQueryStore::start_test();
    let validator_keys: Vec<_> = (0xD2..=0xD5)
        .map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("derive faucet validator fixture")
        })
        .collect();
    cfg.common.key_pair = validator_keys[0].clone();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let domain_id: DomainId = DomainId::try_new("sora", "universal").expect("domain id");
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "xor".parse().expect("asset name"),
    );
    let canonical_selector = asset_definition_id.to_string();
    let authority_kp = checked_faucet_account_key_fixture();
    let authority_id = AccountId::new(authority_kp.public_key().clone());
    let user_kp = checked_faucet_account_key_fixture();
    let user_id = AccountId::new(user_kp.public_key().clone());
    let other_user_kp = checked_faucet_account_key_fixture();
    let other_user_id = AccountId::new(other_user_kp.public_key().clone());
    let domain = Domain::new(domain_id.clone()).build(&authority_id);
    let authority_account = Account::new(authority_id.clone()).build(&authority_id);
    let other_user_account = Account::new(other_user_id.clone()).build(&authority_id);
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "XOR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority_id);
    let mut accounts = vec![authority_account, other_user_account];
    if register_user {
        accounts.push(Account::new(user_id.clone()).build(&authority_id));
    }
    accounts.extend(validator_keys.iter().map(|key_pair| {
        let account_id = AccountId::new(key_pair.public_key().clone());
        Account::new(account_id.clone()).build(&account_id)
    }));
    let staking = iroha_config::parameters::actual::NexusStaking::default();
    let stake_asset_id: AssetDefinitionId = staking.stake_asset_id.parse().expect("stake asset");
    let stake_domain = Domain::new(DomainId::try_new("nexus", "universal").expect("stake domain"))
        .build(&authority_id);
    let stake_definition = AssetDefinition::numeric(
        stake_asset_id.clone(),
        "Staked XOR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority_id);
    let escrow_id =
        AccountId::parse_encoded(&staking.stake_escrow_account_id).expect("stake escrow");
    accounts.push(Account::new(escrow_id.clone()).build(&escrow_id));
    let stake_assets = validator_keys.iter().map(|key_pair| {
        Asset::new(
            AssetId::new(
                stake_asset_id.clone(),
                AccountId::new(key_pair.public_key().clone()),
            ),
            Quantity::from(1_000_u32),
        )
    });
    let chain_id = iroha_model_base::chain::ChainId::from("test-chain");
    let _network_id = iroha_torii::test_utils::signed_query_network_id();
    let world = World::with_assets(
        [domain, stake_domain],
        accounts,
        [asset_definition, stake_definition],
        stake_assets,
        [],
    );
    {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ))
            .expect("valid default consensus parameters");
        block.commit();
    }
    if let Some(selector) = faucet_selector {
        if selector != canonical_selector {
            let alias: AssetDefinitionAlias = selector.parse().expect("asset alias");
            let mut block = world.block();
            let mut tx = block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            tx.bind_asset_definition_alias(&asset_definition_id, alias, None, None, 10_000)
                .expect("bind alias");
            tx.apply();
            block.commit();
        }
    }
    let mut seed_instructions: Vec<InstructionBox> = vec![
        Mint::asset_quantity(
            50_000_u32,
            AssetId::new(asset_definition_id.clone(), authority_id.clone()),
        )
        .into(),
    ];
    if prefund_user {
        seed_instructions.push(
            Mint::asset_quantity(
                1_u32,
                AssetId::new(asset_definition_id.clone(), user_id.clone()),
            )
            .into(),
        );
    }
    for key_pair in &validator_keys {
        let validator = AccountId::new(key_pair.public_key().clone());
        seed_instructions.push(
            RegisterPublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: PeerId::new(key_pair.public_key().clone()),
                stake_account: validator.clone(),
                initial_stake: Quantity::from(1_000_u32),
                metadata: Default::default(),
                monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(stake_asset_id.clone(), validator.clone()),
                    AssetId::new(stake_asset_id.clone(), escrow_id.clone()),
                    Quantity::from(1_000_u32),
                ),
            }
            .into(),
        );
        seed_instructions.push(
            ActivatePublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator,
            }
            .into(),
        );
    }
    let mut native_chain = fixtures::commit_genesis_fixture(
        world,
        chain_id.clone(),
        &authority_kp,
        seed_instructions,
        Some(validator_keys),
        iroha_primitives::time::TimeSource::new_system(),
    );
    let state = native_chain.state().clone();
    let kura = native_chain.kura().clone();
    let network_id = native_chain.network_id();
    let nexus = state.nexus_snapshot();
    let lane_manifests = Arc::new(LaneManifestRegistry::from_config(
        &nexus.lane_catalog,
        &nexus.governance,
        &nexus.registry,
    ));
    state.install_lane_manifests_for_testing(&lane_manifests);
    let committee = state
        .resolve_lane_committee(LaneAuthorityRoute::new(
            LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
        ))
        .expect("committed faucet fixture resolves real lane authority");
    assert_eq!(committee.validators().len(), 4);
    assert!(committee.validators().contains(&local_peer_id));
    advance_faucet_state_chain(
        &mut native_chain,
        &authority_id,
        &authority_kp,
        4,
        "reach faucet beacon pulse height",
    );
    {
        let header = iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(native_chain.height() + 1).unwrap(),
            Some(native_chain.committed(native_chain.height()).block_hash()),
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let (key_record, pulse) =
            signed_faucet_beacon_fixture(network_id, &state.ivm_execution_budget());
        block
            .world
            .install_global_beacon_fixture_for_testing(
                key_record,
                pulse,
                &iroha_core::beacon::pulse_context_fixture_v1(),
            )
            .expect("install proof-valid faucet query fixture bound to original network");
        block
            .commit_world_overlay_for_testing()
            .expect("publish faucet beacon query fixture");
    }
    let current_committee = state
        .resolve_lane_committee(LaneAuthorityRoute::new(
            LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
        ))
        .expect("faucet beacon anchor retains four-validator authority");
    assert_eq!(current_committee.validators().len(), 4);
    let pow_difficulty_bits = 5;
    let pow_scrypt_log_n = 4;
    let pow_scrypt_r = 1;
    let pow_scrypt_p = 1;
    let pow_max_anchor_age_blocks = 4;
    cfg.torii.faucet = faucet_enabled.then(|| iroha_config::parameters::actual::ToriiFaucet {
        authority: authority_id.clone(),
        private_key_file: "/runtime-only/faucet-signer.key".into(),
        signer: authority_kp.clone(),
        asset_definition_id: faucet_selector
            .unwrap_or(canonical_selector.as_str())
            .to_owned(),
        amount: 25_000_u32.into(),
        pow_difficulty_bits: NonZeroU8::new(pow_difficulty_bits)
            .expect("non-zero faucet pow difficulty"),
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        pow_max_anchor_age_blocks: std::num::NonZeroU64::new(pow_max_anchor_age_blocks)
            .expect("non-zero faucet pow anchor age"),
        pow_adaptive_lookback_blocks: 8,
        pow_adaptive_claims_per_extra_bit: 1,
        pow_adaptive_max_extra_bits: 2,
        pow_beacon_seed_enabled: true,
    });
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, events_sender));
    queue.install_lane_manifests_with_state_for_testing(&lane_manifests, &state);
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let da_receipt_signer = cfg.common.key_pair.clone();
    let torii = Torii::new(
        build_identity_test_fixture::build_identity(),
        chain_id.clone(),
        network_id,
        kiso,
        cfg.torii.clone(),
        queue.clone(),
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state.clone(),
        da_receipt_signer,
        iroha_torii::OnlinePeersProvider::new(peers_rx),
    )
    .expect("valid Torii faucet fixture");
    let torii = if authoritative {
        torii.with_local_peer_id(local_peer_id)
    } else {
        torii
    };
    FaucetTestContext {
        native_chain: parking_lot::Mutex::new(native_chain),
        app: torii
            .api_router_for_tests()
            .expect("test Torii router initializes"),
        state,
        queue,
        asset_definition_id,
        authority_id,
        authority_key_pair: authority_kp,
        user_id,
        other_user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        pow_max_anchor_age_blocks,
        _data_dir: data_dir,
    }
}
const FAUCET_POW_DOMAIN_SEPARATOR: &[u8] = b"iroha:accounts:faucet:pow:v1";
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0u32;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
            continue;
        }
        total += byte.leading_zeros();
        break;
    }
    total
}
fn faucet_beacon_seed_for_anchor(state: &State, anchor_height: u64) -> Option<[u8; 32]> {
    let view = state.view();
    iroha_core::beacon::verified_global_threshold_beacon_pulse_at_or_before_v1(
        view.world(),
        state.network_id_ref(),
        anchor_height,
    )
    .ok()
    .map(|pulse| pulse.seed)
}
fn faucet_pow_scrypt_params(log_n: u8, r: u32, p: u32) -> ScryptParams {
    ScryptParams::new(log_n, r, p, 32).expect("valid test scrypt params")
}
async fn expect_status(resp: Response, expected: StatusCode) -> Response {
    let status = resp.status();
    if status == expected {
        return resp;
    }
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body bytes");
    panic!(
        "expected status {}, got {} with body {}",
        expected,
        status,
        String::from_utf8_lossy(&body)
    );
}
fn faucet_post_request(path: &str, body: String) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::ACCEPT, "application/json")
        .extension(axum::extract::connect_info::ConnectInfo(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
        ))
        .body(axum::body::Body::from(body))
        .expect("faucet request")
}
fn faucet_mutation_binding(claim: &norito::json::Value) -> norito::json::Value {
    let typed: iroha::client::AccountFaucetClaimV1 =
        norito::json::from_value(claim.clone()).expect("typed claim");
    let wire = norito::codec::Encode::encode(&typed);
    let semantic = iroha_crypto::Hash::new_from_chunks(&[
        b"iroha:accounts:faucet:claim:v1\0",
        wire.as_slice(),
    ]);
    json_object(vec![
        json_entry("schema", "iroha.prepared-operation.binding.v1"),
        json_entry("semantic_hash_hex", hex::encode(semantic.as_ref())),
        json_entry("kind", "faucet"),
        json_entry("request_id", "22".repeat(32)),
        json_entry("execution_expires_at_unix_ms", u64::MAX),
    ])
}
async fn prepare_faucet_envelope(app: &axum::Router, claim_body: String) -> Response {
    let claim: norito::json::Value =
        norito::json::from_str(&claim_body).expect("decode faucet claim body");
    let request = json_object(vec![
        json_entry("schema", "iroha.accounts.faucet.prepare.v1"),
        json_entry("binding", faucet_mutation_binding(&claim)),
        json_entry(
            "fee_payment",
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        json_entry("claim", claim),
    ]);
    let request = norito::json::to_json(&request).expect("encode faucet prepare request");
    app.clone()
        .oneshot(faucet_post_request("/v1/accounts/faucet/prepare", request))
        .await
        .expect("faucet prepare response")
}
async fn prepare_and_submit_faucet(app: &axum::Router, claim_body: String) -> Response {
    let prepared = expect_status(
        prepare_faucet_envelope(app, claim_body).await,
        StatusCode::OK,
    )
    .await;
    let body = to_bytes(prepared.into_body(), usize::MAX)
        .await
        .expect("prepared faucet body");
    let prepared_json: norito::json::Value =
        norito::json::from_slice(&body).expect("prepared faucet JSON");
    let prepared_wire = hex::decode(
        prepared_json["signed_transaction_wire_hex"]
            .as_str()
            .expect("prepared transaction wire"),
    )
    .expect("decode prepared transaction wire");
    let prepared_tx =
        SignedTransaction::decode_all_versioned(&prepared_wire).expect("decode prepared tx");
    prepared_tx
        .verify_signature()
        .expect("exact current transaction signature");
    app.clone()
        .oneshot(faucet_post_request(
            "/v1/accounts/faucet",
            String::from_utf8(body.to_vec()).expect("prepared faucet UTF-8 JSON"),
        ))
        .await
        .expect("faucet submit response")
}

async fn expect_faucet_submit_without_local_authority(resp: Response) {
    let resp = expect_status(resp, StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|content_type| content_type.split(';').next() == Some("application/json")),
        "strict faucet response must be JSON"
    );
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("strict faucet response body");
    let payload: norito::json::Value =
        norito::json::from_slice(&body).expect("strict faucet response JSON");
    let expected_code = "route_unavailable";
    assert_eq!(payload["code"].as_str(), Some(expected_code), "{payload:?}");
    assert!(
        payload
            .as_object()
            .and_then(|object| object.get("outcome"))
            .is_none(),
        "a faucet write without an authoritative ingress route must not claim Pending"
    );
}

fn register_faucet_user_for_test(
    state: &Arc<State>,
    user_id: &AccountId,
    authority_id: &AccountId,
) {
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(u64::try_from(state.committed_height()).expect("height") + 1)
            .expect("fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing().insert_account_for_testing(
        user_id.clone(),
        Account::new(user_id.clone())
            .build(authority_id)
            .into_key_value()
            .1,
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("install existing account without a synthetic block");
}
fn faucet_pow_challenge(state: &State, account_id: &AccountId, anchor_height: u64) -> [u8; 32] {
    let anchor_block = state
        .block_by_height(
            usize::try_from(anchor_height)
                .ok()
                .and_then(std::num::NonZeroUsize::new)
                .expect("non-zero height"),
        )
        .expect("funded canonical history read")
        .expect("anchor block");
    let anchor_hash = anchor_block.hash();
    let challenge_salt = faucet_beacon_seed_for_anchor(state, anchor_height);
    let mut hasher = Sha256::new();
    hasher.update(FAUCET_POW_DOMAIN_SEPARATOR);
    hasher.update(state.network_id_ref().as_bytes());
    hasher.update(account_id.to_string().as_bytes());
    hasher.update(anchor_height.to_be_bytes());
    hasher.update(anchor_hash.as_ref());
    if let Some(challenge_salt) = challenge_salt.as_ref() {
        hasher.update(challenge_salt);
    }
    hasher.finalize().into()
}
fn solve_faucet_pow(
    state: &State,
    account_id: &AccountId,
    difficulty_bits: u8,
    scrypt_params: &ScryptParams,
) -> (u64, String) {
    let anchor_height = u64::try_from(state.committed_height()).expect("height fits");
    let challenge = faucet_pow_challenge(state, account_id, anchor_height);
    for nonce in 0u64.. {
        let nonce_bytes = nonce.to_be_bytes();
        let mut digest = [0u8; 32];
        derive_scrypt(&nonce_bytes, &challenge, scrypt_params, &mut digest)
            .expect("test scrypt digest");
        if leading_zero_bits(&digest) >= u32::from(difficulty_bits) {
            return (anchor_height, hex::encode(nonce_bytes));
        }
    }
    unreachable!("u64 nonce space exhausted");
}
fn advance_faucet_state_chain(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    authority_id: &AccountId,
    authority_key_pair: &KeyPair,
    blocks: u64,
    message: &str,
) {
    for index in 0..blocks {
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, format!("{message} {index}"))])
        .sign(authority_key_pair.private_key());
        assert_eq!(chain.commit(vec![tx]), vec![true]);
    }
}
fn advance_faucet_chain(context: &FaucetTestContext, blocks: u64) {
    advance_faucet_state_chain(
        &mut context.native_chain.lock(),
        &context.authority_id,
        &context.authority_key_pair,
        blocks,
        "age faucet anchor",
    );
}
#[tokio::test]
async fn accounts_faucet_prepared_transfer_fails_closed_without_local_authority() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        queue,
        asset_definition_id,
        authority_id,
        user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        ..
    } = build_faucet_test_context(false);
    let scrypt_params = faucet_pow_scrypt_params(pow_scrypt_log_n, pow_scrypt_r, pow_scrypt_p);
    let (pow_anchor_height, pow_nonce_hex) =
        solve_faucet_pow(&state, &user_id, pow_difficulty_bits, &scrypt_params);
    let body = json_object(vec![
        json_entry("account_id", user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let body = norito::json::to_json(&body).expect("serialize faucet request");
    let height_before = state.committed_height();
    let resp = prepare_and_submit_faucet(&app, body).await;
    expect_faucet_submit_without_local_authority(resp).await;
    assert_eq!(queue.active_len(), 0);
    assert_eq!(state.committed_height(), height_before);
    let view = state.view();
    let user_asset_id = AssetId::new(asset_definition_id.clone(), user_id.clone());
    assert!(view.world().asset(&user_asset_id).is_err());
    let authority_asset_id = AssetId::new(asset_definition_id, authority_id);
    let authority_asset = view
        .world()
        .asset(&authority_asset_id)
        .expect("authority faucet asset");
    assert_eq!(authority_asset.value().as_ref().to_string(), "50000");
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_faucet_prepares_registration_without_mutating_unfunded_account() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        queue,
        asset_definition_id,
        authority_id,
        user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        ..
    } = build_faucet_test_context_with_registration(false, None, false);
    let scrypt_params = faucet_pow_scrypt_params(pow_scrypt_log_n, pow_scrypt_r, pow_scrypt_p);
    let (pow_anchor_height, pow_nonce_hex) =
        solve_faucet_pow(&state, &user_id, pow_difficulty_bits, &scrypt_params);
    let body = json_object(vec![
        json_entry("account_id", user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let body = norito::json::to_json(&body).expect("serialize faucet request");
    let prepared = expect_status(prepare_faucet_envelope(&app, body).await, StatusCode::OK).await;
    assert_eq!(queue.active_len(), 0, "faucet prepare must not enqueue");
    assert!(state.view().world().account(&user_id).is_err());
    let prepared_body = to_bytes(prepared.into_body(), usize::MAX)
        .await
        .expect("prepared faucet body");
    let prepared_json: norito::json::Value =
        norito::json::from_slice(&prepared_body).expect("prepared faucet JSON");
    let prepared_hash = prepared_json["transaction_hash_hex"]
        .as_str()
        .expect("prepared transaction hash")
        .to_owned();
    let prepared_wire = hex::decode(
        prepared_json["signed_transaction_wire_hex"]
            .as_str()
            .expect("prepared transaction wire"),
    )
    .expect("decode prepared transaction wire");
    let prepared_tx =
        SignedTransaction::decode_all_versioned(&prepared_wire).expect("decode prepared tx");
    prepared_tx
        .verify_signature()
        .expect("exact current transaction signature");
    let marker_key: Name = iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY
        .parse()
        .expect("marker metadata key");
    assert_eq!(
        prepared_tx
            .metadata()
            .get(&marker_key)
            .expect("consensus claim marker version")
            .clone()
            .try_into_any_norito::<u64>()
            .expect("unsigned marker version"),
        iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1
    );
    let operation_key: Name = iroha_data_model::transaction::PREPARED_OPERATION_METADATA_KEY
        .parse()
        .expect("operation metadata key");
    assert_eq!(
        prepared_tx
            .metadata()
            .get(&operation_key)
            .expect("prepared operation")
            .clone()
            .try_into_any_norito::<String>()
            .expect("operation string"),
        iroha_data_model::transaction::PREPARED_FAUCET_OPERATION
    );
    let prepared_instructions: Vec<_> =
        prepared_tx.instructions().explicit_instructions().collect();
    assert_eq!(prepared_instructions.len(), 2);
    assert!(matches!(
        prepared_instructions[0]
            .as_any()
            .downcast_ref::<iroha_data_model::isi::RegisterBox>(),
        Some(iroha_data_model::isi::RegisterBox::Account(_))
    ));
    let prepared_body = String::from_utf8(prepared_body.to_vec()).expect("prepared UTF-8 JSON");
    let resp = app
        .clone()
        .oneshot(faucet_post_request("/v1/accounts/faucet", prepared_body))
        .await
        .expect("faucet submit response");
    expect_faucet_submit_without_local_authority(resp).await;
    assert_eq!(queue.active_len(), 0);
    let view = state.view();
    assert!(view.world().account(&user_id).is_err());
    let user_asset_id = AssetId::new(asset_definition_id, user_id.clone());
    assert!(view.world().asset(&user_asset_id).is_err());
    drop(view);

    // Seed only the account fixture so preparation's one-instruction form can
    // be checked without inventing a committed block.
    register_faucet_user_for_test(&state, &user_id, &authority_id);
    let (pow_anchor_height, pow_nonce_hex) = solve_faucet_pow(
        &state,
        &user_id,
        pow_difficulty_bits.saturating_add(1),
        &scrypt_params,
    );
    let post_onboarding_claim = json_object(vec![
        json_entry("account_id", user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let post_onboarding_claim =
        norito::json::to_json(&post_onboarding_claim).expect("serialize post-onboarding claim");
    let post_onboarding = expect_status(
        prepare_faucet_envelope(&app, post_onboarding_claim).await,
        StatusCode::OK,
    )
    .await;
    let post_body = to_bytes(post_onboarding.into_body(), usize::MAX)
        .await
        .expect("post-onboarding prepared body");
    let post_json: norito::json::Value =
        norito::json::from_slice(&post_body).expect("post-onboarding prepared JSON");
    assert_ne!(
        post_json["transaction_hash_hex"]
            .as_str()
            .expect("post-onboarding hash"),
        prepared_hash
    );
    let post_wire = hex::decode(
        post_json["signed_transaction_wire_hex"]
            .as_str()
            .expect("post-onboarding wire"),
    )
    .expect("decode post-onboarding wire");
    let post_tx =
        SignedTransaction::decode_all_versioned(&post_wire).expect("decode post-onboarding tx");
    post_tx
        .verify_signature()
        .expect("exact current transaction signature");
    assert_eq!(
        post_tx.instructions().explicit_instructions().count(),
        1,
        "post-onboarding faucet preparation must not be interchangeable with registration"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_faucet_preserves_prefunded_balance_without_local_authority() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        queue,
        asset_definition_id,
        authority_id,
        user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        ..
    } = build_faucet_test_context(true);
    let scrypt_params = faucet_pow_scrypt_params(pow_scrypt_log_n, pow_scrypt_r, pow_scrypt_p);
    let (pow_anchor_height, pow_nonce_hex) =
        solve_faucet_pow(&state, &user_id, pow_difficulty_bits, &scrypt_params);
    let body = json_object(vec![
        json_entry("account_id", user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let body = norito::json::to_json(&body).expect("serialize faucet request");
    let resp = prepare_and_submit_faucet(&app, body).await;
    expect_faucet_submit_without_local_authority(resp).await;
    assert_eq!(queue.active_len(), 0);
    let view = state.view();
    let user_asset_id = AssetId::new(asset_definition_id.clone(), user_id.clone());
    let user_asset = view
        .world()
        .asset(&user_asset_id)
        .expect("user faucet asset");
    assert_eq!(user_asset.value().as_ref().to_string(), "1");
    let authority_asset_id = AssetId::new(asset_definition_id, authority_id);
    let authority_asset = view
        .world()
        .asset(&authority_asset_id)
        .expect("authority faucet asset");
    assert_eq!(authority_asset.value().as_ref().to_string(), "50000");
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_faucet_repeated_claims_do_not_spend_without_local_authority() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        queue,
        asset_definition_id,
        authority_id,
        user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        ..
    } = build_faucet_test_context(false);
    let scrypt_params = faucet_pow_scrypt_params(pow_scrypt_log_n, pow_scrypt_r, pow_scrypt_p);
    for expected_extra_bits in [0_u8, 1] {
        let difficulty_bits = pow_difficulty_bits.saturating_add(expected_extra_bits);
        let (pow_anchor_height, pow_nonce_hex) =
            solve_faucet_pow(&state, &user_id, difficulty_bits, &scrypt_params);
        let body = json_object(vec![
            json_entry("account_id", user_id.to_string()),
            json_entry("pow_anchor_height", pow_anchor_height),
            json_entry("pow_nonce_hex", pow_nonce_hex),
        ]);
        let body = norito::json::to_json(&body).expect("serialize faucet request");
        let resp = prepare_and_submit_faucet(&app, body).await;
        expect_faucet_submit_without_local_authority(resp).await;
        assert_eq!(queue.active_len(), 0);
    }
    let view = state.view();
    let user_asset_id = AssetId::new(asset_definition_id.clone(), user_id.clone());
    assert!(view.world().asset(&user_asset_id).is_err());
    let authority_asset_id = AssetId::new(asset_definition_id, authority_id);
    let authority_balance = view
        .world()
        .asset(&authority_asset_id)
        .map(|asset| asset.value().as_ref().to_string())
        .unwrap_or_else(|_| "0".to_owned());
    assert_eq!(authority_balance, "50000");
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_faucet_prepares_alias_selector_config_but_needs_quorum() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        queue,
        asset_definition_id,
        authority_id,
        user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        ..
    } = build_faucet_test_context_with_selector(false, Some("xor#universal"));
    let scrypt_params = faucet_pow_scrypt_params(pow_scrypt_log_n, pow_scrypt_r, pow_scrypt_p);
    let (pow_anchor_height, pow_nonce_hex) =
        solve_faucet_pow(&state, &user_id, pow_difficulty_bits, &scrypt_params);
    let body = json_object(vec![
        json_entry("account_id", user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let body = norito::json::to_json(&body).expect("serialize faucet request");
    let resp = prepare_and_submit_faucet(&app, body).await;
    expect_faucet_submit_without_local_authority(resp).await;
    assert_eq!(queue.active_len(), 0);
    let view = state.view();
    let user_asset_id = AssetId::new(asset_definition_id.clone(), user_id.clone());
    assert!(view.world().asset(&user_asset_id).is_err());
    let authority_asset_id = AssetId::new(asset_definition_id, authority_id);
    let authority_asset = view
        .world()
        .asset(&authority_asset_id)
        .expect("authority faucet asset");
    assert_eq!(authority_asset.value().as_ref().to_string(), "50000");
    app.shutdown().await;
}

#[tokio::test]
async fn faucet_prepared_envelope_aging_reaches_authoritative_routing_gate() {
    let context = build_faucet_test_context(false);
    let scrypt_params = faucet_pow_scrypt_params(
        context.pow_scrypt_log_n,
        context.pow_scrypt_r,
        context.pow_scrypt_p,
    );
    let (pow_anchor_height, pow_nonce_hex) = solve_faucet_pow(
        &context.state,
        &context.user_id,
        context.pow_difficulty_bits,
        &scrypt_params,
    );
    let claim = json_object(vec![
        json_entry("account_id", context.user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let claim = norito::json::to_json(&claim).expect("serialize faucet claim");
    let prepared = expect_status(
        prepare_faucet_envelope(&context.app, claim).await,
        StatusCode::OK,
    )
    .await;
    let prepared_body = to_bytes(prepared.into_body(), usize::MAX)
        .await
        .expect("prepared faucet body");
    assert_eq!(context.queue.active_len(), 0);
    advance_faucet_chain(
        &context,
        context.pow_max_anchor_age_blocks.saturating_add(1),
    );
    let submitted = context
        .app
        .clone()
        .oneshot(faucet_post_request(
            "/v1/accounts/faucet",
            String::from_utf8(prepared_body.to_vec()).expect("prepared UTF-8 JSON"),
        ))
        .await
        .expect("aged faucet submit response");
    expect_faucet_submit_without_local_authority(submitted).await;
    assert_eq!(context.queue.active_len(), 0);
    context.app.shutdown().await;
}

#[tokio::test]
async fn faucet_submit_rejects_old_tampered_and_uncertified_exact_retries() {
    let context = build_faucet_test_context(false);
    let scrypt_params = faucet_pow_scrypt_params(
        context.pow_scrypt_log_n,
        context.pow_scrypt_r,
        context.pow_scrypt_p,
    );
    let (pow_anchor_height, pow_nonce_hex) = solve_faucet_pow(
        &context.state,
        &context.user_id,
        context.pow_difficulty_bits,
        &scrypt_params,
    );
    let claim = json_object(vec![
        json_entry("account_id", context.user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let claim_body = norito::json::to_json(&claim).expect("serialize faucet claim");
    let old = context
        .app
        .clone()
        .oneshot(faucet_post_request(
            "/v1/accounts/faucet",
            claim_body.clone(),
        ))
        .await
        .expect("old faucet request response");
    let _old = expect_status(old, StatusCode::BAD_REQUEST).await;

    let prepared = expect_status(
        prepare_faucet_envelope(&context.app, claim_body).await,
        StatusCode::OK,
    )
    .await;
    let prepared_body = to_bytes(prepared.into_body(), usize::MAX)
        .await
        .expect("prepared faucet body");
    let prepared_json: norito::json::Value =
        norito::json::from_slice(&prepared_body).expect("prepared faucet JSON");
    let prepared_wire = hex::decode(
        prepared_json["signed_transaction_wire_hex"]
            .as_str()
            .expect("prepared transaction wire"),
    )
    .expect("decode prepared transaction wire");
    let prepared_tx =
        SignedTransaction::decode_all_versioned(&prepared_wire).expect("decode prepared tx");
    prepared_tx
        .verify_signature()
        .expect("exact current transaction signature");
    for field in [
        "transaction_hash_hex",
        "signed_transaction_wire_sha256",
        "signed_transaction_wire_hex",
    ] {
        let mut tampered = prepared_json.clone();
        tampered.as_object_mut().expect("prepared object").insert(
            field.to_owned(),
            norito::json::Value::String("00".repeat(32)),
        );
        let response = context
            .app
            .clone()
            .oneshot(faucet_post_request(
                "/v1/accounts/faucet",
                norito::json::to_json(&tampered).expect("tampered JSON"),
            ))
            .await
            .expect("tampered submit response");
        let _response = expect_status(response, StatusCode::BAD_REQUEST).await;
    }
    assert_eq!(context.queue.active_len(), 0);

    let exact_body = String::from_utf8(prepared_body.to_vec()).expect("prepared UTF-8 JSON");
    let submitted = context
        .app
        .clone()
        .oneshot(faucet_post_request(
            "/v1/accounts/faucet",
            exact_body.clone(),
        ))
        .await
        .expect("faucet submit response");
    expect_faucet_submit_without_local_authority(submitted).await;
    let response_loss_replay = context
        .app
        .clone()
        .oneshot(faucet_post_request(
            "/v1/accounts/faucet",
            exact_body.clone(),
        ))
        .await
        .expect("faucet replay response");
    expect_faucet_submit_without_local_authority(response_loss_replay).await;
    assert_eq!(context.queue.active_len(), 0);
    let destination = AssetId::new(context.asset_definition_id.clone(), context.user_id.clone());
    assert!(context.state.view().world().asset(&destination).is_err());
    context.app.shutdown().await;
}

#[tokio::test]
async fn accounts_faucet_policy_exposes_exact_public_configuration() {
    let context = build_faucet_test_context(false);
    let height_before = context.state.committed_height();
    let queue_before = context.queue.active_len();
    let resp = context
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/accounts/faucet/policy")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    40000,
                ))))
                .body(axum::body::Body::empty())
                .expect("public policy request"),
        )
        .await
        .expect("faucet policy response");
    let resp = expect_status(resp, StatusCode::OK).await;
    assert_eq!(resp.headers()[http::header::CACHE_CONTROL], "no-store");
    assert_eq!(
        resp.headers()[http::header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    let body = to_bytes(resp.into_body(), 4096).await.expect("policy body");
    let payload: norito::json::Value = norito::json::from_slice(&body).expect("policy JSON");
    assert_eq!(
        payload,
        json_object(vec![
            json_entry("schema_version", 1_u16),
            json_entry("network_id", *context.state.network_id_ref()),
            json_entry(
                "network_prefix",
                iroha_data_model::account::address::chain_discriminant(),
            ),
            json_entry("authority", context.authority_id.to_string()),
            json_entry(
                "asset_definition_id",
                context.asset_definition_id.to_string()
            ),
            json_entry(
                "amount",
                iroha_primitives::numeric::Quantity::from(25_000_u32)
            ),
        ]),
        "discovery exposes only the exact public policy fields",
    );
    assert_eq!(context.state.committed_height(), height_before);
    assert_eq!(context.queue.active_len(), queue_before);
    context.app.shutdown().await;
}

#[tokio::test]
async fn accounts_faucet_policy_resolves_configured_asset_alias() {
    let context = build_faucet_test_context_with_selector(false, Some("xor#universal"));
    let resp = context
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/accounts/faucet/policy")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    40000,
                ))))
                .body(axum::body::Body::empty())
                .expect("policy alias request"),
        )
        .await
        .expect("policy alias response");
    let resp = expect_status(resp, StatusCode::OK).await;
    assert_eq!(resp.headers()[http::header::CACHE_CONTROL], "no-store");
    let body = to_bytes(resp.into_body(), 4096)
        .await
        .expect("policy alias body");
    let payload: norito::json::Value = norito::json::from_slice(&body).expect("policy alias JSON");
    let expected_asset_definition_id = context.asset_definition_id.to_string();
    assert_eq!(
        payload
            .get("asset_definition_id")
            .and_then(norito::json::Value::as_str),
        Some(expected_asset_definition_id.as_str()),
    );
    assert_eq!(context.queue.active_len(), 0);
    context.app.shutdown().await;
}

#[tokio::test]
async fn accounts_faucet_discovery_reports_disabled_service() {
    let context = build_faucet_test_context_with_enabled(false, None, true, false);
    for (path, status, code, message) in [
        (
            "/v1/accounts/faucet/policy",
            StatusCode::SERVICE_UNAVAILABLE,
            "account_faucet_disabled",
            "This network does not provide a testnet faucet.",
        ),
        (
            "/v1/accounts/faucet/puzzle",
            StatusCode::FORBIDDEN,
            "query_validation_failed",
            "Account faucet disabled",
        ),
    ] {
        let resp = context
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        40000,
                    ))))
                    .header(http::header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .expect("disabled faucet request"),
            )
            .await
            .expect("disabled faucet response");
        let resp = expect_status(resp, status).await;
        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("disabled body");
        let payload: norito::json::Value = norito::json::from_slice(&body).expect("disabled JSON");
        assert_eq!(
            payload.get("code").and_then(norito::json::Value::as_str),
            Some(code)
        );
        assert!(
            payload
                .get("message")
                .and_then(norito::json::Value::as_str)
                .expect("disabled message")
                .contains(message)
        );
    }
    assert_eq!(context.queue.active_len(), 0);
    context.app.shutdown().await;
}

#[tokio::test]
async fn accounts_faucet_puzzle_exposes_current_anchor() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        pow_max_anchor_age_blocks,
        ..
    } = build_faucet_test_context(false);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/accounts/faucet/puzzle")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("faucet puzzle response");
    let resp = expect_status(resp, StatusCode::OK).await;
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("puzzle body bytes");
    let payload =
        norito::json::from_slice::<norito::json::Value>(body.as_ref()).expect("parse puzzle json");
    let object = payload.as_object().expect("puzzle object");
    let anchor_height = u64::try_from(state.committed_height()).expect("height fits");
    let expected_salt = hex::encode(
        faucet_beacon_seed_for_anchor(&state, anchor_height)
            .expect("proof-valid faucet beacon seed"),
    );
    assert_eq!(
        object
            .get("difficulty_bits")
            .and_then(norito::json::Value::as_u64),
        Some(u64::from(pow_difficulty_bits))
    );
    assert_eq!(
        object
            .get("anchor_height")
            .and_then(norito::json::Value::as_u64),
        Some(anchor_height)
    );
    assert_eq!(
        object
            .get("max_anchor_age_blocks")
            .and_then(norito::json::Value::as_u64),
        Some(pow_max_anchor_age_blocks)
    );
    assert_eq!(
        object
            .get("challenge_salt_hex")
            .and_then(norito::json::Value::as_str),
        Some(expected_salt.as_str())
    );
    assert_eq!(
        object
            .get("scrypt_log_n")
            .and_then(norito::json::Value::as_u64),
        Some(u64::from(pow_scrypt_log_n))
    );
    assert_eq!(
        object.get("scrypt_r").and_then(norito::json::Value::as_u64),
        Some(u64::from(pow_scrypt_r))
    );
    assert_eq!(
        object.get("scrypt_p").and_then(norito::json::Value::as_u64),
        Some(u64::from(pow_scrypt_p))
    );
    assert_eq!(
        object
            .get("algorithm")
            .and_then(norito::json::Value::as_str),
        Some("scrypt-leading-zero-bits-v1")
    );
    let puzzle_network_id: iroha_data_model::NetworkId =
        norito::json::from_value(object.get("network_id").expect("puzzle network id").clone())
            .expect("canonical puzzle network id");
    assert_eq!(&puzzle_network_id, state.network_id_ref());
    assert!(!object.contains_key("chain_id"));
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_faucet_rejects_missing_pow_when_required() {
    let FaucetTestContext {
        _data_dir,
        app,
        user_id,
        queue,
        ..
    } = build_faucet_test_context(false);
    let claim = json_object(vec![
        json_entry("account_id", user_id.to_string()),
        json_entry("pow_anchor_height", 1_u64),
        json_entry("pow_nonce_hex", "00".repeat(32)),
    ]);
    let binding = faucet_mutation_binding(&claim);
    for missing in ["pow_anchor_height", "pow_nonce_hex"] {
        // Build the typed binding before deliberately breaking the claim so
        // the actual HTTP extractor, rather than the valid-claim helper, rejects it.
        let mut incomplete = claim.clone();
        incomplete
            .as_object_mut()
            .expect("claim object")
            .remove(missing);
        let body = json_object(vec![
            json_entry("schema", "iroha.accounts.faucet.prepare.v1"),
            json_entry("binding", binding.clone()),
            json_entry(
                "fee_payment",
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            ),
            json_entry("claim", incomplete),
        ]);
        let mut request = faucet_post_request(
            "/v1/accounts/faucet/prepare",
            norito::json::to_json(&body).expect("serialize malformed faucet request"),
        );
        request.headers_mut().insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let resp = app
            .clone()
            .oneshot(request)
            .await
            .expect("malformed faucet response");
        let resp = expect_status(resp, StatusCode::BAD_REQUEST).await;
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("malformed faucet response body");
        let body = String::from_utf8(body.to_vec()).expect("JSON rejection body");
        assert!(body.contains("request_json_invalid"), "{body}");
        assert!(body.contains(missing), "{body}");
    }
    assert_eq!(queue.active_len(), 0);
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_faucet_puzzle_ignores_uncertified_claim() {
    let FaucetTestContext {
        _data_dir,
        app,
        state,
        queue,
        other_user_id,
        pow_difficulty_bits,
        pow_scrypt_log_n,
        pow_scrypt_r,
        pow_scrypt_p,
        ..
    } = build_faucet_test_context(false);
    let scrypt_params = faucet_pow_scrypt_params(pow_scrypt_log_n, pow_scrypt_r, pow_scrypt_p);
    let (pow_anchor_height, pow_nonce_hex) =
        solve_faucet_pow(&state, &other_user_id, pow_difficulty_bits, &scrypt_params);
    let initial_claim_body = json_object(vec![
        json_entry("account_id", other_user_id.to_string()),
        json_entry("pow_anchor_height", pow_anchor_height),
        json_entry("pow_nonce_hex", pow_nonce_hex),
    ]);
    let initial_claim_body =
        norito::json::to_json(&initial_claim_body).expect("serialize initial faucet request");
    let resp = prepare_and_submit_faucet(&app, initial_claim_body).await;
    expect_faucet_submit_without_local_authority(resp).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/accounts/faucet/puzzle")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("faucet puzzle response");
    let resp = expect_status(resp, StatusCode::OK).await;
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("puzzle body bytes");
    let payload =
        norito::json::from_slice::<norito::json::Value>(body.as_ref()).expect("parse puzzle json");
    let object = payload.as_object().expect("puzzle object");
    assert_eq!(
        object
            .get("difficulty_bits")
            .and_then(norito::json::Value::as_u64),
        Some(u64::from(pow_difficulty_bits))
    );
    assert_eq!(
        object
            .get("anchor_height")
            .and_then(norito::json::Value::as_u64),
        Some(u64::try_from(state.committed_height()).expect("height fits"))
    );
    assert_eq!(queue.active_len(), 0);
    app.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;

#[tokio::test]
async fn authoritative_faucet_submission_executes_the_exact_prepared_transfer() {
    let context = build_faucet_test_context_with_authority(false, None, false, true, true);
    let params = faucet_pow_scrypt_params(
        context.pow_scrypt_log_n,
        context.pow_scrypt_r,
        context.pow_scrypt_p,
    );
    let (anchor, nonce) = solve_faucet_pow(
        &context.state,
        &context.user_id,
        context.pow_difficulty_bits,
        &params,
    );
    let body = norito::json::to_json(&json_object(vec![
        json_entry("account_id", context.user_id.to_string()),
        json_entry("pow_anchor_height", anchor),
        json_entry("pow_nonce_hex", nonce),
    ]))
    .unwrap();
    let response = prepare_and_submit_faucet(&context.app, body).await;
    let response = expect_status(response, StatusCode::ACCEPTED).await;
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let pending: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(pending["outcome"].as_str(), Some("Pending"));
    assert_eq!(context.queue.active_len(), 1);
    assert!(
        context
            .state
            .view()
            .world()
            .account(&context.user_id)
            .is_err()
    );
    assert_eq!(
        iroha_torii::test_utils::apply_queued_in_one_block(
            &mut context.native_chain.lock(),
            &context.queue
        ),
        1
    );
    let view = context.state.view();
    assert!(view.world().account(&context.user_id).is_ok());
    let destination = AssetId::new(context.asset_definition_id.clone(), context.user_id.clone());
    let source = AssetId::new(
        context.asset_definition_id.clone(),
        context.authority_id.clone(),
    );
    assert_eq!(
        view.world()
            .asset(&destination)
            .unwrap()
            .value()
            .as_ref()
            .to_string(),
        "25000"
    );
    assert_eq!(
        view.world()
            .asset(&source)
            .unwrap()
            .value()
            .as_ref()
            .to_string(),
        "25000"
    );
    assert_eq!(context.queue.active_len(), 0);
    drop(view);
    context.app.shutdown().await;
}
