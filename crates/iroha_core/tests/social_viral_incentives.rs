//! Viral incentive component flows (SOC-2): rewards, escrows, caps, and controls.
//! The explicit finite protocol pool is fixture custody, not an authenticated
//! Network input, retained finality source, or block publication capability.

use iroha_config::parameters::{actual::ViralIncentives, defaults};
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute as _,
    state::{State, StateTransaction, World, WorldReadOnly},
};
use iroha_crypto::{Hash, KeyPair, PrivateKey, SignatureOf};
use iroha_data_model::{
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
    block::BlockHeader,
    domain::Domain,
    isi::{
        AggregateOracleFeed, RecordTwitterBinding, RegisterOracleFeed, SubmitOracleObservation,
        social::{CancelTwitterEscrow, ClaimTwitterFollowReward, SendToTwitter},
    },
    nexus::UniversalAccountId,
    oracle::{
        FeedConfig, FeedConfigVersion, FeedId, KeyedHash, Observation, ObservationBody,
        ObservationOutcome, TWITTER_FOLLOW_FEED_ID, TwitterBindingAttestation,
        TwitterBindingStatus,
    },
    permission::Permission,
    prelude::*,
};
use iroha_executor_data_model::permission::oracle as oracle_permission;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use norito::codec::Encode;
use std::num::NonZeroU64;
fn oracle_config() -> iroha_config::parameters::actual::Oracle {
    use iroha_config::parameters::actual::{
        Oracle as OracleConfig, OracleChangeThresholds, OracleEconomics, OracleGovernance,
        OracleTwitterBinding,
    };
    OracleConfig {
        history_depth: nonzero!(4_usize),
        economics: OracleEconomics {
            reward_asset: defaults::oracle::reward_asset(),
            reward_pool: defaults::oracle::reward_pool(),
            reward_amount: defaults::oracle::reward_amount(),
            slash_asset: defaults::oracle::slash_asset(),
            slash_receiver: defaults::oracle::slash_receiver(),
            slash_outlier_amount: defaults::oracle::slash_outlier_amount(),
            slash_error_amount: defaults::oracle::slash_error_amount(),
            slash_no_show_amount: defaults::oracle::slash_no_show_amount(),
            dispute_bond_asset: defaults::oracle::dispute_bond_asset(),
            dispute_bond_amount: defaults::oracle::dispute_bond_amount(),
            dispute_reward_amount: defaults::oracle::dispute_reward_amount(),
            frivolous_slash_amount: defaults::oracle::frivolous_slash_amount(),
        },
        governance: OracleGovernance {
            intake_sla_blocks: defaults::oracle::intake_sla_blocks(),
            rules_sla_blocks: defaults::oracle::rules_sla_blocks(),
            cop_sla_blocks: defaults::oracle::cop_sla_blocks(),
            technical_sla_blocks: defaults::oracle::technical_sla_blocks(),
            policy_jury_sla_blocks: defaults::oracle::policy_jury_sla_blocks(),
            enact_sla_blocks: defaults::oracle::enact_sla_blocks(),
            intake_min_votes: defaults::oracle::intake_min_votes(),
            rules_min_votes: defaults::oracle::rules_min_votes(),
            cop_min_votes: OracleChangeThresholds {
                low: defaults::oracle::cop_low_votes(),
                medium: defaults::oracle::cop_medium_votes(),
                high: defaults::oracle::cop_high_votes(),
            },
            technical_min_votes: defaults::oracle::technical_min_votes(),
            policy_jury_min_votes: OracleChangeThresholds {
                low: defaults::oracle::policy_jury_low_votes(),
                medium: defaults::oracle::policy_jury_medium_votes(),
                high: defaults::oracle::policy_jury_high_votes(),
            },
        },
        twitter_binding: OracleTwitterBinding {
            feed_id: defaults::oracle::twitter_binding_feed_id(),
            pepper_id: defaults::oracle::twitter_binding_pepper_id(),
            max_ttl_ms: defaults::oracle::twitter_binding_max_ttl_ms(),
            min_ttl_ms: defaults::oracle::twitter_binding_min_ttl_ms(),
            min_update_spacing_ms: defaults::oracle::twitter_binding_min_update_spacing_ms(),
        },
    }
}
fn feed_config(feed_id: FeedId, providers: Vec<AccountId>) -> FeedConfig {
    use iroha_data_model::oracle::{AggregationRule, OutlierPolicy, RiskClass};
    FeedConfig {
        feed_id,
        feed_config_version: FeedConfigVersion(1),
        providers,
        connector_id: "http-bin".to_string(),
        connector_version: 1,
        cadence_slots: nonzero!(1_u64),
        aggregation: AggregationRule::MedianMad(300),
        outlier_policy: OutlierPolicy::Mad(350),
        min_signers: 1,
        committee_size: 1,
        risk_class: RiskClass::Low,
        max_observers: 4,
        max_value_len: 128,
        max_error_rate_bps: 250,
        dispute_window_slots: nonzero!(4_u64),
        replay_window_slots: nonzero!(2_u64),
    }
}
fn twitter_binding_attestation(
    feed: &FeedConfig,
    uaid: &UniversalAccountId,
    binding_hash: KeyedHash,
    slot: u64,
    observed_at_ms: u64,
) -> TwitterBindingAttestation {
    TwitterBindingAttestation {
        binding_hash,
        uaid: *uaid,
        status: TwitterBindingStatus::Following,
        tweet_id: Some("tweet-viral".to_string()),
        challenge_hash: None,
        expires_at_ms: observed_at_ms + 600_000,
        observed_at_ms,
        request_hash: Hash::new(b"req-twitter-viral"),
        slot,
        feed_config_version: feed.feed_config_version,
    }
}
fn checked_signature_of<T: Encode>(private_key: &PrivateKey, payload: &T) -> SignatureOf<T> {
    SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn twitter_binding_observation(
    provider: &AccountId,
    signer: &KeyPair,
    feed: &FeedConfig,
    attestation: &TwitterBindingAttestation,
) -> Observation {
    let body = ObservationBody {
        feed_id: feed.feed_id.clone(),
        feed_config_version: feed.feed_config_version,
        slot: attestation.slot,
        provider_id: provider.clone(),
        connector_id: feed.connector_id.clone(),
        connector_version: feed.connector_version,
        request_hash: attestation.request_hash,
        outcome: ObservationOutcome::Value(attestation.observation_value()),
        timestamp_ms: Some(attestation.observed_at_ms),
    };
    let signature = checked_signature_of(signer.private_key(), &body);
    Observation { body, signature }
}
fn grant_permission(world: &mut World, account: &AccountId, permission: impl Into<Permission>) {
    let permission = permission.into();
    let mut permissions = {
        let permissions = world.account_permissions_mut_for_testing().view();
        permissions.get(account).cloned().unwrap_or_default()
    };
    permissions.insert(permission);
    world
        .account_permissions_mut_for_testing()
        .insert(account.clone(), permissions);
}
fn grant_oracle_operator_permissions(world: &mut World, account: &AccountId) {
    use iroha_data_model::oracle::OracleChangeStage;
    grant_permission(world, account, oracle_permission::CanRegisterOracleFeed);
    grant_permission(world, account, oracle_permission::CanProposeOracleChange);
    grant_permission(world, account, oracle_permission::CanRollbackOracleChange);
    grant_permission(world, account, oracle_permission::CanResolveOracleDispute);
    grant_permission(world, account, oracle_permission::CanManageTwitterBindings);
    for stage in [
        OracleChangeStage::Intake,
        OracleChangeStage::RulesCommittee,
        OracleChangeStage::CopReview,
        OracleChangeStage::TechnicalAudit,
        OracleChangeStage::PolicyJury,
        OracleChangeStage::Enactment,
    ] {
        grant_permission(
            world,
            account,
            oracle_permission::CanVoteOracleChangeStage { stage },
        );
    }
}
fn social_world_with_provider(
    def_id: &AssetDefinitionId,
    uaid: UniversalAccountId,
    provider: &AccountId,
) -> World {
    social_world_with_owner(def_id, uaid, provider, &ALICE_ID)
}
fn social_world_with_owner(
    def_id: &AssetDefinitionId,
    uaid: UniversalAccountId,
    provider: &AccountId,
    uaid_owner: &AccountId,
) -> World {
    use iroha_data_model::account::Account;
    let oracle_reward_asset = defaults::oracle::reward_asset();
    let oracle_reward_pool = defaults::oracle::reward_pool();
    let oracle_slash_receiver = defaults::oracle::slash_receiver();
    let alice = ALICE_ID.clone();
    let bob = BOB_ID.clone();
    let wonderland_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let validators_id: DomainId = DomainId::try_new("validators", "universal").expect("domain");
    let sora_id: DomainId = DomainId::try_new("sora", "universal").expect("domain");
    let wonderland: Domain = Domain::new(wonderland_id.clone()).build(&alice);
    let validators: Domain = Domain::new(validators_id.clone()).build(provider);
    let sora: Domain = Domain::new(sora_id.clone()).build(&alice);
    let alice_account = {
        let mut builder = Account::new(alice.clone());
        if uaid_owner == &alice {
            builder = builder.with_uaid(Some(uaid));
        }
        builder.build(&alice)
    };
    let bob_account = {
        let mut builder = Account::new(bob.clone());
        if uaid_owner == &bob {
            builder = builder.with_uaid(Some(uaid));
        }
        builder.build(&bob)
    };
    let provider_account = {
        let mut builder = Account::new(provider.clone());
        if uaid_owner == provider {
            builder = builder.with_uaid(Some(uaid));
        }
        builder.build(provider)
    };
    let oracle_reward_pool_account = Account::new(oracle_reward_pool.clone()).build(&alice);
    let oracle_slash_receiver_account = Account::new(oracle_slash_receiver.clone()).build(&alice);
    let asset_def = AssetDefinition::numeric(
        def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice);
    let oracle_asset_def = AssetDefinition::numeric(
        oracle_reward_asset.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice);
    let pool_asset = Asset::new(
        AssetId::new(def_id.clone(), alice.clone()),
        Quantity::from(1_000_u64),
    );
    let escrow_asset = Asset::new(
        AssetId::new(def_id.clone(), bob.clone()),
        Quantity::from(0_u64),
    );
    let oracle_pool_asset = Asset::new(
        AssetId::new(oracle_reward_asset.clone(), oracle_reward_pool),
        Quantity::from(1_000_u64),
    );
    let oracle_slash_asset = Asset::new(
        AssetId::new(oracle_reward_asset.clone(), oracle_slash_receiver),
        Quantity::zero(),
    );
    let mut world = World::with_assets(
        [wonderland, validators, sora],
        [
            alice_account,
            bob_account,
            provider_account,
            oracle_reward_pool_account,
            oracle_slash_receiver_account,
        ],
        [asset_def, oracle_asset_def],
        [
            pool_asset,
            escrow_asset,
            oracle_pool_asset,
            oracle_slash_asset,
        ],
        [],
    );
    grant_oracle_operator_permissions(&mut world, provider);
    world
}
#[derive(Clone, Copy)]
struct BindingCtx<'a> {
    binding_hash: &'a KeyedHash,
    slot: u64,
    observed_at_ms: u64,
}
fn record_binding(
    tx: &mut StateTransaction<'_, '_>,
    feed_cfg: &FeedConfig,
    uaid: UniversalAccountId,
    ctx: BindingCtx<'_>,
    provider: &AccountId,
    signer: &KeyPair,
) {
    let attestation = twitter_binding_attestation(
        feed_cfg,
        &uaid,
        ctx.binding_hash.clone(),
        ctx.slot,
        ctx.observed_at_ms,
    );
    SubmitOracleObservation {
        observation: twitter_binding_observation(provider, signer, feed_cfg, &attestation),
    }
    .execute(provider, tx)
    .expect("submit twitter binding observation");
    AggregateOracleFeed {
        feed_id: feed_cfg.feed_id.clone(),
        slot: attestation.slot,
        request_hash: attestation.request_hash,
        evidence_hashes: Vec::new(),
    }
    .execute(provider, tx)
    .expect("aggregate twitter binding slot");
    RecordTwitterBinding {
        attestation,
        feed_id: feed_cfg.feed_id.clone(),
    }
    .execute(provider, tx)
    .expect("record twitter binding");
}
fn setup_viral_state(
    def_id: &AssetDefinitionId,
    uaid: UniversalAccountId,
    configure: impl FnOnce(&mut ViralIncentives),
) -> (State, AccountId, KeyPair) {
    setup_viral_state_for_owner(def_id, uaid, &ALICE_ID, configure)
}
fn setup_viral_state_for_owner(
    def_id: &AssetDefinitionId,
    uaid: UniversalAccountId,
    uaid_owner: &AccountId,
    configure: impl FnOnce(&mut ViralIncentives),
) -> (State, AccountId, KeyPair) {
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let world = social_world_with_owner(def_id, uaid, &provider, uaid_owner);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query);
    state.set_oracle(oracle_config());
    let mut gov_cfg = state.gov.clone();
    let mut incentives = gov_cfg.viral_incentives.clone();
    configure(&mut incentives);
    gov_cfg.viral_incentives = incentives;
    state.set_gov(gov_cfg);
    (state, provider, signer)
}
fn register_feed(
    tx: &mut StateTransaction<'_, '_>,
    feed_id: FeedId,
    provider: &AccountId,
) -> FeedConfig {
    let feed_cfg = feed_config(feed_id, vec![provider.clone()]);
    RegisterOracleFeed {
        feed: feed_cfg.clone(),
    }
    .execute(provider, tx)
    .expect("register feed");
    feed_cfg
}
fn header(height: u64) -> BlockHeader {
    header_at(height, 0)
}
fn header_at(height: u64, creation_time_ms: u64) -> BlockHeader {
    let nonzero_height = NonZeroU64::new(height).expect("height must be non-zero");
    BlockHeader::new(nonzero_height, None, None, creation_time_ms, 0)
}
fn follow_feed_id() -> FeedId {
    TWITTER_FOLLOW_FEED_ID.parse().expect("feed id")
}
fn twitter_binding(label: &[u8]) -> KeyedHash {
    KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        label,
    )
}
fn register_follow_feed(tx: &mut StateTransaction<'_, '_>, provider: &AccountId) -> FeedConfig {
    register_feed(tx, follow_feed_id(), provider)
}
fn record_follow_binding(
    tx: &mut StateTransaction<'_, '_>,
    feed_cfg: &FeedConfig,
    uaid: UniversalAccountId,
    ctx: BindingCtx<'_>,
    provider: &AccountId,
    signer: &KeyPair,
) {
    record_binding(tx, feed_cfg, uaid, ctx, provider, signer);
}
#[test]
fn viral_reward_flow_claims_releases_escrow_and_pays_single_bonus() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-1"));
    let (state, provider, signer) = setup_viral_state(&def_id, uaid, |viral| {
        viral.incentive_pool_account = (*ALICE_ID).clone();
        viral.escrow_account = (*BOB_ID).clone();
        viral.reward_asset_definition_id = def_id.clone();
        viral.follow_reward_amount = Quantity::from(100_u32);
        viral.sender_bonus_amount = Quantity::from(50_u32);
        viral.max_daily_claims_per_uaid = 4;
        viral.max_claims_per_binding = 2;
        viral.daily_budget = Quantity::from(150_u32);
        viral.campaign_cap = Quantity::from(1_000_u32);
    });
    let binding_hash = twitter_binding(b"user-viral");
    let mut block = state.block(header(1));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = register_follow_feed(&mut tx, &provider);
    // Before binding is claimed, send funds to Twitter (escrow path) and record binding.
    SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(10_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("send to twitter should create escrow");
    let escrow_key = binding_hash.digest;
    record_follow_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash,
            slot: 7,
            observed_at_ms: 1_000,
        },
        &provider,
        &signer,
    );
    // Claim follow reward: should pay reward, release escrow, and pay a one-time bonus.
    ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("claim twitter follow reward");
    assert!(tx.world.viral_escrows().get(&escrow_key).is_none());
    assert!(
        tx.world
            .viral_bonus_paid()
            .get(&escrow_key)
            .copied()
            .unwrap_or(false)
    );
    let budget_spent = tx.world.viral_reward_budget().spent.clone();
    assert_eq!(
        budget_spent,
        Quantity::from(150_u32),
        "budget spent must equal follow reward + bonus"
    );
    let daily_counter = tx
        .world
        .viral_daily_counters()
        .get(&uaid)
        .copied()
        .expect("daily counter stored");
    assert_eq!(
        daily_counter.claims, 1,
        "one reward claim should be recorded for UAID"
    );
    let binding_claims = tx
        .world
        .viral_binding_claims()
        .get(&escrow_key)
        .copied()
        .unwrap_or(0);
    assert_eq!(binding_claims, 1, "binding claim count must be 1");
    // Second send to Twitter for the same binding should not pay an extra bonus.
    SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(5_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("second send to twitter should succeed");
    let budget_after = tx.world.viral_reward_budget();
    assert_eq!(
        budget_after.spent, budget_spent,
        "budget must not increase after second send (bonus already paid)"
    );
}
#[test]
fn viral_reward_respects_halt_and_deny_lists() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-2"));
    let (state, provider, signer) = setup_viral_state(&def_id, uaid, |viral| {
        *viral = ViralIncentives {
            incentive_pool_account: (*ALICE_ID).clone(),
            escrow_account: (*BOB_ID).clone(),
            reward_asset_definition_id: def_id.clone(),
            follow_reward_amount: Quantity::from(10_u32),
            sender_bonus_amount: Quantity::zero(),
            max_daily_claims_per_uaid: 1,
            max_claims_per_binding: 1,
            daily_budget: Quantity::from(10_u32),
            halt: true,
            deny_uaids: vec![uaid],
            ..ViralIncentives::default()
        };
    });
    let binding_hash = twitter_binding(b"user-viral-deny");
    let mut block = state.block(header(1));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = register_follow_feed(&mut tx, &provider);
    let feed_id = feed_cfg.feed_id.clone();
    let attestation = twitter_binding_attestation(&feed_cfg, &uaid, binding_hash.clone(), 8, 2_000);
    SubmitOracleObservation {
        observation: twitter_binding_observation(&provider, &signer, &feed_cfg, &attestation),
    }
    .execute(&provider, &mut tx)
    .expect("submit twitter binding observation");
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: attestation.slot,
        request_hash: attestation.request_hash,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider, &mut tx)
    .expect("aggregate twitter binding slot");
    RecordTwitterBinding {
        attestation,
        feed_id,
    }
    .execute(&provider, &mut tx)
    .expect("record twitter binding");
    // With `halt = true`, any viral incentive instruction should fail fast.
    let claim_err = ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{claim_err:?}").contains("halted"),
        "halt flag must prevent rewards"
    );
    let send_err = SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(1_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{send_err:?}").contains("halted"),
        "halt flag must prevent send-to-twitter"
    );
    let cancel_err = CancelTwitterEscrow {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{cancel_err:?}").contains("halted"),
        "halt flag must prevent escrow cancellation"
    );
}
#[test]
fn send_to_twitter_delivers_immediately_and_pays_bonus_once() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-send"));
    let (state, provider, signer) = setup_viral_state_for_owner(&def_id, uaid, &BOB_ID, |viral| {
        viral.incentive_pool_account = (*ALICE_ID).clone();
        viral.escrow_account = (*BOB_ID).clone();
        viral.reward_asset_definition_id = def_id.clone();
        viral.follow_reward_amount = Quantity::from(1_u32);
        viral.sender_bonus_amount = Quantity::from(25_u32);
        viral.max_daily_claims_per_uaid = 3;
        viral.max_claims_per_binding = 2;
        viral.daily_budget = Quantity::from(50_u32);
        viral.campaign_cap = Quantity::from(100_u32);
    });
    let binding_hash = twitter_binding(b"user-viral-send");
    let mut block = state.block(header(1));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = register_follow_feed(&mut tx, &provider);
    record_follow_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash,
            slot: 11,
            observed_at_ms: 3_000,
        },
        &provider,
        &signer,
    );
    SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(10_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("send to twitter should pay immediately");
    // Second send should not pay another bonus.
    SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(5_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("second send to twitter should also succeed");
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit block");
    let view = state.view();
    let alice_asset_id = AssetId::new(def_id.clone(), ALICE_ID.clone());
    let bob_asset_id = AssetId::new(def_id.clone(), BOB_ID.clone());
    let alice_balance = view
        .world()
        .assets()
        .get(&alice_asset_id)
        .expect("alice balance after sends")
        .clone();
    let bob_balance = view
        .world()
        .assets()
        .get(&bob_asset_id)
        .expect("bob balance after sends")
        .clone();
    assert_eq!(alice_balance.clone().into_inner(), Quantity::from(985_u64));
    assert_eq!(bob_balance.clone().into_inner(), Quantity::from(15_u64));
    let budget = view.world().viral_reward_budget();
    assert_eq!(
        budget.spent,
        Quantity::from(25_u32),
        "only the one-time bonus should hit the budget"
    );
    assert!(
        view.world()
            .viral_bonus_paid()
            .get(&binding_hash.digest)
            .copied()
            .unwrap_or(false),
        "bonus should be marked as paid"
    );
    assert!(
        view.world()
            .viral_escrows()
            .get(&binding_hash.digest)
            .is_none(),
        "no escrow should be stored when binding already active"
    );
}
#[test]
fn viral_reward_enforces_daily_cap_per_uaid() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-cap"));
    let (state, provider, signer) = setup_viral_state(&def_id, uaid, |viral| {
        *viral = ViralIncentives {
            incentive_pool_account: (*ALICE_ID).clone(),
            escrow_account: (*BOB_ID).clone(),
            reward_asset_definition_id: def_id.clone(),
            follow_reward_amount: Quantity::from(50_u32),
            sender_bonus_amount: Quantity::zero(),
            max_daily_claims_per_uaid: 1,
            max_claims_per_binding: 2,
            daily_budget: Quantity::from(200_u32),
            ..ViralIncentives::default()
        };
    });
    let binding_a = twitter_binding(b"user-viral-cap-a");
    let binding_b = twitter_binding(b"user-viral-cap-b");
    // Block 1: record both bindings and claim the first one.
    let mut block = state.block(header(1));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = register_follow_feed(&mut tx, &provider);
    record_follow_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_a,
            slot: 12,
            observed_at_ms: 4_000,
        },
        &provider,
        &signer,
    );
    record_follow_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_b,
            slot: 13,
            observed_at_ms: 4_200,
        },
        &provider,
        &signer,
    );
    ClaimTwitterFollowReward {
        binding_hash: binding_a.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("first claim should succeed");
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit first block");
    // Block 2: second claim for the same UAID should hit the daily cap.
    let mut block = state.block(header(2));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let err = ClaimTwitterFollowReward {
        binding_hash: binding_b.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{err:?}").contains("daily viral reward cap"),
        "daily cap must reject additional claims for the UAID"
    );
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit second block");
    let view = state.view();
    let budget = view.world().viral_reward_budget();
    assert_eq!(
        budget.spent,
        Quantity::from(50_u32),
        "only the first reward should be charged to the budget"
    );
    let claims_a = view
        .world()
        .viral_binding_claims()
        .get(&binding_a.digest)
        .copied()
        .unwrap_or(0);
    let claims_b = view
        .world()
        .viral_binding_claims()
        .get(&binding_b.digest)
        .copied()
        .unwrap_or(0);
    assert_eq!(claims_a, 1, "first binding should record one claim");
    assert_eq!(claims_b, 0, "second binding should not be recorded");
}
#[test]
fn viral_reward_enforces_budget_limit() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-budget"));
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let world = social_world_with_provider(&def_id, uaid, &provider);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query);
    state.set_oracle(oracle_config());
    let mut gov_cfg = state.gov.clone();
    gov_cfg.viral_incentives = ViralIncentives {
        incentive_pool_account: (*ALICE_ID).clone(),
        escrow_account: (*BOB_ID).clone(),
        reward_asset_definition_id: def_id.clone(),
        follow_reward_amount: Quantity::from(50_u32),
        sender_bonus_amount: Quantity::zero(),
        max_daily_claims_per_uaid: 3,
        max_claims_per_binding: 1,
        daily_budget: Quantity::from(10_u32),
        ..ViralIncentives::default()
    };
    state.set_gov(gov_cfg);
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-viral-budget",
    );
    let mut block = state.block(header(1));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = feed_config(feed_id.clone(), vec![provider.clone()]);
    RegisterOracleFeed {
        feed: feed_cfg.clone(),
    }
    .execute(&provider, &mut tx)
    .expect("register feed");
    record_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash,
            slot: 14,
            observed_at_ms: 5_000,
        },
        &provider,
        &signer,
    );
    let result = ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx);
    assert!(
        result.unwrap_err().to_string().contains("budget"),
        "budget exhaustion should reject the claim"
    );
    tx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit block for budget cap check");
    let view = state.view();
    let budget = view.world().viral_reward_budget();
    assert_eq!(budget.spent, Quantity::zero(), "budget must stay untouched");
    let pool_asset_id = AssetId::new(def_id.clone(), ALICE_ID.clone());
    let pool_balance = view
        .world()
        .assets()
        .get(&pool_asset_id)
        .expect("pool asset after rejected claim")
        .clone();
    assert_eq!(pool_balance.clone().into_inner(), Quantity::from(1_000_u64));
}
#[test]
fn viral_promo_window_blocks_flows_outside_schedule() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-promo"));
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let world = social_world_with_provider(&def_id, uaid, &provider);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query);
    state.set_oracle(oracle_config());
    let mut gov_cfg = state.gov.clone();
    gov_cfg.viral_incentives.incentive_pool_account = (*ALICE_ID).clone();
    gov_cfg.viral_incentives.escrow_account = (*BOB_ID).clone();
    gov_cfg.viral_incentives.reward_asset_definition_id = def_id.clone();
    gov_cfg.viral_incentives.follow_reward_amount = Quantity::from(10_u32);
    gov_cfg.viral_incentives.sender_bonus_amount = Quantity::from(5_u32);
    gov_cfg.viral_incentives.daily_budget = Quantity::from(50_u32);
    gov_cfg.viral_incentives.campaign_cap = Quantity::from(50_u32);
    gov_cfg.viral_incentives.promo_starts_at_ms = Some(1_000);
    gov_cfg.viral_incentives.promo_ends_at_ms = Some(2_000);
    state.set_gov(gov_cfg);
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-viral-promo",
    );
    let mut block = state.block(header_at(1, 500));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = feed_config(feed_id.clone(), vec![provider.clone()]);
    RegisterOracleFeed {
        feed: feed_cfg.clone(),
    }
    .execute(&provider, &mut tx)
    .expect("register feed");
    record_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash,
            slot: 3,
            observed_at_ms: 600,
        },
        &provider,
        &signer,
    );
    let send_err = SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(1_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{send_err:?}").contains("promotion window"),
        "send should be gated by the promo window"
    );
    let claim_err = ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{claim_err:?}").contains("promotion window"),
        "claim should be gated by the promo window"
    );
    assert_eq!(
        tx.world.viral_campaign_budget().spent,
        Quantity::zero(),
        "campaign budget must remain untouched when the promo window blocks flows"
    );
}
#[test]
fn viral_follow_game_flow_releases_escrow_and_bonus() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-flow"));
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let world = social_world_with_provider(&def_id, uaid, &provider);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query);
    state.set_oracle(oracle_config());
    let mut gov_cfg = state.gov.clone();
    gov_cfg.viral_incentives.incentive_pool_account = (*ALICE_ID).clone();
    gov_cfg.viral_incentives.escrow_account = (*BOB_ID).clone();
    gov_cfg.viral_incentives.reward_asset_definition_id = def_id.clone();
    gov_cfg.viral_incentives.follow_reward_amount = Quantity::from(10_u32);
    gov_cfg.viral_incentives.sender_bonus_amount = Quantity::from(5_u32);
    gov_cfg.viral_incentives.daily_budget = Quantity::from(100_u32);
    gov_cfg.viral_incentives.max_daily_claims_per_uaid = 3;
    gov_cfg.viral_incentives.max_claims_per_binding = 1;
    state.set_gov(gov_cfg);
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-viral-flow",
    );
    let mut block = state.block(header_at(1, 1_200));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = feed_config(feed_id.clone(), vec![provider.clone()]);
    RegisterOracleFeed {
        feed: feed_cfg.clone(),
    }
    .execute(&provider, &mut tx)
    .expect("register feed");
    SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(5_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("escrow should be created while awaiting binding");
    assert!(
        tx.world.viral_escrows().get(&binding_hash.digest).is_some(),
        "escrow must be recorded after send"
    );
    record_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash,
            slot: 6,
            observed_at_ms: 1_220,
        },
        &provider,
        &signer,
    );
    ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("claim should deliver escrow and bonus");
    assert!(
        tx.world.viral_escrows().get(&binding_hash.digest).is_none(),
        "escrow must be cleared after claim"
    );
    assert!(
        tx.world
            .viral_bonus_paid()
            .get(&binding_hash.digest)
            .copied()
            .unwrap_or(false),
        "bonus must be marked as paid after first delivery"
    );
    assert_eq!(
        tx.world.viral_reward_budget().spent,
        Quantity::from(15_u32),
        "budget must include reward + bonus"
    );
    let replay_err = ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{replay_err:?}").contains("already claimed"),
        "replay claims must be rejected"
    );
}
#[test]
fn viral_campaign_cap_limits_reward_and_bonus_spend() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-viral-cap-campaign"));
    let (state, provider, signer) = setup_viral_state(&def_id, uaid, |viral| {
        *viral = ViralIncentives {
            incentive_pool_account: (*ALICE_ID).clone(),
            escrow_account: (*BOB_ID).clone(),
            reward_asset_definition_id: def_id.clone(),
            follow_reward_amount: Quantity::from(100_u32),
            sender_bonus_amount: Quantity::from(50_u32),
            max_daily_claims_per_uaid: 3,
            max_claims_per_binding: 2,
            daily_budget: Quantity::from(500_u32),
            campaign_cap: Quantity::from(150_u32),
            ..ViralIncentives::default()
        };
    });
    let binding_hash = twitter_binding(b"user-viral-cap-1");
    let binding_hash_second = twitter_binding(b"user-viral-cap-2");
    let mut block = state.block(header_at(1, 1_500));
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    let feed_cfg = register_follow_feed(&mut tx, &provider);
    record_follow_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash,
            slot: 4,
            observed_at_ms: 1_520,
        },
        &provider,
        &signer,
    );
    // Prefund escrow so the sender bonus is exercised during claim.
    SendToTwitter {
        binding_hash: binding_hash.clone(),
        amount: Quantity::from(10_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("send to twitter should create escrow");
    ClaimTwitterFollowReward {
        binding_hash: binding_hash.clone(),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect("first claim should succeed under the campaign cap");
    assert_eq!(
        tx.world.viral_campaign_budget().spent,
        Quantity::from(150_u32),
        "campaign budget must track reward + bonus spend"
    );
    // Record a second binding and confirm the campaign cap prevents another payout.
    record_follow_binding(
        &mut tx,
        &feed_cfg,
        uaid,
        BindingCtx {
            binding_hash: &binding_hash_second,
            slot: 5,
            observed_at_ms: 1_540,
        },
        &provider,
        &signer,
    );
    let capped_err = ClaimTwitterFollowReward {
        binding_hash: binding_hash_second,
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap_err();
    assert!(
        format!("{capped_err:?}").contains("campaign budget"),
        "campaign cap should prevent additional payouts once exhausted"
    );
}

#[test]
fn social_movement_without_component_or_native_owner_is_rejected() {
    let def_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "xor".parse().unwrap(),
    );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-unowned-social"));
    let (state, _, _) = setup_viral_state(&def_id, uaid, |viral| {
        viral.incentive_pool_account = ALICE_ID.clone();
        viral.escrow_account = BOB_ID.clone();
        viral.reward_asset_definition_id = def_id.clone();
    });
    let binding = twitter_binding(b"unowned-social");
    let mut block = state.block(header(1));
    let mut tx = block.transaction();
    let alice_asset = AssetId::new(def_id.clone(), ALICE_ID.clone());
    let bob_asset = AssetId::new(def_id, BOB_ID.clone());
    let before_alice = tx.world.assets().get(&alice_asset).unwrap().clone();
    let before_bob = tx.world.assets().get(&bob_asset).unwrap().clone();
    let err = SendToTwitter {
        binding_hash: binding.clone(),
        amount: Quantity::from(1_u32),
    }
    .execute(&ALICE_ID, &mut tx)
    .expect_err("raw transaction cannot acquire a protocol source owner");
    assert!(
        err.to_string()
            .contains("protocol source has no authenticated mandatory owner")
    );
    assert_eq!(tx.world.assets().get(&alice_asset), Some(&before_alice));
    assert_eq!(tx.world.assets().get(&bob_asset), Some(&before_bob));
    assert!(tx.world.viral_escrows().get(&binding.digest).is_none());
}
