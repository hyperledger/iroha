//! Oracle ISI integration tests.

use iroha_config::parameters::{
    actual::{
        Oracle as OracleConfig, OracleChangeThresholds, OracleEconomics, OracleGovernance,
        OracleTwitterBinding,
    },
    defaults,
};
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute as _,
    smartcontracts::{ValidQuery, ValidSingularQuery},
    state::{State, StateTransaction, World, WorldReadOnly},
    telemetry::StateTelemetry,
};
use iroha_crypto::{Hash, KeyPair, PrivateKey, SignatureOf};
use iroha_data_model::{
    account::Account,
    asset::{Asset, AssetDefinition, AssetTransferAvailability},
    block::BlockHeader,
    domain::Domain,
    isi::{
        AggregateOracleFeed, InstructionBox, OpenOracleDispute, ProposeOracleChange,
        RecordTwitterBinding, RegisterOracleFeed, ResolveOracleDispute, RevokeTwitterBinding,
        RollbackOracleChange, SetAssetHoldingLimit, SetAssetTransferAvailability,
        SubmitOracleObservation, VoteOracleChangeStage,
    },
    nexus::UniversalAccountId,
    oracle::{
        AbsoluteOutlier, AggregationRule, FeedConfig, FeedConfigVersion, FeedEventOutcome, FeedId,
        FeedSlot, KeyedHash, Observation, ObservationBody, ObservationErrorCode,
        ObservationOutcome, ObservationValue, OracleChangeClass, OracleChangeId, OracleChangeStage,
        OracleChangeStatus, OracleProviderKey, OutlierPolicy, RiskClass, TWITTER_FOLLOW_FEED_ID,
        TwitterBindingAttestation, TwitterBindingStatus,
    },
    permission::Permission,
    prelude::*,
    query::dsl::CompoundPredicate,
    role::{Role, RoleId},
};
use iroha_executor_data_model::permission::oracle as oracle_permission;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_telemetry::metrics::Metrics;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    str::FromStr,
    sync::Arc,
};
fn test_telemetry() -> StateTelemetry {
    StateTelemetry::new(Arc::new(Metrics::default()), false)
}
fn oracle_config() -> OracleConfig {
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
    let committee_size = u16::try_from(providers.len()).expect("provider count fits");
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
        committee_size,
        risk_class: RiskClass::Low,
        max_observers: 4,
        max_value_len: 128,
        max_error_rate_bps: 250,
        dispute_window_slots: nonzero!(4_u64),
        replay_window_slots: nonzero!(2_u64),
    }
}
fn checked_signature_of<T: norito::codec::Encode>(
    private_key: &PrivateKey,
    payload: &T,
) -> SignatureOf<T> {
    SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn observation(
    provider: AccountId,
    signer: &KeyPair,
    feed_id: &FeedId,
    slot: u64,
    request_hash: Hash,
    value: i128,
) -> Observation {
    let body = ObservationBody {
        feed_id: feed_id.clone(),
        feed_config_version: FeedConfigVersion(1),
        slot,
        provider_id: provider,
        connector_id: "http-bin".to_string(),
        connector_version: 1,
        request_hash,
        outcome: ObservationOutcome::Value(ObservationValue::new(value, 5)),
        timestamp_ms: Some(1_700_000_000_000),
    };
    let signature = checked_signature_of(signer.private_key(), &body);
    Observation { body, signature }
}
fn error_observation(
    provider: AccountId,
    signer: &KeyPair,
    feed_id: &FeedId,
    slot: u64,
    request_hash: Hash,
    code: ObservationErrorCode,
) -> Observation {
    let body = ObservationBody {
        feed_id: feed_id.clone(),
        feed_config_version: FeedConfigVersion(1),
        slot,
        provider_id: provider,
        connector_id: "http-bin".to_string(),
        connector_version: 1,
        request_hash,
        outcome: ObservationOutcome::Error(code),
        timestamp_ms: Some(1_700_000_000_000),
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
fn execute_boxed(
    instruction: impl Into<InstructionBox>,
    authority: &AccountId,
    tx: &mut StateTransaction<'_, '_>,
) -> Result<(), iroha_data_model::isi::error::InstructionExecutionError> {
    let instruction: InstructionBox = instruction.into();
    instruction.execute(authority, tx)
}
fn assert_rejects_with(
    result: Result<(), iroha_data_model::isi::error::InstructionExecutionError>,
    expected: &str,
) {
    let err = result.expect_err("operation should reject");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains(expected),
        "expected error to contain `{expected}`, got `{rendered}`"
    );
}
fn role_with_permission(role_id: RoleId, permission: impl Into<Permission>) -> Role {
    let mut permissions = BTreeSet::new();
    permissions.insert(permission.into());
    Role {
        id: role_id,
        permissions,
        permission_epochs: BTreeMap::new(),
    }
}
fn world_with_providers(providers: &[AccountId]) -> World {
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let domain: Domain = Domain::new(validator_domain_id.clone())
        .build(providers.first().expect("at least one provider"));
    let accounts = providers
        .iter()
        .map(|id| Account::new(id.clone()).build(id));
    let mut world = World::with([domain], accounts, []);
    for provider in providers {
        grant_oracle_operator_permissions(&mut world, provider);
    }
    world
}
fn world_with_provider_role_permission(
    provider: &AccountId,
    role_id: RoleId,
    permission: impl Into<Permission>,
) -> World {
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let domain: Domain = Domain::new(validator_domain_id).build(provider);
    let account = Account::new(provider.clone()).build(provider);
    let role = role_with_permission(role_id.clone(), permission);
    let mut world = World::with_assets_and_roles(
        [domain],
        [account],
        std::iter::empty::<AssetDefinition>(),
        std::iter::empty::<Asset>(),
        std::iter::empty::<Nft>(),
        [role],
    );
    world.grant_role_for_tests(provider.clone(), role_id);
    world
}
fn header(height: u64) -> BlockHeader {
    let nonzero_height = NonZeroU64::new(height).expect("height must be non-zero");
    BlockHeader::new(nonzero_height, None, None, 0, 0)
}
fn oracle_state_with_accounts(
    providers: &[AccountId],
) -> (State, AssetDefinitionId, AccountId, AccountId) {
    let asset_def_id: AssetDefinitionId = defaults::oracle::reward_asset();
    let reward_pool = defaults::oracle::reward_pool();
    let slash_receiver = defaults::oracle::slash_receiver();
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let validator_domain: Domain =
        Domain::new(validator_domain_id.clone()).build(providers.first().expect("provider"));
    let sora_domain_id: DomainId = DomainId::try_new("sora", "universal").expect("domain");
    let sora_domain: Domain = Domain::new(sora_domain_id.clone()).build(&reward_pool);
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&reward_pool);
    let mut assets = vec![
        Asset::new(
            AssetId::new(asset_def_id.clone(), reward_pool.clone()),
            Quantity::from_str("10").expect("reward pool amount"),
        ),
        Asset::new(
            AssetId::new(asset_def_id.clone(), slash_receiver.clone()),
            Quantity::from_str("5").expect("slash receiver amount"),
        ),
    ];
    let accounts: Vec<_> = providers
        .iter()
        .map(|id| {
            assets.push(Asset::new(
                AssetId::new(asset_def_id.clone(), id.clone()),
                Quantity::from_str("5").expect("provider balance"),
            ));
            Account::new(id.clone()).build(id)
        })
        .collect();
    let mut world = World::with_assets(
        [validator_domain, sora_domain],
        accounts.into_iter().chain([
            Account::new(reward_pool.clone()).build(&reward_pool),
            Account::new(slash_receiver.clone()).build(&slash_receiver),
        ]),
        [asset_def],
        assets,
        [],
    );
    for provider in providers {
        grant_oracle_operator_permissions(&mut world, provider);
    }
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let telemetry = test_telemetry();
    let mut state = State::with_telemetry(world, kura, query, telemetry);
    state.set_oracle(oracle_config());
    (state, asset_def_id, reward_pool, slash_receiver)
}
fn aggregate_round(
    tx: &mut StateTransaction<'_, '_>,
    feed_id: &FeedId,
    providers: [(&AccountId, &KeyPair); 2],
    slot: u64,
    request: Hash,
    value: i128,
    evidence_hashes: Vec<Hash>,
) {
    for (provider, signer) in providers {
        SubmitOracleObservation {
            observation: observation(provider.clone(), signer, feed_id, slot, request, value),
        }
        .execute(provider, tx)
        .expect("submit observation");
    }
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot,
        request_hash: request,
        evidence_hashes,
    }
    .execute(providers[0].0, tx)
    .expect("aggregate slot");
}
fn record_twitter_binding_round(
    tx: &mut StateTransaction<'_, '_>,
    provider: &AccountId,
    signer: &KeyPair,
    feed_config: &FeedConfig,
    attestation: &TwitterBindingAttestation,
) {
    RegisterOracleFeed {
        feed: feed_config.clone(),
    }
    .execute(provider, tx)
    .expect("register feed");
    SubmitOracleObservation {
        observation: twitter_binding_observation(provider, signer, feed_config, attestation),
    }
    .execute(provider, tx)
    .expect("submit twitter binding observation");
    AggregateOracleFeed {
        feed_id: feed_config.feed_id.clone(),
        slot: attestation.slot,
        request_hash: attestation.request_hash,
        evidence_hashes: Vec::new(),
    }
    .execute(provider, tx)
    .expect("aggregate twitter binding slot");
    RecordTwitterBinding {
        attestation: attestation.clone(),
        feed_id: feed_config.feed_id.clone(),
    }
    .execute(provider, tx)
    .expect("record twitter binding");
}
#[test]
fn oracle_flow_persists_history_and_prunes() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "price_xor_usd".parse().expect("feed id");
    let (mut state, _, _, _) =
        oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut oracle_cfg = oracle_config();
    oracle_cfg.history_depth = nonzero!(1_usize);
    state.set_oracle(oracle_cfg);
    // First round: register feed, buffer observations, aggregate, and persist history.
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.replay_window_slots = nonzero!(1_u64);
    RegisterOracleFeed {
        feed: config.clone(),
    }
    .execute(&provider_a, &mut stx)
    .expect("register feed");
    let req0 = Hash::new(b"req-0");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        10,
        req0,
        1_000_000,
        vec![Hash::new(b"bundle-0")],
    );
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit first block");
    {
        let view = state.view();
        let history = view
            .world()
            .oracle_history()
            .get(&feed_id)
            .expect("history exists");
        assert_eq!(history.len(), 1);
        let record = history.last().expect("latest record");
        assert_eq!(record.evidence_hashes.len(), 1);
        match &record.event.outcome {
            FeedEventOutcome::Success(success) => {
                assert_eq!(success.value, ObservationValue::new(1_000_000, 5));
                assert_eq!(success.entries.len(), 2);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert!(view.world().oracle_observations().iter().next().is_none());
    }
    // Second round: new slot should prune history because depth is capped at one.
    let mut sb = state.block(header(2));
    let mut stx = sb.transaction();
    let req1 = Hash::new(b"req-1");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        11,
        req1,
        2_000_000,
        Vec::new(),
    );
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit second block");
    let view = state.view();
    let history = view
        .world()
        .oracle_history()
        .get(&feed_id)
        .expect("history exists");
    assert_eq!(history.len(), 1, "older record pruned to depth");
    assert_eq!(history.last().unwrap().event.slot, 11);
    assert!(view.world().oracle_observations().iter().next().is_none());
}
#[test]
fn oracle_rejects_wrong_authority() {
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let (outsider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "price_xor_usd".parse().expect("feed id");
    let world = world_with_providers(&[provider.clone(), outsider.clone()]);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let telemetry = test_telemetry();
    let state = State::with_telemetry(world, kura, query, telemetry);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    RegisterOracleFeed {
        feed: feed_config(feed_id.clone(), vec![provider.clone()]),
    }
    .execute(&provider, &mut stx)
    .expect("register feed");
    let req = Hash::new(b"req-unauthorized");
    let err = SubmitOracleObservation {
        observation: observation(provider.clone(), &signer, &feed_id, 7, req, 42_000),
    }
    .execute(&outsider, &mut stx)
    .expect_err("authority mismatch must reject");
    assert!(matches!(
        err,
        iroha_data_model::isi::error::InstructionExecutionError::InvalidParameter(_)
    ));
}
#[test]
fn oracle_register_requires_typed_permission_and_accepts_role_permission() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "role_permission_feed".parse().expect("feed id");
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let domain = Domain::new(validator_domain_id).build(&provider);
    let account = Account::new(provider.clone()).build(&provider);
    let mut state = State::with_telemetry(
        World::with([domain], [account], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let err = execute_boxed(
        RegisterOracleFeed {
            feed: feed_config(feed_id.clone(), vec![provider.clone()]),
        },
        &provider,
        &mut stx,
    )
    .expect_err("direct permission or role permission is required");
    assert!(matches!(
        err,
        iroha_data_model::isi::error::InstructionExecutionError::InvalidParameter(_)
    ));
    let role_id: RoleId = "oracle_registerer".parse().expect("role id");
    let role_world = world_with_provider_role_permission(
        &provider,
        role_id,
        oracle_permission::CanRegisterOracleFeed,
    );
    let mut state = State::with_telemetry(
        role_world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config(feed_id.clone(), vec![provider.clone()]),
        },
        &provider,
        &mut stx,
    )
    .expect("role permission should authorize feed registration");
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit role-authorized registration");
    assert!(state.view().world().oracle_feeds().get(&feed_id).is_some());
}
#[test]
fn oracle_instruction_box_dispatch_covers_operator_surface() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "dispatch_price_feed".parse().expect("feed id");
    let (mut state, _, _, _) =
        oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    cfg.governance.rules_min_votes = nonzero!(1_usize);
    cfg.governance.cop_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    cfg.governance.technical_min_votes = nonzero!(1_usize);
    cfg.governance.policy_jury_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch register feed");
    let request = Hash::new(b"dispatch-request");
    for (provider, signer, value) in [
        (&provider_a, &signer_a, 42_000_i128),
        (&provider_b, &signer_b, 42_100_i128),
    ] {
        execute_boxed(
            SubmitOracleObservation {
                observation: observation(provider.clone(), signer, &feed_id, 12, request, value),
            },
            provider,
            &mut stx,
        )
        .expect("dispatch submit observation");
    }
    execute_boxed(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 12,
            request_hash: request,
            evidence_hashes: vec![Hash::new(b"dispatch-bundle")],
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch aggregate feed");
    execute_boxed(
        OpenOracleDispute {
            feed_id: feed_id.clone(),
            slot: 12,
            request_hash: request,
            target: provider_b.clone(),
            bond: None,
            evidence_hashes: vec![Hash::new(b"dispatch-dispute")],
            reason: "provider challenge".to_string(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch open dispute");
    execute_boxed(
        ResolveOracleDispute {
            dispute_id: dispute_id(&feed_id, 12, request, &provider_a, &provider_b),
            outcome: iroha_data_model::oracle::OracleDisputeOutcome::Frivolous,
            notes: "insufficient evidence".to_string(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch resolve dispute");
    let change_id = OracleChangeId(Hash::new(b"dispatch-change"));
    let change_feed_id: FeedId = "dispatch_change_feed".parse().expect("feed id");
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(change_feed_id, vec![provider_a.clone(), provider_b.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"dispatch-change-payload"),
            evidence_hashes: vec![Hash::new(b"dispatch-intake")],
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch propose change");
    execute_boxed(
        VoteOracleChangeStage {
            change_id,
            stage: OracleChangeStage::Intake,
            approve: true,
            evidence_hashes: vec![Hash::new(b"dispatch-vote")],
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch vote stage");
    execute_boxed(
        RollbackOracleChange {
            change_id,
            stage: Some(OracleChangeStage::RulesCommittee),
            reason: "operator rollback".to_string(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch rollback change");
    let twitter_kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut twitter_feed = twitter_kit.feed_config;
    twitter_feed.providers = vec![provider_a.clone()];
    twitter_feed.min_signers = 1;
    twitter_feed.committee_size = 1;
    twitter_feed.feed_id = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"dispatch-uaid"));
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"dispatch-user",
    );
    let attestation = twitter_binding_attestation(&twitter_feed, &uaid, binding_hash.clone(), 100);
    execute_boxed(
        RegisterOracleFeed {
            feed: twitter_feed.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch register twitter feed");
    execute_boxed(
        SubmitOracleObservation {
            observation: twitter_binding_observation(
                &provider_a,
                &signer_a,
                &twitter_feed,
                &attestation,
            ),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch submit twitter observation");
    execute_boxed(
        AggregateOracleFeed {
            feed_id: twitter_feed.feed_id.clone(),
            slot: attestation.slot,
            request_hash: attestation.request_hash,
            evidence_hashes: Vec::new(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch aggregate twitter feed");
    execute_boxed(
        RecordTwitterBinding {
            attestation,
            feed_id: twitter_feed.feed_id.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch record twitter binding");
    execute_boxed(
        RevokeTwitterBinding {
            binding_hash: binding_hash.clone(),
            reason: "operator cleanup".to_string(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("dispatch revoke twitter binding");
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit dispatch block");
    let view = state.view();
    assert!(view.world().oracle_feeds().get(&feed_id).is_some());
    assert_eq!(
        view.world()
            .oracle_history()
            .get(&feed_id)
            .expect("history")
            .len(),
        1
    );
    assert!(
        view.world()
            .twitter_bindings()
            .get(&binding_hash.digest)
            .is_none()
    );
}
#[test]
fn oracle_register_rejects_invalid_feed_configs() {
    let (provider_a, _) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "invalid_feed_config".parse().expect("feed id");
    let world = world_with_providers(&[provider_a.clone(), provider_b.clone()]);
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut duplicate = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_a.clone()],
    );
    duplicate.committee_size = 2;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed { feed: duplicate },
            &provider_a,
            &mut stx,
        ),
        "duplicate oracle provider",
    );
    let mut zero_quorum = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    zero_quorum.min_signers = 0;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed { feed: zero_quorum },
            &provider_a,
            &mut stx,
        ),
        "at least one signer",
    );
    let mut oversized_committee = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    oversized_committee.committee_size = 2;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: oversized_committee,
            },
            &provider_a,
            &mut stx,
        ),
        "committee_size 2 exceeds providers 1",
    );
    let mut min_exceeds_committee = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    min_exceeds_committee.min_signers = 2;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: min_exceeds_committee,
            },
            &provider_a,
            &mut stx,
        ),
        "min_signers 2 exceeds committee_size 1",
    );
    let mut invalid_error_rate = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    invalid_error_rate.max_error_rate_bps = 10_001;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: invalid_error_rate,
            },
            &provider_a,
            &mut stx,
        ),
        "max_error_rate_bps 10001 exceeds 10000",
    );
    let mut replay_exceeds_history = feed_config(feed_id, vec![provider_a]);
    replay_exceeds_history.replay_window_slots = nonzero!(5_u64);
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: replay_exceeds_history,
            },
            &provider_b,
            &mut stx,
        ),
        "replay_window_slots 5 exceeds retained history depth 4",
    );
}
#[test]
fn oracle_register_rejects_empty_oversized_and_duplicate_version_configs() {
    let (provider_a, _) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "invalid_feed_config_adversarial".parse().expect("feed id");
    let world = world_with_providers(&[provider_a.clone(), provider_b.clone()]);
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut empty_providers = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    empty_providers.providers.clear();
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: empty_providers,
            },
            &provider_a,
            &mut stx,
        ),
        "must list at least one provider",
    );
    let mut zero_committee = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    zero_committee.committee_size = 0;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: zero_committee,
            },
            &provider_a,
            &mut stx,
        ),
        "non-zero committee size",
    );
    let mut too_many_observers = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    too_many_observers.max_observers = 1;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: too_many_observers,
            },
            &provider_a,
            &mut stx,
        ),
        "allows 2/1 observers",
    );
    let mut committee_exceeds_observers = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    committee_exceeds_observers.committee_size = 2;
    committee_exceeds_observers.max_observers = 1;
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: committee_exceeds_observers,
            },
            &provider_a,
            &mut stx,
        ),
        "committee_size 2 exceeds max_observers 1",
    );
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config(feed_id.clone(), vec![provider_a.clone()]),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register baseline version");
    assert_rejects_with(
        execute_boxed(
            RegisterOracleFeed {
                feed: feed_config(feed_id, vec![provider_a]),
            },
            &provider_b,
            &mut stx,
        ),
        "already registered with version 1 (incoming 1)",
    );
}
#[test]
fn oracle_operator_calls_reject_unregistered_feed_and_missing_change() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "missing_operator_feed".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    assert_rejects_with(
        execute_boxed(
            AggregateOracleFeed {
                feed_id: feed_id.clone(),
                slot: 1,
                request_hash: Hash::new(b"missing-feed-aggregate"),
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "is not registered",
    );
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id,
                slot: 1,
                request_hash: Hash::new(b"missing-feed-dispute"),
                target: provider.clone(),
                bond: None,
                evidence_hashes: vec![Hash::new(b"missing-feed-evidence")],
                reason: "missing feed".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "is not registered",
    );
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id: OracleChangeId(Hash::new(b"missing-vote-change")),
                stage: OracleChangeStage::Intake,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "is not registered",
    );
}
#[test]
fn oracle_observations_reject_unknown_provider_tampering_duplicates_and_version_mismatch() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let (outsider, outsider_signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "observation_adversarial_guards".parse().expect("feed id");
    let (state, _, _, _) =
        oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone(), outsider.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config(
                feed_id.clone(),
                vec![provider_a.clone(), provider_b.clone()],
            ),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    assert_rejects_with(
        SubmitOracleObservation {
            observation: observation(
                outsider.clone(),
                &outsider_signer,
                &feed_id,
                1,
                Hash::new(b"unknown-provider"),
                10,
            ),
        }
        .execute(&outsider, &mut stx),
        "is not part of feed",
    );
    let mut tampered = observation(
        provider_a.clone(),
        &signer_a,
        &feed_id,
        2,
        Hash::new(b"tampered-signature"),
        10,
    );
    tampered.body.outcome = ObservationOutcome::Value(ObservationValue::new(11, 5));
    assert_rejects_with(
        SubmitOracleObservation {
            observation: tampered,
        }
        .execute(&provider_a, &mut stx),
        "invalid observation signature",
    );
    let mut wrong_version = observation(
        provider_b.clone(),
        &signer_b,
        &feed_id,
        3,
        Hash::new(b"wrong-version"),
        12,
    );
    wrong_version.body.feed_config_version = FeedConfigVersion(2);
    wrong_version.signature = checked_signature_of(signer_b.private_key(), &wrong_version.body);
    assert_rejects_with(
        SubmitOracleObservation {
            observation: wrong_version,
        }
        .execute(&provider_b, &mut stx),
        "feed config version mismatch",
    );
    let request = Hash::new(b"duplicate-observation");
    let valid = observation(provider_a.clone(), &signer_a, &feed_id, 4, request, 42);
    SubmitOracleObservation {
        observation: valid.clone(),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit first observation");
    assert_rejects_with(
        SubmitOracleObservation { observation: valid }.execute(&provider_a, &mut stx),
        "duplicate observation",
    );
}
#[test]
fn oracle_invalid_signature_does_not_poison_window_or_count_for_quorum() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "invalid_signature_window_guard".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 2;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"invalid-signature-window");
    let mut tampered = observation(provider_a.clone(), &signer_a, &feed_id, 6, request, 60);
    tampered.body.outcome = ObservationOutcome::Value(ObservationValue::new(61, 5));
    assert_rejects_with(
        SubmitOracleObservation {
            observation: tampered,
        }
        .execute(&provider_a, &mut stx),
        "invalid observation signature",
    );
    SubmitOracleObservation {
        observation: observation(provider_b.clone(), &signer_b, &feed_id, 6, request, 60),
    }
    .execute(&provider_b, &mut stx)
    .expect("submit valid observation after rejected tamper");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 6,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_b, &mut stx),
        "insufficient oracle quorum",
    );
    SubmitOracleObservation {
        observation: observation(provider_a.clone(), &signer_a, &feed_id, 6, request, 60),
    }
    .execute(&provider_b, &mut stx)
    .expect_err("authority mismatch should still reject");
    SubmitOracleObservation {
        observation: observation(provider_a.clone(), &signer_a, &feed_id, 6, request, 60),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit valid replacement observation");
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: 6,
        request_hash: request,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider_a, &mut stx)
    .expect("valid quorum after tamper rejection");
    assert_eq!(
        stx.world
            .oracle_history()
            .get(&feed_id)
            .expect("history")
            .len(),
        1
    );
}
#[test]
fn oracle_feed_upgrade_rejects_stale_version_observations_and_old_windows() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "feed_upgrade_observation_guards".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config(
                feed_id.clone(),
                vec![provider_a.clone(), provider_b.clone()],
            ),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register v1 feed");
    let request = Hash::new(b"upgrade-stale-window");
    SubmitOracleObservation {
        observation: observation(provider_a.clone(), &signer_a, &feed_id, 1, request, 10),
    }
    .execute(&provider_a, &mut stx)
    .expect("buffer v1 observation");
    let mut upgraded = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    upgraded.feed_config_version = FeedConfigVersion(2);
    execute_boxed(RegisterOracleFeed { feed: upgraded }, &provider_a, &mut stx)
        .expect("register v2 feed");
    assert_rejects_with(
        SubmitOracleObservation {
            observation: observation(provider_b.clone(), &signer_b, &feed_id, 1, request, 10),
        }
        .execute(&provider_b, &mut stx),
        "feed config version mismatch",
    );
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id,
            slot: 1,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "insufficient oracle quorum",
    );
}
#[test]
fn oracle_register_rejects_current_version_replay_and_downgrade_after_upgrade() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "feed_version_replay_guard".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(std::slice::from_ref(&provider));
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let feed_v1 = feed_config(feed_id.clone(), vec![provider.clone()]);
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_v1.clone(),
        },
        &provider,
        &mut stx,
    )
    .expect("register v1 feed");
    let mut feed_v2 = feed_v1.clone();
    feed_v2.feed_config_version = FeedConfigVersion(2);
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_v2.clone(),
        },
        &provider,
        &mut stx,
    )
    .expect("register v2 feed");
    assert_rejects_with(
        execute_boxed(RegisterOracleFeed { feed: feed_v1 }, &provider, &mut stx),
        "already registered with version 2 (incoming 1)",
    );
    assert_rejects_with(
        execute_boxed(RegisterOracleFeed { feed: feed_v2 }, &provider, &mut stx),
        "already registered with version 2 (incoming 2)",
    );
}
#[test]
fn oracle_observations_reject_inactive_slot_and_connector_mismatch() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "observation_metadata_guards".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.cadence_slots = nonzero!(2_u64);
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    assert_rejects_with(
        SubmitOracleObservation {
            observation: observation(
                provider_a.clone(),
                &signer_a,
                &feed_id,
                3,
                Hash::new(b"inactive-slot"),
                10,
            ),
        }
        .execute(&provider_a, &mut stx),
        "slot 3 is not active for cadence 2",
    );
    let mut wrong_connector = observation(
        provider_b.clone(),
        &signer_b,
        &feed_id,
        4,
        Hash::new(b"wrong-connector"),
        11,
    );
    wrong_connector.body.connector_id = "evil-bin".to_string();
    wrong_connector.signature = checked_signature_of(signer_b.private_key(), &wrong_connector.body);
    assert_rejects_with(
        SubmitOracleObservation {
            observation: wrong_connector,
        }
        .execute(&provider_b, &mut stx),
        "connector mismatch",
    );
}
#[test]
fn oracle_observations_reject_unregistered_feed_connector_version_and_processed_window() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "observation_processed_guards".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    assert_rejects_with(
        SubmitOracleObservation {
            observation: observation(
                provider_a.clone(),
                &signer_a,
                &feed_id,
                1,
                Hash::new(b"unregistered-feed"),
                10,
            ),
        }
        .execute(&provider_a, &mut stx),
        "is not registered",
    );
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config(
                feed_id.clone(),
                vec![provider_a.clone(), provider_b.clone()],
            ),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let mut wrong_connector_version = observation(
        provider_a.clone(),
        &signer_a,
        &feed_id,
        1,
        Hash::new(b"wrong-connector-version"),
        11,
    );
    wrong_connector_version.body.connector_version = 2;
    wrong_connector_version.signature =
        checked_signature_of(signer_a.private_key(), &wrong_connector_version.body);
    assert_rejects_with(
        SubmitOracleObservation {
            observation: wrong_connector_version,
        }
        .execute(&provider_a, &mut stx),
        "connector mismatch",
    );
    let request = Hash::new(b"processed-submit");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        2,
        request,
        20,
        Vec::new(),
    );
    assert_rejects_with(
        SubmitOracleObservation {
            observation: observation(provider_a.clone(), &signer_a, &feed_id, 2, request, 21),
        }
        .execute(&provider_a, &mut stx),
        "already processed",
    );
}
#[test]
fn oracle_aggregation_rejects_insufficient_quorum_replay_and_stale_windows() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "aggregation_guards".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 2;
    config.replay_window_slots = nonzero!(1_u64);
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let request_1 = Hash::new(b"quorum-request-1");
    SubmitOracleObservation {
        observation: observation(provider_a.clone(), &signer_a, &feed_id, 1, request_1, 10),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit first observation");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 1,
            request_hash: request_1,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "insufficient oracle quorum",
    );
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register fresh feed");
    let request_2 = Hash::new(b"quorum-request-2");
    for (provider, signer, value) in [
        (&provider_a, &signer_a, 20_i128),
        (&provider_b, &signer_b, 20_i128),
    ] {
        SubmitOracleObservation {
            observation: observation(provider.clone(), signer, &feed_id, 2, request_2, value),
        }
        .execute(provider, &mut stx)
        .expect("submit quorum observation");
    }
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: 2,
        request_hash: request_2,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider_a, &mut stx)
    .expect("aggregate quorum window");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 2,
            request_hash: request_2,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "already processed",
    );
    let request_3 = Hash::new(b"quorum-request-3");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        4,
        request_3,
        30,
        Vec::new(),
    );
    let stale_request = Hash::new(b"quorum-request-stale");
    assert_rejects_with(
        SubmitOracleObservation {
            observation: observation(
                provider_a.clone(),
                &signer_a,
                &feed_id,
                1,
                stale_request,
                12,
            ),
        }
        .execute(&provider_a, &mut stx),
        "stale oracle window",
    );
}
#[test]
fn oracle_aggregation_wrong_request_does_not_consume_matching_window() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "aggregation_request_isolation".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 2;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"correct-aggregate-request");
    for (provider, signer) in [(&provider_a, &signer_a), (&provider_b, &signer_b)] {
        SubmitOracleObservation {
            observation: observation(provider.clone(), signer, &feed_id, 5, request, 55),
        }
        .execute(provider, &mut stx)
        .expect("submit matching observation");
    }
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 5,
            request_hash: Hash::new(b"wrong-aggregate-request"),
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "insufficient oracle quorum",
    );
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: 5,
        request_hash: request,
        evidence_hashes: vec![Hash::new(b"request-isolation-evidence")],
    }
    .execute(&provider_a, &mut stx)
    .expect("matching request window remains aggregatable");
    let history = stx
        .world
        .oracle_history()
        .get(&feed_id)
        .cloned()
        .unwrap_or_default();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event.request_hash, request);
}
#[test]
fn oracle_aggregation_rejects_unauthorized_empty_mismatched_scale_and_stale_manual_windows() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let (outsider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "aggregation_adversarial_guards".parse().expect("feed id");
    let (state, _, _, _) =
        oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone(), outsider.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 2;
    config.replay_window_slots = nonzero!(1_u64);
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 1,
            request_hash: Hash::new(b"unauthorized-aggregate"),
            evidence_hashes: Vec::new(),
        }
        .execute(&outsider, &mut stx),
        "is not part of feed",
    );
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 1,
            request_hash: Hash::new(b"empty-aggregate"),
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "insufficient oracle quorum",
    );
    let request = Hash::new(b"mismatched-scale");
    SubmitOracleObservation {
        observation: observation(provider_a.clone(), &signer_a, &feed_id, 2, request, 10),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit first scale");
    let mut scaled = observation(provider_b.clone(), &signer_b, &feed_id, 2, request, 10);
    scaled.body.outcome = ObservationOutcome::Value(ObservationValue::new(10, 6));
    scaled.signature = checked_signature_of(signer_b.private_key(), &scaled.body);
    SubmitOracleObservation {
        observation: scaled,
    }
    .execute(&provider_b, &mut stx)
    .expect("submit mismatched scale");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 2,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "mismatched scales",
    );
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register fresh feed");
    let stale_request = Hash::new(b"stale-manual-window");
    for (provider, signer, value) in [
        (&provider_a, &signer_a, 20_i128),
        (&provider_b, &signer_b, 20_i128),
    ] {
        SubmitOracleObservation {
            observation: observation(provider.clone(), signer, &feed_id, 1, stale_request, value),
        }
        .execute(provider, &mut stx)
        .expect("buffer stale candidate");
    }
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        3,
        Hash::new(b"fresh-window"),
        30,
        Vec::new(),
    );
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id,
            slot: 1,
            request_hash: stale_request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "stale oracle window",
    );
}
#[test]
fn oracle_aggregation_rejects_value_overflow_and_all_outlier_quorum_collapse() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "aggregation_value_guards".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(feed_id.clone(), vec![provider_a.clone()]);
    config.max_value_len = 4;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register small-value feed");
    let request = Hash::new(b"value-too-long");
    SubmitOracleObservation {
        observation: observation(
            provider_a.clone(),
            &signer_a,
            &feed_id,
            1,
            request,
            i128::MAX,
        ),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit oversized value");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 1,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "observation value too long",
    );
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 1;
    config.outlier_policy = OutlierPolicy::Absolute(AbsoluteOutlier { max_delta: 0 });
    execute_boxed(RegisterOracleFeed { feed: config }, &provider_a, &mut stx)
        .expect("register strict outlier feed");
    let request = Hash::new(b"all-outliers");
    for (provider, signer, value) in [
        (&provider_a, &signer_a, 0_i128),
        (&provider_b, &signer_b, 10_i128),
    ] {
        SubmitOracleObservation {
            observation: observation(provider.clone(), signer, &feed_id, 2, request, value),
        }
        .execute(provider, &mut stx)
        .expect("submit outlier candidate");
    }
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id,
            slot: 2,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "insufficient oracle quorum",
    );
}
#[test]
fn oracle_aggregation_rejects_error_rate_spikes_and_mismatched_error_quorum() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "error_outcome_adversarial".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 1;
    config.max_error_rate_bps = 250;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"error-rate-spike");
    SubmitOracleObservation {
        observation: error_observation(
            provider_a.clone(),
            &signer_a,
            &feed_id,
            1,
            request,
            ObservationErrorCode::Timeout,
        ),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit error observation");
    SubmitOracleObservation {
        observation: observation(provider_b.clone(), &signer_b, &feed_id, 1, request, 100),
    }
    .execute(&provider_b, &mut stx)
    .expect("submit value observation");
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id: feed_id.clone(),
            slot: 1,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "oracle error rate exceeded",
    );
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    config.min_signers = 2;
    config.max_error_rate_bps = 10_000;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"mismatched-error-quorum");
    for (provider, signer, code) in [
        (
            &provider_a,
            &signer_a,
            ObservationErrorCode::ResourceUnavailable,
        ),
        (&provider_b, &signer_b, ObservationErrorCode::Timeout),
    ] {
        SubmitOracleObservation {
            observation: error_observation(provider.clone(), signer, &feed_id, 2, request, code),
        }
        .execute(provider, &mut stx)
        .expect("submit error observation");
    }
    assert_rejects_with(
        AggregateOracleFeed {
            feed_id,
            slot: 2,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx),
        "insufficient oracle quorum",
    );
}
#[test]
fn oracle_dispute_rejects_non_feed_target_wrong_request_and_missing_resolution() {
    let (challenger, challenger_signer) = iroha_test_samples::gen_account_in("validators");
    let (target, target_signer) = iroha_test_samples::gen_account_in("validators");
    let (outsider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "dispute_exact_anchor_guards".parse().expect("feed id");
    let (state, _, _, _) =
        oracle_state_with_accounts(&[challenger.clone(), target.clone(), outsider.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(feed_id.clone(), vec![challenger.clone(), target.clone()]);
    config.min_signers = 2;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &challenger,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"exact-dispute-anchor");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        7,
        request,
        42,
        vec![Hash::new(b"exact-dispute-bundle")],
    );
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 7,
                request_hash: request,
                target: outsider,
                bond: None,
                evidence_hashes: vec![Hash::new(b"outsider-target")],
                reason: "not a feed provider".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "is not part of feed",
    );
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 7,
                request_hash: Hash::new(b"wrong-dispute-request"),
                target: target.clone(),
                bond: None,
                evidence_hashes: vec![Hash::new(b"wrong-request")],
                reason: "wrong request hash".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "no retained oracle feed event",
    );
    assert_rejects_with(
        execute_boxed(
            ResolveOracleDispute {
                dispute_id: iroha_data_model::oracle::OracleDisputeId(1_000_000),
                outcome: iroha_data_model::oracle::OracleDisputeOutcome::Reduced,
                notes: "missing dispute".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "does not exist",
    );
}
#[test]
fn oracle_dispute_rejects_old_version_anchor_after_feed_upgrade() {
    let (challenger, challenger_signer) = iroha_test_samples::gen_account_in("validators");
    let (target, target_signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "dispute_upgrade_anchor_guard".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[challenger.clone(), target.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config_v1 = feed_config(feed_id.clone(), vec![challenger.clone(), target.clone()]);
    config_v1.min_signers = 2;
    execute_boxed(
        RegisterOracleFeed {
            feed: config_v1.clone(),
        },
        &challenger,
        &mut stx,
    )
    .expect("register v1 feed");
    let request = Hash::new(b"old-version-dispute-anchor");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        9,
        request,
        42,
        vec![Hash::new(b"old-version-event-evidence")],
    );
    let mut config_v2 = config_v1;
    config_v2.feed_config_version = FeedConfigVersion(2);
    execute_boxed(
        RegisterOracleFeed { feed: config_v2 },
        &challenger,
        &mut stx,
    )
    .expect("upgrade feed");
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id,
                slot: 9,
                request_hash: request,
                target,
                bond: None,
                evidence_hashes: vec![Hash::new(b"old-version-dispute-evidence")],
                reason: "old version event after upgrade".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "no retained oracle feed event",
    );
}
#[test]
fn oracle_dispute_rejects_oversized_bond_without_recording_dispute() {
    let (challenger, challenger_signer) = iroha_test_samples::gen_account_in("validators");
    let (target, target_signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "dispute_bond_guard_feed".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[challenger.clone(), target.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(feed_id.clone(), vec![challenger.clone(), target.clone()]);
    config.min_signers = 2;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &challenger,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"oversized-bond-dispute");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        8,
        request,
        42,
        Vec::new(),
    );
    let dispute = dispute_id(&feed_id, 8, request, &challenger, &target);
    assert!(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 8,
                request_hash: request,
                target: target.clone(),
                bond: Some(Quantity::from_str("999").expect("quantity")),
                evidence_hashes: vec![Hash::new(b"oversized-bond-evidence")],
                reason: "cannot afford bond".to_string(),
            },
            &challenger,
            &mut stx,
        )
        .is_err(),
        "bond larger than challenger balance must reject"
    );
    assert!(
        stx.world.oracle_disputes().get(&dispute).is_none(),
        "failed dispute opening must not record a dispute"
    );
}
#[test]
fn oracle_dispute_requires_history_anchor_evidence_and_target_relevance() {
    let (challenger, challenger_signer) = iroha_test_samples::gen_account_in("validators");
    let (target, target_signer) = iroha_test_samples::gen_account_in("validators");
    let (uninvolved, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "dispute_anchor_guards".parse().expect("feed id");
    let (state, _, _, _) =
        oracle_state_with_accounts(&[challenger.clone(), target.clone(), uninvolved.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(
        feed_id.clone(),
        vec![challenger.clone(), target.clone(), uninvolved.clone()],
    );
    config.min_signers = 2;
    config.committee_size = 3;
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &challenger,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"dispute-anchor");
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 10,
                request_hash: request,
                target: target.clone(),
                bond: None,
                evidence_hashes: Vec::new(),
                reason: "missing evidence".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "evidence must not be empty",
    );
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 10,
                request_hash: request,
                target: target.clone(),
                bond: None,
                evidence_hashes: vec![Hash::new(b"evidence")],
                reason: "missing history".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "no retained oracle feed event",
    );
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        10,
        request,
        42,
        vec![Hash::new(b"bundle")],
    );
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id,
                slot: 10,
                request_hash: request,
                target: uninvolved,
                bond: None,
                evidence_hashes: vec![Hash::new(b"evidence")],
                reason: "uninvolved provider".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "did not contribute",
    );
}
#[test]
fn oracle_dispute_rejects_stale_duplicate_unauthorized_and_repeat_resolution() {
    let (challenger, challenger_signer) = iroha_test_samples::gen_account_in("validators");
    let (target, target_signer) = iroha_test_samples::gen_account_in("validators");
    let (outsider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "dispute_adversarial_guards".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[challenger.clone(), target.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut config = feed_config(feed_id.clone(), vec![challenger.clone(), target.clone()]);
    config.min_signers = 2;
    config.dispute_window_slots = nonzero!(1_u64);
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &challenger,
        &mut stx,
    )
    .expect("register feed");
    let stale_request = Hash::new(b"stale-dispute");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        10,
        stale_request,
        42,
        vec![Hash::new(b"stale-bundle")],
    );
    let fresh_request = Hash::new(b"fresh-dispute");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        12,
        fresh_request,
        43,
        vec![Hash::new(b"fresh-bundle")],
    );
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 10,
                request_hash: stale_request,
                target: target.clone(),
                bond: None,
                evidence_hashes: vec![Hash::new(b"stale-evidence")],
                reason: "too old".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "outside dispute window",
    );
    execute_boxed(
        OpenOracleDispute {
            feed_id: feed_id.clone(),
            slot: 12,
            request_hash: fresh_request,
            target: target.clone(),
            bond: None,
            evidence_hashes: vec![Hash::new(b"fresh-evidence")],
            reason: "fresh challenge".to_string(),
        },
        &challenger,
        &mut stx,
    )
    .expect("open fresh dispute");
    assert_rejects_with(
        execute_boxed(
            OpenOracleDispute {
                feed_id: feed_id.clone(),
                slot: 12,
                request_hash: fresh_request,
                target: target.clone(),
                bond: None,
                evidence_hashes: vec![Hash::new(b"duplicate-evidence")],
                reason: "duplicate challenge".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "already exists",
    );
    let dispute = dispute_id(&feed_id, 12, fresh_request, &challenger, &target);
    assert_rejects_with(
        execute_boxed(
            ResolveOracleDispute {
                dispute_id: dispute,
                outcome: iroha_data_model::oracle::OracleDisputeOutcome::Reduced,
                notes: "outsider attempt".to_string(),
            },
            &outsider,
            &mut stx,
        ),
        "does not have `CanResolveOracleDispute`",
    );
    execute_boxed(
        ResolveOracleDispute {
            dispute_id: dispute,
            outcome: iroha_data_model::oracle::OracleDisputeOutcome::Reduced,
            notes: "resolved".to_string(),
        },
        &challenger,
        &mut stx,
    )
    .expect("resolve dispute");
    assert_rejects_with(
        execute_boxed(
            ResolveOracleDispute {
                dispute_id: dispute,
                outcome: iroha_data_model::oracle::OracleDisputeOutcome::Upheld,
                notes: "second resolution".to_string(),
            },
            &challenger,
            &mut stx,
        ),
        "already resolved",
    );
}
#[test]
fn oracle_change_votes_reject_missing_permission_and_stage_jumps() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "stage_guard_feed".parse().expect("feed id");
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let domain = Domain::new(validator_domain_id).build(&provider);
    let account = Account::new(provider.clone()).build(&provider);
    let mut world = World::with([domain], [account], []);
    grant_permission(
        &mut world,
        &provider,
        oracle_permission::CanProposeOracleChange,
    );
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"stage-missing-permission"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id.clone(), vec![provider.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"payload"),
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("propose change");
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::Intake,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "does not have `CanVoteOracleChangeStage`",
    );
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "stage_jump_feed".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    cfg.governance.rules_min_votes = nonzero!(1_usize);
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"stage-jump"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id, vec![provider.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"payload"),
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("propose change");
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::RulesCommittee,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "cannot vote future oracle change stage",
    );
    execute_boxed(
        VoteOracleChangeStage {
            change_id,
            stage: OracleChangeStage::Intake,
            approve: true,
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("advance intake");
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::Intake,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "cannot vote past oracle change stage",
    );
}
#[test]
fn oracle_change_duplicate_vote_does_not_satisfy_quorum() {
    let (provider_a, _) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "duplicate_vote_quorum_feed".parse().expect("feed id");
    let world = world_with_providers(&[provider_a.clone(), provider_b.clone()]);
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(2_usize);
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"duplicate-vote-quorum"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id, vec![provider_a.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"duplicate-vote-payload"),
            evidence_hashes: Vec::new(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("propose change");
    for _ in 0..2 {
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::Intake,
                approve: true,
                evidence_hashes: vec![Hash::new(b"duplicate-vote-evidence")],
            },
            &provider_a,
            &mut stx,
        )
        .expect("duplicate vote is accepted but must not count twice");
    }
    let proposal = stx
        .world
        .oracle_changes()
        .get(&change_id)
        .cloned()
        .expect("change exists");
    let intake = proposal
        .stages
        .iter()
        .find(|stage| stage.stage == OracleChangeStage::Intake)
        .expect("intake stage exists");
    assert_eq!(intake.approvals.len(), 1);
    assert!(matches!(proposal.status, OracleChangeStatus::Pending));
    assert_eq!(
        proposal.current_stage().map(|stage| stage.stage),
        Some(OracleChangeStage::Intake)
    );
    execute_boxed(
        VoteOracleChangeStage {
            change_id,
            stage: OracleChangeStage::Intake,
            approve: true,
            evidence_hashes: vec![Hash::new(b"second-voter-evidence")],
        },
        &provider_b,
        &mut stx,
    )
    .expect("second distinct voter satisfies quorum");
    let proposal = stx
        .world
        .oracle_changes()
        .get(&change_id)
        .cloned()
        .expect("change exists");
    assert_eq!(
        proposal.current_stage().map(|stage| stage.stage),
        Some(OracleChangeStage::RulesCommittee)
    );
}
#[test]
fn oracle_change_stage_permission_is_specific_even_when_role_grants_intake() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "stage_specific_role_feed".parse().expect("feed id");
    let role_id: RoleId = "intake_voter".parse().expect("role id");
    let mut world = world_with_provider_role_permission(
        &provider,
        role_id,
        oracle_permission::CanVoteOracleChangeStage {
            stage: OracleChangeStage::Intake,
        },
    );
    grant_permission(
        &mut world,
        &provider,
        oracle_permission::CanProposeOracleChange,
    );
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    cfg.governance.rules_min_votes = nonzero!(1_usize);
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"stage-specific-role"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id, vec![provider.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"stage-specific-role-payload"),
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("propose change");
    execute_boxed(
        VoteOracleChangeStage {
            change_id,
            stage: OracleChangeStage::Intake,
            approve: true,
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("role-granted intake vote succeeds");
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::RulesCommittee,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "does not have `CanVoteOracleChangeStage`",
    );
}
#[test]
fn oracle_change_proposal_rejects_invalid_feeds_and_terminal_enacted_operations() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "change_invalid_feed_guard".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    cfg.governance.rules_min_votes = nonzero!(1_usize);
    cfg.governance.cop_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    cfg.governance.technical_min_votes = nonzero!(1_usize);
    cfg.governance.policy_jury_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let mut duplicate_provider =
        feed_config(feed_id.clone(), vec![provider.clone(), provider.clone()]);
    duplicate_provider.committee_size = 2;
    assert_rejects_with(
        execute_boxed(
            ProposeOracleChange {
                change_id: OracleChangeId(Hash::new(b"invalid-duplicate-provider-change")),
                feed: duplicate_provider,
                class: OracleChangeClass::Low,
                payload_hash: Hash::new(b"invalid-duplicate-provider-payload"),
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "duplicate oracle provider",
    );
    let mut invalid_quorum = feed_config(feed_id.clone(), vec![provider.clone()]);
    invalid_quorum.min_signers = 2;
    assert_rejects_with(
        execute_boxed(
            ProposeOracleChange {
                change_id: OracleChangeId(Hash::new(b"invalid-quorum-change")),
                feed: invalid_quorum,
                class: OracleChangeClass::Low,
                payload_hash: Hash::new(b"invalid-quorum-payload"),
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "min_signers 2 exceeds committee_size 1",
    );
    let change_id = OracleChangeId(Hash::new(b"enacted-terminal-change"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id, vec![provider.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"enacted-terminal-payload"),
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("propose valid change");
    for stage in [
        OracleChangeStage::Intake,
        OracleChangeStage::RulesCommittee,
        OracleChangeStage::CopReview,
        OracleChangeStage::TechnicalAudit,
        OracleChangeStage::PolicyJury,
        OracleChangeStage::Enactment,
    ] {
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        )
        .expect("advance valid change");
    }
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::Enactment,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "already finalized",
    );
    assert_rejects_with(
        execute_boxed(
            RollbackOracleChange {
                change_id,
                stage: None,
                reason: "too late after enactment".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "already finalized",
    );
}
#[test]
fn oracle_change_rejects_vote_and_rollback_after_terminal_rejection() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "change_terminal_guard_feed".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"terminal-change"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id, vec![provider.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"terminal-payload"),
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("propose change");
    execute_boxed(
        VoteOracleChangeStage {
            change_id,
            stage: OracleChangeStage::Intake,
            approve: false,
            evidence_hashes: vec![Hash::new(b"reject-evidence")],
        },
        &provider,
        &mut stx,
    )
    .expect("reject intake");
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::Intake,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "already finalized",
    );
    assert_rejects_with(
        execute_boxed(
            RollbackOracleChange {
                change_id,
                stage: None,
                reason: "too late".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "already finalized",
    );
}
#[test]
fn oracle_change_rejects_duplicate_id_and_late_enactment_conflict() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "change_late_conflict_feed".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    cfg.governance.rules_min_votes = nonzero!(1_usize);
    cfg.governance.cop_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    cfg.governance.technical_min_votes = nonzero!(1_usize);
    cfg.governance.policy_jury_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"change-duplicate-conflict"));
    let feed = feed_config(feed_id.clone(), vec![provider.clone()]);
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed.clone(),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"change-conflict-payload"),
            evidence_hashes: vec![Hash::new(b"change-conflict-evidence")],
        },
        &provider,
        &mut stx,
    )
    .expect("propose change");
    assert_rejects_with(
        execute_boxed(
            ProposeOracleChange {
                change_id,
                feed: feed.clone(),
                class: OracleChangeClass::Low,
                payload_hash: Hash::new(b"duplicate-payload"),
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "already exists",
    );
    execute_boxed(RegisterOracleFeed { feed }, &provider, &mut stx)
        .expect("register conflicting feed before enactment");
    for stage in [
        OracleChangeStage::Intake,
        OracleChangeStage::RulesCommittee,
        OracleChangeStage::CopReview,
        OracleChangeStage::TechnicalAudit,
        OracleChangeStage::PolicyJury,
    ] {
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        )
        .expect("advance change stage");
    }
    assert_rejects_with(
        execute_boxed(
            VoteOracleChangeStage {
                change_id,
                stage: OracleChangeStage::Enactment,
                approve: true,
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "already registered with version 1 (incoming 1)",
    );
}
#[test]
fn oracle_change_rejects_unauthorized_proposal_unknown_change_and_rollback_stage_jumps() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "change_rollback_guard_feed".parse().expect("feed id");
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let domain = Domain::new(validator_domain_id).build(&provider);
    let account = Account::new(provider.clone()).build(&provider);
    let mut state = State::with_telemetry(
        World::with([domain], [account], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    assert_rejects_with(
        execute_boxed(
            ProposeOracleChange {
                change_id: OracleChangeId(Hash::new(b"unauthorized-proposal")),
                feed: feed_config(feed_id.clone(), vec![provider.clone()]),
                class: OracleChangeClass::Low,
                payload_hash: Hash::new(b"unauthorized-payload"),
                evidence_hashes: Vec::new(),
            },
            &provider,
            &mut stx,
        ),
        "does not have `CanProposeOracleChange`",
    );
    let world = world_with_providers(std::slice::from_ref(&provider));
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"rollback-stage-jump"));
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(feed_id, vec![provider.clone()]),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"rollback-payload"),
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("propose change");
    assert_rejects_with(
        execute_boxed(
            RollbackOracleChange {
                change_id,
                stage: Some(OracleChangeStage::RulesCommittee),
                reason: "skip forward".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "cannot roll back future oracle change stage",
    );
    execute_boxed(
        VoteOracleChangeStage {
            change_id,
            stage: OracleChangeStage::Intake,
            approve: true,
            evidence_hashes: Vec::new(),
        },
        &provider,
        &mut stx,
    )
    .expect("advance intake");
    assert_rejects_with(
        execute_boxed(
            RollbackOracleChange {
                change_id,
                stage: Some(OracleChangeStage::Intake),
                reason: "skip backward".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "cannot roll back past oracle change stage",
    );
    assert_rejects_with(
        execute_boxed(
            RollbackOracleChange {
                change_id: OracleChangeId(Hash::new(b"missing-change")),
                stage: None,
                reason: "missing".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "is not registered",
    );
}
#[test]
fn oracle_queries_return_feeds_history_stats_disputes_changes_and_bindings() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "query_surface_feed".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone()],
    );
    execute_boxed(
        RegisterOracleFeed {
            feed: config.clone(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("register feed");
    let request = Hash::new(b"query-request");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        10,
        request,
        50,
        vec![Hash::new(b"query-bundle")],
    );
    execute_boxed(
        OpenOracleDispute {
            feed_id: feed_id.clone(),
            slot: 10,
            request_hash: request,
            target: provider_b.clone(),
            bond: None,
            evidence_hashes: vec![Hash::new(b"query-dispute")],
            reason: "query dispute".to_string(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("open dispute");
    let dispute_id = dispute_id(&feed_id, 10, request, &provider_a, &provider_b);
    let change_id = OracleChangeId(Hash::new(b"query-change"));
    let change_feed_id: FeedId = "query_change_feed".parse().expect("feed id");
    execute_boxed(
        ProposeOracleChange {
            change_id,
            feed: feed_config(
                change_feed_id.clone(),
                vec![provider_a.clone(), provider_b.clone()],
            ),
            class: OracleChangeClass::Low,
            payload_hash: Hash::new(b"query-change-payload"),
            evidence_hashes: Vec::new(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("propose change");
    let twitter_kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut twitter_feed = twitter_kit.feed_config;
    twitter_feed.providers = vec![provider_a.clone()];
    twitter_feed.min_signers = 1;
    twitter_feed.committee_size = 1;
    twitter_feed.feed_id = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"query-uaid"));
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"query-user",
    );
    let attestation = twitter_binding_attestation(&twitter_feed, &uaid, binding_hash.clone(), 500);
    record_twitter_binding_round(
        &mut stx,
        &provider_a,
        &signer_a,
        &twitter_feed,
        &attestation,
    );
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit query state");
    let view = state.view();
    assert_eq!(
        FindOracleFeedById::new(feed_id.clone())
            .execute(&view)
            .expect("find feed")
            .feed_id,
        feed_id
    );
    assert!(
        FindOracleFeeds
            .execute(CompoundPredicate::PASS, &view)
            .expect("find feeds")
            .any(|feed| feed.feed_id == feed_id)
    );
    assert_eq!(
        FindOracleHistoryByFeedId::new(feed_id.clone())
            .execute(CompoundPredicate::PASS, &view)
            .expect("find history")
            .count(),
        1
    );
    let stats_key = OracleProviderKey::new(feed_id.clone(), provider_a.clone());
    assert!(
        FindOracleProviderStatsByKey::new(stats_key.clone())
            .execute(&view)
            .expect("find provider stats")
            .inliers
            > 0
    );
    assert!(
        FindOracleProviderStatsByFeedId::new(feed_id.clone())
            .execute(CompoundPredicate::PASS, &view)
            .expect("find provider stats by feed")
            .any(|record| record.key == stats_key)
    );
    assert_eq!(
        FindOracleDisputeById::new(dispute_id)
            .execute(&view)
            .expect("find dispute")
            .id,
        dispute_id
    );
    assert!(
        FindOracleDisputes
            .execute(CompoundPredicate::PASS, &view)
            .expect("find disputes")
            .any(|dispute| dispute.id == dispute_id)
    );
    assert!(
        FindOracleDisputesByFeedId::new(feed_id)
            .execute(CompoundPredicate::PASS, &view)
            .expect("find disputes by feed")
            .any(|dispute| dispute.id == dispute_id)
    );
    assert_eq!(
        FindOracleChangeById::new(change_id)
            .execute(&view)
            .expect("find change")
            .feed
            .feed_id,
        change_feed_id
    );
    assert!(
        FindOracleChanges
            .execute(CompoundPredicate::PASS, &view)
            .expect("find changes")
            .any(|change| change.id == change_id)
    );
    assert_eq!(
        FindTwitterBindingByHash::new(binding_hash.clone())
            .execute(&view)
            .expect("find twitter binding")
            .attestation
            .uaid,
        uaid
    );
    assert!(
        FindTwitterBindingsByUaid::new(uaid)
            .execute(CompoundPredicate::PASS, &view)
            .expect("find twitter bindings by uaid")
            .any(|binding| binding.attestation.binding_hash == binding_hash)
    );
}
#[test]
fn oracle_iter_queries_do_not_leak_unrelated_feed_records() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let feed_a: FeedId = "query_isolation_a".parse().expect("feed id");
    let feed_b: FeedId = "query_isolation_b".parse().expect("feed id");
    let missing_feed: FeedId = "query_isolation_missing".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    for feed_id in [&feed_a, &feed_b] {
        let mut config = feed_config(
            feed_id.clone(),
            vec![provider_a.clone(), provider_b.clone()],
        );
        config.min_signers = 2;
        execute_boxed(RegisterOracleFeed { feed: config }, &provider_a, &mut stx)
            .expect("register feed");
    }
    let request_a = Hash::new(b"query-isolation-a");
    let request_b = Hash::new(b"query-isolation-b");
    aggregate_round(
        &mut stx,
        &feed_a,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        1,
        request_a,
        10,
        Vec::new(),
    );
    aggregate_round(
        &mut stx,
        &feed_b,
        [(&provider_a, &signer_a), (&provider_b, &signer_b)],
        1,
        request_b,
        20,
        Vec::new(),
    );
    execute_boxed(
        OpenOracleDispute {
            feed_id: feed_a.clone(),
            slot: 1,
            request_hash: request_a,
            target: provider_b.clone(),
            bond: None,
            evidence_hashes: vec![Hash::new(b"query-isolation-dispute")],
            reason: "feed a only".to_string(),
        },
        &provider_a,
        &mut stx,
    )
    .expect("open feed-a dispute");
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit query isolation state");
    let view = state.view();
    let feed_b_history = FindOracleHistoryByFeedId::new(feed_b.clone())
        .execute(CompoundPredicate::PASS, &view)
        .expect("find feed-b history")
        .collect::<Vec<_>>();
    assert_eq!(feed_b_history.len(), 1);
    assert_eq!(feed_b_history[0].event.feed_id, feed_b);
    assert_eq!(feed_b_history[0].event.request_hash, request_b);
    assert_eq!(
        FindOracleDisputesByFeedId::new(feed_b)
            .execute(CompoundPredicate::PASS, &view)
            .expect("find feed-b disputes")
            .count(),
        0
    );
    assert_eq!(
        FindOracleProviderStatsByFeedId::new(missing_feed)
            .execute(CompoundPredicate::PASS, &view)
            .expect("find missing feed stats")
            .count(),
        0
    );
}
#[test]
fn oracle_singular_queries_reject_missing_records() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "missing_query_feed".parse().expect("feed id");
    let (state, _, _, _) = oracle_state_with_accounts(std::slice::from_ref(&provider));
    let view = state.view();
    assert!(
        FindOracleFeedById::new(feed_id.clone())
            .execute(&view)
            .is_err()
    );
    assert!(
        FindOracleDisputeById::new(iroha_data_model::oracle::OracleDisputeId(999))
            .execute(&view)
            .is_err()
    );
    assert!(
        FindOracleChangeById::new(OracleChangeId(Hash::new(b"missing-change-query")))
            .execute(&view)
            .is_err()
    );
    assert!(
        FindOracleProviderStatsByKey::new(OracleProviderKey::new(feed_id, provider))
            .execute(&view)
            .is_err()
    );
    assert!(
        FindTwitterBindingByHash::new(KeyedHash::new(
            defaults::oracle::twitter_binding_pepper_id(),
            b"missing-pepper",
            b"missing-user",
        ))
        .execute(&view)
        .is_err()
    );
}
fn dispute_id(
    feed_id: &FeedId,
    slot: FeedSlot,
    request_hash: Hash,
    challenger: &AccountId,
    target: &AccountId,
) -> iroha_data_model::oracle::OracleDisputeId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(feed_id.as_str().as_bytes());
    hasher.update(&slot.to_le_bytes());
    hasher.update(request_hash.as_ref());
    hasher.update(challenger.to_string().as_bytes());
    hasher.update(target.to_string().as_bytes());
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    iroha_data_model::oracle::OracleDisputeId(u64::from_le_bytes(buf))
}
fn asset_value(view: &impl WorldReadOnly, asset_id: &AssetId) -> Quantity {
    view.asset(asset_id)
        .unwrap_or_else(|_| panic!("missing asset {asset_id}"))
        .as_ref()
        .clone()
}
#[test]
fn oracle_applies_rewards_and_penalties() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let (provider_c, signer_c) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "price_xor_usd".parse().expect("feed id");
    let (state, asset_def_id, reward_pool, slash_receiver) =
        oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone(), provider_c.clone()]);
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone(), provider_c.clone()],
    );
    config.outlier_policy = OutlierPolicy::Absolute(AbsoluteOutlier { max_delta: 5 });
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    RegisterOracleFeed {
        feed: config.clone(),
    }
    .execute(&provider_a, &mut stx)
    .expect("register feed");
    let req = Hash::new(b"reward-penalty");
    SubmitOracleObservation {
        observation: observation(provider_a.clone(), &signer_a, &feed_id, 42, req, 10),
    }
    .execute(&provider_a, &mut stx)
    .expect("submit observation a");
    SubmitOracleObservation {
        observation: observation(provider_b.clone(), &signer_b, &feed_id, 42, req, 12),
    }
    .execute(&provider_b, &mut stx)
    .expect("submit observation b");
    SubmitOracleObservation {
        observation: observation(provider_c.clone(), &signer_c, &feed_id, 42, req, 100),
    }
    .execute(&provider_c, &mut stx)
    .expect("submit observation c");
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: 42,
        request_hash: req,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider_a, &mut stx)
    .expect("aggregate slot");
    stx.apply();
    sb.commit_world_overlay_for_testing().expect("commit block");
    let view = state.view();
    let a_id = AssetId::new(asset_def_id.clone(), provider_a.clone());
    let b_id = AssetId::new(asset_def_id.clone(), provider_b.clone());
    let c_id = AssetId::new(asset_def_id.clone(), provider_c.clone());
    let pool_id = AssetId::new(asset_def_id.clone(), reward_pool.clone());
    let slash_id = AssetId::new(asset_def_id, slash_receiver.clone());
    assert_eq!(
        asset_value(view.world(), &a_id),
        Quantity::from_str("6").expect("quantity")
    );
    assert_eq!(
        asset_value(view.world(), &b_id),
        Quantity::from_str("6").expect("quantity")
    );
    assert_eq!(
        asset_value(view.world(), &c_id),
        Quantity::from_str("4").expect("quantity")
    );
    assert_eq!(
        asset_value(view.world(), &pool_id),
        Quantity::from_str("8").expect("quantity")
    );
    assert_eq!(
        asset_value(view.world(), &slash_id),
        Quantity::from_str("6").expect("quantity")
    );
    let stats_a = view
        .world()
        .oracle_provider_stats()
        .get(&OracleProviderKey::new(feed_id.clone(), provider_a.clone()))
        .copied()
        .expect("provider a stats");
    let stats_b = view
        .world()
        .oracle_provider_stats()
        .get(&OracleProviderKey::new(feed_id.clone(), provider_b.clone()))
        .copied()
        .expect("provider b stats");
    let stats_c = view
        .world()
        .oracle_provider_stats()
        .get(&OracleProviderKey::new(feed_id.clone(), provider_c.clone()))
        .copied()
        .expect("provider c stats");
    assert_eq!(10_000, stats_a.reputation_score_bps());
    assert_eq!(10_000, stats_b.reputation_score_bps());
    assert_eq!(0, stats_c.reputation_score_bps());
    assert_eq!(10_000, stats_c.adjusted_reputation_score_bps(10_000));
    assert_eq!(0, stats_a.adjusted_reputation_score_bps(-10_000));
}
#[test]
fn oracle_reward_respects_reward_pool_outgoing_availability() {
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "reward_pool_control".parse().expect("feed id");
    let (state, asset_def_id, reward_pool, _) =
        oracle_state_with_accounts(std::slice::from_ref(&provider));
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    SetAssetTransferAvailability::new(
        reward_pool.clone(),
        asset_def_id.clone(),
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Disabled,
        Some("oracle reward pool maintenance".to_owned()),
    )
    .execute(&reward_pool, &mut stx)
    .expect("asset owner can suspend reward-pool debits");
    RegisterOracleFeed {
        feed: feed_config(feed_id.clone(), vec![provider.clone()]),
    }
    .execute(&provider, &mut stx)
    .expect("register feed");
    let request = Hash::new(b"reward-pool-control");
    SubmitOracleObservation {
        observation: observation(provider.clone(), &signer, &feed_id, 1, request, 10),
    }
    .execute(&provider, &mut stx)
    .expect("submit observation");
    let pool_id = AssetId::new(asset_def_id.clone(), reward_pool);
    let provider_id = AssetId::new(asset_def_id, provider.clone());
    let pool_before = asset_value(&stx.world, &pool_id);
    let provider_before = asset_value(&stx.world, &provider_id);
    let error = AggregateOracleFeed {
        feed_id,
        slot: 1,
        request_hash: request,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider, &mut stx)
    .expect_err("Oracle rewards must not bypass reward-pool transfer controls");
    assert!(format!("{error:?}").contains("OutgoingDisabled"));
    assert_eq!(asset_value(&stx.world, &pool_id), pool_before);
    assert_eq!(asset_value(&stx.world, &provider_id), provider_before);
}
#[test]
fn oracle_penalty_is_an_explicit_mandatory_control_exception() {
    let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
    let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
    let (outlier, outlier_signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "mandatory_penalty_control".parse().expect("feed id");
    let (state, asset_def_id, reward_pool, slash_receiver) =
        oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone(), outlier.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    SetAssetTransferAvailability::new(
        outlier.clone(),
        asset_def_id.clone(),
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Disabled,
        Some("account outgoing suspension".to_owned()),
    )
    .execute(&reward_pool, &mut stx)
    .expect("asset owner can suspend provider debits");
    let voluntary_transfer = Transfer::asset_quantity(
        AssetId::new(asset_def_id.clone(), outlier.clone()),
        Quantity::one(),
        slash_receiver.clone(),
    )
    .execute(&outlier, &mut stx)
    .expect_err("ordinary provider transfers must still respect outgoing suspension");
    assert!(format!("{voluntary_transfer:?}").contains("OutgoingDisabled"));
    let mut config = feed_config(
        feed_id.clone(),
        vec![provider_a.clone(), provider_b.clone(), outlier.clone()],
    );
    config.outlier_policy = OutlierPolicy::Absolute(AbsoluteOutlier { max_delta: 5 });
    RegisterOracleFeed { feed: config }
        .execute(&provider_a, &mut stx)
        .expect("register feed");
    let request = Hash::new(b"mandatory-penalty-control");
    for (provider, signer, value) in [
        (&provider_a, &signer_a, 10),
        (&provider_b, &signer_b, 12),
        (&outlier, &outlier_signer, 100),
    ] {
        SubmitOracleObservation {
            observation: observation(provider.clone(), signer, &feed_id, 1, request, value),
        }
        .execute(provider, &mut stx)
        .expect("submit observation");
    }
    AggregateOracleFeed {
        feed_id,
        slot: 1,
        request_hash: request,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider_a, &mut stx)
    .expect("a retained mandatory penalty is not a voluntary outbound transfer");
    let outlier_id = AssetId::new(asset_def_id.clone(), outlier);
    let receiver_id = AssetId::new(asset_def_id, slash_receiver);
    assert_eq!(
        asset_value(&stx.world, &outlier_id),
        Quantity::from_str("4").expect("quantity")
    );
    assert_eq!(
        asset_value(&stx.world, &receiver_id),
        Quantity::from_str("6").expect("quantity")
    );
}
#[test]
fn oracle_penalty_preserves_receiver_admission() {
    for incoming_disabled in [true, false] {
        let (provider_a, signer_a) = iroha_test_samples::gen_account_in("validators");
        let (provider_b, signer_b) = iroha_test_samples::gen_account_in("validators");
        let (outlier, outlier_signer) = iroha_test_samples::gen_account_in("validators");
        let feed_id: FeedId = "penalty_receiver_control".parse().expect("feed id");
        let (state, asset_def_id, reward_pool, slash_receiver) =
            oracle_state_with_accounts(&[provider_a.clone(), provider_b.clone(), outlier.clone()]);
        let mut sb = state.block(header(1));
        let mut stx = sb.transaction();
        SetAssetTransferAvailability::new(
            outlier.clone(),
            asset_def_id.clone(),
            0,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Disabled,
            None,
        )
        .execute(&reward_pool, &mut stx)
        .expect("suspend provider debits");
        let expected_error = if incoming_disabled {
            SetAssetTransferAvailability::new(
                slash_receiver.clone(),
                asset_def_id.clone(),
                0,
                AssetTransferAvailability::Disabled,
                AssetTransferAvailability::Enabled,
                None,
            )
            .execute(&reward_pool, &mut stx)
            .expect("suspend receiver credits");
            "IncomingDisabled"
        } else {
            SetAssetHoldingLimit::new(
                slash_receiver.clone(),
                asset_def_id.clone(),
                Some(Quantity::from(5_u32)),
            )
            .execute(&reward_pool, &mut stx)
            .expect("limit receiver balance");
            "HoldingLimitExceeded"
        };
        let mut config = feed_config(
            feed_id.clone(),
            vec![provider_a.clone(), provider_b.clone(), outlier.clone()],
        );
        config.outlier_policy = OutlierPolicy::Absolute(AbsoluteOutlier { max_delta: 5 });
        RegisterOracleFeed { feed: config }
            .execute(&provider_a, &mut stx)
            .expect("register feed");
        let request = Hash::new(b"penalty-receiver-control");
        for (provider, signer, value) in [
            (&provider_a, &signer_a, 10),
            (&provider_b, &signer_b, 12),
            (&outlier, &outlier_signer, 100),
        ] {
            SubmitOracleObservation {
                observation: observation(provider.clone(), signer, &feed_id, 1, request, value),
            }
            .execute(provider, &mut stx)
            .expect("submit observation");
        }
        let error = AggregateOracleFeed {
            feed_id,
            slot: 1,
            request_hash: request,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider_a, &mut stx)
        .expect_err("mandatory source debit must preserve receiver admission");
        assert!(format!("{error:?}").contains(expected_error), "{error:?}");
        for account in [outlier, slash_receiver] {
            assert_eq!(
                asset_value(&stx.world, &AssetId::new(asset_def_id.clone(), account)),
                Quantity::from(5_u32),
            );
        }
    }
}
#[test]
fn oracle_dispute_bond_and_resolution_flow() {
    let (challenger, challenger_signer) = iroha_test_samples::gen_account_in("validators");
    let (target, target_signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "price_xor_usd".parse().expect("feed id");
    let (state, asset_def_id, _reward_pool, slash_receiver) =
        oracle_state_with_accounts(&[challenger.clone(), target.clone()]);
    let config = feed_config(feed_id.clone(), vec![challenger.clone(), target.clone()]);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    RegisterOracleFeed {
        feed: config.clone(),
    }
    .execute(&challenger, &mut stx)
    .expect("register feed");
    let slot = 10;
    let request = Hash::new(b"dispute-request");
    aggregate_round(
        &mut stx,
        &feed_id,
        [(&challenger, &challenger_signer), (&target, &target_signer)],
        slot,
        request,
        42_000,
        vec![Hash::new(b"dispute-bundle")],
    );
    OpenOracleDispute {
        feed_id: feed_id.clone(),
        slot,
        request_hash: request,
        target: target.clone(),
        bond: None,
        evidence_hashes: vec![Hash::new(b"dispute-evidence")],
        reason: "outlier".to_string(),
    }
    .execute(&challenger, &mut stx)
    .expect("open dispute");
    let dispute = dispute_id(&feed_id, slot, request, &challenger, &target);
    ResolveOracleDispute {
        dispute_id: dispute,
        outcome: iroha_data_model::oracle::OracleDisputeOutcome::Upheld,
        notes: String::new(),
    }
    .execute(&challenger, &mut stx)
    .expect("resolve dispute");
    stx.apply();
    sb.commit_world_overlay_for_testing().expect("commit block");
    let view = state.view();
    let challenger_id = AssetId::new(asset_def_id.clone(), challenger.clone());
    let target_id = AssetId::new(asset_def_id.clone(), target.clone());
    let slash_id = AssetId::new(asset_def_id, slash_receiver.clone());
    assert_eq!(
        asset_value(view.world(), &challenger_id),
        Quantity::from_str("7").expect("quantity")
    );
    assert_eq!(
        asset_value(view.world(), &target_id),
        Quantity::from_str("5").expect("quantity")
    );
    assert_eq!(
        asset_value(view.world(), &slash_id),
        Quantity::from_str("5").expect("quantity")
    );
    let dispute_record = view
        .world()
        .oracle_disputes()
        .get(&dispute)
        .expect("dispute recorded");
    assert!(matches!(
        dispute_record.status,
        iroha_data_model::oracle::OracleDisputeStatus::Resolved(
            iroha_data_model::oracle::OracleDisputeOutcome::Upheld
        )
    ));
}
#[test]
fn oracle_change_pipeline_applies_feed() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "change_price_feed".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let telemetry = test_telemetry();
    let mut state = State::with_telemetry(world, kura, query, telemetry);
    let mut cfg = oracle_config();
    cfg.governance.intake_min_votes = nonzero!(1_usize);
    cfg.governance.rules_min_votes = nonzero!(1_usize);
    cfg.governance.cop_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    cfg.governance.technical_min_votes = nonzero!(1_usize);
    cfg.governance.policy_jury_min_votes = OracleChangeThresholds {
        low: nonzero!(1_usize),
        medium: nonzero!(1_usize),
        high: nonzero!(1_usize),
    };
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let feed = feed_config(feed_id.clone(), vec![provider.clone()]);
    let change_id = OracleChangeId(Hash::new(b"change-ok"));
    ProposeOracleChange {
        change_id,
        feed: feed.clone(),
        class: OracleChangeClass::High,
        payload_hash: Hash::new(b"payload-1"),
        evidence_hashes: vec![Hash::new(b"evidence-intake")],
    }
    .execute(&provider, &mut stx)
    .expect("propose change");
    for stage in [
        OracleChangeStage::Intake,
        OracleChangeStage::RulesCommittee,
        OracleChangeStage::CopReview,
        OracleChangeStage::TechnicalAudit,
        OracleChangeStage::PolicyJury,
        OracleChangeStage::Enactment,
    ] {
        VoteOracleChangeStage {
            change_id,
            stage,
            approve: true,
            evidence_hashes: Vec::new(),
        }
        .execute(&provider, &mut stx)
        .expect("stage vote");
    }
    stx.apply();
    sb.commit_world_overlay_for_testing().expect("commit block");
    let view = state.view();
    let stored = view
        .world()
        .oracle_feeds()
        .get(&feed_id)
        .cloned()
        .expect("feed enacted");
    assert_eq!(stored.feed_config_version, feed.feed_config_version);
    let change = view
        .world()
        .oracle_changes()
        .get(&change_id)
        .cloned()
        .expect("change persisted");
    assert!(matches!(change.status, OracleChangeStatus::Enacted(_)));
    let enact = change
        .stages
        .iter()
        .find(|stage| stage.stage == OracleChangeStage::Enactment)
        .expect("enact stage present");
    assert!(enact.completed_at.is_some());
}
#[test]
fn oracle_change_deadline_rolls_back() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = "change_deadline_feed".parse().expect("feed id");
    let world = world_with_providers(std::slice::from_ref(&provider));
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let telemetry = test_telemetry();
    let mut state = State::with_telemetry(world, kura, query, telemetry);
    let mut cfg = oracle_config();
    cfg.governance.intake_sla_blocks = 1;
    cfg.governance.rules_sla_blocks = 1;
    cfg.governance.cop_sla_blocks = 1;
    cfg.governance.technical_sla_blocks = 1;
    cfg.governance.policy_jury_sla_blocks = 1;
    cfg.governance.enact_sla_blocks = 1;
    state.set_oracle(cfg);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    let change_id = OracleChangeId(Hash::new(b"change-deadline"));
    ProposeOracleChange {
        change_id,
        feed: feed_config(feed_id, vec![provider.clone()]),
        class: OracleChangeClass::Low,
        payload_hash: Hash::new(b"payload-2"),
        evidence_hashes: Vec::new(),
    }
    .execute(&provider, &mut stx)
    .expect("propose change");
    stx.apply();
    sb.commit_world_overlay_for_testing()
        .expect("commit proposal block");
    let sb2 = state.block(header(3));
    sb2.commit_world_overlay_for_testing()
        .expect("commit sweep block");
    let view = state.view();
    let change = view
        .world()
        .oracle_changes()
        .get(&change_id)
        .cloned()
        .expect("change persisted");
    assert!(matches!(
        &change.status,
        OracleChangeStatus::Failed(failure)
            if matches!(failure.reason, iroha_data_model::oracle::OracleChangeStageFailure::DeadlineMissed)
    ));
}
fn twitter_binding_attestation(
    feed_config: &FeedConfig,
    uaid: &UniversalAccountId,
    binding_hash: KeyedHash,
    observed_at_ms: u64,
) -> TwitterBindingAttestation {
    let cadence = feed_config.cadence_slots.get();
    let base_slot: FeedSlot = 42;
    let slot = if base_slot.is_multiple_of(cadence) {
        base_slot
    } else {
        base_slot + (cadence - (base_slot % cadence))
    };
    TwitterBindingAttestation {
        binding_hash,
        uaid: *uaid,
        status: TwitterBindingStatus::Following,
        tweet_id: Some("tweet-1".to_string()),
        challenge_hash: None,
        expires_at_ms: observed_at_ms + 600_000,
        observed_at_ms,
        request_hash: Hash::new(b"req-twitter"),
        slot,
        feed_config_version: feed_config.feed_config_version,
    }
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
#[test]
fn record_twitter_binding_updates_registry_and_index() {
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-123"));
    let (state, _, _, _) = oracle_state_with_accounts(std::slice::from_ref(&provider));
    let kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut feed_config = kit.feed_config;
    feed_config.providers = vec![provider.clone()];
    feed_config.min_signers = 1;
    feed_config.committee_size = 1;
    feed_config.feed_id = feed_id.clone();
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-123",
    );
    let attestation = twitter_binding_attestation(&feed_config, &uaid, binding_hash.clone(), 1_000);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    RegisterOracleFeed {
        feed: feed_config.clone(),
    }
    .execute(&provider, &mut stx)
    .expect("register feed");
    SubmitOracleObservation {
        observation: twitter_binding_observation(&provider, &signer, &feed_config, &attestation),
    }
    .execute(&provider, &mut stx)
    .expect("submit twitter binding observation");
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: attestation.slot,
        request_hash: attestation.request_hash,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider, &mut stx)
    .expect("aggregate twitter binding slot");
    RecordTwitterBinding {
        attestation: attestation.clone(),
        feed_id: feed_id.clone(),
    }
    .execute(&provider, &mut stx)
    .expect("record twitter binding");
    stx.apply();
    sb.commit_world_overlay_for_testing().expect("commit block");
    let view = state.view();
    let stored = view
        .world()
        .twitter_bindings()
        .get(&binding_hash.digest)
        .cloned()
        .expect("stored binding");
    assert_eq!(stored.attestation.uaid, uaid);
    assert_eq!(stored.attestation.status, TwitterBindingStatus::Following);
    let by_uaid = view
        .world()
        .twitter_bindings_by_uaid()
        .get(&uaid)
        .cloned()
        .expect("uaid index");
    assert!(by_uaid.contains(&binding_hash.digest));
}
#[test]
fn record_twitter_binding_rejects_wrong_feed_pepper_missing_history_and_missing_revoke() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-negative"));
    let (state, _, _, _) = oracle_state_with_accounts(std::slice::from_ref(&provider));
    let kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut feed_config = kit.feed_config;
    feed_config.providers = vec![provider.clone()];
    feed_config.min_signers = 1;
    feed_config.committee_size = 1;
    feed_config.feed_id = feed_id.clone();
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-negative",
    );
    let attestation = twitter_binding_attestation(&feed_config, &uaid, binding_hash.clone(), 5_000);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config.clone(),
        },
        &provider,
        &mut stx,
    )
    .expect("register twitter feed");
    assert_rejects_with(
        execute_boxed(
            RecordTwitterBinding {
                attestation: attestation.clone(),
                feed_id: "wrong_twitter_feed".parse().expect("feed id"),
            },
            &provider,
            &mut stx,
        ),
        "does not match configured feed",
    );
    let mut wrong_pepper = attestation.clone();
    wrong_pepper.binding_hash = KeyedHash::new("wrong-pepper", b"wrong", b"user-negative");
    assert_rejects_with(
        execute_boxed(
            RecordTwitterBinding {
                attestation: wrong_pepper,
                feed_id: feed_id.clone(),
            },
            &provider,
            &mut stx,
        ),
        "does not match expected",
    );
    assert_rejects_with(
        execute_boxed(
            RecordTwitterBinding {
                attestation,
                feed_id,
            },
            &provider,
            &mut stx,
        ),
        "no oracle feed event found",
    );
    assert_rejects_with(
        execute_boxed(
            RevokeTwitterBinding {
                binding_hash,
                reason: "missing binding".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "twitter binding not found",
    );
}
#[test]
fn record_twitter_binding_rejects_missing_registered_feed_before_binding_lookup() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-missing-twitter-feed"));
    let (state, _, _, _) = oracle_state_with_accounts(std::slice::from_ref(&provider));
    let kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut feed_config = kit.feed_config;
    feed_config.providers = vec![provider.clone()];
    feed_config.min_signers = 1;
    feed_config.committee_size = 1;
    feed_config.feed_id = feed_id.clone();
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-missing-twitter-feed",
    );
    let attestation = twitter_binding_attestation(&feed_config, &uaid, binding_hash.clone(), 1_000);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    assert_rejects_with(
        execute_boxed(
            RecordTwitterBinding {
                attestation,
                feed_id,
            },
            &provider,
            &mut stx,
        ),
        "is not registered",
    );
    assert_rejects_with(
        execute_boxed(
            RevokeTwitterBinding {
                binding_hash,
                reason: "missing feed".to_string(),
            },
            &provider,
            &mut stx,
        ),
        "is not registered",
    );
}
#[test]
fn record_twitter_binding_requires_management_permission_before_history_checks() {
    let (provider, _) = iroha_test_samples::gen_account_in("validators");
    let (outsider, _) = iroha_test_samples::gen_account_in("validators");
    let validator_domain_id: DomainId =
        DomainId::try_new("validators", "universal").expect("domain");
    let domain = Domain::new(validator_domain_id).build(&provider);
    let mut world = World::with(
        [domain],
        [
            Account::new(provider.clone()).build(&provider),
            Account::new(outsider.clone()).build(&outsider),
        ],
        [],
    );
    grant_oracle_operator_permissions(&mut world, &provider);
    let mut state = State::with_telemetry(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        test_telemetry(),
    );
    state.set_oracle(oracle_config());
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-permission-negative"));
    let kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut feed_config = kit.feed_config;
    feed_config.providers = vec![provider.clone()];
    feed_config.min_signers = 1;
    feed_config.committee_size = 1;
    feed_config.feed_id = feed_id.clone();
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-permission-negative",
    );
    let attestation = twitter_binding_attestation(&feed_config, &uaid, binding_hash.clone(), 1_000);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed { feed: feed_config },
        &provider,
        &mut stx,
    )
    .expect("register twitter feed");
    assert_rejects_with(
        execute_boxed(
            RecordTwitterBinding {
                attestation,
                feed_id,
            },
            &outsider,
            &mut stx,
        ),
        "does not have `CanManageTwitterBindings`",
    );
    assert_rejects_with(
        execute_boxed(
            RevokeTwitterBinding {
                binding_hash,
                reason: "no permission".to_string(),
            },
            &outsider,
            &mut stx,
        ),
        "does not have `CanManageTwitterBindings`",
    );
}
#[test]
fn record_twitter_binding_rejects_attestation_value_not_anchored_to_history() {
    let (provider, signer) = iroha_test_samples::gen_account_in("validators");
    let feed_id: FeedId = TWITTER_FOLLOW_FEED_ID.parse().expect("feed id");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid-history-mismatch"));
    let (state, _, _, _) = oracle_state_with_accounts(std::slice::from_ref(&provider));
    let kit = iroha_data_model::oracle::kits::twitter_follow_binding();
    let mut feed_config = kit.feed_config;
    feed_config.providers = vec![provider.clone()];
    feed_config.min_signers = 1;
    feed_config.committee_size = 1;
    feed_config.feed_id = feed_id.clone();
    let binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-history-mismatch",
    );
    let attestation = twitter_binding_attestation(&feed_config, &uaid, binding_hash.clone(), 1_000);
    let mut sb = state.block(header(1));
    let mut stx = sb.transaction();
    execute_boxed(
        RegisterOracleFeed {
            feed: feed_config.clone(),
        },
        &provider,
        &mut stx,
    )
    .expect("register twitter feed");
    SubmitOracleObservation {
        observation: twitter_binding_observation(&provider, &signer, &feed_config, &attestation),
    }
    .execute(&provider, &mut stx)
    .expect("submit twitter binding observation");
    AggregateOracleFeed {
        feed_id: feed_id.clone(),
        slot: attestation.slot,
        request_hash: attestation.request_hash,
        evidence_hashes: Vec::new(),
    }
    .execute(&provider, &mut stx)
    .expect("aggregate twitter binding slot");
    let mut mismatched = attestation;
    mismatched.binding_hash = KeyedHash::new(
        defaults::oracle::twitter_binding_pepper_id(),
        defaults::oracle::twitter_binding_pepper_id(),
        b"user-history-mismatch-other",
    );
    assert_rejects_with(
        execute_boxed(
            RecordTwitterBinding {
                attestation: mismatched,
                feed_id,
            },
            &provider,
            &mut stx,
        ),
        "no oracle feed event found",
    );
}
include!("oracle_tail_tests.rs");
