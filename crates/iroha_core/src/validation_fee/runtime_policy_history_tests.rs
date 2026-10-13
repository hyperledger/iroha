//! Real scheduled conversion and signed claims after original policy history compaction.
use super::*;
use iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1;

fn registry(fixture: &ScheduledRewardFixture) -> ValidationFeePolicyRegistryV1 {
    let view = fixture.chain.state().view();
    ValidationFeePolicyRegistryV1::from_custom_parameter(
        view.world
            .parameters()
            .custom()
            .get(&ValidationFeePolicyRegistryV1::parameter_id())
            .unwrap(),
    )
    .unwrap()
}

fn prepare_compacted_fixture() -> ScheduledRewardFixture {
    let mut fixture = prepare_scheduled_reward_fixture(false, true);
    let mut policies = registry(&fixture);
    let mut binding = fixture.binding.clone();
    for revision in 2..=3 {
        binding.min_reward_claim_xor_minor = revision;
        policies
            .payout_policies
            .entries
            .push(payout_registry_entry(&binding, revision, 20));
    }
    fixture.chain.setup_world_at(EARNING_TIME + 1_003, |stx| {
        install_policy_registry_fixture(&policies, stx);
    });
    fixture.chain.commit_at(EARNING_TIME + 2_002, Vec::new());
    assert_eq!(
        registry(&fixture).payout_policies.entries.len(),
        3,
        "unarchived component revisions cannot supply their own historical custody"
    );
    let source_height = fixture.chain.height();
    fixture.chain.commit_at(EARNING_TIME + 3_002, Vec::new());
    let hot = registry(&fixture);
    assert_eq!(hot.payout_policies.entries.len(), 1);
    assert_eq!(hot.payout_policies.entries[0].revision, 3);
    assert_eq!(
        hot.history.as_ref().unwrap().archived_at_height,
        source_height
    );
    let original = crate::query::native_receipts::committed_fee_evidence(
        &fixture.chain.state().view(),
        source_height,
    )
    .unwrap();
    assert_eq!(original.registry(), Some(&policies));
    let key = validation_fee_reward_state_key(&binding, "State").unwrap();
    let view = fixture.chain.state().view();
    let state: ValidationFeeRewardsState =
        norito::decode_canonical(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
    assert_eq!(
        (
            state.pending_sbd_total,
            state.reserved_xor,
            state.next_allocation
        ),
        (1_000, 0, 0),
        "compaction precedes delayed funding and cannot discard an earning obligation"
    );
    drop(view);
    fixture.binding = binding;
    fixture.prefix_hash =
        crate::snapshot::canonical_state_snapshot_hash(fixture.chain.state()).unwrap();
    fixture
}

fn restart(fixture: &ScheduledRewardFixture) -> ScheduledRewardFixture {
    let mut restored = prepare_compacted_fixture();
    assert_eq!(restored.prefix_hash, fixture.prefix_hash);
    restored.chain.replay_from(&fixture.chain).unwrap();
    let expected = crate::snapshot::canonical_state_snapshot_hash(fixture.chain.state()).unwrap();
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(restored.chain.state()).unwrap(),
        expected
    );
    restored.chain.replay_from(&fixture.chain).unwrap();
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(restored.chain.state()).unwrap(),
        expected
    );
    restored
}

fn claim_entitlement(fixture: &mut ScheduledRewardFixture, seed: u8, amount: &str) {
    let owner = account(seed);
    let height = fixture.chain.height() + 1;
    let fee_claim = crate::validation_fee_rewards::fee_reward_claim_plan(
        &fixture.chain.state().view().world,
        height,
        &owner,
        LaneId::SINGLE,
    )
    .unwrap()
    .expect("compacted policy retains the actual automatic entitlement");
    assert_eq!(fee_claim.amount, amount.parse::<Quantity>().unwrap());
    let claim = ClaimPublicLaneRewards {
        lane_id: LaneId::SINGLE,
        account: owner.clone(),
        claim_plan: PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
            valid_until_height: height,
            fee_claim,
        },
    };
    let timestamp = CONVERSION_TIME + height * 1_000;
    let signed = fixture
        .chain
        .sign(&key_pair(seed), [claim.into()], timestamp);
    assert_eq!(fixture.chain.commit_at(timestamp, vec![signed]), vec![true]);
    let expected = amount
        .parse::<Quantity>()
        .unwrap()
        .checked_add(&if seed == 2 || seed == 5 {
            Quantity::from(100_u32)
        } else {
            Quantity::zero()
        })
        .unwrap();
    assert_eq!(
        fixture
            .chain
            .state()
            .view()
            .world
            .assets
            .get(&AssetId::new(fixture.pool.xor.clone(), owner))
            .unwrap()
            .as_ref(),
        &expected
    );
}

#[test]
fn compacted_policy_history_preserves_delayed_funding_signed_nominator_claims_and_restart() {
    let mut fixture = prepare_compacted_fixture();
    fixture.chain.commit_at(CONVERSION_TIME + 2, Vec::new());
    fixture.chain.commit_at(CONVERSION_TIME + 1_002, Vec::new());
    fixture = restart(&fixture);
    fixture.chain.commit_at(CONVERSION_TIME + 2_002, Vec::new());
    for (seed, amount) in [(2, "2"), (3, "3"), (4, "5"), (5, "10")] {
        claim_entitlement(&mut fixture, seed, amount);
        if seed == 2 {
            fixture = restart(&fixture);
        }
    }
    fixture.chain.commit_at(
        CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000,
        Vec::new(),
    );
    fixture = restart(&fixture);
    let view = fixture.chain.state().view();
    let key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
    let state: ValidationFeeRewardsState =
        norito::decode_canonical(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
    assert_eq!(
        (
            state.pending_sbd_total,
            state.reserved_xor,
            state.next_allocation,
            state.next_claim
        ),
        (0, 0, 1, 4)
    );
    assert!(
        view.world
            .assets
            .get(&AssetId::new(
                fixture.pool.xor.clone(),
                fixture.pool.reward_pool.clone()
            ))
            .is_none()
    );
    for seed in [2, 5] {
        assert_eq!(
            view.world
                .public_lane_stake_reserves
                .get(&AssetId::new(fixture.pool.xor.clone(), account(seed))),
            Some(&Quantity::from(100_u32))
        );
    }
    crate::validation_fee::policy_history::validate_retained_history(
        &view,
        &registry(&fixture),
        fixture.chain.height(),
    )
    .unwrap();
}

/// Resource qualification: each distinct signed policy entry is admitted into component prestate,
/// then normal certified block execution archives and compacts it. The bootstrap does not model
/// a live Parliament enactment; native service, custody, funded conversion and claims are real.
#[test]
#[ignore = "resource qualification: cumulative policy history exceeds one MiB across certified blocks"]
fn repeated_certified_policy_compaction_exceeds_former_byte_limit_then_claims() {
    use iroha_data_model::validation_fee::MAX_VALIDATION_FEE_REGISTRY_BYTES;
    let mut fixture = prepare_compacted_fixture();
    let mut cumulative = registry(&fixture)
        .payout_policies
        .entries
        .iter()
        .map(|entry| norito::encode_canonical(entry).unwrap().len())
        .sum::<usize>();
    let mut revision = registry(&fixture).payout_policies.head().unwrap().revision;
    let mut timestamp = EARNING_TIME + 10_000;
    let mut cycles = 0_u64;
    while cumulative <= MAX_VALIDATION_FEE_REGISTRY_BYTES {
        revision += 1;
        let mut next = registry(&fixture);
        let mut binding = fixture.binding.clone();
        binding.min_reward_claim_xor_minor = revision;
        let entry = payout_registry_entry(&binding, revision, 20);
        cumulative = cumulative
            .checked_add(norito::encode_canonical(&entry).unwrap().len())
            .unwrap();
        next.payout_policies.entries.push(entry);
        next.validate().unwrap();
        fixture
            .chain
            .setup_world_at(timestamp, |stx| install_policy_registry_fixture(&next, stx));
        fixture.chain.commit_at(timestamp + 1, Vec::new());
        assert_eq!(
            registry(&fixture),
            next,
            "unarchived revisions cannot authenticate their own checkpoint"
        );
        let source_height = fixture.chain.height();
        fixture.chain.commit_at(timestamp + 2, Vec::new());
        let hot = registry(&fixture);
        assert_eq!(hot.payout_policies.entries.len(), 1);
        assert_eq!(hot.payout_policies.head().unwrap().revision, revision);
        assert!(
            norito::encode_canonical(&hot).unwrap().len() < MAX_VALIDATION_FEE_REGISTRY_BYTES / 8
        );
        let view = fixture.chain.state().view();
        let original =
            crate::query::native_receipts::committed_fee_evidence(&view, source_height).unwrap();
        assert_eq!(original.registry(), Some(&next));
        hot.validate_history_source(source_height, original.registry().unwrap())
            .unwrap();
        crate::validation_fee::policy_history::validate_retained_history(
            &view,
            &hot,
            fixture.chain.height(),
        )
        .unwrap();
        let key = validation_fee_reward_state_key(&binding, "State").unwrap();
        let state: ValidationFeeRewardsState =
            norito::decode_canonical(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
        assert_eq!(
            (
                state.pending_sbd_total,
                state.reserved_xor,
                state.next_allocation
            ),
            (1_000, 0, 0)
        );
        drop(view);
        fixture.binding = binding;
        timestamp += 1_000;
        cycles += 1;
    }
    assert!(cumulative > MAX_VALIDATION_FEE_REGISTRY_BYTES);
    assert!(cycles > 1);
    assert!(timestamp < CONVERSION_TIME);
    fixture.chain.commit_at(CONVERSION_TIME + 2, Vec::new());
    fixture.chain.commit_at(CONVERSION_TIME + 1_002, Vec::new());
    fixture.chain.commit_at(CONVERSION_TIME + 2_002, Vec::new());
    for (seed, amount) in [(2, "2"), (3, "3"), (4, "5"), (5, "10")] {
        claim_entitlement(&mut fixture, seed, amount);
    }
    let view = fixture.chain.state().view();
    let key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
    let state: ValidationFeeRewardsState =
        norito::decode_canonical(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
    assert_eq!(
        (
            state.pending_sbd_total,
            state.reserved_xor,
            state.next_allocation,
            state.next_claim
        ),
        (0, 0, 1, 4)
    );
    assert!(
        view.world
            .assets
            .get(&AssetId::new(
                fixture.pool.xor.clone(),
                fixture.pool.reward_pool.clone()
            ))
            .is_none()
    );
    for seed in [2, 5] {
        assert_eq!(
            view.world
                .public_lane_stake_reserves
                .get(&AssetId::new(fixture.pool.xor.clone(), account(seed))),
            Some(&Quantity::from(100_u32))
        );
    }
    eprintln!(
        "certified policy history: {cycles} cycles, {cumulative} admitted canonical bytes, {} blocks, four exact signed claims",
        fixture.chain.height()
    );
}
