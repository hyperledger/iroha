fn stake_index_demand_account(seed: u8) -> AccountId {
    let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("deterministic stake-index demand account");
    AccountId::new(pair.public_key().clone())
}

fn stake_index_demand_row(
    lane_id: LaneId,
    validator: &AccountId,
    staker: &AccountId,
) -> (PublicLaneStakeShareKey, PublicLaneStakeShare) {
    (
        (lane_id, validator.clone(), staker.clone()),
        PublicLaneStakeShare {
            lane_id,
            validator: validator.clone(),
            staker: staker.clone(),
            bonded: Quantity::from(1_u64),
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        },
    )
}

#[test]
fn stake_index_demand_compares_validator_totals_without_quantity_clones() {
    let validator = stake_index_demand_account(0x19);
    let mut indexed = IndexedValidatorStake::new(LaneId::SINGLE, validator, 0);
    indexed.0.3 = Quantity::from(19_u64);
    indexed.0.4 = Quantity::from(7_u64);

    assert!(indexed_validator_totals_match(
        Some(&indexed),
        &Quantity::from(19_u64),
        &Quantity::from(7_u64),
    ));
    assert!(!indexed_validator_totals_match(
        Some(&indexed),
        &Quantity::from(20_u64),
        &Quantity::from(7_u64),
    ));
    assert!(!indexed_validator_totals_match(
        Some(&indexed),
        &Quantity::from(19_u64),
        &Quantity::from(8_u64),
    ));
    assert!(indexed_validator_totals_match(
        None,
        &Quantity::zero(),
        &Quantity::zero(),
    ));
    assert!(!indexed_validator_totals_match(
        None,
        &Quantity::from(1_u64),
        &Quantity::zero(),
    ));
    assert!(!indexed_validator_totals_match(
        None,
        &Quantity::zero(),
        &Quantity::from(1_u64),
    ));
}

#[test]
fn stake_index_demand_counts_canonical_groups_and_fixed_layouts() {
    assert_eq!(
        std::mem::size_of::<PublicLaneStakeShareKey>()
            + std::mem::size_of::<IndexedValidatorStake>()
            + 3 * (33 + std::mem::size_of::<AllocationCharge>())
            + 4 * std::mem::size_of::<AllocationCharge>()
            + 3 * std::mem::size_of::<usize>(),
        iroha_config::parameters::defaults::nexus::storage::CONSENSUS_STAKE_INDEX_MIN_BYTES,
        "configured minimum must cover fixed owners, every key and exact quantity magnitudes"
    );
    let first = stake_index_demand_account(0x11);
    let second = stake_index_demand_account(0x22);
    let delegator = stake_index_demand_account(0x33);
    let mut rows = vec![
        stake_index_demand_row(LaneId::new(2), &first, &first),
        stake_index_demand_row(LaneId::new(1), &second, &second),
        stake_index_demand_row(LaneId::new(2), &first, &delegator),
    ];
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let demand =
        PublicLaneStakeIndexDemand::from_rows(rows.iter().map(|(key, share)| (key, share)), 2, 0)
            .expect("canonical rows fit both groups");
    assert_eq!(demand.share_rows, 3);
    assert_eq!(demand.validator_groups, 2);
    assert_eq!(demand.account_clone_charges, 8);
    assert_eq!(demand.account_clone_bytes, 8 * 33);
    let (_, _, charges, retained_bytes) = demand.checked_retained_layouts().unwrap();
    assert_eq!(demand.quantity_charges, 8);
    assert_eq!(demand.quantity_bytes, 6 * std::mem::size_of::<usize>());
    assert_eq!(charges, Layout::array::<AllocationCharge>(16).unwrap());
    assert_eq!(
        retained_bytes,
        3 * std::mem::size_of::<PublicLaneStakeShareKey>()
            + 2 * std::mem::size_of::<IndexedValidatorStake>()
            + 8 * (33 + std::mem::size_of::<AllocationCharge>())
            + 8 * std::mem::size_of::<AllocationCharge>()
            + 6 * std::mem::size_of::<usize>()
    );
    assert_eq!(
        demand.checked_fixed_layouts().expect("fixed layouts"),
        (
            Layout::array::<PublicLaneStakeShareKey>(3).expect("three keys"),
            Layout::array::<IndexedValidatorStake>(2).expect("two groups")
        )
    );
    let error =
        PublicLaneStakeIndexDemand::from_rows(rows.iter().map(|(key, share)| (key, share)), 1, 0)
            .expect_err("one group has two shares");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("stake-share capacity"))
    );
}

#[test]
fn stake_index_demand_multisig_clones_retain_exact_nested_charges_until_keys_drop() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};

    let first = stake_index_demand_account(0x91);
    let second = stake_index_demand_account(0x92);
    let validator = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(first.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(second.expect_single_signatory().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    let staker = stake_index_demand_account(0x93);
    let row = stake_index_demand_row(LaneId::SINGLE, &validator, &staker);
    let demand = PublicLaneStakeIndexDemand::from_rows(std::iter::once((&row.0, &row.1)), 1, 0)
        .expect("one canonical multisig share");
    let one_multisig_bytes = 2 * std::mem::size_of::<MultisigMember>() + 2 * 33;
    assert_eq!(demand.account_clone_charges, 7);
    assert_eq!(demand.account_clone_bytes, 2 * one_multisig_bytes + 33);
    let (_, _, _, all_bytes) = demand.checked_retained_layouts().unwrap();
    let full_budget = AllocationBudget::new(all_bytes);
    let held = full_budget.try_reserve_bytes(1).unwrap();
    assert!(matches!(
        full_budget.try_reserve_bytes(all_bytes),
        Err(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. })
            if requested_bytes == all_bytes
    ));
    drop(held);
    assert_eq!(full_budget.reserved_bytes(), 0);

    let charge_layout = Layout::array::<AllocationCharge>(3).unwrap();
    let nested_bytes = one_multisig_bytes + charge_layout.size();
    let budget = AllocationBudget::new(nested_bytes);
    let mut reservation = budget.try_reserve_bytes(nested_bytes).unwrap();
    let charges_charge = reservation.try_split(charge_layout).unwrap();
    let mut charges = ChargedBuffer::<AllocationCharge>::try_from_charge(3, charges_charge)
        .unwrap_or_else(|_| panic!("charged nested owner backing"));
    let copied = clone_index_account(&validator, &mut reservation, &mut charges).unwrap();
    assert_eq!(copied, validator);
    assert_eq!(reservation.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), nested_bytes);
    drop(copied);
    assert_eq!(budget.reserved_bytes(), nested_bytes);
    drop(charges);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn stake_index_multisig_key_clone_refusal_refunds_prepaid_owner_after_partial_allocation() {
    let first = stake_index_demand_account(0x95);
    let second = stake_index_demand_account(0x96);
    let account = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(first.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(second.expect_single_signatory().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    let mut nested_bytes = 0_usize;
    let mut count = 0_usize;
    account
        .for_each_admission_clone_layout(|layout| {
            nested_bytes += layout.size();
            count += 1;
        })
        .unwrap();
    let charge_layout = Layout::array::<AllocationCharge>(count).unwrap();
    let budget = AllocationBudget::new(nested_bytes + charge_layout.size());
    let mut reservation = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    let backing_charge = reservation.try_split(charge_layout).unwrap();
    let mut charges = ChargedBuffer::<AllocationCharge>::try_from_charge(count, backing_charge)
        .unwrap_or_else(|_| panic!("prepaid nested charge backing"));
    let limits = norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let result = norito::core::with_decode_limits_scope(limits, || {
        clone_index_account(&account, &mut reservation, &mut charges)
    });
    assert!(matches!(
        result,
        Err(EvidencePreparationError::DecodeScope {
            attempted_bytes: 33,
            limit_bytes: 0,
        })
    ));
    assert_eq!(charges.as_slice().len(), count);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(charges);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn stake_index_demand_refuses_noncanonical_and_over_capacity_rows() {
    let validator = stake_index_demand_account(0x44);
    let staker = stake_index_demand_account(0x55);
    let mut rows = vec![
        stake_index_demand_row(LaneId::new(1), &validator, &validator),
        stake_index_demand_row(LaneId::new(1), &validator, &staker),
    ];
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let error = PublicLaneStakeIndexDemand::from_rows(
        rows.iter().rev().map(|(key, share)| (key, share)),
        2,
        0,
    )
    .expect_err("source must be in canonical order");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("canonical key order"))
    );

    rows[0].1.staker = stake_index_demand_account(0x66);
    let error =
        PublicLaneStakeIndexDemand::from_rows(rows.iter().map(|(key, share)| (key, share)), 2, 0)
            .expect_err("retained share must match its key");
    assert!(matches!(error, Error::InvariantViolation(message) if message.contains("storage key")));

    let mut row = stake_index_demand_row(LaneId::new(1), &validator, &staker);
    let request_id = Hash::new(b"stake-index demand pending request");
    row.1.pending_unbonds.insert(
        request_id,
        PublicLaneUnbonding {
            request_id,
            amount: Quantity::from(1_u64),
            release_at_ms: 1,
            slashable_through_height: 1,
            liability_release_height: 2,
        },
    );
    let error = PublicLaneStakeIndexDemand::from_rows(std::iter::once((&row.0, &row.1)), 1, 0)
        .expect_err("one pending request exceeds zero configured capacity");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("pending-unbond capacity"))
    );
}

#[test]
fn stake_index_demand_zero_and_overflow_layouts() {
    let demand = PublicLaneStakeIndexDemand::from_rows(
        std::iter::empty::<(&PublicLaneStakeShareKey, &PublicLaneStakeShare)>(),
        0,
        0,
    )
    .expect("empty stake state has zero demand");
    assert_eq!(demand.share_rows, 0);
    assert_eq!(demand.validator_groups, 0);
    let (shares, groups) = demand.checked_fixed_layouts().expect("zero layouts");
    assert_eq!(shares.size(), 0);
    assert_eq!(groups.size(), 0);
    let (_, _, charges, retained_bytes) = demand.checked_retained_layouts().unwrap();
    assert_eq!(charges.size(), 0);
    assert_eq!(retained_bytes, 0);

    assert!(
        PublicLaneStakeIndexDemand {
            share_rows: usize::MAX,
            validator_groups: 0,
            account_clone_bytes: 0,
            account_clone_charges: 0,
            quantity_bytes: 0,
            quantity_charges: 0,
        }
        .checked_fixed_layouts()
        .is_err()
    );
    assert!(
        PublicLaneStakeIndexDemand {
            share_rows: 0,
            validator_groups: usize::MAX,
            account_clone_bytes: 0,
            account_clone_charges: 0,
            quantity_bytes: 0,
            quantity_charges: 0,
        }
        .checked_fixed_layouts()
        .is_err()
    );
}

#[test]
fn stake_index_empty_source_uses_zero_nested_and_flat_backing_and_refunds() {
    let state = setup_state();
    let view = state.view();
    assert_eq!(view.world().public_lane_stake_shares().iter().count(), 0);
    let budget = AllocationBudget::new(0);
    let index = PublicLaneStakeIndex::from_world(view.world(), 1, 0, &budget).unwrap();
    assert!(
        index
            .share_keys(LaneId::SINGLE, &stake_index_demand_account(0x94))
            .is_empty()
    );
    assert_eq!(budget.reserved_bytes(), 0);
    drop(index);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn stake_index_demand_rejects_materialization_count_drift() {
    let validator = stake_index_demand_account(0x77);
    let mut materialized = vec![IndexedValidatorStake::new(
        LaneId::new(1),
        validator.clone(),
        0,
    )];
    let error = PublicLaneStakeIndexDemand {
        share_rows: 0,
        validator_groups: 0,
        account_clone_bytes: 0,
        account_clone_charges: 0,
        quantity_bytes: 0,
        quantity_charges: 0,
    }
    .validate_materialized(&materialized, &[])
    .expect_err("materialized extra group must refuse");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("group count changed"))
    );

    let one_row = PublicLaneStakeIndexDemand {
        share_rows: 1,
        validator_groups: 1,
        account_clone_bytes: 0,
        account_clone_charges: 0,
        quantity_bytes: 0,
        quantity_charges: 0,
    };
    let error = one_row
        .validate_materialized(&materialized, &[])
        .expect_err("missing materialized share must refuse");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("row count changed"))
    );

    materialized[0].0.2 = 0..1;
    let key = stake_index_demand_row(LaneId::new(1), &validator, &validator).0;
    one_row
        .validate_materialized(&materialized, &[key])
        .expect("exact materialized row/group count");
}

#[test]
fn stake_index_demand_rejects_nonpartitioning_or_wrong_group_ranges() {
    let validator = stake_index_demand_account(0x78);
    let other = stake_index_demand_account(0x79);
    let key = stake_index_demand_row(LaneId::new(1), &validator, &validator).0;
    let wrong = stake_index_demand_row(LaneId::new(1), &other, &other).0;
    let mut materialized = vec![IndexedValidatorStake::new(LaneId::new(1), validator, 1)];
    materialized[0].0.2 = 1..2;
    let demand = PublicLaneStakeIndexDemand {
        share_rows: 2,
        validator_groups: 1,
        account_clone_bytes: 0,
        account_clone_charges: 0,
        quantity_bytes: 0,
        quantity_charges: 0,
    };
    let error = demand
        .validate_materialized(&materialized, &[key.clone(), key.clone()])
        .expect_err("range cannot skip the first charged key");
    assert!(matches!(error, Error::InvariantViolation(message) if message.contains("partition")));

    materialized[0].0.2 = 0..1;
    let error = PublicLaneStakeIndexDemand {
        share_rows: 1,
        validator_groups: 1,
        account_clone_bytes: 0,
        account_clone_charges: 0,
        quantity_bytes: 0,
        quantity_charges: 0,
    }
    .validate_materialized(&materialized, &[wrong])
    .expect_err("range must match its indexed validator identity");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("validator group"))
    );
}

#[test]
fn stake_index_demand_rejects_reordered_or_duplicate_flat_groups() {
    let first = stake_index_demand_account(0x81);
    let second = stake_index_demand_account(0x82);
    let mut keys = vec![
        stake_index_demand_row(LaneId::new(1), &first, &first).0,
        stake_index_demand_row(LaneId::new(1), &second, &second).0,
    ];
    keys.sort();
    let mut groups = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let mut group = IndexedValidatorStake::new(key.0, key.1.clone(), index);
            group.0.2 = index..index + 1;
            group
        })
        .collect::<Vec<_>>();
    let demand = PublicLaneStakeIndexDemand {
        share_rows: 2,
        validator_groups: 2,
        account_clone_bytes: 0,
        account_clone_charges: 0,
        quantity_bytes: 0,
        quantity_charges: 0,
    };
    demand
        .validate_materialized(&groups, &keys)
        .expect("canonical flat groups partition the source");
    assert!(PublicLaneStakeIndex::find_group(&groups, keys[0].0, &keys[0].1).is_some());
    assert!(PublicLaneStakeIndex::find_group(&groups, keys[1].0, &keys[1].1).is_some());
    assert!(PublicLaneStakeIndex::find_group(&groups, LaneId::new(2), &keys[0].1).is_none());

    groups.swap(0, 1);
    let error = demand
        .validate_materialized(&groups, &keys)
        .expect_err("reordered groups must fail even if each range is valid");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("canonical order"))
    );
    groups.swap(0, 1);
    let duplicate_validator = groups[0].validator().clone();
    groups[1].0.1 = duplicate_validator;
    let error = demand
        .validate_materialized(&groups, &keys)
        .expect_err("duplicate group must fail before borrowed binary search");
    assert!(
        matches!(error, Error::InvariantViolation(message) if message.contains("canonical order"))
    );
}

#[test]
fn stake_index_partial_second_backing_refusal_refunds_original_pool() {
    use iroha_allocation::ChargedBufferFromChargeError;

    let share_layout = Layout::array::<PublicLaneStakeShareKey>(1).expect("one share layout");
    let group_layout = Layout::array::<IndexedValidatorStake>(1).expect("one group layout");
    let combined = share_layout.size() + group_layout.size();
    let budget = AllocationBudget::new(combined);
    let mut reservation = budget
        .try_reserve_layouts([share_layout, group_layout])
        .expect("admit exact original pool demand atomically");
    let share_charge = reservation
        .try_split(share_layout)
        .expect("share demand prepaid");
    let group_charge = reservation
        .try_split(group_layout)
        .expect("group demand prepaid");
    let share_backing =
        match ChargedBuffer::<PublicLaneStakeShareKey>::try_from_charge(1, share_charge) {
            Ok(backing) => backing,
            Err(_) => panic!("first prepaid backing must allocate"),
        };
    let refused_group =
        match ChargedBuffer::<IndexedValidatorStake>::try_from_charge(2, group_charge) {
            Ok(_) => panic!("second backing must reject a wrong exact-layout charge"),
            Err((original_charge, error)) => {
                assert!(matches!(
                    error,
                    ChargedBufferFromChargeError::LayoutMismatch { .. }
                ));
                original_charge
            }
        };
    assert_eq!(budget.reserved_bytes(), combined);
    drop(refused_group);
    drop(share_backing);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Build canonical original stake custody independently of its ephemeral index.
fn stake_index_quantity_state(
    validator: &AccountId,
    bonded: Quantity,
    pending: Quantity,
) -> (State, PublicLaneStakeShareKey, PublicLaneStakeShare) {
    use iroha_data_model::IntoKeyValue as _;
    let state = setup_state();
    let (key, mut share) = stake_index_demand_row(LaneId::SINGLE, validator, validator);
    share.bonded = bonded.clone();
    let request = Hash::new(b"original index pending custody");
    share.pending_unbonds.insert(
        request,
        PublicLaneUnbonding {
            request_id: request,
            amount: pending,
            release_at_ms: 1,
            slashable_through_height: 1,
            liability_release_height: 2,
        },
    );
    {
        let mut accounts = state.world.accounts.block();
        let account = Account::new(validator.clone()).build(validator);
        let (id, account) = account.into_key_value();
        accounts.insert(id, account);
        accounts.commit();
        let mut validators = state.world.public_lane_validators.block();
        validators.insert(
            (LaneId::SINGLE, validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: validator_peer_id(validator),
                stake_account: validator.clone(),
                total_stake: bonded.clone(),
                self_stake: bonded,
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        validators.commit();
        let mut shares = state.world.public_lane_stake_shares.block();
        shares.insert(key.clone(), share.clone());
        shares.commit();
    }
    (state, key, share)
}

#[test]
fn stake_index_quantities_prepaid_and_borrowed_from_original_pool() {
    let validator = stake_index_demand_account(0x9a);
    let (state, key, share) =
        stake_index_quantity_state(&validator, Quantity::from(7_u64), Quantity::from(5_u64));
    let view = state.view();
    let demand =
        PublicLaneStakeIndexDemand::from_rows(view.world().public_lane_stake_shares().iter(), 1, 1)
            .unwrap();
    assert_eq!(demand.quantity_charges, 4);
    assert_eq!(demand.quantity_bytes, 4 * std::mem::size_of::<usize>());
    let (_, _, _, expected_bytes) = demand.checked_retained_layouts().unwrap();
    let original_pool = AllocationBudget::new(expected_bytes);
    let held = original_pool.try_reserve_bytes(1).unwrap();
    let error = match PublicLaneStakeIndex::from_world(view.world(), 1, 1, &original_pool) {
        Ok(_) => panic!("one byte short cannot admit any retained index"),
        Err(error) => error,
    };
    assert!(
        matches!(error.downcast_ref::<EvidencePreparationError>(), Some(EvidencePreparationError::Admission(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. })) if *requested_bytes == expected_bytes)
    );
    assert_eq!(original_pool.reserved_bytes(), 1);
    assert_eq!(
        view.world().public_lane_stake_shares().get(&key),
        Some(&share)
    );
    drop(held);
    let index = PublicLaneStakeIndex::from_world(view.world(), 1, 1, &original_pool).unwrap();
    assert_eq!(original_pool.reserved_bytes(), expected_bytes);
    assert_eq!(
        index.total_exposure(LaneId::SINGLE, &validator).unwrap(),
        &Quantity::from(12_u64)
    );
    let original = std::ptr::from_ref(index.total_exposure(LaneId::SINGLE, &validator).unwrap());
    for _ in 0..16 {
        assert_eq!(
            std::ptr::from_ref(index.total_exposure(LaneId::SINGLE, &validator).unwrap()),
            original
        );
        assert_eq!(original_pool.reserved_bytes(), expected_bytes);
    }
    let moved = index;
    assert_eq!(
        std::ptr::from_ref(moved.total_exposure(LaneId::SINGLE, &validator).unwrap()),
        original
    );
    assert_eq!(original_pool.reserved_bytes(), expected_bytes);
    drop(moved);
    assert_eq!(original_pool.reserved_bytes(), 0);
    assert_eq!(
        view.world().public_lane_stake_shares().get(&key),
        Some(&share)
    );
}

#[test]
fn stake_index_exposure_preserves_bonded_and_complete_pending_grouping() {
    use iroha_primitives::bigint::BigInt;
    let validator = stake_index_demand_account(0x9b);
    let delegator = stake_index_demand_account(0x9c);
    let max = Quantity::try_from_numeric(Numeric::new(
        BigInt::from_twos_bytes(&[vec![0xff; 63], vec![0x7f]].concat()).unwrap(),
        0,
    ))
    .unwrap();
    let bonded = max.checked_sub(&Quantity::one()).unwrap();
    let mut first = stake_index_demand_row(LaneId::SINGLE, &validator, &validator);
    first.1.bonded = bonded;
    let mut second = stake_index_demand_row(LaneId::SINGLE, &validator, &delegator);
    second.1.bonded = Quantity::zero();
    for (ordinal, row) in [&mut first, &mut second].into_iter().enumerate() {
        let request = Hash::new(ordinal.to_le_bytes());
        row.1.pending_unbonds.insert(
            request,
            PublicLaneUnbonding {
                request_id: request,
                amount: "0.5".parse().unwrap(),
                release_at_ms: 1,
                slashable_through_height: 1,
                liability_release_height: 2,
            },
        );
    }
    let mut rows = [first, second];
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let demand =
        PublicLaneStakeIndexDemand::from_rows(rows.iter().map(|(key, share)| (key, share)), 2, 1)
            .unwrap();
    assert_eq!(demand.quantity_charges, 4);
    let mut sums = [QuantityAccumulator::zero(); 3];
    for (key, share) in &rows {
        aggregate_index_share(&mut sums, key, share).unwrap();
    }
    assert_eq!(
        aggregate_index_exposure(&sums)
            .unwrap()
            .try_into_quantity()
            .unwrap(),
        max
    );
    assert!(
        max.checked_sub(&Quantity::one())
            .unwrap()
            .checked_add(&"0.5".parse().unwrap())
            .is_err(),
        "interleaving the final exposure would introduce a false rejection"
    );
}

#[test]
fn stake_index_quantity_demand_rejects_layout_count_and_bytes_overflow() {
    for demand in [
        PublicLaneStakeIndexDemand {
            share_rows: 0,
            validator_groups: 0,
            account_clone_bytes: 0,
            account_clone_charges: usize::MAX,
            quantity_bytes: 0,
            quantity_charges: 1,
        },
        PublicLaneStakeIndexDemand {
            share_rows: 1,
            validator_groups: 1,
            account_clone_bytes: 0,
            account_clone_charges: 0,
            quantity_bytes: usize::MAX,
            quantity_charges: 4,
        },
    ] {
        assert!(demand.checked_retained_layouts().is_err());
    }
}

#[test]
fn stake_index_exposure_overflow_preserves_canonical_index_and_read_refusal() {
    use iroha_primitives::bigint::BigInt;
    let validator = stake_index_demand_account(0x9d);
    let max = Quantity::try_from_numeric(Numeric::new(
        BigInt::from_twos_bytes(&[vec![0xff; 63], vec![0x7f]].concat()).unwrap(),
        0,
    ))
    .unwrap();
    assert!(max.checked_add(&Quantity::one()).is_err());
    let (state, key, share) = stake_index_quantity_state(&validator, max, Quantity::one());
    let view = state.view();
    let demand =
        PublicLaneStakeIndexDemand::from_rows(view.world().public_lane_stake_shares().iter(), 1, 1)
            .expect("individually canonical aggregates still form a valid index");
    assert_eq!(demand.quantity_charges, 4);
    assert_eq!(demand.quantity_bytes, 2 * 64 + std::mem::size_of::<usize>());
    let (_, _, _, bytes) = demand.checked_retained_layouts().unwrap();
    let budget = AllocationBudget::new(bytes);
    let index = PublicLaneStakeIndex::from_world(view.world(), 1, 1, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(
        index.share_keys(LaneId::SINGLE, &validator),
        std::slice::from_ref(&key)
    );
    assert!(matches!(
        index.total_exposure(LaneId::SINGLE, &validator),
        Err(Error::Math(MathError::Overflow))
    ));
    let absent = stake_index_demand_account(0x9e);
    assert_eq!(
        index.total_exposure(LaneId::SINGLE, &absent).unwrap(),
        &Quantity::zero()
    );
    assert_eq!(
        view.world().public_lane_stake_shares().get(&key),
        Some(&share)
    );
    drop(index);
    assert_eq!(budget.reserved_bytes(), 0);
}
