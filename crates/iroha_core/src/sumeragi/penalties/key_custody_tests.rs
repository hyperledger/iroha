// Registration lookup borrows exact original-pool locator keys, including multisig descendants.
// These zero-stake records exercise lookup/custody only; monetary and evidence attribution
// remain covered by the real signed-genesis penalty controls in the enclosing module.

#[test]
fn validator_registration_lookup_borrows_original_single_and_multisig_keys_without_allocation() {
    use crate::smartcontracts::Execute as _;
    use iroha_data_model::{
        account::{Account, MultisigMember, MultisigPolicy},
        isi::Register,
        nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    };

    let first = KeyPair::try_from_seed(vec![0x91; 32], Algorithm::Ed25519).unwrap();
    let second = KeyPair::try_from_seed(vec![0x92; 32], Algorithm::Ed25519).unwrap();
    let accounts = [
        AccountId::new(first.public_key().clone()),
        AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(first.public_key().clone(), 1).unwrap(),
                    MultisigMember::new(second.public_key().clone(), 1).unwrap(),
                ],
            )
            .unwrap(),
        ),
    ];
    let peer = roster().remove(0);
    for account in accounts {
        let state = fresh_state();
        let mut state_block = state.block(penalty_staking_fixture_header());
        let mut transaction = state_block.transaction();
        Register::account(Account::new(account.clone()))
            .execute(&account, &mut transaction)
            .unwrap();
        transaction.world.public_lane_validators.insert(
            (LaneId::SINGLE, account.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: account.clone(),
                peer_id: peer.clone(),
                stake_account: account.clone(),
                total_stake: Quantity::zero(),
                self_stake: Quantity::zero(),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        transaction.apply();
        state_block.commit_world_overlay_for_testing().unwrap();

        let view = state.view();
        let original = view
            .world()
            .public_lane_validators()
            .get(&(LaneId::SINGLE, account.clone()))
            .unwrap();
        let index =
            PublicLaneStakeIndex::from_world(view.world(), 16, 16, state.stake_index_budget())
                .unwrap();
        let required = ValidatorMapDemand::from_world(&view)
            .unwrap()
            .retained_bytes()
            .unwrap();
        let budget = AllocationBudget::new(required);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = ValidatorMap::from_world(&view, &index, &budget)
            .err()
            .expect("the original locator pool must refuse before cloning its key");
        assert!(matches!(
            refusal.downcast_ref::<EvidencePreparationError>(),
            Some(EvidencePreparationError::Admission(AllocationRefusal::Capacity {
                requested_bytes, reserved_bytes: 1, ..
            })) if *requested_bytes == required
        ));
        assert_eq!(budget.reserved_bytes(), 1);
        drop(occupied);
        let map = ValidatorMap::from_world(&view, &index, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), required);
        let locator = &map.get(peer.public_key()).unwrap()[0];
        let retained_key = std::ptr::from_ref(&locator.registration_key);
        let absent = fresh_state();
        let absent_view = absent.view();
        let mut observed = None;
        let mut missing = false;
        // The actual source pool is completely occupied. Both hit and miss must borrow
        // the same prepaid single/multisig key rather than allocate a replacement.
        let allocations = crate::test_allocations::allocations_during(|| {
            for _ in 0..8 {
                observed = locator.registration(view.world());
                missing = locator.registration(absent_view.world()).is_none();
                let _ = std::hint::black_box(observed);
            }
        });
        assert_eq!(
            allocations, 0,
            "penalty registration lookup must borrow the exact funded key without replacement allocation"
        );
        assert!(std::ptr::eq(observed.unwrap(), original));
        assert!(missing);
        assert_eq!(std::ptr::from_ref(&locator.registration_key), retained_key);
        assert_eq!(locator.registration_key.1, account);
        assert_eq!(budget.reserved_bytes(), required);
        drop(map);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            view.world()
                .public_lane_validators()
                .get(&(LaneId::SINGLE, account)),
            Some(original)
        );
    }
}
