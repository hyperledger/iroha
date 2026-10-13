//! Funded reward custody and claim ownership across repeated beneficiary rekeys.
use super::*;
use iroha_data_model::{IntoKeyValue, fee_evidence::FeeEvidencePayloadV1};

#[test]
fn current_owner_requires_explicit_alias_before_initial_and_recovered_claims() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = super::super::tests::network_xor_claim_fixture(stx, policy);
        let original = super::super::tests::account(2);
        let recovered = super::super::tests::account(4);
        let stranger = super::super::tests::account(5);
        super::super::tests::seed_claim_credit(stx, &binding, &original, 200, 200);
        // Recovery must retain both the current owner alias and the original
        // self-alias used by delayed exposure and authenticated evidence.
        for (alias_account, expected_owner) in [
            (&original, &original),
            (&recovered, &recovered),
            (&original, &recovered),
        ] {
            if alias_account == &recovered {
                rekey_beneficiary(stx, &original, &recovered).unwrap();
            }
            let key = alias_key(&binding, alias_account).unwrap();
            let exact = stx.world.smart_contract_state.remove(key.clone()).unwrap();
            assert!(owner_in_world(&stx.world, &binding, &original).is_err());
            assert!(super::super::reconciliation::validate(&stx.world, &binding).is_err());
            for substituted in [
                Alias {
                    account_id: alias_account.clone(),
                    beneficiary_id: stranger.clone(),
                },
                Alias {
                    account_id: stranger.clone(),
                    beneficiary_id: original.clone(),
                },
            ] {
                stx.world
                    .smart_contract_state
                    .insert(key.clone(), norito::to_bytes(&substituted).unwrap());
                assert!(owner_in_world(&stx.world, &binding, &original).is_err());
                assert!(super::super::reconciliation::validate(&stx.world, &binding).is_err());
            }
            stx.world.smart_contract_state.insert(key, exact);
            assert_eq!(
                owner(stx, &binding, &original).unwrap().unwrap().account_id,
                *expected_owner
            );
            super::super::reconciliation::validate(&stx.world, &binding).unwrap();
            assert_eq!(
                read::<u128>(stx, &claimable_key(&binding, &original).unwrap()).unwrap(),
                Some(200)
            );
            assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 200);
        }
        super::super::tests::signed_claim_all(stx, &binding, &recovered);
        let paid = AssetId::new(binding.xor_asset_id.clone(), recovered);
        assert_eq!(
            minor_units(stx.world.assets.get(&paid).unwrap().as_ref(), 9).unwrap(),
            200
        );
        assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 0);
        super::super::reconciliation::validate(&stx.world, &binding).unwrap();
    });
}

#[test]
fn recovery_preserves_reserved_and_delayed_rewards_through_repeated_rekeys() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (policy, binding) = super::super::tests::network_xor_claim_fixture(stx, policy);
        let old = super::super::tests::account(2);
        let middle = super::super::tests::account(3);
        let latest = super::super::tests::account(4);
        let stranger = super::super::tests::account(5);
        let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
        let weights = BTreeMap::from([(old.clone(), 3)]);
        let treasury = AssetId::new(
            binding.ds_asset_id.clone(),
            binding.treasury_account_id.clone(),
        );
        let (_, treasury_balance) =
            Asset::new(treasury.clone(), quantity(200, 2).unwrap()).into_key_value();
        stx.world.assets.insert(treasury, treasury_balance);
        super::super::tests::seed_service(stx, &binding, period, &weights);
        write(stx, pending_key(&binding, period).unwrap(), &200u64).unwrap();
        save_state(
            stx,
            &binding,
            &ValidationFeeRewardsState {
                pending_sbd_total: 200,
                ..Default::default()
            },
        )
        .unwrap();
        reserve_conversion(
            stx,
            &binding,
            &ConversionOffer {
                earning_period_start_ms: period,
                sbd_minor: 100,
                min_xor_minor: 100,
                sequence: 0,
            },
            100,
        )
        .unwrap();
        super::super::tests::accrue_all(stx, &binding);
        let pool = AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
        let (_, value) = Asset::new(pool.clone(), quantity(200, 9).unwrap()).into_key_value();
        stx.world.assets.insert(pool.clone(), value);
        let allocated_key = state_key(&binding, "Allocation/0").unwrap();
        let original_allocation = stx
            .world
            .smart_contract_state
            .get(&allocated_key)
            .unwrap()
            .clone();
        let active_registry =
            crate::validation_fee::tests::policy_registry(&[policy.clone()], &[binding.clone()]);
        let mut retained_registry = active_registry.clone();
        retained_registry.payout_policies.entries =
            vec![crate::validation_fee::tests::payout_registry_entry(
                &binding,
                1,
                stx.block_height(),
            )];
        crate::validation_fee::tests::install_policy_registry_fixture(&retained_registry, stx);
        assert!(active_bindings(stx).unwrap().is_empty());
        rekey_beneficiary(stx, &old, &middle).unwrap();
        assert_eq!(root(stx, &binding, &middle).unwrap(), old);
        assert_eq!(
            read::<u128>(stx, &claimable_key(&binding, &old).unwrap()).unwrap(),
            Some(100)
        );
        let corpus = pending_fee_evidence_records(stx).unwrap();
        assert!(
            corpus.iter().any(|record| matches!(
                &record.payload,
                FeeEvidencePayloadV1::RewardCustody(custody) if custody.state.reserved_xor == 100
            )),
            "retained custody remains visible before conversion activation"
        );
        let latest_revision = owner(stx, &binding, &old).unwrap().unwrap();
        let mut recovery_sources = vec![iroha_data_model::fee_evidence::FeeEvidenceRecordV1 {
            key: revision_key(&binding, &old, latest_revision.revision).unwrap(),
            recorded_at_height: stx.block_height(),
            payload: FeeEvidencePayloadV1::RewardBeneficiaryRevision(latest_revision),
        }];
        append_evidence_sources(stx, &mut recovery_sources).unwrap();
        assert!(recovery_sources.iter().any(|record| matches!(
            &record.payload,
            FeeEvidencePayloadV1::RewardBeneficiaryAlias(alias) if alias.account_id == middle && alias.beneficiary_id == old
        )));
        assert!(recovery_sources.iter().any(|record| matches!(
            &record.payload,
            FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision) if revision.revision == 0 && revision.account_id == old
        )), "inactive recovery includes the previous authorized owner source");
        crate::validation_fee::tests::install_policy_registry_fixture(&active_registry, stx);
        assert!(
            super::super::tests::claim_current_fee_credit(stx, &old, binding.validator_lane_id)
                .is_err()
        );
        assert!(rekey_beneficiary(stx, &old, &stranger).is_err());
        assert!(rekey_beneficiary(stx, &stranger, &middle).is_err());
        assert_eq!(
            owner(stx, &binding, &old).unwrap().unwrap().account_id,
            middle
        );
        super::super::tests::claim_current_fee_credit(stx, &middle, binding.validator_lane_id)
            .unwrap();
        assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 0);
        // A later conversion still uses the unchanged pre-recovery earning account.
        reserve_conversion(
            stx,
            &binding,
            &ConversionOffer {
                earning_period_start_ms: period,
                sbd_minor: 100,
                min_xor_minor: 100,
                sequence: 1,
            },
            100,
        )
        .unwrap();
        super::super::tests::accrue_all(stx, &binding);
        rekey_beneficiary(stx, &middle, &latest).unwrap();
        assert_eq!(root(stx, &binding, &latest).unwrap(), old);
        assert_eq!(owner(stx, &binding, &old).unwrap().unwrap().revision, 2);
        assert!(
            super::super::tests::claim_current_fee_credit(stx, &middle, binding.validator_lane_id)
                .is_err()
        );
        super::super::tests::claim_current_fee_credit(stx, &latest, binding.validator_lane_id)
            .unwrap();
        super::super::tests::claim_current_fee_credit(stx, &latest, binding.validator_lane_id)
            .unwrap();
        let state = read_state(stx, &binding).unwrap();
        assert_eq!(
            (
                state.pending_sbd_total,
                state.reserved_xor,
                state.next_allocation,
                state.next_claim
            ),
            (0, 0, 2, 2)
        );
        assert_eq!(
            stx.world.smart_contract_state.get(&allocated_key).unwrap(),
            &original_allocation
        );
        assert_eq!(service_weights(stx, &binding, period).unwrap(), weights);
        for account in [&middle, &latest] {
            let paid = AssetId::new(binding.xor_asset_id.clone(), account.clone());
            assert_eq!(
                minor_units(stx.world.assets.get(&paid).unwrap().as_ref(), 9).unwrap(),
                100
            );
        }
        let corpus = pending_fee_evidence_records(stx).unwrap();
        let claims = corpus
            .iter()
            .filter_map(|r| match &r.payload {
                FeeEvidencePayloadV1::RewardClaim(c) => Some(c),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].beneficiary_id, old);
        assert_eq!(
            (
                claims[0].beneficiary_revision,
                claims[1].beneficiary_revision
            ),
            (1, 2)
        );
        assert!(corpus.iter().any(|r| matches!(&r.payload, FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision) if revision.account_id == middle && revision.revision == 1)), "claim before same-block rekey retains its exact earlier owner source");
        assert!(corpus.iter().any(|r| matches!(&r.payload, FeeEvidencePayloadV1::RewardEntitlement(a) if a.allocation_sequence == 1 && a.beneficiaries.get(&old) == Some(&old))));
    });
}

#[test]
fn superseded_owner_retirement_requires_exact_successor_and_journal() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
        let binding = active_bindings(stx).unwrap().remove(0);
        let original = super::super::tests::account(2);
        ensure(stx, &binding, &original).unwrap();
        let initial = owner(stx, &binding, &original).unwrap().unwrap();
        assert_eq!(
            retirement_height(&stx.world, &binding, &initial).unwrap(),
            None
        );
        let mut previous = original.clone();
        for seed in 40..72 {
            let next = super::super::tests::account(seed);
            rekey_beneficiary(stx, &previous, &next).unwrap();
            previous = next;
        }
        let current = owner(stx, &binding, &original).unwrap().unwrap();
        assert_eq!(current.revision, 32);
        assert_eq!(
            retirement_height(&stx.world, &binding, &current).unwrap(),
            None
        );
        assert_eq!(
            retirement_height(&stx.world, &binding, &initial).unwrap(),
            Some(stx.block_height())
        );
        history::validate_journals(&stx.world, &binding, &history::Checkpoint::default()).unwrap();
        let key = revision_key(&binding, &original, 1).unwrap();
        let bytes = stx.world.smart_contract_state.remove(key.clone()).unwrap();
        assert!(retirement_height(&stx.world, &binding, &initial).is_err());
        assert!(super::super::reconciliation::validate(&stx.world, &binding).is_err());
        let mut substituted: Revision = norito::decode_canonical(&bytes).unwrap();
        substituted.previous_account_id = Some(super::super::tests::account(99));
        stx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&substituted).unwrap());
        assert!(retirement_height(&stx.world, &binding, &initial).is_err());
        stx.world.smart_contract_state.insert(key, bytes);
        let journal_prefix = state_key(&binding, "HistoryJournal/").unwrap();
        let journals: Vec<_> = stx
            .world
            .smart_contract_state
            .range(journal_prefix.clone()..)
            .take_while(|(key, _)| key.as_ref().starts_with(journal_prefix.as_ref()))
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect();
        assert_eq!(journals.len(), 32);
        let (journal_key, journal_bytes) = &journals[0];
        stx.world.smart_contract_state.remove(journal_key.clone());
        assert!(
            history::validate_journals(&stx.world, &binding, &history::Checkpoint::default())
                .is_err()
        );
        stx.world
            .smart_contract_state
            .insert(journal_key.clone(), journal_bytes.clone());
        super::super::reconciliation::validate(&stx.world, &binding).unwrap();
        // Current owner revisions are live authority, not retirement candidates.
        let current_key = revision_key(&binding, &original, current.revision).unwrap();
        let current_bytes = stx
            .world
            .smart_contract_state
            .get(&current_key)
            .unwrap()
            .clone();
        history::journal_superseded_revision(stx, &current_key, &current_bytes).unwrap();
        assert!(
            history::validate_journals(&stx.world, &binding, &history::Checkpoint::default())
                .is_err()
        );
    });
}

#[test]
fn dropped_recovery_discards_retirement_journal_and_keeps_claim_owner() {
    crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, _| {
        let original = super::super::tests::account(2);
        let successor = super::super::tests::account(40);
        let binding = {
            let mut stx = block.transaction();
            let binding = active_bindings(&stx).unwrap().remove(0);
            ensure(&mut stx, &binding, &original).unwrap();
            stx.apply();
            binding
        };
        let before: BTreeMap<_, _> = block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect();
        {
            let mut stx = block.transaction();
            rekey_beneficiary(&mut stx, &original, &successor).unwrap();
            history::validate_journals(&stx.world, &binding, &history::Checkpoint::default())
                .unwrap();
            assert_eq!(
                owner(&stx, &binding, &original)
                    .unwrap()
                    .unwrap()
                    .account_id,
                successor
            );
            // A failed surrounding transaction discards the complete journal.
        }
        let after: BTreeMap<_, _> = block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect();
        assert_eq!(before, after);
        let retry = block.transaction();
        assert_eq!(
            owner(&retry, &binding, &original)
                .unwrap()
                .unwrap()
                .account_id,
            original
        );
    });
}
