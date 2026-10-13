/// Native handler controls for owner-governed, independently signed completion.
/// These use the existing hash-only prefix fixture; they do not claim certified execution or fees.
mod dedicated_completion_authority_tests {
    use super::*;
    use iroha_executor_data_model::permission::sorafs::CanCompleteSorafsReplicationOrder;

    fn grant(
        stx: &mut crate::state::StateTransaction<'_, '_>,
        signer: &AccountId,
        provider: ProviderId,
    ) {
        stx.world.add_account_permission(
            signer,
            Permission::from(CanCompleteSorafsReplicationOrder {
                provider_id: provider,
            }),
        );
    }
    fn prepare(stx: &mut crate::state::StateTransaction<'_, '_>) -> CompleteReplicationOrder {
        insert_manifest_with_status(
            stx,
            default_digest(),
            default_chunk_digest(),
            None,
            PinStatus::Approved(5),
        );
        let providers = [
            ProviderId::new([0x34; 32]),
            ProviderId::new([0x44; 32]),
            ProviderId::new([0x54; 32]),
        ];
        seed_provider_owners(stx, &providers, &alice());
        let previous = completion_authority(&alice(), 1);
        let selected =
            ProviderIngestCompletionAuthorityV1::new(alice(), bob(), completion_signer_policy(2));
        SetProviderIngestCompletionAuthority::new(providers[0], Some(previous), selected.clone())
            .execute(&alice(), stx)
            .expect("only owner selects independent signer");
        grant(stx, &bob(), providers[0]);
        let order_id = ReplicationOrderId::new([0x78; 32]);
        IssueReplicationOrder {
            order_id,
            order_payload: encode_replication_order_for_epoch_window(
                replication_order_struct(order_id, default_digest(), &providers, 3),
                5,
                15,
            ),
            issued_epoch: 5,
            deadline_epoch: 15,
            musubi_archive: None,
        }
        .execute(&alice(), stx)
        .unwrap();
        CompleteReplicationOrder {
            order_id,
            provider_id: providers[0],
            completion_epoch: 10,
            expected_authority: selected,
            expected_assignment_revision: 1,
            finalized_anchor: completion_anchor(),
        }
    }

    #[test]
    fn dedicated_signer_completes_and_owner_cannot_impersonate_it() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(10));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let selected = prepare(&mut stx);
        let before = stx
            .world
            .replication_orders
            .get(&selected.order_id)
            .unwrap()
            .clone();
        let error = selected.clone().execute(&alice(), &mut stx).unwrap_err();
        assert!(
            matches!(error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("exact governed completion signer"))
        );
        assert_eq!(
            stx.world.replication_orders.get(&selected.order_id),
            Some(&before)
        );
        selected
            .clone()
            .execute(&bob(), &mut stx)
            .expect("registered independent signer with exact provider grant");
        let after = stx
            .world
            .replication_orders
            .get(&selected.order_id)
            .unwrap()
            .clone();
        let completion = after.provider_completion(selected.provider_id).unwrap();
        assert_eq!(completion.completed_by, bob());
        assert_eq!(completion.completion_authority.provider_owner, alice());
        assert_eq!(completion.completion_authority.completion_signer, bob());
        validate_stored_replication_order(&after, "dedicated completion").unwrap();
        selected
            .clone()
            .execute(&bob(), &mut stx)
            .expect("exact original replay");
        assert_eq!(
            stx.world.replication_orders.get(&selected.order_id),
            Some(&after)
        );
        let mut substituted = after;
        substituted.provider_completions[0].completed_by = alice();
        assert!(validate_stored_replication_order(&substituted, "wrong completed_by").is_err());
    }

    #[test]
    fn completion_rejects_wrong_scope_and_stale_full_authority_without_mutation() {
        let state = make_state_with_completion_anchor();
        let mut block = state.block(block_header_at_epoch(10));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let selected = prepare(&mut stx);
        let before = stx
            .world
            .replication_orders
            .get(&selected.order_id)
            .unwrap()
            .clone();
        for permission in [
            Permission::new("CanCompleteSorafsReplicationOrder".into(), Json::new(())),
            Permission::from(CanCompleteSorafsReplicationOrder {
                provider_id: ProviderId::new([0xEE; 32]),
            }),
        ] {
            stx.world
                .account_permissions
                .insert(bob(), Permissions::from([permission]));
            assert!(selected.clone().execute(&bob(), &mut stx).is_err());
            assert_eq!(
                stx.world.replication_orders.get(&selected.order_id),
                Some(&before)
            );
        }
        grant(&mut stx, &bob(), selected.provider_id);
        let mut outdated = selected.clone();
        outdated.expected_authority.completion_signer = alice();
        assert!(outdated.execute(&bob(), &mut stx).is_err());
        let mut outdated = selected.clone();
        outdated.expected_authority.provider_owner = bob();
        assert!(outdated.execute(&bob(), &mut stx).is_err());
        let mut outdated = selected.clone();
        outdated.expected_assignment_revision += 1;
        assert!(outdated.execute(&bob(), &mut stx).is_err());
        let mut outdated = selected.clone();
        outdated.finalized_anchor.block_hash = [0xEE; 32];
        assert!(outdated.execute(&bob(), &mut stx).is_err());
        assert_eq!(
            stx.world.replication_orders.get(&selected.order_id),
            Some(&before)
        );
        selected.execute(&bob(), &mut stx).unwrap();
    }

    #[test]
    fn signer_selection_requires_registered_account_full_cas_and_policy_successor() {
        let state = make_state();
        let mut block = state.block(block_header());
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x51; Hash::LENGTH]));
        let provider = ProviderId::new([0xA6; 32]);
        stx.world.provider_owners.insert(provider, alice());
        let original =
            ProviderIngestCompletionAuthorityV1::new(alice(), bob(), completion_signer_policy(1));
        let unknown = AccountId::new(
            KeyPair::try_from_seed(vec![123; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let mut unregistered = original.clone();
        unregistered.completion_signer = unknown;
        assert!(
            SetProviderIngestCompletionAuthority::new(provider, None, unregistered)
                .execute(&alice(), &mut stx)
                .is_err()
        );
        assert!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider)
                .is_none()
        );
        assert!(
            SetProviderIngestCompletionAuthority::new(provider, None, original.clone())
                .execute(&bob(), &mut stx)
                .is_err()
        );
        SetProviderIngestCompletionAuthority::new(provider, None, original.clone())
            .execute(&alice(), &mut stx)
            .unwrap();
        let mut same_policy_new_key = original.clone();
        same_policy_new_key.completion_signer = alice();
        assert!(
            SetProviderIngestCompletionAuthority::new(
                provider,
                Some(original.clone()),
                same_policy_new_key
            )
            .execute(&alice(), &mut stx)
            .is_err()
        );
        assert_eq!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider),
            Some(&original)
        );
        let next =
            ProviderIngestCompletionAuthorityV1::new(alice(), alice(), completion_signer_policy(2));
        let mut false_predecessor = original.clone();
        false_predecessor.completion_signer = alice();
        assert!(
            SetProviderIngestCompletionAuthority::new(
                provider,
                Some(false_predecessor),
                next.clone()
            )
            .execute(&alice(), &mut stx)
            .is_err()
        );
        SetProviderIngestCompletionAuthority::new(provider, Some(original.clone()), next.clone())
            .execute(&alice(), &mut stx)
            .unwrap();
        assert!(
            RevokeProviderIngestCompletionAuthority::new(provider, original)
                .execute(&alice(), &mut stx)
                .is_err()
        );
        assert!(
            RevokeProviderIngestCompletionAuthority::new(provider, next.clone())
                .execute(&bob(), &mut stx)
                .is_err()
        );
        assert_eq!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider),
            Some(&next)
        );
        RevokeProviderIngestCompletionAuthority::new(provider, next)
            .execute(&alice(), &mut stx)
            .unwrap();
        assert!(
            stx.world
                .provider_ingest_completion_authorities
                .get(&provider)
                .is_none()
        );
    }
}
