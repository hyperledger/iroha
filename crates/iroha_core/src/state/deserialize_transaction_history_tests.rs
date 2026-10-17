mod transaction_history_restore_tests {
    use super::*;

    const EMPTY: &str = r#"{"latest_block":null,"blocks":{}}"#;

    #[test]
    fn original_admission_survives_backend_snapshot_and_durable_error_mapping() {
        let budget = iroha_allocation::AllocationBudget::new(1);
        let _occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let membership = storage_transactions::MembershipAdmissionError::Capacity(refusal.clone());
        let backend = storage_transactions::MembershipRestoreError::Admission(membership.clone());
        let restored = StateRestoreError::from(backend);
        let crate::snapshot::TryReadError::StateAdmission(StateAdmissionError::Membership(actual)) =
            crate::snapshot::TryReadError::from(restored)
        else {
            panic!("local membership refusal must not become serialization failure");
        };
        assert_eq!(actual, membership);
        let restored = durable_state_restore_error(MergeLedgerCommitError::MembershipAdmission(
            membership.clone(),
        ));
        assert!(
            matches!(restored, StateRestoreError::Admission(StateAdmissionError::Membership(actual))
            if actual == membership)
        );
        let history = BlockHashAdmissionError::Capacity(refusal);
        let restored = durable_state_restore_error(MergeLedgerCommitError::BlockHashAdmission(
            history.clone(),
        ));
        let crate::snapshot::TryReadError::StateAdmission(StateAdmissionError::History(actual)) =
            crate::snapshot::TryReadError::from(restored)
        else {
            panic!("local block-history refusal must not become serialization failure");
        };
        assert_eq!(actual, history);
    }

    #[test]
    fn borrowed_membership_restore_uses_the_original_store_pool() {
        let kura = Kura::blank_kura_for_testing();
        let budget = kura.transaction_history_budget();
        assert_eq!(budget.reserved_bytes(), 0);
        let restored = SnapshotJsonField::Borrowed { raw: EMPTY }
            .decode_transactions(kura.transaction_history_budget())
            .expect("restore into the original configured pool");
        assert!(budget.reserved_bytes() > 0, "native owner must be prepaid");
        assert_eq!(json::to_json(&restored).unwrap(), EMPTY);
        drop(kura);
        assert!(
            budget.reserved_bytes() > 0,
            "storage retains its original pool"
        );
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn membership_restore_refuses_a_full_original_pool_and_can_retry() {
        let kura = Kura::blank_kura_for_testing();
        let budget = kura.transaction_history_budget();
        let full = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let result = SnapshotJsonField::Borrowed { raw: EMPTY }
            .decode_transactions(kura.transaction_history_budget());
        assert!(matches!(
            result,
            Err(StateRestoreError::Admission(
                StateAdmissionError::Membership(_)
            ))
        ));
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(full);
        let restored = SnapshotJsonField::Borrowed { raw: EMPTY }
            .decode_transactions(kura.transaction_history_budget())
            .expect("retry after releasing the original reservation");
        assert!(budget.reserved_bytes() > 0);
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn membership_restore_rejects_noncanonical_fields_and_refunds_the_pool() {
        let kura = Kura::blank_kura_for_testing();
        let budget = kura.transaction_history_budget();
        for raw in [
            r#"{"blocks":{},"latest_block":null}"#,
            r#"{"latest_block": null,"blocks":{}}"#,
            r#"{"latest_block":null,"latest_block":null,"blocks":{}}"#,
            r#"{"latest_block":null,"blocks":{},"retired":{}}"#,
        ] {
            let result = SnapshotJsonField::Borrowed { raw }
                .decode_transactions(kura.transaction_history_budget());
            assert!(
                matches!(result, Err(StateRestoreError::Serialization(json::Error::InvalidField { ref field, .. }))
                if field == "transactions"),
                "{raw}"
            );
            assert_eq!(
                budget.reserved_bytes(),
                0,
                "failed restore retains no credit"
            );
        }
    }

    #[test]
    fn owned_fixture_restore_still_uses_the_supplied_pool() {
        let kura = Kura::blank_kura_for_testing();
        let budget = kura.transaction_history_budget();
        let restored = SnapshotJsonField::Owned(json::from_str(EMPTY).unwrap())
            .decode_transactions(kura.transaction_history_budget())
            .expect("fixture representation uses the production pool constructor");
        assert!(budget.reserved_bytes() > 0);
        assert_eq!(json::to_json(&restored).unwrap(), EMPTY);
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn fresh_state_refuses_membership_capacity_without_replacing_its_pool() {
        let kura = Kura::blank_kura_for_testing();
        let budget = kura.transaction_history_budget();
        let full = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let constructor_world = World::default();
        let result = State::try_new(
            constructor_world
                .sccp_committee_generations
                .allocation_budget()
                .clone(),
            constructor_world,
            Arc::clone(&kura),
            crate::query::store::LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
        );
        assert!(matches!(
            result,
            Err(MergeLedgerCommitError::MembershipAdmission(_))
        ));
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(full);
        let constructor_world = World::default();
        let state = State::try_new(
            constructor_world
                .sccp_committee_generations
                .allocation_budget()
                .clone(),
            constructor_world,
            kura,
            crate::query::store::LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
        )
        .expect("fresh construction retries on the same original pool");
        assert!(budget.reserved_bytes() > 0);
        drop(state);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
