// Atomic native credit projection CAS controls; these direct ISI tests do not
// claim transaction-fee settlement or live-network qualification.

fn assert_provider_credit_cas_refusal(error: InstructionExecutionError) {
    assert!(matches!(error,
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message))
        if message == "provider credit expected current record does not match"));
}

#[test]
fn provider_credit_cas_initial_creation_requires_absence_and_preserves_custody() {
    let state = make_state();
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x61; Hash::LENGTH]));
    let provider = ProviderId::new([0x62; 32]);
    seed_provider_owners(&mut stx, &[provider], &alice());
    super::sorafs_reserve::seed_verified_provider_bond_for_test(
        &mut stx,
        provider,
        &alice(),
        1,
        Quantity::from(2_u32),
    )
    .unwrap();
    let record = ProviderCreditRecord::new(
        provider,
        Quantity::from(3_u32),
        Quantity::from(2_u32),
        Quantity::from(1_u32),
        Quantity::zero(),
        0,
        0,
        Metadata::default(),
    );
    let custody_before: Vec<_> = stx
        .world
        .assets
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let reserve_before: Vec<_> = stx
        .world
        .smart_contract_state
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let _ = stx.world.take_external_events();
    UpsertProviderCredit::new(None, record.clone())
        .execute(&alice(), &mut stx)
        .unwrap();
    assert_eq!(
        stx.world.provider_credit_ledger.get(&provider),
        Some(&record)
    );
    assert_provider_credit_cas_refusal(
        UpsertProviderCredit::new(None, record.clone())
            .execute(&alice(), &mut stx)
            .unwrap_err(),
    );
    assert_eq!(
        stx.world.provider_credit_ledger.get(&provider),
        Some(&record)
    );
    assert_eq!(
        stx.world
            .assets
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        custody_before
    );
    assert_eq!(
        stx.world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        reserve_before
    );
    assert!(stx.world.take_external_events().is_empty());
    assert!(!stx.is_execution_deferred());
}

#[test]
fn provider_credit_cas_exact_update_rejects_stale_and_cross_provider_hashes_without_mutation() {
    let state = make_state();
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x63; Hash::LENGTH]));
    let provider = ProviderId::new([0x64; 32]);
    seed_governed_capacity_provider(&mut stx, provider, &alice(), Quantity::from(2_u32));
    let original = stx
        .world
        .provider_credit_ledger
        .get(&provider)
        .unwrap()
        .clone();
    let predecessor = iroha_crypto::HashOf::new(&original);
    let mut updated = original.clone();
    updated.available_credit = Quantity::from(7_u32);
    let _ = updated
        .metadata
        .insert("projection".parse().unwrap(), Json::new("governed"));
    UpsertProviderCredit::new(Some(predecessor), updated.clone())
        .execute(&alice(), &mut stx)
        .unwrap();
    let custody_before: Vec<_> = stx
        .world
        .assets
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let reserve_before: Vec<_> = stx
        .world
        .smart_contract_state
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let _ = stx.world.take_external_events();
    let mut different_provider = updated.clone();
    different_provider.provider_id = ProviderId::new([0x65; 32]);
    for expected in [
        None,
        Some(predecessor),
        Some(iroha_crypto::HashOf::new(&different_provider)),
    ] {
        assert_provider_credit_cas_refusal(
            UpsertProviderCredit::new(expected, original.clone())
                .execute(&alice(), &mut stx)
                .unwrap_err(),
        );
        assert_eq!(
            stx.world.provider_credit_ledger.get(&provider),
            Some(&updated)
        );
        assert!(!stx.is_execution_deferred());
    }
    assert_eq!(
        stx.world
            .assets
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        custody_before
    );
    assert_eq!(
        stx.world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        reserve_before
    );
    assert!(stx.world.take_external_events().is_empty());
    // The exact current guard admits an update without treating prior nominal
    // credit as new collateral or rewriting the native reserve partition.
    UpsertProviderCredit::new(Some(iroha_crypto::HashOf::new(&updated)), original.clone())
        .execute(&alice(), &mut stx)
        .unwrap();
    assert_eq!(
        stx.world.provider_credit_ledger.get(&provider),
        Some(&original)
    );
}

#[test]
fn provider_credit_cas_expected_presence_rejects_absent_before_reserve_work() {
    let state = make_state();
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x66; Hash::LENGTH]));
    let provider = ProviderId::new([0x67; 32]);
    let record = provider_credit_nanos(provider, 1, 0);
    // Deliberately no provider owner or reserve: the failed compare must precede
    // those unrelated checks, leave the absent target alone, and emit no event.
    let _ = stx.world.take_external_events();
    assert_provider_credit_cas_refusal(
        UpsertProviderCredit::new(Some(iroha_crypto::HashOf::new(&record)), record)
            .execute(&alice(), &mut stx)
            .unwrap_err(),
    );
    assert!(stx.world.provider_credit_ledger.get(&provider).is_none());
    assert!(stx.world.take_external_events().is_empty());
    assert!(!stx.is_execution_deferred());
}

#[test]
fn provider_credit_cas_hash_uses_borrowed_stream_under_original_allowance() {
    let mut record = provider_credit_nanos(ProviderId::new([0x68; 32]), 3, 2);
    let _ = record
        .metadata
        .insert("projection".parse().unwrap(), Json::new("governed"));
    let expected = iroha_crypto::HashOf::new(&record);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    norito::core::with_decode_limits_scope(limits, || {
        // The current borrowed numeric/metadata encoder needs no owned graph or
        // raw frame. Do not manufacture an allocation failure for this path.
        assert_eq!(iroha_crypto::HashOf::try_new(&record).unwrap(), expected);
        assert!(
            norito::core::reserve_decode_allocation(1).is_err(),
            "hashing must not renew the inherited allowance"
        );
    });
}
