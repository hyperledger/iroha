// Conversion-offer capacity backpressure preserves funded work and original refusals.

fn offer_projection_key(binding: &ValidationFeeTreasuryPayoutBindingV1, index: i128) -> StatePath {
    let digest = hex::encode(Hash::new(binding.contract_address.to_string().as_bytes()).as_ref());
    let path = ivm::host::canonical_state_map_path(
        &"ValidationFeeConversion".parse().unwrap(),
        &conversion_projection_map_key(index).unwrap(),
    )
    .unwrap();
    format!("sc/{digest}/{path}").parse().unwrap()
}

fn seed_capacity_offer(
    block: &mut StateBlock<'_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    full: bool,
) -> ValidationFeeRewardsState {
    use iroha_data_model::validation_fee::{
        RETAIL_FEE_NOTICE_MS, RetailFeeReceiptKindV1, RetailFeeReceiptV1, RetailFeeScheduleV1,
        VALIDATION_FEE_POLICY_SCHEMA_VERSION, VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS,
        ValidationFeeChargingMode, retail_fee_receipt_chain_hash_v1,
        retail_fee_receipt_state_key_v1,
    };
    let mut stx = block.transaction();
    let now = stx.block_unix_timestamp_ms();
    let height = stx.block_height();
    let policy = ValidationFeePolicyV1 {
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: stx.network_id,
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: binding.ds_asset_id.clone(),
        ds_scale: 2,
        fee: "0.10".parse().unwrap(),
        treasury_account_id: binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
        retail_schedule: RetailFeeScheduleV1::default(),
        effective_from_ms: now,
        notice_published_at_ms: now - RETAIL_FEE_NOTICE_MS,
        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.into()],
        reward_custody: binding.custody(),
    };
    let registry =
        crate::validation_fee::tests::policy_registry(&[policy.clone()], &[binding.clone()]);
    crate::validation_fee::tests::install_policy_registry_fixture(&registry, &mut stx);
    let period = earning_month(now - 1).unwrap();
    let state = ValidationFeeRewardsState {
        pending_sbd_total: 1_000,
        service_height: height - 1,
        ..Default::default()
    };
    save_state(&mut stx, binding, &state).unwrap();
    write(&mut stx, pending_key(binding, period).unwrap(), &1_000u64).unwrap();
    seed_service(
        &mut stx,
        binding,
        period,
        &BTreeMap::from([(account(2), 1u64)]),
    );
    let treasury = AssetId::new(
        binding.ds_asset_id.clone(),
        binding.treasury_account_id.clone(),
    );
    **stx
        .world
        .asset_or_insert_exact(&treasury, Quantity::zero())
        .unwrap() = Quantity::from(10u32);
    for seed in 10..13 {
        let observation = observation(seed, now - 1, now - 1, height - 1);
        let leaf = format!(
            "Oracle/{}",
            hex::encode(Hash::new(account(seed).to_string().as_bytes()).as_ref())
        );
        write(&mut stx, state_key(binding, &leaf).unwrap(), &observation).unwrap();
    }
    let offer = conversion_offer(&stx, binding)
        .unwrap()
        .expect("live closed-month offer");
    assert_eq!(offer.sbd_minor, 1_000);
    assert_eq!(offer.min_xor_minor, 19_800_000_000);
    for index in [0, 1] {
        stx.world.smart_contract_state.insert(
            offer_projection_key(binding, index),
            crate::validation_fee::encode_conversion_quantity_state_value(&Quantity::from(777u32))
                .unwrap(),
        );
    }
    if full {
        let existing = collect_pending_fee_evidence_records(&stx).unwrap().len();
        let remaining =
            iroha_data_model::fee_evidence::MAX_FEE_EVIDENCE_RECORDS_V1 as usize - existing;
        let mut previous_receipt_hash = None;
        let wallet = account(2);
        let policy_hash = policy.policy_hash().unwrap();
        for index in 0..remaining {
            let sequence = u64::try_from(index).unwrap() + 1;
            let mut receipt_id = [0; 32];
            receipt_id[..8].copy_from_slice(&sequence.to_le_bytes());
            let receipt = RetailFeeReceiptV1 {
                wallet_id: wallet.clone(),
                sequence,
                previous_receipt_hash,
                receipt_id,
                account_id: wallet.clone(),
                kind: RetailFeeReceiptKindV1::Maintenance,
                billing_month_start_ms: period,
                policy_revision: policy.policy_version,
                policy_hash,
                scheduled_minor: 100,
                collected_minor: 0,
                waived_minor: 100,
                payment_count: 0,
                source_transaction_hash: None,
                effective_at_ms: Some(now),
                recorded_at_height: height,
                assessment: None,
            };
            previous_receipt_hash = Some(retail_fee_receipt_chain_hash_v1(&receipt).unwrap());
            write(
                &mut stx,
                retail_fee_receipt_state_key_v1(&receipt).unwrap(),
                &receipt,
            )
            .unwrap();
        }
        assert_eq!(
            collect_pending_fee_evidence_records(&stx).unwrap().len(),
            4_096
        );
    }
    assert!(pending_fee_evidence_fits(&stx).unwrap());
    stx.apply();
    state
}

#[test]
fn full_fee_evidence_defers_offer_without_consuming_attempt_and_retries_next_block() {
    const NOW: u64 = 1_793_451_600_000;
    const HEIGHT: u64 = 200_000;
    let (chain, binding) = crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture();
    let state = chain.state();
    let header = |height, now| {
        BlockHeader::new(
            std::num::NonZeroU64::new(height).unwrap(),
            state.view().latest_block_hash(),
            None,
            now,
            0,
        )
    };
    let mut block = state.block(header(HEIGHT, NOW));
    let original = seed_capacity_offer(&mut block, &binding, true);
    publish_conversion_offers(&mut block)
        .expect("valid full corpus postpones only optional conversion");
    {
        let check = block.transaction();
        assert_eq!(read_state(&check, &binding).unwrap(), original);
        assert!(
            check
                .world
                .smart_contract_state
                .get(&state_key(&binding, &format!("Attempt/{HEIGHT}")).unwrap())
                .is_none()
        );
        assert_eq!(
            read::<u64>(
                &check,
                &pending_key(&binding, earning_month(NOW - 1).unwrap()).unwrap()
            )
            .unwrap(),
            Some(1_000)
        );
        assert_eq!(
            collect_pending_fee_evidence_records(&check).unwrap().len(),
            4_096
        );
        assert!(pending_fee_evidence_fits(&check).unwrap());
        let zero = crate::validation_fee::encode_conversion_quantity_state_value(&Quantity::zero())
            .unwrap();
        for index in [0, 1] {
            assert_eq!(
                check
                    .world
                    .smart_contract_state
                    .get(&offer_projection_key(&binding, index)),
                Some(&zero)
            );
        }
    }
    block.commit_world_overlay_for_testing().unwrap();
    let mut next = state.block(header(HEIGHT + 1, NOW + 1));
    {
        let mut stx = next.transaction();
        let mut source = read_state(&stx, &binding).unwrap();
        source.service_height = HEIGHT;
        save_state(&mut stx, &binding, &source).unwrap();
        assert!(
            conversion_offer(&stx, &binding).unwrap().is_some(),
            "deferred offer retained its pending credit and rate window"
        );
        stx.apply();
    }
    publish_conversion_offers(&mut next)
        .expect("following roomy block publishes the original pending work");
    let check = next.transaction();
    let current = read_state(&check, &binding).unwrap();
    assert_eq!(current.pending_sbd_total, 1_000);
    assert_eq!(current.last_attempt_height, HEIGHT + 1);
    assert_eq!(current.last_attempt_ms, Some(NOW + 1));
    assert!(
        check
            .world
            .smart_contract_state
            .get(&state_key(&binding, &format!("Attempt/{HEIGHT}")).unwrap())
            .is_none()
    );
    let attempt = read::<ValidationFeeConversionAttempt>(
        &check,
        &state_key(&binding, &format!("Attempt/{}", HEIGHT + 1)).unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(attempt.sbd_minor, 1_000);
    assert_eq!(
        attempt.earning_period_start_ms,
        earning_month(NOW - 1).unwrap()
    );
    for (index, amount) in [
        (0, Quantity::from(10u32)),
        (1, "19.8".parse::<Quantity>().unwrap()),
    ] {
        assert_eq!(
            check
                .world
                .smart_contract_state
                .get(&offer_projection_key(&binding, index)),
            Some(&crate::validation_fee::encode_conversion_quantity_state_value(&amount).unwrap())
        );
    }
}

#[test]
fn malformed_conversion_source_cannot_enter_capacity_deferral_or_clear_projection() {
    const NOW: u64 = 1_793_451_600_000;
    let (chain, binding) = crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture();
    let mut block = chain.state().block(BlockHeader::new(
        std::num::NonZeroU64::new(200_000).unwrap(),
        chain.state().view().latest_block_hash(),
        None,
        NOW,
        0,
    ));
    let original = seed_capacity_offer(&mut block, &binding, false);
    {
        let mut stx = block.transaction();
        let leaf = format!(
            "Oracle/{}",
            hex::encode(Hash::new(account(10).to_string().as_bytes()).as_ref())
        );
        stx.world
            .smart_contract_state
            .insert(state_key(&binding, &leaf).unwrap(), vec![0xff]);
        stx.apply();
    }
    assert!(matches!(
        publish_conversion_offers(&mut block),
        Err(crate::state::ExecutionOutputAttemptError::Owner(_))
    ));
    let check = block.transaction();
    assert_eq!(read_state(&check, &binding).unwrap(), original);
    let stale =
        crate::validation_fee::encode_conversion_quantity_state_value(&Quantity::from(777u32))
            .unwrap();
    for index in [0, 1] {
        assert_eq!(
            check
                .world
                .smart_contract_state
                .get(&offer_projection_key(&binding, index)),
            Some(&stale)
        );
    }
    assert!(
        check
            .world
            .smart_contract_state
            .get(&state_key(&binding, "Attempt/200000").unwrap())
            .is_none()
    );
}

#[test]
fn refused_conversion_source_remains_deferred_and_preserves_original_projection() {
    const NOW: u64 = 1_793_451_600_000;
    let (chain, binding) = crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture();
    let mut block = chain.state().block(BlockHeader::new(
        std::num::NonZeroU64::new(200_000).unwrap(),
        chain.state().view().latest_block_hash(),
        None,
        NOW,
        0,
    ));
    let original = seed_capacity_offer(&mut block, &binding, false);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, 0, usize::MAX, usize::MAX);
    let result = norito::with_decode_limits_scope(limits, || publish_conversion_offers(&mut block));
    assert!(matches!(
        result,
        Err(crate::state::ExecutionOutputAttemptError::Deferred(_))
    ));
    assert_eq!(
        block
            .world
            .smart_contract_state
            .get(&state_key(&binding, "State").unwrap()),
        Some(&norito::to_bytes(&original).unwrap()),
    );
    let stale =
        crate::validation_fee::encode_conversion_quantity_state_value(&Quantity::from(777u32))
            .unwrap();
    for index in [0, 1] {
        assert_eq!(
            block
                .world
                .smart_contract_state
                .get(&offer_projection_key(&binding, index)),
            Some(&stale)
        );
    }
    assert!(
        block
            .world
            .smart_contract_state
            .get(&state_key(&binding, "Attempt/200000").unwrap())
            .is_none()
    );
}
