// Same-scope orderbook regressions extracted to keep the parent source budget bounded.
#[test]
fn receipt_rejects_misauthorized_expired_unregistered_and_untraced_locks_atomically() {
    let settlement = keypair(0x53);
    let buyer = keypair(0x54);
    let provider = keypair(0x55);
    let treasury = keypair(0x56);
    let authority = account(&settlement);
    let buyer_id = account(&buyer);
    let provider_id = account(&provider);
    let treasury_id = account(&treasury);
    let mut state = state_with_settlement_accounts(
        &settlement,
        &buyer,
        &provider,
        &treasury,
        TEST_TRADE_LOCK_MICRO,
    );
    let mut block = state.block(block_header());
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xA7; Hash::LENGTH]));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA6; Hash::LENGTH]));
    let policy_digest = activate_policy(&mut stx, &authority);
    let candidate = receipt(&provider, 1, 16, 17, 0, 10);
    open_settlement_lock(&mut stx, &buyer_id, &provider_id, &authority, &candidate);
    let escrow_id = orderbook_settlement_escrow_id(candidate.channel_id);
    let custody = stx
        .world
        .asset_escrows
        .get(&escrow_id)
        .expect("settlement lock")
        .custody
        .clone();
    let configured_asset = stx.gov.sorafs_pin_fee_asset_id.clone();
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("retain original settlement lock before fee-asset change");
    state.gov.sorafs_pin_fee_asset_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("sorafs", "universal").expect("settlement domain"),
        "not_xor".parse().expect("wrong asset name"),
    );
    let mut block = state.block(block_header());
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xA7; Hash::LENGTH]));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA6; Hash::LENGTH]));
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    drop(stx);
    drop(block);
    state.gov.sorafs_pin_fee_asset_id = configured_asset;
    let mut block = state.block(block_header());
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xA7; Hash::LENGTH]));
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA6; Hash::LENGTH]));
    stx.world
        .asset_escrows
        .get_mut(&escrow_id)
        .expect("settlement lock")
        .remaining_amount = micro_quantity(TEST_TRADE_LOCK_MICRO - 1);
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    stx.world
        .asset_escrows
        .get_mut(&escrow_id)
        .expect("settlement lock")
        .remaining_amount = micro_quantity(TEST_TRADE_LOCK_MICRO);
    stx.world
        .asset_escrows
        .get_mut(&escrow_id)
        .expect("settlement lock")
        .release_authority = Some(buyer_id.clone());
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    {
        let escrow = stx
            .world
            .asset_escrows
            .get_mut(&escrow_id)
            .expect("settlement lock");
        escrow.release_authority = Some(authority.clone());
        escrow.expires_at_ms = Some(NOW * 1_000);
    }
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    stx.world
        .asset_escrows
        .get_mut(&escrow_id)
        .expect("settlement lock")
        .expires_at_ms = None;
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err(),
        "a settlement lock without the channel expiry must fail closed"
    );
    stx.world
        .asset_escrows
        .get_mut(&escrow_id)
        .expect("settlement lock")
        .expires_at_ms = Some((NOW + 100) * 1_000);
    stx.world
        .provider_owners
        .remove(ProviderId::new([0x71; 32]));
    stx.world
        .provider_owners
        .insert(ProviderId::new([0x72; 32]), provider_id.clone());
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err(),
        "an unrelated provider id for the same signer must not revive a revoked channel binding"
    );
    stx.world
        .provider_owners
        .remove(ProviderId::new([0x72; 32]));
    stx.world
        .provider_owners
        .insert(ProviderId::new([0x71; 32]), buyer_id.clone());
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err(),
        "reassigning the channel provider id must revoke the original provider signer"
    );
    stx.world
        .provider_owners
        .remove(ProviderId::new([0x71; 32]));
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    stx.world
        .provider_owners
        .insert(ProviderId::new([0x71; 32]), provider_id.clone());
    stx.tx_call_hash = None;
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    assert_eq!(asset_balance(&stx, &provider_id), Quantity::zero());
    assert_eq!(asset_balance(&stx, &treasury_id), Quantity::zero());
    assert_eq!(
        asset_balance(&stx, &custody),
        micro_quantity(TEST_TRADE_LOCK_MICRO)
    );
    assert_eq!(
        stx.world
            .asset_escrows
            .get(&escrow_id)
            .expect("settlement lock")
            .remaining_amount,
        micro_quantity(TEST_TRADE_LOCK_MICRO)
    );
    assert!(
        read_receipt(stx.world(), candidate.receipt_id)
            .expect("read receipt")
            .is_none()
    );
    assert!(
        read_receipt_index(stx.world(), candidate.channel_id)
            .expect("read index")
            .is_none()
    );
    assert_no_receipt_status_mutation(&stx);
    stx.tx_call_hash = Some(Hash::prehashed([0xA7; Hash::LENGTH]));
    RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
        .execute(&authority, &mut stx)
        .expect("restored valid lock settles");
    assert_eq!(
        asset_balance(&stx, &provider_id),
        candidate.provider_credit.clone().into_quantity()
    );
    assert_eq!(
        asset_balance(&stx, &treasury_id),
        candidate.fee_amount.clone().into_quantity()
    );
}
#[test]
fn receipt_without_funded_lock_fails_closed() {
    let settlement = keypair(0x4A);
    let buyer = keypair(0x4B);
    let provider = keypair(0x4C);
    let treasury = keypair(0x4D);
    let authority = account(&settlement);
    let buyer_id = account(&buyer);
    let provider_id = account(&provider);
    let state = state_with_settlement_accounts(
        &settlement,
        &buyer,
        &provider,
        &treasury,
        TEST_TRADE_LOCK_MICRO,
    );
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA3; Hash::LENGTH]));
    let policy_digest = activate_policy(&mut stx, &authority);
    let candidate = receipt(&provider, 1, 10, 11, 0, 10);
    seed_settlement_channel(&mut stx, &buyer_id, &provider_id, &authority, &candidate);
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    assert!(
        read_receipt(stx.world(), candidate.receipt_id)
            .expect("read receipt")
            .is_none()
    );
    assert!(
        read_receipt_index(stx.world(), candidate.channel_id)
            .expect("read index")
            .is_none()
    );
    assert_no_receipt_status_mutation(&stx);
}
#[test]
fn receipt_overdraw_rejects_without_asset_or_audit_mutation() {
    let settlement = keypair(0x4B);
    let buyer = keypair(0x4C);
    let provider = keypair(0x4D);
    let treasury = keypair(0x4E);
    let authority = account(&settlement);
    let buyer_id = account(&buyer);
    let provider_id = account(&provider);
    let treasury_id = account(&treasury);
    let state = state_with_settlement_accounts(
        &settlement,
        &buyer,
        &provider,
        &treasury,
        TEST_TRADE_LOCK_MICRO,
    );
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA4; Hash::LENGTH]));
    let policy_digest = activate_policy(&mut stx, &authority);
    let candidate = receipt(&provider, 1, 12, 13, 0, 10);
    open_settlement_lock(&mut stx, &buyer_id, &provider_id, &authority, &candidate);
    let escrow_id = orderbook_settlement_escrow_id(candidate.channel_id);
    let custody = stx
        .world
        .asset_escrows
        .get(&escrow_id)
        .expect("settlement lock")
        .custody
        .clone();
    let mut overdraw = candidate;
    overdraw.xor_debited = xor_micro(TEST_TRADE_LOCK_MICRO + 1);
    overdraw.provider_credit = overdraw
        .xor_debited
        .checked_sub(&overdraw.fee_amount)
        .expect("overdraw receipt remains internally balanced");
    let candidate = sign_receipt(overdraw, &provider);
    let error = RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
        .execute(&authority, &mut stx)
        .expect_err("a balanced signed receipt cannot debit more than the funded channel");
    assert!(
        matches!(
            &error,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message))
                if message.contains("does not equal deterministic channel split")
        ),
        "unexpected overdraw error: {error:?}"
    );
    assert_eq!(asset_balance(&stx, &provider_id), Quantity::zero());
    assert_eq!(asset_balance(&stx, &treasury_id), Quantity::zero());
    assert_eq!(
        asset_balance(&stx, &custody),
        micro_quantity(TEST_TRADE_LOCK_MICRO)
    );
    assert_eq!(
        stx.world
            .asset_escrows
            .get(&escrow_id)
            .expect("settlement lock")
            .remaining_amount,
        micro_quantity(TEST_TRADE_LOCK_MICRO)
    );
    assert!(
        read_receipt(stx.world(), candidate.receipt_id)
            .expect("read receipt")
            .is_none()
    );
    assert!(
        read_receipt_index(stx.world(), candidate.channel_id)
            .expect("read index")
            .is_none()
    );
    assert_no_receipt_status_mutation(&stx);
}
#[test]
fn receipt_destination_overflow_rejects_without_partial_fee_or_custody_mutation() {
    let settlement = keypair(0x4F);
    let buyer = keypair(0x50);
    let provider = keypair(0x51);
    let treasury = keypair(0x52);
    let authority = account(&settlement);
    let buyer_id = account(&buyer);
    let provider_id = account(&provider);
    let treasury_id = account(&treasury);
    let state = state_with_settlement_accounts(
        &settlement,
        &buyer,
        &provider,
        &treasury,
        TEST_TRADE_LOCK_MICRO,
    );
    let mut block = state.block(block_header());
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA5; Hash::LENGTH]));
    let policy_digest = activate_policy(&mut stx, &authority);
    let candidate = receipt(&provider, 1, 14, 15, 0, 10);
    open_settlement_lock(&mut stx, &buyer_id, &provider_id, &authority, &candidate);
    let escrow_id = orderbook_settlement_escrow_id(candidate.channel_id);
    let custody = stx
        .world
        .asset_escrows
        .get(&escrow_id)
        .expect("settlement lock")
        .custody
        .clone();
    let mut maximum_bytes = vec![0xFF; iroha_primitives::numeric::MAX_MANTISSA_BYTES];
    *maximum_bytes.last_mut().expect("non-empty mantissa") = 0x7F;
    let maximum_mantissa =
        BigInt::from_twos_bytes(&maximum_bytes).expect("maximum signed 512-bit positive mantissa");
    let mut maximum_source = maximum_mantissa.to_string();
    let decimal_index = maximum_source
        .len()
        .checked_sub(6)
        .expect("maximum mantissa has at least six decimal digits");
    maximum_source.insert(decimal_index, '.');
    let maximum: Quantity = maximum_source
        .parse()
        .expect("positive maximum is a valid quantity");
    assert!(
        maximum
            .checked_add(&candidate.provider_credit.clone().into_quantity())
            .is_err()
    );
    let provider_asset = Asset::new(
        AssetId::of(settlement_asset_definition(), provider_id.clone()),
        maximum.clone(),
    );
    let (provider_asset_id, provider_asset_value) = provider_asset.into_key_value();
    stx.world
        .assets
        .insert(provider_asset_id, provider_asset_value);
    assert!(
        RecordSorafsOrderbookSettlementReceipt::new(encode(&candidate), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    assert_eq!(asset_balance(&stx, &provider_id), maximum);
    assert_eq!(asset_balance(&stx, &treasury_id), Quantity::zero());
    assert_eq!(
        asset_balance(&stx, &custody),
        micro_quantity(TEST_TRADE_LOCK_MICRO)
    );
    assert_eq!(
        stx.world
            .asset_escrows
            .get(&escrow_id)
            .expect("settlement lock")
            .remaining_amount,
        micro_quantity(TEST_TRADE_LOCK_MICRO)
    );
    assert!(
        read_receipt(stx.world(), candidate.receipt_id)
            .expect("read receipt")
            .is_none()
    );
    assert!(
        read_receipt_index(stx.world(), candidate.channel_id)
            .expect("read index")
            .is_none()
    );
    assert_no_receipt_status_mutation(&stx);
}
#[test]
fn corrupted_authoritative_state_fails_closed_before_new_mutation() {
    let buyer = keypair(0x51);
    let authority = account(&buyer);
    let mut state = state_with_accounts(&[&buyer]);
    let mut block = state.block(block_header());
    let mut stx = block.transaction();
    let policy_digest = activate_policy(&mut stx, &authority);
    let order = order(&buyer, 1);
    stx.world
        .smart_contract_state
        .insert(order_key(order.order_id), vec![0xFF; 16]);
    assert!(
        SubmitSorafsOrderbookOrder::new(encode(&order), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    assert!(
        read_nonce(stx.world(), &authority)
            .expect("read nonce")
            .is_none()
    );
    assert_eq!(
        stx.world
            .smart_contract_state
            .get(&order_key(order.order_id))
            .expect("corrupt state remains"),
        &vec![0xFF; 16]
    );
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit corrupt order query fixture");
    state.push_block_hash_for_testing(iroha_crypto::HashOf::new(&block_header()));
    assert!(
        FindSorafsOrderbookOrders::new(None, None, None, 10)
            .execute(&state.view())
            .is_err(),
        "typed listings must fail closed on corrupt committed records"
    );
}
#[test]
fn missing_or_corrupt_status_fails_closed_before_order_mutation() {
    let buyer = keypair(0x57);
    let authority = account(&buyer);
    let state = state_with_accounts(&[&buyer]);
    let mut block = state.block(block_header());
    let mut stx = block.transaction();
    let policy_digest = activate_policy(&mut stx, &authority);
    let order = order(&buyer, 1);
    stx.world.smart_contract_state.remove(status_key().clone());
    assert!(
        SubmitSorafsOrderbookOrder::new(encode(&order), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    assert!(
        read_order(stx.world(), order.order_id)
            .expect("read order")
            .is_none()
    );
    assert!(
        read_nonce(stx.world(), &authority)
            .expect("read nonce")
            .is_none()
    );
    let corrupt = OrderbookLedgerStatusV1 {
        open_orders: 0,
        partially_filled_orders: 0,
        filled_orders: 0,
        cancelled_orders: 0,
        expired_orders: 0,
        provider_revoked_orders: 0,
        trades: 0,
        settlement_receipts: 0,
        settlement_channels: 1,
        open_settlement_channels: 2,
        book_revision: 0,
        last_match_scan_book_revision: 0,
        next_admission_sequence: 1,
        next_trade_sequence: 1,
        updated_at_unix: NOW,
    };
    stx.world
        .smart_contract_state
        .insert(status_key().clone(), encode(&corrupt));
    assert!(FindSorafsOrderbookStatus.execute(&stx).is_err());
    assert!(
        SubmitSorafsOrderbookOrder::new(encode(&order), policy_digest)
            .execute(&authority, &mut stx)
            .is_err()
    );
    assert!(
        read_order(stx.world(), order.order_id)
            .expect("read order")
            .is_none()
    );
    assert!(
        read_nonce(stx.world(), &authority)
            .expect("read nonce")
            .is_none()
    );
    let saturated = OrderbookLedgerStatusV1 {
        open_orders: u64::MAX,
        partially_filled_orders: 0,
        filled_orders: 0,
        cancelled_orders: 0,
        expired_orders: 0,
        provider_revoked_orders: 0,
        trades: 0,
        settlement_receipts: 0,
        settlement_channels: 0,
        open_settlement_channels: 0,
        book_revision: 0,
        last_match_scan_book_revision: 0,
        next_admission_sequence: 1,
        next_trade_sequence: 1,
        updated_at_unix: NOW,
    };
    stx.world
        .smart_contract_state
        .insert(status_key().clone(), encode(&saturated));
    assert!(
        SubmitSorafsOrderbookOrder::new(encode(&order), policy_digest)
            .execute(&authority, &mut stx)
            .is_err(),
        "saturated counters must reject rather than wrap"
    );
    assert!(
        read_order(stx.world(), order.order_id)
            .expect("read order")
            .is_none()
    );
    assert!(
        read_nonce(stx.world(), &authority)
            .expect("read nonce")
            .is_none()
    );
}
#[test]
fn filtered_pages_fail_closed_before_sparse_or_absent_match_beyond_scan_budget() {
    let settlement = keypair(0x2C);
    let buyer = keypair(0x2D);
    let provider = keypair(0x2E);
    let authority = account(&settlement);
    let buyer_id = account(&buyer);
    let provider_id = account(&provider);
    let mut state = state_with_accounts(&[&settlement, &buyer, &provider]);
    transact(&mut state, 1, NOW, |transaction| {
        let policy_digest = activate_policy(transaction, &authority);
        let fixture_provider_id = ProviderId::new([0x72; 32]);
        transaction
            .world
            .provider_owners
            .insert(fixture_provider_id, authority.clone());
        let mut orders = vec![
            ask_order(&settlement, 1, 100, 10),
            ask_order(&settlement, 2, 100, 10),
        ];
        orders.sort_unstable_by_key(|candidate| candidate.order_id);
        for (index, candidate) in orders.into_iter().enumerate() {
            let is_sparse_match = index == 1;
            let record = OrderbookOrderRecord {
                order_id: candidate.order_id,
                owner: authority.clone(),
                canonical_order: encode(&candidate),
                admitted_policy_digest: policy_digest,
                admitted_at_unix: NOW,
                admission_sequence: u64::try_from(index + 1)
                    .expect("two-record fixture sequence fits u64"),
                remaining_gib: if is_sparse_match {
                    0
                } else {
                    candidate.quantity_gib
                },
                bid_escrow: None,
                provider_id: Some(fixture_provider_id),
                status: if is_sparse_match {
                    OrderbookOrderStatusV1::Filled
                } else {
                    OrderbookOrderStatusV1::Open
                },
                updated_at_unix: NOW,
                canonical_cancel: None,
                cancelled_at_unix: None,
                cancelled_policy_digest: None,
            };
            transaction
                .world
                .smart_contract_state
                .insert(order_key(record.order_id), encode(&record));
        }
        let first_receipt = receipt(&provider, 1, 0, 8, 0, 10);
        let second_receipt = receipt(&provider, 2, 0, 8, 10, 20);
        let other_channel_receipt = receipt(&provider, 3, 0, 9, 0, 10);
        seed_settlement_channel(
            transaction,
            &buyer_id,
            &provider_id,
            &authority,
            &first_receipt,
        );
        seed_settlement_channel(
            transaction,
            &buyer_id,
            &provider_id,
            &authority,
            &other_channel_receipt,
        );
        let mut channel_ids = [first_receipt.channel_id, other_channel_receipt.channel_id];
        channel_ids.sort_unstable();
        let closed_channel_id = channel_ids[1];
        let mut closed_channel = read_channel(transaction.world(), closed_channel_id)
            .expect("read sparse-match channel")
            .expect("sparse-match channel exists");
        closed_channel.remaining_bytes = 0;
        closed_channel.remaining_xor_locked = XorQuantity::zero();
        closed_channel.remaining_fee_xor_locked = XorQuantity::zero();
        closed_channel.status = OrderbookSettlementChannelStatusV1::Closed;
        closed_channel.updated_at_unix = NOW;
        transaction
            .world
            .smart_contract_state
            .insert(channel_key(closed_channel_id), encode(&closed_channel));
        let receipt_index = OrderbookSettlementIndexRecord {
            channel_id: first_receipt.channel_id,
            trade_id: first_receipt.trade_id,
            ranges: vec![
                OrderbookSettlementRangeRecord {
                    receipt_id: first_receipt.receipt_id,
                    start: first_receipt.range.start,
                    end: first_receipt.range.end,
                    issued_at_unix: first_receipt.issued_at_unix,
                },
                OrderbookSettlementRangeRecord {
                    receipt_id: second_receipt.receipt_id,
                    start: second_receipt.range.start,
                    end: second_receipt.range.end,
                    issued_at_unix: second_receipt.issued_at_unix,
                },
            ],
        };
        transaction.world.smart_contract_state.insert(
            receipt_index_key(first_receipt.channel_id),
            encode(&receipt_index),
        );
        for candidate in [&first_receipt, &second_receipt] {
            let record = OrderbookSettlementReceiptRecord {
                receipt_id: candidate.receipt_id,
                channel_id: candidate.channel_id,
                trade_id: candidate.trade_id,
                canonical_receipt: encode(candidate),
                admitted_policy_digest: policy_digest,
                admitted_at_unix: NOW,
                recorded_by: authority.clone(),
            };
            transaction
                .world
                .smart_contract_state
                .insert(receipt_key(record.receipt_id), encode(&record));
        }
        Ok(())
    })
    .expect("commit sparse filtered-query fixture");
    let view = state.view();
    let finalized_cursor =
        resolve_finalized_cursor(&view).expect("resolve committed fixture cursor");
    let test_limits = OrderbookQueryScanLimitsV1 {
        max_inspected_records: 1,
        max_read_bytes: ORDERBOOK_QUERY_MAX_READ_BYTES_V1,
    };
    let mut order_budget = OrderbookQueryScanBudgetV1::new(test_limits);
    assert_eq!(
        query_order_page_with_budget(
            &FindSorafsOrderbookOrders::new(None, Some(OrderbookOrderStatusV1::Filled), None, 1,),
            &view,
            finalized_cursor,
            &mut order_budget,
        ),
        Err(QueryExecutionFail::Conversion(
            "SoraFS orderbook order page query exceeded inspected-record budget 1".to_owned()
        ))
    );
    let mut receipt_budget = OrderbookQueryScanBudgetV1::new(test_limits);
    assert_eq!(
        query_receipt_page_with_budget(
            &FindSorafsOrderbookReceipts::new(None, Some([0xFF; 32]), None, 1),
            &view,
            finalized_cursor,
            &mut receipt_budget,
        ),
        Err(QueryExecutionFail::Conversion(
            "SoraFS orderbook receipt page query exceeded inspected-record budget 1".to_owned()
        ))
    );
    let mut channel_budget = OrderbookQueryScanBudgetV1::new(test_limits);
    assert_eq!(
        query_channel_page_with_budget(
            &FindSorafsOrderbookChannels::new(
                None,
                Some(OrderbookSettlementChannelStatusV1::Closed),
                None,
                1,
            ),
            &view,
            finalized_cursor,
            &mut channel_budget,
        ),
        Err(QueryExecutionFail::Conversion(
            "SoraFS orderbook channel page query exceeded inspected-record budget 1".to_owned()
        ))
    );
}
