#[test]
fn transaction_result_json_roundtrip() {
    let ok_result = TransactionResult::new(Ok(DataTriggerSequence::default()));
    let json = norito::json::to_json(&ok_result).expect("serialize ok result");
    let decoded: TransactionResult = norito::json::from_str(&json).expect("deserialize ok result");
    assert_eq!(ok_result, decoded);
    let err_reason = error::TransactionRejectionReason::LimitCheck(error::TransactionLimitError {
        reason: "limit exceeded".into(),
    });
    let err_result = TransactionResult::new(Err(err_reason));
    let json = norito::json::to_json(&err_result).expect("serialize err result");
    let decoded: TransactionResult = norito::json::from_str(&json).expect("deserialize err result");
    assert_eq!(err_result, decoded);
}

#[test]
fn transaction_entrypoint_json_roundtrip() {
    let network_id = test_network_id(0x29);
    let _domain: DomainId = DomainId::try_new("default", "universal").unwrap();
    let public_key: iroha_crypto::PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .unwrap();
    let private_key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let authority = AccountId::new(public_key);
    let tx = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(Vec::new().into()))
    .sign(&private_key);
    let entry = TransactionEntrypoint::External(tx);
    let json = norito::json::to_json(&entry).expect("serialize external entrypoint");
    let decoded: TransactionEntrypoint =
        norito::json::from_str(&json).expect("deserialize external entrypoint");
    assert_eq!(entry, decoded);
    let retired =
        norito::json!({"Time": {"id":"trigger", "instructions":[], "authority":authority}});
    assert!(norito::json::from_value::<TransactionEntrypoint>(retired).is_err());
}

// Codec fixtures only; this does not establish charge, authority or finality.
fn transaction_result_fee_receipt_fixture() -> NexusFeeReceipt {
    let public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
        .parse()
        .expect("public codec fixture key");
    NexusFeeReceipt {
        version: NexusFeeReceipt::VERSION,
        source_id: [0x53; 32],
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
        lane_id: iroha_model_base::topology::LaneId::new(1),
        block_height: 42,
        debit_source: crate::nexus::FeeDebitSource::Account(AccountId::new(public_key)),
        fee_asset_id: "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
            .parse()
            .expect("canonical asset definition codec fixture"),
        program_revision: None,
        lease_id: None,
        fee_amount: Quantity::from(3_u32),
        settlement: crate::block::consensus::NexusFeeSettlementV1::Burn,
        schedule: crate::block::consensus::NexusFeeScheduleInputs {
            tx_bytes_len: 100,
            instruction_count: 1,
            gas_used: 0,
            base_fee: Quantity::from(3_u32),
            per_byte_fee: Quantity::zero(),
            per_instruction_fee: Quantity::zero(),
            per_gas_unit_fee: Quantity::zero(),
        },
    }
}

#[test]
fn transaction_result_fee_receipt_uses_four_mandatory_tuple_frames() {
    for receipt in [None, Some(transaction_result_fee_receipt_fixture())] {
        let mut result = TransactionResult::new(Ok(DataTriggerSequence::default()));
        result.set_nexus_fee_receipt(receipt);
        for requested in [0, norito::core::header_flags::COMPACT_LEN] {
            let (payload, flags) = {
                let _flags = norito::core::DecodeFlagsGuard::enter(requested);
                norito::codec::encode_with_header_flags(&result)
            };
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let fields = [
                norito::codec::encode_with_header_flags(&result.0).0,
                norito::codec::encode_with_header_flags(&result.1).0,
                norito::codec::encode_with_header_flags(&result.2).0,
                norito::codec::encode_with_header_flags(&result.3).0,
            ];
            let mut expected = Vec::new();
            for field in &fields {
                norito::core::write_len_to_vec_with_flags(
                    &mut expected,
                    u64::try_from(field.len()).expect("field length fits u64"),
                    flags,
                );
                expected.extend_from_slice(field);
            }
            assert_eq!(
                payload, expected,
                "exact tuple framing for layout {flags:#x}"
            );
            if result.nexus_fee_receipt().is_none() {
                assert_eq!(fields[2], [0], "None still owns a canonical Option tag");
            }
            let framed =
                norito::core::frame_bare_with_header_flags::<TransactionResult>(&payload, flags)
                    .expect("frame exact transaction result");
            let decoded = norito::core::decode_from_bytes::<TransactionResult>(&framed)
                .expect("decode all four result fields");
            assert_eq!(decoded, result, "layout {flags:#x}");
        }
    }
}

#[test]
fn transaction_result_fee_receipt_rejects_missing_truncated_and_trailing_frame() {
    let result = TransactionResult::new(Ok(DataTriggerSequence::default()));
    for requested in [0, norito::core::header_flags::COMPACT_LEN] {
        let (payload, flags) = {
            let _flags = norito::core::DecodeFlagsGuard::enter(requested);
            norito::codec::encode_with_header_flags(&result)
        };
        let mut third_frame_start = 0;
        for _ in 0..2 {
            let (length, prefix) =
                norito::core::read_len_from_slice_with_flags(&payload[third_frame_start..], flags)
                    .expect("mandatory preceding tuple field");
            third_frame_start += prefix + length;
        }
        assert!(third_frame_start < payload.len(), "None has its own frame");
        for end in third_frame_start..payload.len() {
            let truncated = norito::core::frame_bare_with_header_flags::<TransactionResult>(
                &payload[..end],
                flags,
            )
            .expect("frame deliberately truncated result with a valid header");
            assert!(
                norito::core::decode_from_bytes::<TransactionResult>(&truncated).is_err(),
                "accepted omitted or truncated receipt frame at {end} for layout {flags:#x}"
            );
        }
        let mut trailing = payload;
        trailing.push(0);
        let framed =
            norito::core::frame_bare_with_header_flags::<TransactionResult>(&trailing, flags)
                .expect("frame result with an extra byte");
        assert!(
            norito::core::decode_from_bytes::<TransactionResult>(&framed).is_err(),
            "accepted trailing tuple bytes for layout {flags:#x}"
        );
    }
}

#[test]
fn transaction_result_fee_receipt_json_requires_key_and_rejects_duplicate_null() {
    let unpaid = TransactionResult::new(Ok(DataTriggerSequence::default()));
    let json = norito::json::to_json(&unpaid).expect("serialize explicit absent receipt");
    let (prefix, receipt) = json
        .rsplit_once(",\"nexus_fee_receipt\":")
        .expect("mandatory receipt key");
    let (receipt, suffix) = receipt
        .split_once(',')
        .expect("mandatory contract events follow the receipt");
    assert_eq!(receipt, "null");
    assert_eq!(suffix, "\"contract_events\":[]}");
    assert_eq!(
        norito::json::from_str::<TransactionResult>(&json).expect("explicit null is present"),
        unpaid
    );
    let missing = format!("{prefix},{suffix}");
    let error = norito::json::from_str::<TransactionResult>(&missing)
        .expect_err("missing receipt key must not synthesize None");
    assert!(error.to_string().contains("nexus_fee_receipt"));
    let duplicate =
        format!("{prefix},\"nexus_fee_receipt\":null,\"nexus_fee_receipt\":null,{suffix}");
    let error = norito::json::from_str::<TransactionResult>(&duplicate)
        .expect_err("a first null value still marks the key as present");
    assert!(error.to_string().contains("nexus_fee_receipt"));
}

#[test]
fn transaction_result_fee_receipt_commits_charge_in_hash_and_checked_json() {
    let mut result = TransactionResult::new(Ok(DataTriggerSequence::default()));
    let unpaid_hash = result.hash();
    let receipt = transaction_result_fee_receipt_fixture();
    result.set_nexus_fee_receipt(Some(receipt.clone()));
    assert_eq!(result.nexus_fee_receipt(), Some(&receipt));
    assert_ne!(
        result.hash(),
        unpaid_hash,
        "the actual charge changes the result leaf"
    );
    let json = norito::json::to_json(&result).expect("serialize charged result");
    assert_eq!(
        norito::json::from_str::<TransactionResult>(&json).expect("decode charged result"),
        result
    );
    assert_exact_json(&result);
    result.set_nexus_fee_receipt(None);
    assert!(result.nexus_fee_receipt().is_none());
    assert_eq!(result.hash(), unpaid_hash);
}
