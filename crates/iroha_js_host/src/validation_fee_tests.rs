// Native first-release policy/SDK wire parity. Fixtures never assert live enactment.
fn validation_fee_account(seed: u8) -> AccountId {
    let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap();
    AccountId::new(pair.public_key().clone())
}
fn validation_fee_asset(domain: &str, name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new(domain, "universal").unwrap(),
        name.parse().unwrap(),
    )
}
fn validation_fee_payout_binding_fixture() -> ValidationFeeTreasuryPayoutBindingV1 {
    let contract_address: ContractAddress =
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .unwrap();
    let pool_contract_address = ContractAddress::derive(
        &NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x13; 32]),
        )),
        &validation_fee_account(2),
        43,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    ValidationFeeTreasuryPayoutBindingV1 {
        treasury_account_id: contract_address.subject_id(),
        contract_address,
        code_hash: [0x34; 32],
        entrypoint: "autonomous_validation_fee_tick".parse().unwrap(),
        ds_asset_id: validation_fee_asset("cbsi", "ds"),
        xor_asset_id: validation_fee_asset("xor", "xor"),
        pool_vault_account_id: pool_contract_address.subject_id(),
        pool_contract_address,
        pool_code_hash: [0x36; 32],
        reward_pool_account_id: validation_fee_account(3),
        reference_feed_id: "xor_per_sbd".parse().unwrap(),
        reference_feed_config_version: 1,
        reference_provider_accounts: (20..25).map(validation_fee_account).collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100_000,
        min_interval_ms: 60000,
        max_source_age_ms: 300_000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    }
}
fn validation_fee_policy_fixture() -> ValidationFeePolicyV1 {
    let binding = validation_fee_payout_binding_fixture();
    ValidationFeePolicyV1 {
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x13; 32]),
        )),
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: binding.ds_asset_id.clone(),
        ds_scale: VALIDATION_FEE_DS_SCALE,
        retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
        effective_from_ms: 1_793_451_600_000,
        notice_published_at_ms: 1_790_859_600_000,
        fee: initial_validation_fee_amount(),
        treasury_account_id: binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.to_owned()],
        reward_custody: binding.custody(),
    }
}
fn assert_validation_fee_policy_instruction_roundtrip(policy: ValidationFeePolicyV1) {
    const WIRE_ID: &str = "iroha.instruction.v1::governance::ProposeValidationFeePolicy";
    let instruction: InstructionBox = ProposeValidationFeePolicy { policy }.into();
    let original_dyn_bytes = InstructionTrait::dyn_encode(&*instruction);
    assert_eq!(
        iroha_data_model::isi::instruction_wire_id(&instruction),
        Some(WIRE_ID)
    );
    let framed =
        iroha_data_model::isi::frame_instruction_payload(WIRE_ID, original_dyn_bytes.as_slice())
            .expect("frame validation-fee instruction");
    assert!(
        decode_instruction_aligned(&framed).is_err(),
        "a concrete instruction frame is not a public InstructionBox frame"
    );
    let typed = iroha_data_model::isi::decode_instruction_from_pair(WIRE_ID, &framed)
        .expect("decode registered concrete validation-fee instruction");
    assert_eq!(InstructionTrait::dyn_encode(&*typed), original_dyn_bytes);
    let public_frame =
        norito::encode_canonical(&instruction).expect("frame public validation-fee InstructionBox");
    let decoded = decode_instruction_aligned(&public_frame)
        .expect("decode public validation-fee InstructionBox");
    assert_eq!(
        InstructionTrait::id(&*decoded),
        InstructionTrait::id(&*instruction)
    );
    assert_eq!(
        InstructionTrait::dyn_encode(&*decoded),
        original_dyn_bytes,
        "typed frame decode must preserve exact native instruction bytes"
    );
    let json_value =
        instruction_to_json_value(&decoded).expect("render validation-fee instruction JSON");
    let json_payload = json::to_json(&json_value).expect("encode validation-fee JSON");
    let reconstructed =
        value_to_instruction(json_value).expect("rebuild validation-fee instruction");
    assert_eq!(
        iroha_data_model::isi::instruction_wire_id(&reconstructed),
        Some(WIRE_ID)
    );
    assert_eq!(
        InstructionTrait::dyn_encode(&*reconstructed),
        original_dyn_bytes,
        "decoded JSON must rebuild the exact native instruction bytes"
    );
    let network_id = test_network_id(b"validation-fee-js-test");
    let draft = build_transaction_payload_from_instructions_json(
        network_id,
        validation_fee_account(7),
        vec![json_payload],
        authority_fee_payment_json(),
        None,
        Some(1_700_000_000_000),
        Some(60_000),
        Some(9),
    )
    .expect("build validation-fee transaction payload");
    let payload: TransactionPayload =
        json::from_json(&draft.payload_json).expect("decode validation-fee draft payload");
    assert_eq!(
        payload.domain,
        iroha_data_model::transaction::TransactionDomain::Network(network_id),
        "validation-fee draft must bind the exact requested NetworkId"
    );
    let Executable::Instructions(batch) = &payload.instructions else {
        panic!("validation-fee draft must contain an instruction batch")
    };
    let rebuilt = batch
        .iter()
        .next()
        .expect("validation-fee draft instruction");
    assert_eq!(
        iroha_data_model::isi::instruction_wire_id(rebuilt),
        Some(WIRE_ID)
    );
    assert_eq!(
        InstructionTrait::dyn_encode(&**rebuilt),
        original_dyn_bytes,
        "buildTransactionPayload path must preserve exact native instruction bytes"
    );
}

#[test]
fn monthly_policy_instruction_preserves_native_bytes_and_transaction_payload() {
    let policy = validation_fee_policy_fixture();
    assert_validation_fee_policy_instruction_roundtrip(policy);
}
#[test]
fn policy_fingerprint_binds_native_schedule_and_operator() {
    let policy = validation_fee_policy_fixture();
    let operator = validation_fee_account(7);
    let fingerprint = validation_fee_policy_proposal_fingerprint_v1(
        operator.to_string(),
        json::to_json(&policy).unwrap(),
    )
    .unwrap();
    let expected = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: operator,
        policy: policy.clone(),
    })
    .fingerprint();
    assert_eq!(fingerprint.as_ref(), expected);
    let other = validation_fee_policy_proposal_fingerprint_v1(
        validation_fee_account(8).to_string(),
        json::to_json(&policy).unwrap(),
    )
    .unwrap();
    assert_ne!(fingerprint.as_ref(), other.as_ref());
    let mut updated = policy;
    updated.retail_schedule.included_payments = 60;
    let changed = validation_fee_policy_proposal_fingerprint_v1(
        validation_fee_account(7).to_string(),
        json::to_json(&updated).unwrap(),
    )
    .unwrap();
    assert_ne!(fingerprint.as_ref(), changed.as_ref());
}
#[test]
fn conversion_lifecycle_fingerprint_matches_native_kind() {
    let binding = validation_fee_payout_binding_fixture();
    let operator = validation_fee_account(7);
    let expected =
        ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
            proposal_operator: operator.clone(),
            payout_binding: binding.clone(),
        })
        .fingerprint();
    let actual = validation_fee_payout_lifecycle_proposal_fingerprint_v1(
        operator.to_string(),
        json::to_json(&binding).unwrap(),
    )
    .unwrap();
    assert_eq!(actual.as_ref(), expected);
}
#[test]
fn sdk_rejects_removed_fields_missing_custody_and_hidden_exemptions() {
    for field in ["fee_asset_id", "enabled", "recipients"] {
        let mut value = json::to_value(&validation_fee_policy_fixture()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), json::Value::Bool(true));
        assert!(validation_fee_policy_from_json_value(value).is_err());
    }
    let mut missing = json::to_value(&validation_fee_policy_fixture()).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .insert("reward_custody".to_owned(), json::Value::Null);
    assert!(validation_fee_policy_from_json_value(missing).is_err());
    let mut binding = json::to_value(&validation_fee_payout_binding_fixture()).unwrap();
    binding
        .as_object_mut()
        .unwrap()
        .insert("recipients".to_owned(), json::Value::Array(vec![]));
    assert!(validation_fee_payout_binding_from_json_value(binding, "binding").is_err());
}
#[test]
fn sdk_rejects_invalid_policy_notice_and_custody() {
    for kind in 0..3 {
        let mut policy = validation_fee_policy_fixture();
        match kind {
            0 => policy.notice_published_at_ms += 1,
            1 => policy.treasury_account_id = validation_fee_account(9),
            _ => policy.retail_schedule.overage_minor = 0,
        }
        assert!(
            validation_fee_policy_proposal_fingerprint_v1(
                validation_fee_account(7).to_string(),
                json::to_json(&policy).unwrap(),
            )
            .is_err()
        );
    }
}

#[test]
fn validation_fee_proof_request_uses_complete_original_native_checkpoint() {
    use iroha_data_model::testing::native_finality::NativeFinalityFixture;
    // Genuine native signatures certify synthetic fixture outputs only; no World execution
    // or validation-fee policy authority is claimed by this request-codec test.
    for (expected_height, fixture) in [
        (1_u64, NativeFinalityFixture::start("js-fee-checkpoint")),
        (2, NativeFinalityFixture::new()),
    ] {
        let checkpoint = fixture.checkpoint();
        let bytes = checkpoint
            .encode_canonical()
            .expect("canonical full checkpoint");
        let request =
            validation_fee_current_policy_proof_request_v1(Uint8Array::from(bytes.clone()))
                .expect("full independently selected checkpoint request");
        let decoded: iroha::client::ValidationFeeCurrentPolicyProofRequestV1 =
            norito::decode_canonical(request.as_ref()).expect("sole request layout");
        assert_eq!(
            decoded.version,
            iroha::client::VALIDATION_FEE_POLICY_PROOF_VERSION_V1
        );
        assert_eq!(decoded.trusted_checkpoint_height, expected_height);
        assert_eq!(validation_fee_checkpoint(&bytes).unwrap(), checkpoint);
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(validation_fee_current_policy_proof_request_v1(Uint8Array::from(suffix)).is_err());
        assert!(validation_fee_checkpoint(&bytes[..bytes.len() - 1]).is_err());
    }
    assert!(validation_fee_current_policy_proof_request_v1(Uint8Array::from(vec![1; 32])).is_err());
    assert!(validation_fee_checkpoint(&[]).is_err());
}

#[test]
fn validation_fee_native_verifier_rejects_scalar_checkpoint_and_malformed_proof() {
    use iroha_data_model::testing::native_finality::NativeFinalityFixture;
    let fixture = NativeFinalityFixture::new();
    let checkpoint = fixture.checkpoint().encode_canonical().unwrap();
    for anchor in [vec![1; 32], checkpoint] {
        let result = validation_fee_verify_current_policy_proof_v1(
            Uint8Array::from(vec![1]),
            Uint8Array::from(fixture.network_id().as_bytes().to_vec()),
            Uint8Array::from(vec![0x35; 32]),
            Uint8Array::from(anchor),
            753.0,
        );
        assert!(
            result.is_err(),
            "no projected policy or promoted authority from malformed input"
        );
    }
}
