#[test]
fn successful_claim_fee_exempt_draft_returns_zero_quote_in_direct_mode() {
    let (world, mut nexus, pipeline, mut payload) = multi_component_fee_quote_fixture();
    let fee_asset = AssetDefinitionId::parse_address_literal(&nexus.fees.fee_asset_id)
        .expect("fixture fee asset address");
    payload.fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset.clone(),
            Quantity::from(9_u32),
        )],
        None,
    );
    let authority_literal = payload.authority.to_string();
    nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .insert(payload.authority.clone());
    nexus.fees.settlement_mode = iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
    payload.metadata.insert(
        SORA_V2_CLAIM_TX_HASH_METADATA_KEY
            .parse()
            .expect("claim hash metadata key"),
        Json::new("ab".repeat(32)),
    );
    payload.metadata.insert(
        SORA_NEXUS_CLAIM_RECIPIENT_METADATA_KEY
            .parse()
            .expect("claim recipient metadata key"),
        Json::new(authority_literal),
    );
    payload.instructions = vec![InstructionBox::from(Mint::asset_quantity(
        1_u32,
        AssetId::new(fee_asset, payload.authority.clone()),
    ))]
    .into();
    assert_direct_fee_exempt_draft(world, &nexus, &pipeline, payload);
}
#[test]
fn successful_claim_fee_exemption_uses_exact_account_identity() {
    let (_, mut nexus, _, payload) = multi_component_fee_quote_fixture();
    let authority = payload.authority;
    let (other_authority, _) = gen_account_in("fee_quote_other");
    assert!(!successful_claim_fee_authority_allowed(&nexus, &authority));
    nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .insert(authority.clone());
    assert!(successful_claim_fee_authority_allowed(&nexus, &authority));
    assert!(!successful_claim_fee_authority_allowed(
        &nexus,
        &other_authority
    ));
}

fn original_claim_fee_payload(
    authority: AccountId,
    asset: AssetDefinitionId,
    recipient_literal: String,
    recipient: AccountId,
) -> TransactionPayload {
    let mut payload = TransactionBuilder::new(
        executor_test_network_id(b"original-claim-fee"),
        authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Mint::asset_quantity(1_u32, AssetId::new(asset, recipient))])
    .into_payload()
    .unwrap();
    payload.metadata.insert(
        SORA_V2_CLAIM_TX_HASH_METADATA_KEY.parse().unwrap(),
        Json::new("ab".repeat(32)),
    );
    payload.metadata.insert(
        SORA_NEXUS_CLAIM_RECIPIENT_METADATA_KEY.parse().unwrap(),
        Json::new(recipient_literal),
    );
    payload
}

#[test]
fn original_claim_metadata_refusal_defers_fee_quote_and_retries_exact_payload() {
    use crate::execution_attempt::ExecutionAttemptError;
    let (world, authority, _, _, _) = sns_permission_original_world();
    let world = component_world_for_testing(world);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(2_u32);
    let pipeline = Pipeline::default();
    let asset = AssetDefinitionId::parse_address_literal(&nexus.fees.fee_asset_id).unwrap();
    let payload = original_claim_fee_payload(
        authority.clone(),
        asset,
        authority.to_string(),
        authority.clone(),
    );
    nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .insert(authority);
    let original = payload.clone();
    let quote = || {
        quote_nexus_fee_admission_draft(
            &world.view(),
            &nexus,
            &pipeline,
            &crate::gas::DEFAULT_ZK_GAS,
            &payload,
            50,
            2,
            Some(DataSpaceId::UNIVERSAL),
        )
    };
    assert!(quote().unwrap().quote.charges.is_empty());
    // Probe the original claim reader directly as well as its complete fee-quote caller.
    // Otherwise an earlier root-scope decode refusal could mask an erased claim refusal.
    let original_reader = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
        || successful_claim_fee_exempt_payload(&world.view(), &nexus, &payload, 50).unwrap_err(),
    );
    assert_eq!(
        original_reader.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
        || quote().unwrap_err(),
    );
    assert!(
        matches!(error, ExecutionAttemptError::Deferred(ref reason)
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "original claim metadata refusal became a completed fee verdict: {error:?}"
    );
    assert_eq!(payload, original);
    assert!(quote().unwrap().quote.charges.is_empty());
}

#[test]
fn original_claim_alias_refusal_after_metadata_defers_fee_quote_and_retries() {
    use crate::execution_attempt::ExecutionAttemptError;
    let (world, authority, recipient, record_key, record_bytes) = sns_permission_original_world();
    let world = component_world_for_testing(world);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .insert(authority.clone());
    let asset = AssetDefinitionId::parse_address_literal(&nexus.fees.fee_asset_id).unwrap();
    let payload =
        original_claim_fee_payload(authority, asset, "customer@fi.universal".into(), recipient);
    let original = payload.clone();
    let pipeline = Pipeline::default();
    let quote = || {
        quote_nexus_fee_admission_draft(
            &world.view(),
            &nexus,
            &pipeline,
            &crate::gas::DEFAULT_ZK_GAS,
            &payload,
            50,
            2,
            Some(DataSpaceId::UNIVERSAL),
        )
    };
    assert!(quote().unwrap().quote.charges.is_empty());
    // Measure both real call prefixes. The direct claim reader consumes the two
    // metadata strings; its fee-quote caller first consumes the immutable root scope.
    let prefix_fits = |limit, include_root| {
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 32),
            || {
                if include_root && !private_fees::permits_public_exemption(&world.view())? {
                    return Ok(false);
                }
                metadata_string(&payload.metadata, SORA_V2_CLAIM_TX_HASH_METADATA_KEY).and_then(
                    |hash| {
                        metadata_string(&payload.metadata, SORA_NEXUS_CLAIM_RECIPIENT_METADATA_KEY)
                            .map(|recipient| hash.is_some() && recipient.is_some())
                    },
                )
            },
        )
    };
    let minimum_prefix = |include_root| {
        let (mut lower, mut upper) = (0, 65_536);
        assert_eq!(prefix_fits(upper, include_root), Ok(true));
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            if prefix_fits(middle, include_root) == Ok(true) {
                upper = middle;
            } else {
                lower = middle + 1;
            }
        }
        assert_eq!(prefix_fits(lower, include_root), Ok(true));
        lower
    };
    let metadata_prefix = minimum_prefix(false);
    let original_reader = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, metadata_prefix, 32),
        || successful_claim_fee_exempt_payload(&world.view(), &nexus, &payload, 50).unwrap_err(),
    );
    assert_eq!(
        original_reader.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let quote_prefix = minimum_prefix(true);
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, quote_prefix, 32),
        || quote().unwrap_err(),
    );
    assert!(
        matches!(error, ExecutionAttemptError::Deferred(ref reason)
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "original SNS read refusal became a completed fee verdict: {error:?}"
    );
    assert_eq!(
        world.smart_contract_state.view().get(&record_key),
        Some(&record_bytes)
    );
    assert_eq!(payload, original);
    assert!(quote().unwrap().quote.charges.is_empty());
}

#[test]
fn claim_metadata_absence_malformed_and_empty_values_remain_completed() {
    let mut metadata = Metadata::default();
    assert_eq!(metadata_string(&metadata, "claim").unwrap(), None);
    for raw in [Json::new(7_u32), Json::new(" \n\t "), Json::new(false)] {
        metadata.insert("claim".parse().unwrap(), raw);
        assert_eq!(metadata_string(&metadata, "claim").unwrap(), None);
    }
    metadata.insert("claim".parse().unwrap(), Json::new("  exact original  "));
    assert_eq!(
        metadata_string(&metadata, "claim").unwrap(),
        Some("exact original".into())
    );
}

#[test]
fn original_claim_fee_admission_latches_refusal_before_debit_and_publication() {
    let authority = ALICE_ID.clone();
    let fee_asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    let mut world = World::with_assets(
        [],
        [Account::new(authority.clone()).build(&authority)],
        [AssetDefinition::numeric(
            fee_asset.clone(),
            "network XOR",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority)],
        [Asset::new(
            AssetId::new(fee_asset.clone(), authority.clone()),
            Quantity::from(100_u32),
        )],
        [],
    );
    seed_test_asset_supply(&mut world, &fee_asset);
    let state = state_after_genesis(world);
    let mut payload = original_claim_fee_payload(
        authority.clone(),
        fee_asset.clone(),
        authority.to_string(),
        authority.clone(),
    );
    payload.domain = iroha_data_model::transaction::TransactionDomain::Network(state.network_id);
    let transaction = TransactionBuilder::from_payload(payload)
        .unwrap()
        .sign(ALICE_KEYPAIR.private_key());
    let mut block = state.block(BlockHeader::new(
        nonzero!(2_u64),
        Some(state.view().latest_block_hash().unwrap()),
        None,
        50,
        0,
    ));
    block
        .nexus
        .fees
        .successful_claim_fee_exempt_authorities
        .insert(authority.clone());
    let payer = AssetId::new(fee_asset, authority.clone());
    let marker = DomainId::try_new("refused_claim", "universal").unwrap();
    {
        let mut attempt = block.transaction();
        assert!(!is_initial_genesis_context(&attempt));
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || validate_transaction_fee_admission(&mut attempt, &transaction).unwrap_err(),
        );
        assert!(matches!(error, ValidationFail::InternalError(_)));
        assert_eq!(
            attempt.execution_deferral().unwrap().reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert_eq!(
            attempt.world.assets().get(&payer).unwrap().as_ref(),
            &Quantity::from(100_u32)
        );
        // Even an erroneous later apply must abandon semantic writes under the sticky refusal.
        attempt.world.domains.insert(
            marker.clone(),
            Domain::new(marker.clone()).build(&authority),
        );
        attempt.apply();
    }
    assert!(block.world.domains.get(&marker).is_none());
    assert_eq!(
        block.world.assets().get(&payer).unwrap().as_ref(),
        &Quantity::from(100_u32)
    );
    let mut retry = block.transaction();
    validate_transaction_fee_admission(&mut retry, &transaction).unwrap();
    assert!(retry.execution_deferral().is_none());
    assert_eq!(
        retry.world.assets().get(&payer).unwrap().as_ref(),
        &Quantity::from(100_u32)
    );
}

#[test]
fn original_network_xor_pin_refusal_defers_quote_and_retries_same_parameter() {
    use crate::execution_attempt::ExecutionAttemptError;
    let (world, nexus, pipeline, payload) = multi_component_fee_quote_fixture();
    let parameter_id = iroha_data_model::parameter::system::SumeragiNposParameters::parameter_id();
    let original = world
        .view()
        .parameters()
        .custom()
        .get(&parameter_id)
        .unwrap()
        .payload()
        .clone();
    let quote = || {
        quote_nexus_fee_admission_draft(
            &world.view(),
            &nexus,
            &pipeline,
            &crate::gas::DEFAULT_ZK_GAS,
            &payload,
            50,
            2,
            Some(DataSpaceId::UNIVERSAL),
        )
    };
    let expected = quote().unwrap();
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
        || quote().unwrap_err(),
    );
    assert!(
        matches!(refused, ExecutionAttemptError::Deferred(ref reason)
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "{refused:?}"
    );
    assert_eq!(
        world
            .view()
            .parameters()
            .custom()
            .get(&parameter_id)
            .unwrap()
            .payload(),
        &original
    );
    assert_eq!(quote().unwrap(), expected);
}

#[test]
fn fee_quote_discovers_pipeline_gas_and_matches_strict_signed_payload_quote() {
    let (world, nexus, pipeline, mut payload) = multi_component_fee_quote_fixture();
    let world = world.block();
    let draft = quote_nexus_fee_admission_draft(
        &world,
        &nexus,
        &pipeline,
        &crate::gas::DEFAULT_ZK_GAS,
        &payload,
        0,
        1,
        Some(DataSpaceId::UNIVERSAL),
    )
    .expect("draft quote");
    assert_eq!(
        draft
            .quote
            .charges
            .iter()
            .map(|charge| charge.kind)
            .collect::<Vec<_>>(),
        vec![FeeChargeKind::Nexus, FeeChargeKind::PipelineGas]
    );
    payload.fee_payment = draft.recommended_intent.clone();
    let strict = quote_nexus_fee_admission_payload(
        &world,
        &nexus,
        &pipeline,
        &crate::gas::DEFAULT_ZK_GAS,
        &payload,
        0,
        1,
        Some(DataSpaceId::UNIVERSAL),
    )
    .expect("strict quote for exact recommended intent");
    assert_eq!(strict, draft.quote);
    assert_eq!(strict.authority_balances.len(), 2);
    assert_eq!(strict.authority_charge_assets.len(), 2);
}
/// The fee bound and the fee quote of a proof-bearing transaction follow the verification
/// gas schedule of the committed ZK validity policy the quoting view holds: not the protocol
/// default, and not a schedule the node installed.
#[test]
fn fee_quote_prices_a_proof_instruction_with_the_committed_gas_schedule() {
    use iroha_data_model::{
        isi::zk::VerifyProof,
        parameter::Parameter,
        proof::{ProofAttachment, VerifyingKeyId},
        zk_validity_policy::ZkValidityPolicyV1,
    };
    let (world, nexus, pipeline, log_payload) = multi_component_fee_quote_fixture();
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.gas.proof_base += 19;
    policy.gas.per_proof_byte += 2;
    policy
        .validate()
        .expect("a policy that differs in gas is valid");
    {
        let mut parameters = world.parameters.block();
        parameters.set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()));
        parameters.commit();
    }
    let fixture = crate::zk::test_utils::halo2_fixture_envelope("halo2/ipa:fee-quote", [0u8; 32]);
    let proof_box = fixture.proof_box("halo2/ipa");
    let attachment = ProofAttachment::new_ref(
        proof_box.backend.clone(),
        proof_box,
        VerifyingKeyId::new("halo2/ipa", "vk-fee-quote"),
    );
    let proof_bytes = attachment.proof.bytes.len() as u64;
    let delta = 19 + 2 * proof_bytes;
    let payload = TransactionBuilder::new(
        executor_test_network_id(b"fee-quote"),
        log_payload.authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([VerifyProof::new(attachment)])
    .into_payload()
    .expect("canonical unsigned payload");

    let mut state = crate::state::State::new_for_testing(
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    // A node that installed another schedule: the view must not expose it.
    let mut divergent = crate::state::default_zk_config();
    divergent.gas.proof_base = 1;
    divergent.gas.per_proof_byte = 1_000;
    state
        .install_node_zk(divergent)
        .expect("node ZK resources install");
    let view = state.view();
    let committed = view.zk.gas;
    assert_eq!(committed.proof_base, policy.gas.proof_base);
    assert_eq!(committed.per_proof_byte, policy.gas.per_proof_byte);

    // The fee bound meters the instructions with the schedule it is given.
    let (_, count, gas_committed) =
        fee_bound_for_admission_payload(&payload, &committed).expect("bound under the policy");
    let (_, _, gas_default) =
        fee_bound_for_admission_payload(&payload, &crate::gas::DEFAULT_ZK_GAS)
            .expect("bound under the default");
    assert_eq!(count, 1);
    assert_eq!(gas_committed - gas_default, delta);

    // The quote charges pipeline gas at three units per gas unit (the fixture rate).
    let pipeline_gas_bound = |zk_gas: &ConfidentialGas| {
        let draft = quote_nexus_fee_admission_draft(
            view.world(),
            &nexus,
            &pipeline,
            zk_gas,
            &payload,
            0,
            1,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect("draft quote");
        draft
            .quote
            .charges
            .iter()
            .find(|charge| charge.kind == FeeChargeKind::PipelineGas)
            .expect("the fixture charges pipeline gas")
            .max_bound
            .clone()
    };
    assert_eq!(
        pipeline_gas_bound(&committed),
        Quantity::from(u128::from(gas_committed) * 3)
    );
    assert_eq!(
        pipeline_gas_bound(&crate::gas::DEFAULT_ZK_GAS),
        Quantity::from(u128::from(gas_default) * 3)
    );
    assert_ne!(
        pipeline_gas_bound(&committed),
        pipeline_gas_bound(&crate::gas::DEFAULT_ZK_GAS)
    );
}
