// Native intent/journal controls. Projection fixtures below test persistence only;
// certified carrier authentication is exercised by the HTTP/runtime integration controls.

fn native_journal_fixture() -> (
    TransactionPayload,
    IsoMessageContext,
    iroha_data_model::isi::SettleAtomic,
) {
    let (runtime, _reference) = payment_runtime_with_bic_reference(sample_config());
    let parsed = PaymentRail::CustomerCreditTransfer.message(
        "10",
        "USD",
        "GB82WEST12345698765432",
        "DEUTDEFF",
        "",
    );
    let world = sample_world(None);
    let (payload, context) = PaymentRail::CustomerCreditTransfer
        .build(
            &runtime,
            &parsed,
            &world.view(),
            &"native-test".parse().unwrap(),
            &MaybeTelemetry::for_tests(),
        )
        .unwrap();
    let intent = context.native_payment.as_ref().unwrap().intent().unwrap();
    (payload, context, intent)
}

fn native_projection_fixture(
    runtime: &Iso20022BridgeRuntime,
    payload: TransactionPayload,
    intent: &iroha_data_model::isi::SettleAtomic,
) -> IsoNativeBusinessSettlement {
    use iroha_data_model::{
        block::BlockHeader,
        isi::project_atomic_payment_receipt_unverified,
        transaction::{TransactionEntrypoint, TransactionResult},
    };
    let transaction = runtime.sign_transaction_payload(payload).unwrap();
    let hash = transaction.hash().to_string();
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        Some(*intent.network_id.as_genesis_hash()),
        None,
        1000,
        0,
    );
    let receipt = project_atomic_payment_receipt_unverified(
        intent.network_id,
        intent,
        &header,
        &TransactionEntrypoint::External(transaction),
        &TransactionResult::new(Ok(Vec::new())),
    )
    .unwrap();
    IsoNativeBusinessSettlement::from_canonical_projection(hash, &receipt, None).unwrap()
}

#[test]
fn native_iso_builder_reuses_payer_uetr_and_exact_terms_across_gateway_envelopes() {
    use iroha_data_model::transaction::Executable;
    let (runtime, _reference) = payment_runtime_with_bic_reference(sample_config());
    let world = sample_world(None);
    let mut intents = Vec::new();
    for rail in [
        PaymentRail::CustomerCreditTransfer,
        PaymentRail::FinancialInstitutionCreditTransfer,
    ] {
        for id in ["gateway-a", "gateway-b"] {
            let parsed = rail.message(
                "10",
                "USD",
                "GB82WEST12345698765432",
                "DEUTDEFF",
                &format!("SplmtryData/LedgerId={id}"),
            );
            let (payload, context) = rail
                .build(
                    &runtime,
                    &parsed,
                    &world.view(),
                    &id.parse().unwrap(),
                    &MaybeTelemetry::for_tests(),
                )
                .unwrap();
            let intent = context.native_payment.unwrap().intent().unwrap();
            assert_eq!(intent.settlement_id.owner(), &sample_account_bundle().0);
            assert_eq!(
                intent.settlement_id.reference().as_ref(),
                "123e4567-e89b-42d3-a456-426614174000"
            );
            assert_eq!(intent.expires_at_height.get(), 100);
            assert!(intent.metadata.iter().next().is_none());
            let Executable::Instructions(instructions) = &payload.instructions else {
                panic!("direct payment")
            };
            let instructions: &[InstructionBox] = instructions.as_ref();
            assert_eq!(instructions.len(), 1);
            let Some(iroha_data_model::isi::SettlementInstructionBox::Atomic(actual)) =
                instructions[0]
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::SettlementInstructionBox>()
            else {
                panic!("canonical native payment instruction")
            };
            assert_eq!(actual, &intent);
            intents.push(intent);
        }
    }
    assert!(intents.windows(2).all(|pair| pair[0] == pair[1]));
    let mut changed = intents[0].clone();
    changed.expires_at_height = std::num::NonZeroU64::new(101).unwrap();
    assert_eq!(changed.settlement_id, intents[0].settlement_id);
    assert_ne!(
        changed.intent_hash().unwrap(),
        intents[0].intent_hash().unwrap()
    );
}

#[test]
fn native_iso_builder_requires_explicit_canonical_terms_and_valid_payer_uetr() {
    let (_, _, intent) = native_journal_fixture();
    let movement = &intent.movements.as_slice()[0];
    let fields = format!(
        "UETR=123e4567-e89b-42d3-a456-426614174000\nNexusSettlement/NetworkId={}\nNexusSettlement/ExpiresAtHeight=100\nNexusSettlement/SourceAccountId={}\nNexusSettlement/TargetAccountId={}\nNexusSettlement/AssetDefinitionId={}",
        intent.network_id,
        movement.source.account(),
        movement.recipient,
        movement.source.definition()
    );
    for invalid in [
        fields.replace("NexusSettlement/ExpiresAtHeight=100", ""),
        fields.replace(
            &format!(
                "NexusSettlement/SourceAccountId={}",
                movement.source.account()
            ),
            "",
        ),
        fields.replace(
            &format!("NexusSettlement/TargetAccountId={}", movement.recipient),
            "",
        ),
        fields.replace(
            &format!(
                "NexusSettlement/AssetDefinitionId={}",
                movement.source.definition()
            ),
            "",
        ),
        fields.replace(
            &format!("SourceAccountId={}", movement.source.account()),
            &format!("SourceAccountId={}", movement.recipient),
        ),
        fields.replace(
            &format!("TargetAccountId={}", movement.recipient),
            &format!("TargetAccountId={}", movement.source.account()),
        ),
        fields.replace(
            &format!("AssetDefinitionId={}", movement.source.definition()),
            "AssetDefinitionId=usd#test",
        ),
        fields.replace("ExpiresAtHeight=100", "ExpiresAtHeight=0100"),
        fields.replace("ExpiresAtHeight=100", "ExpiresAtHeight=0"),
        fields.replace("UETR=123e4567-e89b-42d3-a456-426614174000", "UETR=invalid"),
        fields.replace(
            &format!("NetworkId={}", intent.network_id),
            "NetworkId=invalid",
        ),
    ] {
        let base = format!(
            "MsgId=native\nIntrBkSttlmAmt=10\nIntrBkSttlmCcy=USD\nIntrBkSttlmDt=2024-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nDbtrAgt=DEUTDEFF\nCdtrAgt=DEUTDEFF\n{invalid}"
        );
        // The builder is stricter than the general ISO parser's optional native extension.
        if let Ok(parsed) = parse_message("pacs.008", base.as_bytes()) {
            assert!(
                native_payment::build_native_iso_payment_intent(
                    &parsed,
                    intent.network_id,
                    movement.source.clone(),
                    movement.quantity.clone(),
                    movement.recipient.clone()
                )
                .is_err()
            );
        }
    }
}

#[test]
fn native_iso_signed_terms_refuse_gateway_mapping_drift() {
    for rail in [
        PaymentRail::CustomerCreditTransfer,
        PaymentRail::FinancialInstitutionCreditTransfer,
    ] {
        let parsed = rail.message("10", "USD", "GB82WEST12345698765432", "DEUTDEFF", "");
        let world = sample_world(None);
        let other = AccountId::new(fixture_key_pair(0xAE).public_key().clone());
        for field in ["SourceAccountId", "TargetAccountId", "AssetDefinitionId"] {
            let (mut runtime, _reference) = payment_runtime_with_bic_reference(sample_config());
            match field {
                "SourceAccountId" => {
                    Arc::make_mut(&mut runtime.account_aliases)
                        .insert("GB82WEST12345698765432".into(), other.clone());
                }
                "TargetAccountId" => {
                    Arc::make_mut(&mut runtime.account_aliases)
                        .insert("GB33BUKB20201555555555".into(), other.clone());
                }
                "AssetDefinitionId" => {
                    let other_asset = AssetDefinitionId::derive_from_components(
                        DomainId::try_new("test", "universal").unwrap(),
                        "eur".parse().unwrap(),
                    );
                    Arc::make_mut(&mut runtime.currency_assets)
                        .get_mut("USD")
                        .unwrap()
                        .asset_definition = other_asset.to_string();
                }
                _ => unreachable!(),
            }
            assert!(
                rail.build(
                    &runtime,
                    &parsed,
                    &world.view(),
                    &"test-chain".parse().unwrap(),
                    &MaybeTelemetry::for_tests()
                )
                .is_err(),
                "gateway mapping cannot replace signed {field}"
            );
        }
    }
}

#[test]
fn native_iso_journal_restoration_never_grants_settlement_authority() {
    let store = TempDir::new().unwrap();
    let mut config = sample_config();
    config.store_dir = Some(store.path().to_owned());
    let (runtime, _reference) = payment_runtime_with_bic_reference(config.clone());
    let (payload, context, intent) = native_journal_fixture();
    assert!(runtime.check_and_record_message("native-original"));
    assert!(runtime.update_message_context("native-original", context));
    let attempt = "17".repeat(32);
    assert!(runtime.bind_transaction_hash("native-original", &attempt));
    assert!(
        !runtime.mark_transaction_applied(&attempt, SystemTime::now()),
        "scalar carrier success cannot bypass the native business join"
    );
    let request = runtime.native_payment_requests().unwrap().remove(0);
    let effect = native_projection_fixture(&runtime, payload, &intent);
    let carrier = IsoNativeCarrierOutcome {
        height: 3,
        applied: false,
        rejection: Some("replay of original payment".into()),
    };
    runtime
        .publish_native_payment_projection(
            &request,
            Some(carrier.clone()),
            Some(effect.clone()),
            false,
        )
        .unwrap();
    let status = runtime.message_status("native-original").unwrap();
    assert_eq!(status.pacs002_code(), "ACSC");
    assert_eq!(status.transaction_hash(), Some(attempt.as_str()));
    assert_ne!(effect.transaction_hash, attempt);
    assert_eq!(
        status.native_payment_json()["verified"].as_bool(),
        Some(true)
    );
    let path = store
        .path()
        .join("messages")
        .join(message_filename("native-original"));
    let before = fs::read(&path).unwrap();
    runtime
        .publish_native_payment_projection(
            &request,
            Some(carrier.clone()),
            Some(effect.clone()),
            false,
        )
        .unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "identical canonical observations do not republish"
    );
    assert!(
        runtime
            .publish_native_payment_projection(&request, None, Some(effect.clone()), false)
            .is_err(),
        "missing original attempt proof cannot retain authority"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(runtime);
    let (restored, _reference) = payment_runtime_with_bic_reference(config);
    let status = restored.message_status("native-original").unwrap();
    assert_eq!(status.pacs002_code(), "PDNG");
    assert!(status.settled_at().is_none());
    assert_eq!(
        status.native_payment_json()["verified"].as_bool(),
        Some(false)
    );
    assert!(
        restored
            .publish_native_payment_projection(
                &request,
                Some(carrier.clone()),
                Some(effect.clone()),
                false
            )
            .is_err(),
        "old incarnation cannot publish into a restored journal"
    );
    let recovered = restored.native_payment_requests().unwrap().remove(0);
    restored
        .publish_native_payment_projection(&recovered, Some(carrier), Some(effect), false)
        .unwrap();
    assert_eq!(
        restored
            .message_status("native-original")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
}

#[test]
fn native_iso_journal_refuses_changed_intent_and_disappearing_conflict() {
    let (runtime, _reference) = payment_runtime_with_bic_reference(sample_config());
    let (_, context, _) = native_journal_fixture();
    assert!(runtime.check_and_record_message("native-conflict"));
    assert!(runtime.update_message_context("native-conflict", context.clone()));
    assert!(!runtime.update_message_context("native-conflict", context));
    let request = runtime.native_payment_requests().unwrap().remove(0);
    runtime
        .publish_native_payment_projection(&request, None, None, true)
        .unwrap();
    let before = runtime
        .message_status("native-conflict")
        .unwrap()
        .native_payment_json();
    assert!(
        runtime
            .publish_native_payment_projection(&request, None, None, false)
            .is_err()
    );
    assert_eq!(
        runtime
            .message_status("native-conflict")
            .unwrap()
            .native_payment_json(),
        before
    );
    let value = native_payment_value(
        runtime
            .records
            .get("native-conflict")
            .unwrap()
            .context
            .native_payment
            .as_ref(),
    );
    assert!(native_payment_from_value(&value).flatten().is_some());
    let mut extra = value.clone();
    extra
        .as_object_mut()
        .unwrap()
        .insert("verified".into(), JsonValue::from(true));
    assert!(
        native_payment_from_value(&extra).is_none(),
        "persisted self-asserted authority is not a supported field"
    );
}
