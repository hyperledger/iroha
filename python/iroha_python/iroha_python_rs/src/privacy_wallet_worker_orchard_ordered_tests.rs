/// Closed public request and custody-order regressions for ordered Orchard execution.
mod orchard_ordered {
    use super::*;
    use iroha_data_model::{
        smart_contract::{
            ContractAddress,
            entrypoint::{
                EntrypointArgumentFieldV1, EntrypointArgumentRecordV1, EntrypointArgumentSchemaV1,
                EntrypointValueAtomV1, EntrypointValueKindV1, EntrypointValueTypeNodeV1,
                EntrypointValueTypeV1, entrypoint_argument_schema_hash_v1,
            },
        },
        transaction::executable::{ContractArgumentRecord, ContractInvocation},
    };
    use iroha_model_base::topology::DataSpaceId;
    use norito::json::Value;

    const ORCHARD: &str = "orchard-halo2-actions-v1";
    const OPERATION: &str = "orchard_note_action_v1";

    fn canonical(value: &Value) -> Vec<u8> {
        norito::json::to_json(value).unwrap().into_bytes()
    }
    fn arguments(enabled: bool) -> ContractArgumentRecord {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "enabled".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)],
                },
            }],
        };
        let schema_bytes = ivm::codec::encode_canonical_norito(&schema).unwrap();
        let record = EntrypointArgumentRecordV1 {
            schema_hash: entrypoint_argument_schema_hash_v1(&schema_bytes),
            atoms: vec![EntrypointValueAtomV1::Bool(enabled)],
        };
        ContractArgumentRecord::try_new(ivm::codec::encode_canonical_norito(&record).unwrap())
            .unwrap()
    }
    fn calls() -> Value {
        let (_, _, authority) = test_signer();
        let call = |name: &str, nonce| {
            norito::json::to_value(&ContractInvocation {
                contract_address: ContractAddress::derive(
                    &network_id_from_genesis_hash_bytes([1; 32]),
                    &authority,
                    nonce,
                    DataSpaceId::UNIVERSAL,
                )
                .unwrap(),
                expected_code_hash: Hash::new(name.as_bytes()),
                entrypoint: name.to_owned(),
                arguments: Some(arguments(true)),
            })
            .unwrap()
        };
        let mut value =
            norito::json::parse_value(r#"{"after":[],"before":[],"schema_version":1}"#).unwrap();
        let object = value.as_object_mut().unwrap();
        object.insert(
            "before".into(),
            Value::Array(vec![call("open", 1), call("record", 2)]),
        );
        object.insert(
            "after".into(),
            Value::Array(vec![call("count", 3), call("close", 4)]),
        );
        value
    }
    fn intent(ordered: bool) -> Value {
        let mut value =
            norito::json::parse_value(std::str::from_utf8(CANONICAL_JINDO_PUBLIC_INTENT).unwrap())
                .unwrap();
        let object = value.as_object_mut().unwrap();
        for field in ["algorithm_id", "protocol_id"] {
            object.insert(field.into(), Value::String(ORCHARD.into()));
        }
        object.insert("operation_schema".into(), Value::String(OPERATION.into()));
        // Import inspects custody metadata only. This intentionally invalid witness/public action
        // cannot produce an accepted proof; all rejection tests must stop before decoding it.
        object.insert(
            "public_action".into(),
            norito::json::parse_value(r#"{"negative_fixture":true}"#).unwrap(),
        );
        for field in ["selected_features", "selected_criteria"] {
            let flags = object.get_mut(field).unwrap().as_object_mut().unwrap();
            for bit in ["hide_amount", "hide_sender", "hide_receiver"] {
                flags.insert(bit.into(), Value::Bool(true));
            }
        }
        if ordered {
            object.insert("orchard_contract_calls".into(), calls());
        }
        value
    }
    fn plan(public: &Value) -> Value {
        let mut value =
            norito::json::parse_value(std::str::from_utf8(&canonical_execution_plan()).unwrap())
                .unwrap();
        let object = value.as_object_mut().unwrap();
        object.insert("protocol_id".into(), Value::String(ORCHARD.into()));
        object.insert("operation_schema".into(), Value::String(OPERATION.into()));
        object.insert(
            "public_action".into(),
            public.as_object().unwrap()["public_action"].clone(),
        );
        if let Some(calls) = public.as_object().unwrap().get("orchard_contract_calls") {
            object.insert("orchard_contract_calls".into(), calls.clone());
        }
        value
    }
    fn imported(public: &Value) -> (WitnessVault, WitnessLease, WitnessBinding) {
        let mut bound = binding();
        bound.protocol = ORCHARD.into();
        bound.public_intent_digest = canonical_public_intent_digest(&canonical(public));
        let (_, _, authority) = test_signer();
        let mut bundle = Vec::new();
        bundle.extend_from_slice(b"IPWB");
        bundle.push(1);
        put_text(&mut bundle, &bound.signer);
        put_text(&mut bundle, &authority.to_string());
        put_text(&mut bundle, ORCHARD);
        put_text(&mut bundle, OPERATION);
        put_bytes_u32(
            &mut bundle,
            &canonical(&public.as_object().unwrap()["public_action"]),
        )
        .unwrap();
        bundle.extend_from_slice(&TEST_SIGNER_SEED);
        put_bytes_u32(&mut bundle, b"{}").unwrap();
        let directory = TempDir::new().unwrap();
        let path = credential_file(&directory, "negative-native-bundle", &bundle);
        let mut vault = WitnessVault::default();
        let lease = vault
            .import_credential(ImportRequest {
                credential_path: path,
                binding: bound.clone(),
                ttl_millis: 120_000,
            })
            .unwrap();
        (vault, lease, bound)
    }
    fn refused(
        vault: &mut WitnessVault,
        lease: &WitnessLease,
        original: &WitnessBinding,
        requested: &WitnessBinding,
        public: &Value,
        plan: &Value,
        expected: WorkerError,
    ) {
        let payload = encode_execute_payload(
            lease.handle,
            requested,
            &canonical(public),
            &canonical(plan),
        )
        .unwrap();
        assert!(
            matches!(dispatch(vault, CommandKind::Execute, &payload), CommandResponse::Error(error) if error == expected)
        );
        assert!(
            vault.inspect(lease.handle, original).is_ok(),
            "rejected public input consumed native custody"
        );
    }
    #[test]
    fn ordered_worker_rejects_changed_prefix_suffix_and_preserves_custody() {
        let public = intent(true);
        let valid_plan = plan(&public);
        let (mut vault, lease, bound) = imported(&public);
        let approved = validate_canonical_public_intent(&canonical(&public), &bound).unwrap();
        assert!(
            validate_execution_plan_v1(&canonical(&valid_plan), &bound, &lease.manifest, &approved)
                .unwrap()
                .orchard_contract_calls
                .is_some()
        );
        for side in ["before", "after"] {
            for field in [
                "entrypoint",
                "expected_code_hash",
                "contract_address",
                "arguments",
            ] {
                let mut changed = valid_plan.clone();
                let call = changed
                    .as_object_mut()
                    .unwrap()
                    .get_mut("orchard_contract_calls")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut(side)
                    .unwrap()
                    .as_array_mut()
                    .unwrap()[0]
                    .as_object_mut()
                    .unwrap();
                let replacement = match field {
                    "entrypoint" => Value::String("changed".into()),
                    "expected_code_hash" => norito::json::to_value(&Hash::new(b"changed")).unwrap(),
                    "contract_address" => calls().as_object().unwrap()["after"].as_array().unwrap()
                        [1]
                    .as_object()
                    .unwrap()["contract_address"]
                        .clone(),
                    _ => norito::json::to_value(&arguments(false)).unwrap(),
                };
                call.insert(field.into(), replacement);
                refused(
                    &mut vault,
                    &lease,
                    &bound,
                    &bound,
                    &public,
                    &changed,
                    WorkerError::WrongBinding,
                );
            }
            let mut reordered = valid_plan.clone();
            reordered
                .as_object_mut()
                .unwrap()
                .get_mut("orchard_contract_calls")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .get_mut(side)
                .unwrap()
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
            refused(
                &mut vault,
                &lease,
                &bound,
                &bound,
                &public,
                &reordered,
                WorkerError::WrongBinding,
            );
        }
    }
    #[test]
    fn ordered_worker_cannot_strip_add_or_reapprove_calls_for_an_existing_handle() {
        for ordered in [true, false] {
            let public = intent(ordered);
            let mut changed_plan = plan(&public);
            let (mut vault, lease, bound) = imported(&public);
            let approved = validate_canonical_public_intent(&canonical(&public), &bound).unwrap();
            assert_eq!(
                validate_execution_plan_v1(
                    &canonical(&changed_plan),
                    &bound,
                    &lease.manifest,
                    &approved
                )
                .unwrap()
                .orchard_contract_calls
                .is_some(),
                ordered
            );
            if ordered {
                changed_plan
                    .as_object_mut()
                    .unwrap()
                    .remove("orchard_contract_calls");
            } else {
                changed_plan
                    .as_object_mut()
                    .unwrap()
                    .insert("orchard_contract_calls".into(), calls());
            }
            refused(
                &mut vault,
                &lease,
                &bound,
                &bound,
                &public,
                &changed_plan,
                WorkerError::WrongBinding,
            );
        }
        let public = intent(true);
        let valid_plan = plan(&public);
        let (mut vault, lease, bound) = imported(&public);
        for remove in [false, true] {
            let mut changed_public = public.clone();
            if remove {
                changed_public
                    .as_object_mut()
                    .unwrap()
                    .remove("orchard_contract_calls");
            } else {
                changed_public
                    .as_object_mut()
                    .unwrap()
                    .get_mut("orchard_contract_calls")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("before")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .swap(0, 1);
            }
            refused(
                &mut vault,
                &lease,
                &bound,
                &bound,
                &changed_public,
                &valid_plan,
                WorkerError::PublicIntentDigestMismatch,
            );
            let mut changed_binding = bound.clone();
            changed_binding.public_intent_digest =
                canonical_public_intent_digest(&canonical(&changed_public));
            refused(
                &mut vault,
                &lease,
                &bound,
                &changed_binding,
                &changed_public,
                &valid_plan,
                WorkerError::WrongBinding,
            );
        }
    }
    #[test]
    fn ordered_worker_rejects_other_protocols_without_consuming() {
        let directory = TempDir::new().unwrap();
        let path = execution_bundle_file(&directory, "valid-jindo", JINDO_WITNESS);
        let mut vault = WitnessVault::default();
        let lease = import_now(&mut vault, &path);
        let public =
            norito::json::parse_value(std::str::from_utf8(CANONICAL_JINDO_PUBLIC_INTENT).unwrap())
                .unwrap();
        let mut plan =
            norito::json::parse_value(std::str::from_utf8(&canonical_execution_plan()).unwrap())
                .unwrap();
        plan.as_object_mut()
            .unwrap()
            .insert("orchard_contract_calls".into(), calls());
        refused(
            &mut vault,
            &lease,
            &binding(),
            &binding(),
            &public,
            &plan,
            WorkerError::InvalidExecutionPlan,
        );
        let mut wrong_public = public.clone();
        wrong_public
            .as_object_mut()
            .unwrap()
            .insert("orchard_contract_calls".into(), calls());
        let mut wrong_binding = binding();
        wrong_binding.public_intent_digest =
            canonical_public_intent_digest(&canonical(&wrong_public));
        refused(
            &mut vault,
            &lease,
            &binding(),
            &wrong_binding,
            &wrong_public,
            &plan,
            WorkerError::InvalidPublicIntent,
        );
    }
    #[test]
    fn ordered_worker_request_shape_is_closed_and_null_is_not_standalone() {
        for mutation in 0..8 {
            let mut value = calls();
            match mutation {
                0 => value = Value::Null,
                1 => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("extra".into(), Value::Bool(true));
                }
                2 => {
                    value.as_object_mut().unwrap().remove("before");
                }
                3 => {
                    value.as_object_mut().unwrap().insert(
                        "schema_version".into(),
                        norito::json::parse_value("2").unwrap(),
                    );
                }
                4 => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("after".into(), Value::Array(Vec::new()));
                }
                5 => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .get_mut("before")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()[0]
                        .as_object_mut()
                        .unwrap()
                        .insert("instruction".into(), Value::Null);
                }
                6 => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .get_mut("after")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()[0]
                        .as_object_mut()
                        .unwrap()
                        .remove("arguments");
                }
                _ => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .get_mut("before")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()[0]
                        .as_object_mut()
                        .unwrap()
                        .insert("entrypoint".into(), Value::Bool(true));
                }
            }
            assert!(matches!(
                validate_orchard_contract_calls_v1(
                    Some(&value),
                    ORCHARD,
                    WorkerError::InvalidPublicIntent
                ),
                Err(WorkerError::InvalidPublicIntent)
            ));
        }
        assert!(
            validate_orchard_contract_calls_v1(None, ORCHARD, WorkerError::InvalidPublicIntent)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn ordered_worker_limits_and_time_types_are_checked_before_consumption() {
        let public = intent(true);
        let valid_plan = plan(&public);
        let (mut vault, lease, bound) = imported(&public);
        let mut oversized = valid_plan.clone();
        oversized.as_object_mut().unwrap().get_mut("transaction_metadata").unwrap().as_object_mut().unwrap().insert("padding".into(), Value::String("x".repeat(crate::privacy_native_actions::PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1)));
        assert!(canonical(&oversized).len() < MAX_CANONICAL_EXECUTION_PLAN_BYTES);
        refused(
            &mut vault,
            &lease,
            &bound,
            &bound,
            &public,
            &oversized,
            WorkerError::InvalidExecutionPlan,
        );
        for field in ["creation_time_ms", "ttl_ms"] {
            let mut fractional = valid_plan.clone();
            fractional
                .as_object_mut()
                .unwrap()
                .insert(field.into(), norito::json::parse_value("1.5").unwrap());
            refused(
                &mut vault,
                &lease,
                &bound,
                &bound,
                &public,
                &fractional,
                WorkerError::InvalidExecutionPlan,
            );
        }
        let limit = usize::try_from(
            iroha_data_model::parameter::TransactionParameters::default()
                .max_instructions()
                .get(),
        )
        .unwrap();
        let mut too_many = calls();
        let mut one = too_many.as_object().unwrap()["before"].as_array().unwrap()[0].clone();
        one.as_object_mut()
            .unwrap()
            .insert("arguments".into(), Value::Null);
        too_many
            .as_object_mut()
            .unwrap()
            .insert("before".into(), Value::Array(vec![one.clone(); limit / 2]));
        too_many
            .as_object_mut()
            .unwrap()
            .insert("after".into(), Value::Array(vec![one; limit - limit / 2]));
        assert!(
            matches!(
                validate_orchard_contract_calls_v1(
                    Some(&too_many),
                    ORCHARD,
                    WorkerError::InvalidExecutionPlan
                ),
                Err(WorkerError::InvalidExecutionPlan)
            ),
            "count includes the one direct Submit"
        );
    }
    #[test]
    fn ordered_worker_response_checks_both_real_native_wires() {
        use crate::privacy_native_actions::OrchardNoteActionRequestV1;
        use iroha_core_privacy::privacy_engines::orchard::{
            OrchardChangeProverInputV1, Scope, SpendingKey, orchard_empty_root_v1,
        };
        use iroha_data_model::{
            asset::{AssetBalanceScope, AssetDefinitionId},
            privacy::{PrivacyPoolIdV1, PrivacyRootV1},
        };
        use iroha_model_base::domain::DomainId;
        use std::time::Duration;

        let (key, public_key, authority) = test_signer();
        let context = PrivacyActionTransactionContextV1 {
            network_id: network_id_from_genesis_hash_bytes([1; 32]),
            authority: authority.clone(),
            creation_time: Duration::from_millis(NOW),
            time_to_live: Some(Duration::from_secs(120)),
            nonce: NonZeroU32::new(7),
            fee_payment: FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(1_000_000),
            ),
            metadata: Metadata::default(),
        };
        let calls_json = calls();
        let expected_calls = validate_orchard_contract_calls_v1(
            Some(&calls_json),
            ORCHARD,
            WorkerError::InvalidExecutionPlan,
        )
        .unwrap()
        .unwrap();
        let spending_key = (1_u8..=u8::MAX)
            .find_map(|counter| {
                let mut bytes = [0x71; 32];
                bytes[0] = counter;
                Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            })
            .unwrap();
        let request = OrchardNoteActionRequestV1 {
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").unwrap(),
                "worker_wire_fixture".parse().unwrap(),
            ),
            public_balance_scope: AssetBalanceScope::Global,
            pool_id: PrivacyPoolIdV1::new([0x72; 32]),
            anchor: PrivacyRootV1::new(orchard_empty_root_v1()),
            anchor_epoch: 1,
            expiry_height: 100,
            spends: Vec::new(),
            changes: vec![OrchardChangeProverInputV1::new(
                spending_key,
                Scope::External,
                1,
                17,
                [0x73; 512],
            )],
            minimum_action_count: 1,
        };
        // A real producer/self-verifier exercises the response boundary. This is not an
        // opaque-handle spend or funded-chain fixture and makes no such qualification claim.
        let signed = build_signed_orchard_note_action_with_contract_calls_v1(
            context.clone(),
            request,
            expected_calls.clone(),
            [1; 32],
            &key,
        )
        .unwrap();
        let manifest = PrivacyWalletExecutionBundleManifestV1 {
            schema_version: 1,
            wallet_id: "alice@wonderland".into(),
            authority,
            public_key,
            protocol_id: PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            operation_schema: OPERATION,
        };
        let mut response = signed_action_response_v1(signed, &manifest, [1; 32]).unwrap();
        inspect_ordered_response_v1(&response, &context, &expected_calls).unwrap();
        let mut changed = calls_json;
        changed
            .as_object_mut()
            .unwrap()
            .get_mut("after")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        let changed = validate_orchard_contract_calls_v1(
            Some(&changed),
            ORCHARD,
            WorkerError::InvalidExecutionPlan,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            inspect_ordered_response_v1(&response, &context, &changed),
            Err(WorkerError::NativeSelfInspectionFailed)
        ));
        response.versioned_signed_transaction[0] ^= 1;
        assert!(inspect_ordered_response_v1(&response, &context, &expected_calls).is_err());
        response.versioned_signed_transaction[0] ^= 1;
        response.adaptive_signed_transaction[0] ^= 1;
        assert!(inspect_ordered_response_v1(&response, &context, &expected_calls).is_err());
        response.adaptive_signed_transaction[0] ^= 1;
        response.transaction_hash[0] ^= 1;
        assert!(inspect_ordered_response_v1(&response, &context, &expected_calls).is_err());
    }
}
