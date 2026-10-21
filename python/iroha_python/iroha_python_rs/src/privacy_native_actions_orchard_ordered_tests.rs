/// Real native producers bind fixed calls and transaction context before authorization.
mod orchard_ordered {
    use super::*;
    use iroha_core_privacy::privacy_engines::orchard::{Scope, SpendingKey, orchard_empty_root_v1};
    use iroha_data_model::{
        smart_contract::{
            ContractAddress,
            entrypoint::{
                EntrypointArgumentFieldV1, EntrypointArgumentRecordV1, EntrypointArgumentSchemaV1,
                EntrypointValueAtomV1, EntrypointValueKindV1, EntrypointValueTypeNodeV1,
                EntrypointValueTypeV1, entrypoint_argument_schema_hash_v1,
            },
        },
        transaction::executable::ContractArgumentRecord,
    };
    use iroha_model_base::{domain::DomainId, name::Name};
    use iroha_primitives::json::Json;

    fn arguments(value: bool) -> ContractArgumentRecord {
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
            atoms: vec![EntrypointValueAtomV1::Bool(value)],
        };
        assert!(schema.validate_atoms(&record.atoms));
        ContractArgumentRecord::try_new(ivm::codec::encode_canonical_norito(&record).unwrap())
            .unwrap()
    }
    fn call(
        context: &PrivacyActionTransactionContextV1,
        name: &str,
        nonce: u64,
    ) -> ContractInvocation {
        ContractInvocation {
            contract_address: ContractAddress::derive(
                &context.network_id,
                &context.authority,
                nonce,
                DataSpaceId::UNIVERSAL,
            )
            .unwrap(),
            expected_code_hash: Hash::new(name.as_bytes()),
            entrypoint: name.to_owned(),
            arguments: Some(arguments(true)),
        }
    }
    fn calls(context: &PrivacyActionTransactionContextV1) -> OrchardOrderedContractCallsV1 {
        OrchardOrderedContractCallsV1::try_new(
            vec![call(context, "open", 1), call(context, "record", 2)],
            vec![call(context, "count", 3), call(context, "close", 4)],
        )
        .unwrap()
    }
    fn request() -> OrchardNoteActionRequestV1 {
        let spending_key = (1_u8..=u8::MAX)
            .find_map(|counter| {
                let mut bytes = [0x71; 32];
                bytes[0] = counter;
                Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            })
            .expect("native fixture spending key");
        OrchardNoteActionRequestV1 {
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").unwrap(),
                "ordered_fixture".parse().unwrap(),
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
        }
    }
    fn assert_rebound_rejected(
        original: &SignedTransaction,
        context: &PrivacyActionTransactionContextV1,
        calls: &OrchardOrderedContractCallsV1,
    ) {
        let (_, submission) = original
            .privacy_transaction_intent_binding_if_present_v1()
            .unwrap()
            .unwrap();
        let changed =
            orchard_ordered_payload(context, calls, Some(submission.envelope.clone())).unwrap();
        let signed = TransactionBuilder::from_payload(changed)
            .unwrap()
            .try_sign(&signing_key())
            .unwrap();
        signed.verify_signature().unwrap();
        assert_eq!(
            inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                &signed, context, calls
            )
            .expect_err("a new valid signature cannot rebind the old proof")
            .stage(),
            "inspect-intent"
        );
    }
    #[test]
    fn orchard_ordered_real_proof_binds_calls_positions_and_fixed_context() {
        let mut context = action_context();
        context.fee_payment =
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(1_000_000));
        context
            .metadata
            .insert("scenario".parse::<Name>().unwrap(), Json::new(true));
        let plan = calls(&context);
        // Production prepare/authorize performs real proving and independent native self-verification.
        let built = build_signed_orchard_note_action_with_contract_calls_v1(
            context.clone(),
            request(),
            plan.clone(),
            [1; 32],
            &signing_key(),
        )
        .expect("real whole-Batch Orchard action");
        assert!(built.proof_bytes() > 0);
        let signed = built.signed_transaction();
        let inspected = inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
            signed, &context, &plan,
        )
        .unwrap();
        assert_eq!(inspected.direct_instruction_index(), 2);
        assert_eq!(inspected.action().statement().context().action_index, 0);
        assert_eq!(
            inspected.action().transaction_hash(),
            built.transaction_hash()
        );
        assert_eq!(
            inspected.action().transaction_intent_digest(),
            built.transaction_intent_digest()
        );
        let Executable::Batch(items) = signed.instructions() else {
            panic!("ordered Batch")
        };
        assert_eq!(items.len(), 5);
        assert!(
            matches!(&items[2], ExecutableBatchItem::Instruction(i) if i.as_any().is::<SubmitPrivacyProofV1>())
        );
        assert_eq!(signed.creation_time(), context.creation_time);
        assert_eq!(signed.time_to_live(), context.time_to_live);
        assert_eq!(signed.nonce(), context.nonce);
        assert_eq!(signed.fee_payment_intent(), &context.fee_payment);
        assert_eq!(signed.metadata(), &context.metadata);
        for field in 0..8 {
            let mut changed = context.clone();
            match field {
                0 => changed.network_id = network_id_from_genesis_hash_bytes([2; 32]),
                1 => changed.authority = AccountId::new(PublicKey::from(foreign_signing_key())),
                2 => changed.creation_time += Duration::from_millis(1),
                3 => changed.time_to_live = Some(Duration::from_secs(61)),
                4 => changed.nonce = NonZeroU32::new(8),
                5 => {
                    changed.fee_payment = FeePaymentIntent::authority(
                        Vec::new(),
                        core::num::NonZeroU64::new(2_000_000),
                    )
                }
                6 => {
                    changed
                        .metadata
                        .insert("scenario".parse::<Name>().unwrap(), Json::new(false));
                }
                _ => changed.time_to_live = None,
            }
            assert_eq!(
                inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                    signed, &changed, &plan
                )
                .expect_err("every independently fixed context field is exact")
                .stage(),
                "inspect-orchard-ordered-payload"
            );
            if field != 1 {
                assert_rebound_rejected(signed, &changed, &plan);
            }
        }
        for field in 0..2 {
            let mut changed = context.clone();
            if field == 0 {
                changed.creation_time += Duration::from_nanos(1);
            } else {
                changed.time_to_live =
                    Some(changed.time_to_live.unwrap() + Duration::from_nanos(1));
            }
            assert_eq!(
                inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                    signed, &changed, &plan
                )
                .expect_err("submillisecond expectations cannot alias the signed time")
                .stage(),
                "orchard-ordered-context-precision"
            );
        }
        for side in 0..2 {
            for field in 0..4 {
                let mut before = plan.before().to_vec();
                let mut after = plan.after().to_vec();
                let target = if side == 0 {
                    &mut before[0]
                } else {
                    &mut after[0]
                };
                match field {
                    0 => target.contract_address = call(&context, "foreign", 99).contract_address,
                    1 => target.expected_code_hash = Hash::new(b"changed-code"),
                    2 => target.entrypoint = "changed".to_owned(),
                    _ => target.arguments = Some(arguments(false)),
                }
                let changed = OrchardOrderedContractCallsV1::try_new(before, after).unwrap();
                assert_eq!(
                    inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                        signed, &context, &changed
                    )
                    .expect_err("both sides' address/code/selector/arguments are exact")
                    .stage(),
                    "inspect-orchard-ordered-payload"
                );
                assert_rebound_rejected(signed, &context, &changed);
            }
        }
        for mutation in 0..3 {
            let mut before = plan.before().to_vec();
            let mut after = plan.after().to_vec();
            match mutation {
                0 => before.swap(0, 1),
                1 => after.swap(0, 1),
                _ => after.insert(0, before.pop().unwrap()),
            }
            let changed = OrchardOrderedContractCallsV1::try_new(before, after).unwrap();
            assert!(
                inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                    signed, &context, &changed
                )
                .is_err()
            );
            assert_rebound_rejected(signed, &context, &changed);
        }
        let mut extra = items.to_vec();
        extra.push(items[2].clone());
        let duplicate = TransactionBuilder::from_payload(signed.payload().clone())
            .unwrap()
            .with_executable(Executable::Batch(extra.into()))
            .try_sign(&signing_key())
            .unwrap();
        assert!(
            inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                &duplicate, &context, &plan
            )
            .is_err()
        );
    }
    #[test]
    fn orchard_standalone_real_builder_preserves_single_instruction_carrier() {
        let context = action_context();
        let built = build_signed_orchard_note_action_v1(
            context.clone(),
            request(),
            [1; 32],
            &signing_key(),
        )
        .unwrap();
        let Executable::Instructions(items) = built.signed_transaction().instructions() else {
            panic!("original standalone carrier")
        };
        assert_eq!(items.len(), 1);
        assert!(built.proof_bytes() > 0);
        inspect_signed_privacy_orchard_note_action_v1(built.signed_transaction()).unwrap();
        assert!(
            inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
                built.signed_transaction(),
                &context,
                &calls(&context)
            )
            .is_err()
        );
    }
    #[test]
    fn orchard_ordered_rejects_submillisecond_context_before_proving() {
        for field in 0..2 {
            let mut context = action_context();
            let plan = calls(&context);
            if field == 0 {
                context.creation_time += Duration::from_nanos(1);
            } else {
                context.time_to_live =
                    Some(context.time_to_live.unwrap() + Duration::from_nanos(1));
            }
            assert_eq!(
                build_signed_orchard_note_action_with_contract_calls_v1(
                    context,
                    request(),
                    plan,
                    [1; 32],
                    &signing_key()
                )
                .expect_err("submillisecond context is rejected before native proving")
                .stage(),
                "orchard-ordered-context-precision"
            );
        }
    }
    #[test]
    fn orchard_ordered_limits_reuse_native_request_and_transaction_bounds() {
        let mut context = action_context();
        let one = call(&context, "open", 1);
        for (before, after) in [(vec![], vec![one.clone()]), (vec![one.clone()], vec![])] {
            assert_eq!(
                OrchardOrderedContractCallsV1::try_new(before, after)
                    .err()
                    .unwrap()
                    .stage(),
                "orchard-ordered-empty-side"
            );
        }
        let limit = usize::try_from(
            iroha_data_model::parameter::TransactionParameters::default()
                .max_instructions()
                .get(),
        )
        .unwrap();
        for (before, after) in [
            (vec![one.clone(); limit], vec![one.clone()]),
            (
                vec![one.clone(); limit / 2],
                vec![one.clone(); limit - limit / 2],
            ),
        ] {
            assert_eq!(
                OrchardOrderedContractCallsV1::try_new(before, after)
                    .err()
                    .unwrap()
                    .stage(),
                "orchard-ordered-call-count"
            );
        }
        let mut oversized = one.clone();
        oversized.arguments = Some(
            ContractArgumentRecord::try_new(
                vec![0; PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1],
            )
            .unwrap(),
        );
        assert_eq!(
            OrchardOrderedContractCallsV1::try_new(vec![oversized], vec![one])
                .err()
                .unwrap()
                .stage(),
            "orchard-ordered-call-bytes"
        );
        let plan = calls(&context);
        // Include JSON string quotes in the per-value cap; framing exceeds the request cap.
        let padding =
            Json::try_new("x".repeat(PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1 - 2))
                .expect("padding stays within the native JSON value limit");
        assert_eq!(
            padding.get().len(),
            PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1
        );
        context.metadata.insert("padding".parse().unwrap(), padding);
        assert_eq!(
            build_signed_orchard_note_action_with_contract_calls_v1(
                context,
                request(),
                plan,
                [1; 32],
                &signing_key()
            )
            .expect_err("complete public context is bounded before proving")
            .stage(),
            "orchard-ordered-request-bytes"
        );
    }
}
