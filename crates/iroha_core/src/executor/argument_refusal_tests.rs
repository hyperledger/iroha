/// Original argument decoder owners survive all four prepared dispatch contexts.
mod argument_refusal_tests {
    use super::*;
    use crate::execution_attempt::{ExecutionAttemptError, expect_completed_rejection};
    use norito::core::{DecodeLimits, with_decode_limits_measured, with_decode_limits_scope};

    #[derive(Clone, Copy, Debug)]
    enum Route {
        Invocation,
        Metadata,
        TriggerInvocation,
        TriggerMetadata,
    }

    fn limits(bytes: usize) -> DecodeLimits {
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    }

    fn invoke(
        route: Route,
        contract: &ivm::PreparedContract,
        invocation: &ContractInvocation,
        metadata: &Metadata,
        event: &Json,
    ) -> Result<ContractCallExecutionContext, ExecutionAttemptError<ValidationFail>> {
        match route {
            Route::Invocation => parse_prepared_contract_invocation_execution_context(
                invocation,
                contract,
                None,
                invocation.contract_address.subject_id(),
                u64::MAX,
            ),
            Route::Metadata => {
                parse_prepared_contract_call_execution_context(metadata, contract, u64::MAX)
                    .map(|context| context.expect("explicit prepared entrypoint"))
            }
            Route::TriggerInvocation => parse_prepared_trigger_invocation_execution_context(
                invocation,
                contract,
                None,
                invocation.contract_address.subject_id(),
                event,
                u64::MAX,
            ),
            Route::TriggerMetadata => {
                parse_prepared_trigger_call_execution_context(metadata, contract, event, u64::MAX)
            }
        }
    }

    #[test]
    fn prepared_dispatch_keeps_original_decode_owner_before_state_bridge_and_retries() {
        let contract = prepared_parameterized_trigger_contract();
        let schema = contract
            .entrypoint_descriptor("run")
            .unwrap()
            .argument_schema
            .as_ref()
            .unwrap();
        let original_schema = norito::encode_canonical(schema).unwrap();
        let original_artifact = contract.artifact().to_vec();
        let event = Json::from(norito::json!({"val": "1.25"}));
        let original_record =
            ivm_abi::arguments::encode_argument_record_from_json(schema, &event).unwrap();
        let address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .unwrap(),
            &ALICE_ID,
            97,
            DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        for route in [
            Route::Invocation,
            Route::Metadata,
            Route::TriggerInvocation,
            Route::TriggerMetadata,
        ] {
            let invocation = ContractInvocation {
                contract_address: address.clone(),
                expected_code_hash: contract.code_hash(),
                entrypoint: "run".to_owned(),
                arguments: matches!(route, Route::Invocation).then(|| {
                    iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(
                        original_record.clone(),
                    )
                    .unwrap()
                }),
            };
            let mut metadata = Metadata::default();
            metadata.insert(
                "contract_entrypoint".parse().unwrap(),
                Json::new("run".to_owned()),
            );
            if matches!(route, Route::Metadata) {
                metadata.insert("contract_payload".parse().unwrap(), event.clone());
            }
            // Fund the actual selector/JSON-encoding prefix, then refuse at the
            // canonical decoder. Earlier raw JSON-owner repairs are separate.
            let (_, prefix) = with_decode_limits_measured(limits(usize::MAX), || {
                if matches!(route, Route::Metadata | Route::TriggerMetadata) {
                    requested_contract_address(&metadata).unwrap();
                    requested_contract_alias(&metadata).unwrap();
                    requested_contract_entrypoint(&metadata).unwrap();
                }
                if !matches!(route, Route::Invocation) {
                    encode_contract_argument_record(Some(schema), Some(&event)).unwrap();
                }
            });
            let state = State::new_for_testing(
                World::default(),
                Kura::blank_kura_for_testing(),
                query::store::LiveQueryStore::start_test(),
            );
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut transaction = block.transaction();
            let pool = transaction
                .pipeline_ivm_prepared_cache
                .execution_budget()
                .clone();
            let before = (
                transaction.last_tx_gas_used,
                transaction.executor_fuel_remaining,
                transaction.confidential_gas_used_in_tx,
                transaction.pipeline_ivm_prepared_cache.stats(),
                pool.reserved_bytes(),
                transaction.world.accounts().iter().count(),
            );
            let error = with_decode_limits_scope(limits(prefix.total_allocated_bytes()), || {
                invoke(route, &contract, &invocation, &metadata, &event)
            })
            .expect_err("the original canonical record must refuse after the admitted prefix");
            let ExecutionAttemptError::Deferred(owner) = &error else {
                panic!("{route:?} turned an unfinished canonical decode into rejection: {error}");
            };
            let original = owner
                .decode_refusal()
                .expect("exact decoder owner, not reason-only")
                .clone();
            assert_eq!(
                original.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert!(
                owner.allocation_refusal().is_none(),
                "no invented pool wake source"
            );
            assert!(transaction.execution_deferral().is_none());
            transaction.attempt_error_to_validation_fail(error);
            let sticky = transaction.execution_deferral().unwrap();
            assert_eq!(sticky.decode_refusal(), Some(&original));
            let roundtrip = crate::execution_attempt::ExecutionDeferred::from_vm_error(
                &sticky.clone().into_vm_error(),
            )
            .unwrap();
            assert_eq!(roundtrip, sticky);
            assert_eq!(
                (
                    transaction.last_tx_gas_used,
                    transaction.executor_fuel_remaining,
                    transaction.confidential_gas_used_in_tx,
                    transaction.pipeline_ivm_prepared_cache.stats(),
                    pool.reserved_bytes(),
                    transaction.world.accounts().iter().count(),
                ),
                before,
                "{route:?} must not enter a VM, charge gas, prepare cache entries or mutate World",
            );
            assert!(
                transaction
                    .pipeline_ivm_prepared_cache
                    .execution_budget()
                    .same_pool(&pool)
            );
            drop(transaction);
            // Retry the same signed bytes and schema after only the local limit
            // retires. The failed transaction's sticky guard was not cleared.
            let retried = invoke(route, &contract, &invocation, &metadata, &event).unwrap();
            let prepared = retried.prepared_argument_record().unwrap();
            assert_eq!(prepared.canonical_bytes(), original_record);
            assert_eq!(prepared.schema_bytes(), original_schema);
            assert_eq!(contract.artifact(), original_artifact);
            assert_eq!(norito::encode_canonical(schema).unwrap(), original_schema);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn live_resolved_executor_arms_original_argument_owner_and_retries_same_signed_call() {
        let signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku DeferredArguments { permission Admin;
  kotoage fn run(quantity val) authorize(Admin) { let _val = val; }
}
"#,
            )
            .unwrap();
        let prepared = ivm::prepare_contract(Arc::<[u8]>::from(program.clone())).unwrap();
        let schema = prepared
            .entrypoint_descriptor("run")
            .unwrap()
            .argument_schema
            .as_ref()
            .unwrap();
        let record = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({"val": "1.25"})),
        )
        .unwrap();
        let authority = ALICE_ID.clone();
        let state = state_after_genesis(World::with(
            [],
            [Account::new(authority.clone()).build(&authority)],
            [],
        ));
        let code_hash = ivm::contract_code_hash(&program);
        let address =
            ContractAddress::derive(&state.network_id, &authority, 96, DataSpaceId::UNIVERSAL)
                .unwrap();
        let artifact_id =
            iroha_data_model::smart_contract::ContractArtifactId::for_address(&address, code_hash)
                .unwrap();
        let mut world = state.world.block();
        world.contract_code.insert(artifact_id.clone(), program);
        world.contract_manifests.insert(
            artifact_id,
            manifest
                .try_signed(signing.context(), signing.max_frame_bytes(), &ALICE_KEYPAIR)
                .unwrap(),
        );
        world.commit();
        bind_executor_test_contract_after_genesis(&state, &address, &authority, code_hash);
        let invocation = ContractInvocation {
            contract_address: address.clone(),
            expected_code_hash: code_hash,
            entrypoint: "run".to_owned(),
            arguments: Some(
                iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(
                    record.clone(),
                )
                .unwrap(),
            ),
        };
        let signed = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(1_000_000)),
        )
        .with_executable(Executable::ContractCall(invocation.clone()))
        .sign(ALICE_KEYPAIR.private_key());
        let signed_bytes = norito::encode_canonical(&signed).unwrap();
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(state.view().latest_block_hash().unwrap()),
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: address.clone(),
                permission: "Admin".parse().unwrap(),
            }
            .into();
        Grant::account_permission(permission, authority.clone())
            .execute(&authority, &mut tx)
            .unwrap();
        tx.apply();
        for refuse in [true, false] {
            let mut tx = block.transaction();
            tx.current_tx_hash = Some(signed.hash());
            tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
            tx.begin_execution_effect_budget(&signed).unwrap();
            let executor = tx.world.executor.clone();
            let cache = tx.ivm_cache;
            let resolved = {
                let mut guard = cache.lock();
                executor
                    .resolve_contract_invocation(&mut tx, &invocation, &mut guard)
                    .unwrap()
            };
            // Measure the real admitted prefix of execute_resolved_contract_invocation.
            // Its earlier root/permission JSON decoders have separate owner follow-ons.
            // An argument-owner assertion below prevents an earlier refusal passing this test.
            let (_, prefix) = with_decode_limits_measured(limits(usize::MAX), || {
                root_scope::ensure_contract_scope(&mut tx, &address).unwrap();
                validate_prepared_ivm_execution_policy(&tx, &resolved.summary.metadata).unwrap();
                let manifest = tx
                    .world
                    .contract_manifests()
                    .get(
                        &iroha_data_model::smart_contract::ContractArtifactId::for_address(
                            &address, code_hash,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                crate::smartcontracts::ivm::validate_manifest_hashes(
                    manifest,
                    resolved.summary.code_hash,
                    resolved.summary.abi_hash,
                )
                .unwrap();
                validate_prepared_contract_lifecycle_call(
                    &tx.world,
                    &address,
                    code_hash,
                    resolved.summary.prepared_contract(),
                    "run",
                )
                .unwrap();
                authorize_prepared_contract_selector(
                    &tx.world,
                    &authority,
                    resolved.summary.prepared_contract(),
                    "run",
                    &resolved.identity,
                )
                .unwrap();
            });
            let prepared_cache = resolved.summary.prepared_contract_cache();
            let pool = prepared_cache.execution_budget().clone();
            let before = (
                tx.last_tx_gas_used,
                tx.executor_fuel_remaining,
                tx.confidential_gas_used_in_tx,
                prepared_cache.stats(),
                pool.reserved_bytes(),
            );
            let durable_before = tx
                .world
                .smart_contract_state()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            ivm::reset_argument_record_decode_count();
            let run = || {
                executor.execute_resolved_contract_invocation(
                    &mut tx,
                    &authority,
                    &invocation,
                    resolved,
                    1_000_000,
                    0,
                    None,
                )
            };
            let result = if refuse {
                with_decode_limits_scope(limits(prefix.total_allocated_bytes()), run)
            } else {
                run()
            };
            assert_eq!(
                ivm::argument_record_decode_count(),
                1,
                "the actual executor must reach the canonical argument decoder exactly once"
            );
            if refuse {
                result.expect_err("canonical argument admission must defer the actual executor");
                let sticky = tx.execution_deferral().expect(
                    "the live executor boundary, without a manual test bridge, must arm State",
                );
                let original = sticky
                    .decode_refusal()
                    .expect("the original argument counter owner");
                assert_eq!(
                    original.kind(),
                    norito::core::DecodeLocalRefusalKind::EnclosingLimit
                );
                assert_eq!(
                    crate::execution_attempt::ExecutionDeferred::from_vm_error(
                        &sticky.clone().into_vm_error(),
                    )
                    .unwrap(),
                    sticky
                );
                assert!(sticky.allocation_refusal().is_none());
                assert_eq!(
                    (
                        tx.last_tx_gas_used,
                        tx.executor_fuel_remaining,
                        tx.confidential_gas_used_in_tx,
                        prepared_cache.stats(),
                        pool.reserved_bytes(),
                    ),
                    before,
                    "unfinished decode must precede runtime checkout and gas charging"
                );
                assert_eq!(
                    tx.world
                        .smart_contract_state()
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>(),
                    durable_before
                );
                assert!(prepared_cache.execution_budget().same_pool(&pool));
            } else {
                result
                    .expect("the unchanged signed call must execute after the local scope retires");
                assert!(tx.execution_deferral().is_none());
                tx.finish_execution_effect_budget().unwrap();
            }
            assert_eq!(invocation.arguments.as_deref(), Some(record.as_slice()));
            assert_eq!(norito::encode_canonical(&signed).unwrap(), signed_bytes);
            // Do not apply either attempt or clear a sticky guard in place.
        }
    }

    #[test]
    fn argument_preparation_preserves_malformed_nominal_schema_and_gas_rejections() {
        let contract = prepared_parameterized_trigger_contract();
        let schema = contract
            .entrypoint_descriptor("run")
            .unwrap()
            .argument_schema
            .as_ref()
            .unwrap();
        let payload = Json::from(norito::json!({"val": "1.25"}));
        let record =
            ivm_abi::arguments::encode_argument_record_from_json(schema, &payload).unwrap();
        let mut malformed = record.clone();
        malformed[0] ^= 0xff;
        let invalid = with_decode_limits_scope(limits(0), || {
            prepare_validated_contract_argument_record(Some(schema), Some(&malformed), u64::MAX)
        })
        .map_err(expect_completed_rejection)
        .unwrap_err();
        assert!(matches!(invalid, ValidationFail::NotPermitted(ref message)
            if message.contains("invalid contract argument record")));
        let mut wrong_schema = schema.clone();
        wrong_schema.fields[0].name = "different_nominal_field".to_owned();
        for (schema, gas) in [(&wrong_schema, u64::MAX), (schema, 0)] {
            let invalid =
                prepare_validated_contract_argument_record(Some(schema), Some(&record), gas)
                    .map_err(expect_completed_rejection)
                    .unwrap_err();
            assert!(matches!(invalid, ValidationFail::NotPermitted(ref message)
                if message.contains("invalid contract argument record")));
        }
        let invalid_json = Json::from(norito::json!({"val": "not-a-quantity"}));
        let invalid =
            prepare_contract_argument_record_from_json(Some(schema), Some(&invalid_json), u64::MAX)
                .map_err(expect_completed_rejection)
                .unwrap_err();
        assert!(matches!(invalid, ValidationFail::NotPermitted(ref message)
            if message.contains("contract payload does not match")));
        let prepared =
            prepare_validated_contract_argument_record(Some(schema), Some(&record), u64::MAX)
                .unwrap()
                .unwrap();
        assert_eq!(prepared.canonical_bytes(), record);
    }
}
