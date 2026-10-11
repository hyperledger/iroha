/// Actual signed root work admits complete instruction groups before dispatch.
mod effect_budget {
    use super::*;
    use crate::executor::Executor;

    const GAS: u64 = 50_000_000;

    fn fixture() -> State {
        state_after_genesis(World::with(
            [],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [],
        ))
    }

    fn next_block(state: &State) -> crate::state::StateBlock<'_> {
        state.block(BlockHeader::new(
            core::num::NonZeroU64::new(state.committed_height() as u64 + 1)
                .expect("post-genesis fixture height"),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        ))
    }

    fn writes() -> Vec<InstructionBox> {
        ["effect_first", "effect_second"]
            .into_iter()
            .map(|key| {
                SetKeyValue::account(ALICE_ID.clone(), key.parse().unwrap(), Json::new(true)).into()
            })
            .collect()
    }

    fn signed(state: &State, executable: Executable) -> SignedTransaction {
        TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(GAS)),
        )
        .with_executable(executable)
        .sign(ALICE_KEYPAIR.private_key())
    }

    fn assert_limit(error: &ValidationFail, expected: &str) {
        assert!(
            matches!(error, ValidationFail::NotPermitted(reason) if reason == expected),
            "{error:?}"
        );
    }

    #[test]
    fn plain_instruction_group_checks_exact_count_before_first_effect() {
        let mut cache = IvmCache::new();
        for cap in [0, 2, 1] {
            let state = fixture();
            let source = signed(&state, Executable::Instructions(writes().into()));
            let mut block = next_block(&state);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.overlay_max_instructions = cap;
            tx.pipeline.overlay_max_bytes = 0;
            let result = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, source, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            if cap == 1 {
                assert_limit(
                    &result.unwrap_err(),
                    "overlay exceeds max instructions: 2 > 1",
                );
                assert!(tx.execution_effect_limit_exceeded());
                assert_eq!(
                    tx.last_tx_gas_used, 0,
                    "preflight must precede authored work"
                );
                for key in ["effect_first", "effect_second"] {
                    assert!(
                        tx.world
                            .account(&ALICE_ID)
                            .unwrap()
                            .metadata()
                            .get(key)
                            .is_none()
                    );
                }
                drop(tx);
                assert_eq!(block.committed_fragment_count(), fragments);
            } else {
                result.unwrap();
                assert!(!tx.execution_effect_limit_exceeded());
                tx.apply();
                assert_eq!(block.committed_fragment_count(), fragments + 1);
            }
            for key in ["effect_first", "effect_second"] {
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get(key)
                        .is_some(),
                    cap != 1
                );
            }
        }
    }

    #[test]
    fn plain_instruction_group_checks_exact_bare_bytes_before_first_effect() {
        let instructions = writes();
        let exact: u64 = instructions
            .iter()
            .map(|instruction| u64::try_from(instruction.encode().len()).unwrap())
            .sum();
        assert!(exact > 1);
        let mut cache = IvmCache::new();
        for cap in [0, exact, exact - 1] {
            let state = fixture();
            let source = signed(
                &state,
                Executable::Instructions(instructions.clone().into()),
            );
            let mut block = next_block(&state);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.overlay_max_instructions = 0;
            tx.pipeline.overlay_max_bytes = cap;
            let result = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, source, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            if cap == exact - 1 {
                assert_limit(
                    &result.unwrap_err(),
                    &format!("overlay exceeds max bytes: more than {cap}"),
                );
                assert!(tx.execution_effect_limit_exceeded());
                assert_eq!(tx.last_tx_gas_used, 0);
                for key in ["effect_first", "effect_second"] {
                    assert!(
                        tx.world
                            .account(&ALICE_ID)
                            .unwrap()
                            .metadata()
                            .get(key)
                            .is_none()
                    );
                }
                drop(tx);
                assert_eq!(block.committed_fragment_count(), fragments);
            } else {
                result.unwrap();
                assert!(!tx.execution_effect_limit_exceeded());
                tx.apply();
                assert_eq!(block.committed_fragment_count(), fragments + 1);
            }
            for key in ["effect_first", "effect_second"] {
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get(key)
                        .is_some(),
                    cap != exact - 1
                );
            }
        }
    }

    fn contract_fixture() -> (State, Vec<u8>, ContractAddress, Hash) {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(r#"
seiyaku ActualEffectGroups { permission CanInvokeContractEntrypoint;
  kotoage fn first() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("effect_first"), value: Json::parse("true"));
  }
  kotoage fn second() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("effect_second"), value: Json::parse("true"));
  }
  kotoage fn pair() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("effect_first"), value: Json::parse("true"));
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("effect_second"), value: Json::parse("true"));
  }
}
"#).expect("compile genuine effect-producing contract");
        let hash = ivm::contract_code_hash(&program);
        let state = fixture();
        let address =
            ContractAddress::derive(&state.network_id, &ALICE_ID, 161, DataSpaceId::UNIVERSAL)
                .unwrap();
        let mut block = next_block(&state);
        let mut setup = block.transaction();
        setup.world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                address.dataspace_id().unwrap(),
                hash,
            ),
            program.clone(),
        );
        setup.world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                address.dataspace_id().unwrap(),
                hash,
            ),
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &ALICE_KEYPAIR,
                )
                .expect("sign bounded fixture manifest"),
        );
        setup.world.accounts.insert(
            address.subject_id(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        setup.world.contract_instances.insert(address.clone(), hash);
        setup
            .world
            .contract_subject_addresses
            .insert(address.subject_id(), address.clone());
        setup.world.contract_subject_bindings.insert(
            address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &address,
                ALICE_ID.clone(),
            )
            .with_active_code_hash(hash),
        );
        // Contract execution retains its own subject; its authored writes to the caller's
        // account need the exact account-scoped grant even though the caller owns it.
        setup.world.account_permissions.insert(
            address.subject_id(),
            BTreeSet::from([executor_permission::account::CanModifyAccountMetadata {
                account: ALICE_ID.clone(),
            }
            .into()]),
        );
        setup.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("bound contract fixture World setup");
        (state, program, address, hash)
    }

    fn grant_entrypoints(block: &mut crate::state::StateBlock<'_>, address: &ContractAddress) {
        let mut setup = block.transaction();
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: address.clone(),
                permission: "CanInvokeContractEntrypoint".parse().unwrap(),
            }
            .into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut setup)
            .unwrap();
        setup.apply();
    }

    #[test]
    fn bound_raw_artifact_group_rejects_before_first_effect() {
        // The same cache is reused across fresh signed attempts and worlds.
        let mut cache = IvmCache::new();
        let mut successful_gas = None;
        for cap in [2, 1] {
            let (state, program, address, hash) = contract_fixture();
            let mut metadata = Metadata::default();
            for (key, value) in [
                ("contract_address", address.to_string()),
                ("contract_code_hash", hash.to_string()),
                ("contract_entrypoint", "pair".to_owned()),
            ] {
                metadata.insert(key.parse().unwrap(), Json::new(value));
            }
            let source = TransactionBuilder::new(
                state.network_id,
                ALICE_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(GAS)),
            )
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
            .sign(ALICE_KEYPAIR.private_key());
            let mut block = next_block(&state);
            grant_entrypoints(&mut block, &address);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.overlay_max_instructions = cap;
            tx.pipeline.overlay_max_bytes = 0;
            let result = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, source, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            assert!(
                tx.last_tx_gas_used > 0,
                "actual VM must finish before artifact admission"
            );
            if cap == 1 {
                assert_limit(
                    &result.unwrap_err(),
                    "overlay exceeds max instructions: 2 > 1",
                );
                assert!(tx.execution_effect_limit_exceeded());
                assert_eq!(Some(tx.last_tx_gas_used), successful_gas);
                for key in ["effect_first", "effect_second"] {
                    assert!(
                        tx.world
                            .account(&ALICE_ID)
                            .unwrap()
                            .metadata()
                            .get(key)
                            .is_none()
                    );
                }
                drop(tx);
                assert_eq!(block.committed_fragment_count(), fragments);
            } else {
                result.unwrap();
                assert!(!tx.execution_effect_limit_exceeded());
                successful_gas = Some(tx.last_tx_gas_used);
                tx.apply();
                assert_eq!(block.committed_fragment_count(), fragments + 1);
            }
            for key in ["effect_first", "effect_second"] {
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get(key)
                        .is_some(),
                    cap == 2
                );
            }
        }
    }

    #[test]
    fn mixed_batch_cumulative_artifact_denial_precedes_second_group_effect() {
        let mut cache = IvmCache::new();
        let mut successful_gas = None;
        for cap in [3, 2] {
            let (state, _program, address, hash) = contract_fixture();
            let mut items = vec![ExecutableBatchItem::Instruction(
                SetKeyValue::account(
                    ALICE_ID.clone(),
                    "effect_authored".parse().unwrap(),
                    Json::new(true),
                )
                .into(),
            )];
            items.extend(["first", "second"].into_iter().map(|entrypoint| {
                ExecutableBatchItem::ContractCall(ContractInvocation {
                    contract_address: address.clone(),
                    expected_code_hash: hash,
                    entrypoint: entrypoint.to_owned(),
                    arguments: None,
                })
            }));
            let source = signed(&state, Executable::Batch(items.into()));
            let mut block = next_block(&state);
            grant_entrypoints(&mut block, &address);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.overlay_max_instructions = cap;
            tx.pipeline.overlay_max_bytes = 0;
            let result = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, source, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            assert!(tx.last_tx_gas_used > 0);
            assert!(
                tx.world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("effect_authored")
                    .is_some()
            );
            assert!(
                tx.world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("effect_first")
                    .is_some(),
                "first admitted group executes before the next contract runs"
            );
            if cap == 2 {
                assert_limit(
                    &result.unwrap_err(),
                    "overlay exceeds max instructions: 3 > 2",
                );
                assert!(tx.execution_effect_limit_exceeded());
                assert_eq!(
                    Some(tx.last_tx_gas_used),
                    successful_gas,
                    "both actual VMs complete even when the second artifact group cannot apply"
                );
                assert!(
                    tx.world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("effect_second")
                        .is_none(),
                    "cumulative denial must precede the second group's first effect"
                );
                drop(tx);
                assert_eq!(block.committed_fragment_count(), fragments);
            } else {
                result.unwrap();
                assert!(!tx.execution_effect_limit_exceeded());
                successful_gas = Some(tx.last_tx_gas_used);
                tx.apply();
                assert_eq!(block.committed_fragment_count(), fragments + 1);
            }
            for key in ["effect_authored", "effect_first", "effect_second"] {
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get(key)
                        .is_some(),
                    cap == 3,
                    "discarding a rejected mixed batch rolls back its earlier admitted group"
                );
            }
        }
    }

    // Independently execute the compiled callable to identify the exact refused work.
    // This host queues the native write but does not apply it to State.
    fn second_entrypoint_return_work(program: &[u8]) -> (u64, u64, u64) {
        let mut completed = None;
        for limited in [false, true] {
            let mut vm = ivm::IVM::new(GAS);
            vm.load_program(program).unwrap();
            vm.select_entrypoint("second").unwrap();
            vm.set_trace_mode(ivm::TraceMode::PcOnly);
            let interface = vm.contract_interface().unwrap();
            let entry = interface
                .entrypoints
                .iter()
                .find(|entry| entry.name == "second")
                .unwrap();
            let callable = interface
                .callables
                .iter()
                .find(|callable| callable.entry_pc == entry.entry_pc)
                .unwrap();
            assert_eq!(callable.results, ivm::call::CallSchemaV1::unit());
            let mut host = crate::smartcontracts::ivm::host::CoreHost::new(ALICE_ID.clone());
            if limited {
                let (cycles, gas, trace): (u64, u64, Vec<u64>) = completed.take().unwrap();
                let budget =
                    ivm::VmCycleBudget::new(core::num::NonZeroU64::new(cycles - 1).unwrap());
                assert_eq!(
                    vm.run_with_host_and_cycle_budget(&mut host, &budget),
                    Err(ivm::VMError::ExceededMaxCycles)
                );
                assert_eq!(vm.get_cycle_count(), cycles - 1);
                assert_eq!(budget.consumed(), cycles - 1);
                assert!(budget.exhausted());
                // Tracing records the fetched instruction before the cycle reservation.
                assert_eq!(vm.trace_pcs(), trace);
                assert_eq!(Some(&vm.pc()), trace.last());
                let refused = vm.memory.load_u32(vm.pc()).unwrap();
                assert_eq!(
                    refused,
                    ivm::encoding::wide::encode_ri(ivm::instruction::wide::control::JALR, 0, 1, 0)
                );
                let refused_gas = gas - (GAS - vm.remaining_gas());
                assert_eq!(
                    refused_gas,
                    ivm::gas::cost_of(refused).unwrap() + ivm::call_gas::NODE + ivm::call_gas::WORD,
                    "return dispatch validates the Unit schema node and its result word"
                );
                return (cycles, gas, refused_gas);
            }
            vm.run_with_host(&mut host).unwrap();
            assert_eq!(vm.call_result_word_count(), Ok(1));
            assert_eq!(vm.public_call_result_word(0), Ok(0));
            completed = Some((
                vm.get_cycle_count(),
                GAS - vm.remaining_gas(),
                vm.trace_pcs().to_vec(),
            ));
        }
        unreachable!("the second run checks the exact return boundary")
    }

    #[test]
    fn signed_mixed_batch_contract_runs_share_one_exact_cycle_allowance() {
        let mut cache = IvmCache::new();
        let mut segment_cycles = Vec::new();
        let mut segment_gas = Vec::new();
        let mut successful_batch_gas = None;
        let authored_gas = isi_gas::meter_instructions(
            &[SetKeyValue::account(
                ALICE_ID.clone(),
                "effect_authored".parse().unwrap(),
                Json::new(true),
            )
            .into()],
            &crate::gas::DEFAULT_ZK_GAS,
        );
        assert!(authored_gas > 0);
        let mut refused_return_gas = None;
        for case in 0..5 {
            let (state, program, address, hash) = contract_fixture();
            let call = |entrypoint: &str| ContractInvocation {
                contract_address: address.clone(),
                expected_code_hash: hash,
                entrypoint: entrypoint.to_owned(),
                arguments: None,
            };
            let executable = if case < 2 {
                Executable::ContractCall(call(if case == 0 { "first" } else { "second" }))
            } else {
                Executable::Batch(
                    vec![
                        ExecutableBatchItem::Instruction(
                            SetKeyValue::account(
                                ALICE_ID.clone(),
                                "effect_authored".parse().unwrap(),
                                Json::new(true),
                            )
                            .into(),
                        ),
                        ExecutableBatchItem::ContractCall(call("first")),
                        ExecutableBatchItem::ContractCall(call("second")),
                    ]
                    .into(),
                )
            };
            let total: u64 = segment_cycles.iter().sum();
            let cap = match case {
                0..=2 => 1_000_000,
                3 => total,
                _ => total - 1,
            };
            let mut metadata = iroha_model_base::metadata::Metadata::default();
            metadata.insert(
                crate::tx::QUARANTINE_METADATA_KEY.parse().unwrap(),
                Json::new(true),
            );
            let source = TransactionBuilder::new(
                state.network_id,
                ALICE_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(GAS)),
            )
            .with_metadata(metadata)
            .with_executable(executable)
            .sign(ALICE_KEYPAIR.private_key());
            let mut block = next_block(&state);
            grant_entrypoints(&mut block, &address);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.quarantine_tx_max_cycles = cap;
            tx.pipeline.overlay_max_instructions = 0;
            tx.pipeline.overlay_max_bytes = 0;
            let result = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, source, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            let cycles = tx
                .completed_execution_cycles_for_tests()
                .unwrap_or_else(|| panic!("signed contract execution did not finish: {result:?}"));
            assert!(!tx.execution_effect_limit_exceeded());
            if case < 2 {
                result.unwrap();
                assert!(cycles > 1);
                if case == 1 {
                    let (independent_cycles, independent_gas, return_gas) =
                        second_entrypoint_return_work(&program);
                    assert_eq!(cycles, independent_cycles);
                    assert_eq!(tx.last_tx_gas_used, independent_gas);
                    refused_return_gas = Some(return_gas);
                }
                segment_cycles.push(cycles);
                segment_gas.push(tx.last_tx_gas_used);
                drop(tx);
                continue;
            }
            assert!(
                tx.world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("effect_authored")
                    .is_some()
            );
            assert!(
                tx.world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("effect_first")
                    .is_some()
            );
            if case == 4 {
                assert_limit(
                    &result.unwrap_err(),
                    &format!("quarantine cycle budget exceeded: {cap}"),
                );
                assert_eq!(cycles, cap);
                assert!(tx.last_tx_gas_used > segment_gas[0]);
                // The final JALR and its Unit-result validation were refused before
                // dispatch. All earlier VM work remains charged; the queued second
                // native write never becomes an applied State effect.
                assert_eq!(
                    tx.last_tx_gas_used.checked_add(refused_return_gas.unwrap()),
                    successful_batch_gas
                );
                assert_eq!(
                    tx.last_tx_gas_used.checked_sub(authored_gas),
                    Some(segment_gas.iter().sum::<u64>() - refused_return_gas.unwrap()),
                    "failed batch retains exactly the independently completed VM work"
                );
                assert!(
                    tx.world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("effect_second")
                        .is_none()
                );
                assert!(!tx.execution_effects_allow_apply());
                drop(tx);
            } else {
                result.unwrap();
                assert_eq!(
                    cycles, total,
                    "Batch shares precisely the two actual VM runs"
                );
                if case == 2 {
                    successful_batch_gas = Some(tx.last_tx_gas_used);
                }
                assert_eq!(Some(tx.last_tx_gas_used), successful_batch_gas);
                assert_eq!(
                    tx.last_tx_gas_used.checked_sub(authored_gas),
                    Some(segment_gas.iter().sum()),
                    "successful batch adds only the authored native instruction gas to its two VM runs"
                );
                tx.apply();
            }
            assert_eq!(
                block.committed_fragment_count(),
                fragments + usize::from(case != 4)
            );
            for key in ["effect_authored", "effect_first", "effect_second"] {
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get(key)
                        .is_some(),
                    case != 4,
                    "rejected Batch rolls back its earlier authored and contract effects"
                );
            }
        }
    }
}
