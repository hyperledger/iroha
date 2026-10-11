/// Actual generic raw-IVM runs retain consumed work through every rejection boundary.
mod raw_ivm_work {
    use super::*;
    use crate::executor::Executor;
    use crate::smartcontracts::ivm::host::CoreHost;
    use ivm::{encoding::wide, instruction::wide as opcode, pointer_abi::PointerType};

    const GAS: u64 = 50_000_000;
    const CYCLES: u64 = 1_000;

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

    fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(kind as u16).to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(Hash::new(payload).as_ref());
        bytes
    }

    // Literal descriptors bind each pointer to canonical, hashed TLV bytes; no
    // test register injection or unindexed literal access reaches the executor.
    fn program(literals: &[Vec<u8>], instructions: &[u32]) -> Vec<u8> {
        let mut bytes = ivm::ProgramMetadata {
            max_cycles: CYCLES,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        if !literals.is_empty() {
            let data_offset = 16 + literals.len() * 8;
            let data_len: usize = literals.iter().map(Vec::len).sum();
            let pad = (4 - (data_offset + data_len) % 4) % 4;
            bytes.extend_from_slice(b"LTLB");
            bytes.extend_from_slice(&u32::try_from(literals.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(pad).unwrap().to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(data_len).unwrap().to_le_bytes());
            let mut offset = data_offset;
            for literal in literals {
                let descriptor = ivm::encode_literal_descriptor(
                    ivm::LiteralKindV1::PointerTlv,
                    u64::try_from(offset).unwrap(),
                )
                .unwrap();
                bytes.extend_from_slice(&descriptor.to_le_bytes());
                offset += literal.len();
            }
            for literal in literals {
                bytes.extend_from_slice(literal);
            }
            bytes.extend(std::iter::repeat_n(0, pad));
        }
        for instruction in instructions {
            bytes.extend_from_slice(&instruction.to_le_bytes());
        }
        let mut cache = IvmCache::new();
        assert!(matches!(
            cache.summarize_executable(&bytes).unwrap(),
            ExecutableProgramSummary::Generic(_)
        ));
        bytes
    }

    fn signed(state: &State, program: &[u8], gas: u64) -> SignedTransaction {
        TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(gas)),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(
            program.to_vec(),
        )))
        .sign(ALICE_KEYPAIR.private_key())
    }

    // Independently execute the exact program to establish actual VM completion
    // and gas consumption before inspecting the higher-level failure boundary.
    fn run_vm(program: &[u8], gas: u64) -> (Result<(), ivm::VMError>, u64, CoreHost) {
        let mut vm = ivm::IVM::new(gas);
        vm.load_program(program).unwrap();
        vm.set_max_cycles(CYCLES);
        vm.set_gas_limit(gas);
        let mut host = CoreHost::with_accounts(ALICE_ID.clone(), Arc::new(vec![ALICE_ID.clone()]));
        host.set_generic_execution();
        host.set_output_limits_from_parameters(
            iroha_data_model::parameter::SmartContractParameters::default(),
        );
        let result = vm.run_with_host(&mut host);
        let used = gas.saturating_sub(vm.remaining_gas());
        (result, used, host)
    }

    #[test]
    fn generic_admission_pool_pressure_defers_before_execution_or_gas() {
        use crate::execution_attempt::ExecutionAttemptError;
        use crate::smartcontracts::ivm::cache::PreparedContractCache;
        use iroha_allocation::{AllocationBudget, AllocationRefusal};

        let state = fixture();
        let bytes = program(&[], &[wide::encode_halt()]);
        let transaction = signed(&state, &bytes, GAS);
        let budget = AllocationBudget::new(0);
        let mut cache = IvmCache::with_prepared_contract_cache(
            0,
            PreparedContractCache::with_execution_budget(0, budget.clone()),
        );
        let before_proof = enforce_transaction_contract_permission_before_proof_verification(
            &state.view(),
            &ALICE_ID,
            &transaction,
            &mut cache,
            state.committed_height() as u64 + 1,
            DataSpaceId::UNIVERSAL,
        );
        let Err(ExecutionAttemptError::Deferred(expected)) = before_proof else {
            panic!("pre-proof admission must retain local pool refusal");
        };
        assert!(matches!(
            expected.allocation_refusal(),
            Some(AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. })
        ));
        let mut block = next_block(&state);
        let fragments = block.committed_fragment_count();
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let result =
            Executor::Initial.execute_transaction(&mut tx, &ALICE_ID, transaction, &mut cache);
        assert_eq!(
            result,
            Err(ExecutionAttemptError::Deferred(expected.clone()))
        );
        assert_eq!(tx.execution_deferral(), Some(expected));
        assert_eq!(tx.last_tx_gas_used, 0);
        assert_eq!(budget.peak_reserved_bytes(), 0);
        drop(tx);
        assert_eq!(block.committed_fragment_count(), fragments);
    }

    #[test]
    fn runtime_rejection_retains_real_vm_work_under_signed_and_remaining_block_limits() {
        let mut code = vec![wide::encode_ri(opcode::arithmetic::ADDI, 5, 5, 1); 100];
        code.push(wide::encode_halt());
        let program = program(&[], &code);
        for (signed_limit, block_limit, already_used) in [(5_u64, 0_u64, 0_u64), (10, 7, 4)] {
            let effective = if block_limit == 0 {
                signed_limit
            } else {
                signed_limit.min(block_limit - already_used)
            };
            let (vm_result, expected_gas, _) = run_vm(&program, effective);
            assert_eq!(vm_result, Err(ivm::VMError::OutOfGas));
            assert!((1..=effective).contains(&expected_gas));
            let state = fixture();
            let transaction = signed(&state, &program, signed_limit);
            let mut block = next_block(&state);
            block.gas_limit_per_block = block_limit;
            block.gas_used_in_block = already_used;
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let error = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, transaction, &mut IvmCache::new())
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("the actual raw VM must exhaust its effective gas limit");
            assert!(
                matches!(error, ValidationFail::IvmFault(ref fault) if fault.kind == iroha_data_model::executor::fault::IvmFaultKindV1::OutOfGas),
                "{error:?}"
            );
            assert_eq!(tx.last_tx_gas_used, expected_gas);
            drop(tx);
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(
                block.gas_used_in_block, already_used,
                "outer disposition owns block accounting"
            );
        }
    }

    #[test]
    fn bound_raw_contract_runtime_rejection_retains_actual_work() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku RawMeteredFailure { permission CanInvokeContractEntrypoint;
  kotoage fn run() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("raw_contract_not_written"),
      value: Json::parse("true")
    );
  }
}
"#,
            )
            .expect("compile actual raw contract");
        let mut cache = IvmCache::new();
        assert!(matches!(
            cache.summarize_executable(&program).unwrap(),
            ExecutableProgramSummary::Contract(_)
        ));
        let code_hash = ivm::contract_code_hash(&program);
        let state = fixture();
        let address =
            ContractAddress::derive(&state.network_id, &ALICE_ID, 150, DataSpaceId::UNIVERSAL)
                .unwrap();
        let mut block = next_block(&state);
        let mut setup = block.transaction();
        setup.world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                address.dataspace_id().unwrap(),
                code_hash,
            ),
            program.clone(),
        );
        setup.world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                address.dataspace_id().unwrap(),
                code_hash,
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
        setup
            .world
            .contract_instances
            .insert(address.clone(), code_hash);
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
            .with_active_code_hash(code_hash),
        );
        setup.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("bound contract fixture World setup");

        let mut metadata = Metadata::default();
        for (key, value) in [
            ("contract_address", address.to_string()),
            ("contract_code_hash", code_hash.to_string()),
            ("contract_entrypoint", "run".to_owned()),
        ] {
            metadata.insert(key.parse().unwrap(), Json::new(value));
        }
        let transaction = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(10)),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(ALICE_KEYPAIR.private_key());
        let mut block = next_block(&state);
        let mut setup = block.transaction();
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: address,
                permission: "CanInvokeContractEntrypoint".parse().unwrap(),
            }
            .into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut setup)
            .unwrap();
        setup.apply();
        let fragments = block.committed_fragment_count();
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = Executor::Initial
            .execute_transaction(&mut tx, &ALICE_ID, transaction, &mut cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("the genuinely bound and permitted raw contract must exhaust VM gas");
        assert!(
            matches!(&error, ValidationFail::IvmFault(fault) if fault.kind == iroha_data_model::executor::fault::IvmFaultKindV1::OutOfGas),
            "{error:?}"
        );
        assert!((1..=10).contains(&tx.last_tx_gas_used));
        drop(tx);
        assert_eq!(block.committed_fragment_count(), fragments);
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("raw_contract_not_written")
                .is_none()
        );
    }

    #[test]
    fn artifact_validation_rejection_retains_completed_vm_work() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        // Generic-v1 cannot call this syscall. The canonical inline builder
        // supplies the NoritoBytes pointer required by the typed bridge; a
        // contract bytes argument is a Blob and cannot stand in for that type.
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku UnverifiedBallot { permission CanInvokeContractEntrypoint;
    kotoage fn run() authorize(CanInvokeContractEntrypoint) {
        let instruction = ledger::governance::build_submit_ballot(
            election_id: "raw-work-election",
            ciphertext: b"ciphertext",
            nullifier: b"0123456789abcdef0123456789abcdef",
            backend: "halo2/ipa",
            proof: b"unverified-proof",
            verification_key: b"unverified-key",
        );
        ledger::governance::submit_ballot(value: instruction);
    }
}
"#,
            )
            .unwrap();
        let code_hash = ivm::contract_code_hash(&program);
        let state = fixture();
        let address =
            ContractAddress::derive(&state.network_id, &ALICE_ID, 151, DataSpaceId::UNIVERSAL)
                .unwrap();
        let mut block = next_block(&state);
        let mut setup = block.transaction();
        setup.world.contract_code.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                address.dataspace_id().unwrap(),
                code_hash,
            ),
            program.clone(),
        );
        setup.world.contract_manifests.insert(
            iroha_data_model::smart_contract::ContractArtifactId::new(
                address.dataspace_id().unwrap(),
                code_hash,
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
        setup
            .world
            .contract_instances
            .insert(address.clone(), code_hash);
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
            .with_active_code_hash(code_hash),
        );
        setup.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("bound contract fixture World setup");

        let mut metadata = Metadata::default();
        for (key, value) in [
            ("contract_address", address.to_string()),
            ("contract_code_hash", code_hash.to_string()),
            ("contract_entrypoint", "run".to_owned()),
        ] {
            metadata.insert(key.parse().unwrap(), Json::new(value));
        }
        let transaction = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(GAS)),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(ALICE_KEYPAIR.private_key());
        let mut block = next_block(&state);
        let mut setup = block.transaction();
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: address,
                permission: "CanInvokeContractEntrypoint".parse().unwrap(),
            }
            .into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut setup)
            .unwrap();
        setup.apply();
        let fragments = block.committed_fragment_count();
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = Executor::Initial
            .execute_transaction(&mut tx, &ALICE_ID, transaction, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err(
                "completed VM must fail artifact export without actual ballot verification",
            );
        assert!(
            matches!(&error, ValidationFail::NotPermitted(reason)
            if reason == "missing ZK_VOTE_VERIFY_BALLOT prior to SubmitBallot"),
            "{error:?}"
        );
        assert!((1..=GAS).contains(&tx.last_tx_gas_used));
        // The exact error comes from post-run artifact validation, before the
        // queued ballot could apply; no proof latch or accepted artifact is seeded.
        assert!(tx.world.elections.get("raw-work-election").is_none());
        drop(tx);
        assert_eq!(block.committed_fragment_count(), fragments);
    }

    fn account_write_program(failing_tail: bool) -> Vec<u8> {
        let key: Name = "raw_work_written".parse().unwrap();
        let missing: Name = "raw_work_missing_role".parse().unwrap();
        let literals = [
            tlv(
                PointerType::AccountId,
                &norito::to_bytes(&*ALICE_ID).unwrap(),
            ),
            tlv(PointerType::Name, &norito::to_bytes(&key).unwrap()),
            tlv(PointerType::Json, &norito::to_bytes(&Json::new(7)).unwrap()),
            tlv(PointerType::Name, &norito::to_bytes(&missing).unwrap()),
        ];
        let mut code = vec![
            wide::encode_literal(opcode::memory::LDLIT, 10, 0),
            wide::encode_literal(opcode::memory::LDLIT, 11, 1),
            wide::encode_literal(opcode::memory::LDLIT, 12, 2),
            wide::encode_sys(
                opcode::system::SCALL,
                u8::try_from(ivm::syscalls::SYSCALL_SET_ACCOUNT_DETAIL).unwrap(),
            ),
        ];
        if failing_tail {
            code.extend([
                wide::encode_literal(opcode::memory::LDLIT, 10, 3),
                wide::encode_sys(
                    opcode::system::SCALL,
                    u8::try_from(ivm::syscalls::SYSCALL_DELETE_ROLE).unwrap(),
                ),
            ]);
        }
        code.push(wide::encode_halt());
        program(&literals, &code)
    }

    #[test]
    fn artifact_application_rejection_retains_work_and_rolls_back_prior_actual_write() {
        let program = account_write_program(true);
        let (vm_result, expected_gas, host) = run_vm(&program, GAS);
        vm_result.expect("the VM completes both real instruction syscalls");
        assert!(expected_gas > 0);
        let artifacts = host.into_execution_artifacts(None).unwrap();
        assert_eq!(artifacts.queued_instructions().len(), 2);
        let state = fixture();
        let transaction = signed(&state, &program, GAS);
        let mut block = next_block(&state);
        let fragments = block.committed_fragment_count();
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        // Authorize the real role instruction so its missing target, not permission admission,
        // tests rollback after the preceding account write.
        tx.world.account_permissions.insert(
            ALICE_ID.clone(),
            BTreeSet::from([executor_permission::role::CanManageRoles.into()]),
        );
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = Executor::Initial
            .execute_transaction(&mut tx, &ALICE_ID, transaction, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("the deferred missing-role instruction must reject after the first write");
        assert!(
            matches!(error, ValidationFail::InstructionFailed(
            iroha_data_model::isi::error::InstructionExecutionError::Find(
                iroha_data_model::query::error::FindError::Role(ref role)))
                if role == &"raw_work_missing_role".parse::<RoleId>().unwrap()),
            "{error:?}"
        );
        assert_eq!(
            tx.world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("raw_work_written"),
            Some(&Json::new(7))
        );
        assert_eq!(tx.last_tx_gas_used, expected_gas);
        drop(tx);
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("raw_work_written")
                .is_none()
        );
        assert_eq!(block.committed_fragment_count(), fragments);
    }

    #[test]
    fn successful_raw_vm_retains_exact_root_work_once_and_applies_actual_artifact() {
        let program = account_write_program(false);
        let (vm_result, expected_gas, _) = run_vm(&program, GAS);
        vm_result.unwrap();
        assert!(expected_gas > 0);
        let state = fixture();
        let transaction = signed(&state, &program, GAS);
        let mut block = next_block(&state);
        let fragments = block.committed_fragment_count();
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::from(transaction.hash_as_entrypoint()));
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        Executor::Initial
            .execute_transaction(&mut tx, &ALICE_ID, transaction, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .unwrap();
        assert_eq!(tx.last_tx_gas_used, expected_gas);
        tx.apply();
        assert_eq!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("raw_work_written"),
            Some(&Json::new(7))
        );
        assert_eq!(block.committed_fragment_count(), fragments + 1);
    }

    #[test]
    fn generic_artifact_group_limit_rejects_before_first_actual_write() {
        let program = account_write_program(true);
        let (vm_result, expected_gas, host) = run_vm(&program, GAS);
        vm_result.expect("actual VM completes both deferred instruction syscalls");
        let artifacts = host.into_execution_artifacts(None).unwrap();
        let instructions = artifacts.queued_instructions();
        assert_eq!(instructions.len(), 2);
        let exact_bytes: u64 = instructions
            .iter()
            .map(|instruction| u64::try_from(instruction.encode().len()).unwrap())
            .sum();
        assert!(exact_bytes > 1);
        let mut cache = IvmCache::new();
        for (count_cap, byte_cap, expected_limit) in [
            (
                1,
                0,
                Some("overlay exceeds max instructions: 2 > 1".to_owned()),
            ),
            (
                0,
                exact_bytes - 1,
                Some(format!(
                    "overlay exceeds max bytes: more than {}",
                    exact_bytes - 1
                )),
            ),
            (2, exact_bytes, None),
        ] {
            let state = fixture();
            let source = signed(&state, &program, GAS);
            let mut block = next_block(&state);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            // Authorize the real role instruction so its missing target, not permission admission,
            // tests rollback after the preceding account write.
            tx.world.account_permissions.insert(
                ALICE_ID.clone(),
                BTreeSet::from([executor_permission::role::CanManageRoles.into()]),
            );
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.overlay_max_instructions = count_cap;
            tx.pipeline.overlay_max_bytes = byte_cap;
            let error = Executor::Initial.execute_transaction(&mut tx, &ALICE_ID, source, &mut cache).map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("the actual group either exceeds admission or reaches its missing-role instruction");
            assert_eq!(
                tx.last_tx_gas_used, expected_gas,
                "cap refusal after a completed VM must retain exactly its real work"
            );
            if let Some(reason) = expected_limit {
                assert!(
                    matches!(&error, ValidationFail::NotPermitted(actual) if actual == &reason),
                    "{error:?}"
                );
                assert!(tx.execution_effect_limit_exceeded());
                assert!(
                    tx.world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("raw_work_written")
                        .is_none(),
                    "the complete exported group is admitted before its first effect"
                );
            } else {
                // The exact boundary passes the real artifact group. Its second
                // instruction then fails through the normal missing-role policy.
                assert!(
                    matches!(&error, ValidationFail::InstructionFailed(
                    iroha_data_model::isi::error::InstructionExecutionError::Find(
                        iroha_data_model::query::error::FindError::Role(role)))
                    if role == &"raw_work_missing_role".parse::<RoleId>().unwrap()),
                    "{error:?}"
                );
                assert!(!tx.execution_effect_limit_exceeded());
                assert_eq!(
                    tx.world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("raw_work_written"),
                    Some(&Json::new(7))
                );
            }
            drop(tx);
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("raw_work_written")
                    .is_none()
            );
            assert_eq!(block.committed_fragment_count(), fragments);
        }
    }

    #[test]
    fn signed_quarantine_cycle_limit_uses_actual_work_and_exact_boolean_classification() {
        let program = account_write_program(false);
        let (independent_result, expected_gas, _) = run_vm(&program, GAS);
        independent_result.unwrap();
        let mut cache = IvmCache::new();
        let mut measured_cycles = None;
        for case in 0..7 {
            let (marker, cap, success, finite) = match case {
                0 => (Some(Json::new(true)), CYCLES, true, true),
                1 => (Some(Json::new(true)), measured_cycles.unwrap(), true, true),
                2 => (
                    Some(Json::new(true)),
                    measured_cycles.unwrap() - 1,
                    false,
                    true,
                ),
                3 => (Some(Json::new(true)), 0, true, false),
                4 => (Some(Json::new(false)), 1, true, false),
                5 => (Some(Json::new("true")), 1, true, false),
                _ => (None, 1, true, false),
            };
            let state = fixture();
            let mut metadata = iroha_model_base::metadata::Metadata::default();
            if let Some(marker) = marker {
                metadata.insert(crate::tx::QUARANTINE_METADATA_KEY.parse().unwrap(), marker);
            }
            let source = TransactionBuilder::new(
                state.network_id,
                ALICE_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(GAS)),
            )
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program.clone())))
            .sign(ALICE_KEYPAIR.private_key());
            let mut block = next_block(&state);
            let fragments = block.committed_fragment_count();
            let mut tx =
                block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.pipeline.quarantine_tx_max_cycles = cap;
            let result = Executor::Initial
                .execute_transaction(&mut tx, &ALICE_ID, source, &mut cache)
                .map_err(crate::execution_attempt::expect_completed_rejection);
            let cycles = tx.completed_execution_cycles_for_tests();
            assert_eq!(cycles.is_some(), finite);
            assert!(
                !tx.execution_effect_limit_exceeded(),
                "actual VM work is not fee-exempt instruction preflight"
            );
            if case == 0 {
                measured_cycles = cycles;
                assert!(cycles.unwrap() > 1);
            }
            if success {
                result.unwrap();
                assert_eq!(tx.last_tx_gas_used, expected_gas);
                if finite {
                    assert_eq!(cycles, measured_cycles);
                }
                tx.apply();
            } else {
                assert!(
                    matches!(result, Err(ValidationFail::NotPermitted(ref reason))
                    if reason == &format!("quarantine cycle budget exceeded: {cap}"))
                );
                assert_eq!(cycles, Some(cap));
                // Only the final, zero-gas HALT is refused. All metered work
                // completed, even though its queued effects cannot be applied.
                assert_eq!(tx.last_tx_gas_used, expected_gas);
                assert!(!tx.execution_effects_allow_apply());
                assert!(
                    tx.world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("raw_work_written")
                        .is_none(),
                    "a queued write cannot apply after HALT was refused"
                );
                drop(tx);
            }
            assert_eq!(
                block.committed_fragment_count(),
                fragments + usize::from(success)
            );
            assert_eq!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("raw_work_written")
                    .is_some(),
                success
            );
        }
    }
}
