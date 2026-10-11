#[test]
fn state_syscall_works_without_access_logging() {
    let authority: AccountId = fixture_account("alice");
    let mut host = local_contract_host(authority);
    let mut vm = IVM::new(10_000);
    let path: StatePath = "counter".parse().unwrap();
    let path_ptr = store_state_path_tlv(&mut vm, &path);
    let value_bytes = norito::to_bytes(&1_u64).expect("encode state value");
    let value_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &value_bytes);
    vm.set_register(10, path_ptr);
    vm.set_register(11, value_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_SET, &mut vm),
        Ok(test_state_value_gas(&path, value_bytes.len())),
        "STATE_SET should succeed without access logging"
    );
    vm.set_register(10, path_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_GET, &mut vm),
        Ok(test_state_value_gas(&path, value_bytes.len())),
        "STATE_GET should succeed without access logging"
    );
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("state get tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let value: u64 = norito::decode_from_bytes(tlv.payload).expect("decode state value");
    assert_eq!(value, 1);
}
#[test]
fn state_set_budget_exhaustion_traps_without_staging_a_write() {
    let authority: AccountId = fixture_account("alice");
    let mut host = local_contract_host(authority);
    host.restrict_output_limits(HostOutputLimits::new(0, u64::MAX));
    let mut vm = IVM::new(10_000);
    let path: StatePath = "counter".parse().expect("valid state path");
    let path_ptr = store_state_path_tlv(&mut vm, &path);
    let value_bytes = norito::to_bytes(&1_u64).expect("encode state value");
    let value_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &value_bytes);
    vm.set_register(10, path_ptr);
    vm.set_register(11, value_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_SET, &mut vm),
        Err(ivm::VMError::HostOutputBudgetExceeded {
            resource: ivm::HostOutputResource::Items,
            attempted: 1,
            limit: 0,
        })
    );
    assert!(
        host.durable_state_overlay.is_empty(),
        "a rejected durable write must not be staged"
    );
}

// Existing namespace and generic/debug state boundary tests, included in host::tests.
#[test]
fn reserve_namespace_syscalls_preserve_reads_but_refuse_raw_mutations() {
    let authority = fixture_account("alice");
    for text in [
        "sorafs_reserve_state_v1",
        "sorafs_reserve_provider_v1_00",
        "sorafs_reserve_movement_v1_00",
        "sorafs_reserve_appeal_v1_00",
        "sorafs_reserve_event_v1_0001",
        "sorafs_reserve_unknown_record",
    ] {
        let path: StatePath = text.parse().unwrap();
        let original = norito::to_bytes(&7_u64).unwrap();
        // Local-debug execution reaches the lower-level namespace admission. Ordinary generic
        // execution separately forbids all durable syscalls; this test grants no on-chain scope.
        let mut host = local_contract_host(authority.clone());
        host.set_durable_state_snapshot(BTreeMap::from([(path.clone(), original.clone())]));
        let mut vm = IVM::new(10_000);
        let path_ptr = store_state_path_tlv(&mut vm, &path);
        let value_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &original);
        for syscall in [ivm_sys::SYSCALL_STATE_SET, ivm_sys::SYSCALL_STATE_DEL] {
            vm.set_register(10, path_ptr);
            vm.set_register(11, value_ptr);
            assert_eq!(
                host.syscall(syscall, &mut vm),
                Err(ivm::VMError::PermissionDenied),
                "{text} syscall {syscall}"
            );
            assert!(host.durable_state_overlay.is_empty());
        }
        vm.set_register(10, path_ptr);
        host.syscall(ivm_sys::SYSCALL_STATE_GET, &mut vm)
            .expect("existing reserve read policy is unchanged");
        let value = vm.memory.validate_tlv(vm.register(10)).unwrap();
        assert_eq!(value.payload, original.as_slice());
    }
}

#[test]
fn reserve_namespace_syscalls_allow_adjacent_user_keys() {
    for text in [
        "sorafs_reserve",
        "sorafs_reserve/user",
        "sorafs_reservex_state_v1",
    ] {
        let path: StatePath = text.parse().unwrap();
        let mut host = local_contract_host(fixture_account("alice"));
        let mut vm = IVM::new(10_000);
        let path_ptr = store_state_path_tlv(&mut vm, &path);
        let original = norito::to_bytes(&7_u64).unwrap();
        let value_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &original);
        vm.set_register(10, path_ptr);
        vm.set_register(11, value_ptr);
        host.syscall(ivm_sys::SYSCALL_STATE_SET, &mut vm)
            .expect("adjacent ordinary key remains writable");
        assert_eq!(host.durable_state_overlay.get(&path), Some(&Some(original)));
        vm.set_register(10, path_ptr);
        host.syscall(ivm_sys::SYSCALL_STATE_DEL, &mut vm)
            .expect("adjacent ordinary key remains deletable");
        assert_eq!(host.durable_state_overlay.get(&path), Some(&None));
    }
}

#[test]
fn reserve_namespace_retained_host_artifacts_refuse_before_any_effect() {
    let authority = fixture_account("alice");
    let state = contract_test_state(&authority);
    let mut block = state.block(BlockHeader::new(
        (u64::try_from(state.view().height()).unwrap() + 1)
            .try_into()
            .unwrap(),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    for text in ["sorafs_reserve_state_v1", "sorafs_reserve_event_v1_0001"] {
        for replacement in [Some(vec![8]), None] {
            let path: StatePath = text.parse().unwrap();
            let ordinary: StatePath = "ordinary_before_reserve".parse().unwrap();
            let metadata: Name = "reserve_artifact_must_not_apply".parse().unwrap();
            let original = vec![7];
            let mut tx = block.transaction();
            tx.world
                .smart_contract_state
                .insert(path.clone(), original.clone());
            bind_artifact_test_signed_root(&mut tx, &authority);
            // Deliberately model a retained artifact that bypassed syscall admission. This is
            // data supplied to the production application owner, not native reserve authority.
            let writes = BTreeMap::from([
                (ordinary.clone(), Some(vec![1])),
                (path.clone(), replacement),
            ]);
            let artifacts = HostExecutionArtifacts {
                queued: vec![QueuedEffect {
            payload: crate::smartcontracts::ivm::host::QueuedEffectPayload::Instruction(SetKeyValue::account(
                        authority.clone(),
                        metadata.clone(),
                        Json::new(true),
                    )
                    .into()),
                    authority: authority.clone(),
                    contract_runtime_context: None,
                    entrypoint_authorization: None,
                }],
                entrypoint_authorization: None,
                confidential_gas_delta: 7,
                completed_axt: Vec::new(),
                durable_state_authorizations: writes
                    .keys()
                    .cloned()
                    .map(|key| (key, None))
                    .collect(),
                durable_state_overlay: writes,
            };
            let error = artifacts
                .apply_to_transaction(&mut tx, &authority)
                .unwrap_err();
            assert!(
                matches!(error, ValidationFail::NotPermitted(reason) if reason.contains("native reserve state"))
            );
            assert_eq!(tx.world.smart_contract_state.get(&path), Some(&original));
            assert!(tx.world.smart_contract_state.get(&ordinary).is_none());
            assert!(
                tx.world
                    .account(&authority)
                    .unwrap()
                    .metadata()
                    .get(&metadata)
                    .is_none()
            );
            assert_eq!(tx.confidential_gas_used_in_tx, 0);
            tx.finish_execution_effect_budget().unwrap();
        }
    }
    for replacement in [Some(vec![8]), None] {
        let path: StatePath = "sorafs_reservex_state_v1".parse().unwrap();
        let mut tx = block.transaction();
        tx.world.smart_contract_state.insert(path.clone(), vec![7]);
        bind_artifact_test_signed_root(&mut tx, &authority);
        let artifacts = HostExecutionArtifacts {
            queued: Vec::new(),
            entrypoint_authorization: None,
            confidential_gas_delta: 0,
            completed_axt: Vec::new(),
            durable_state_authorizations: BTreeMap::from([(path.clone(), None)]),
            durable_state_overlay: BTreeMap::from([(path.clone(), replacement.clone())]),
        };
        artifacts
            .apply_to_transaction(&mut tx, &authority)
            .expect("adjacent ordinary artifacts still apply");
        assert_eq!(
            tx.world.smart_contract_state.get(&path),
            replacement.as_ref()
        );
        tx.finish_execution_effect_budget().unwrap();
    }
}

#[test]
fn contract_state_namespace_access_covers_consensus_owned_prefixes() {
    for key in [
        "retail_day_policy_v1",
        "retail_day_policy_v1/deadbeef/7",
        "retail_day_activation_v1/deadbeef",
        "retail_day_identity_v1/deadbeef/7/cafebabe",
        "retail_day_usage_v1/deadbeef/7/cafebabe/86400000",
        "retail_day_monetary_operation_v1/deadbeef/cafebabe",
        "sc",
        "sc/0123456789abcdef/counter",
        "da_ingest_quota_v1",
        "da_ingest_quota_v1/authority/deadbeef",
        "faucet_claim_consumed_v1",
        "faucet_claim_consumed_v1/deadbeef",
        "merge_execution_batch_applied_1_deadbeef",
        "merge_execution_lane_applied_1_2_3_deadbeef",
        "merge_lane_frontier_v1",
        "merge_lane_frontier_v1_1_2_deadbeef",
        "queue_plan_admission_v2_deadbeef_cafebabe",
        "queue_plan_pending_obligation_v1_deadbeef_cafebabe",
        "queue_plan_pending_route_member_v1_0_0_deadbeef_cafebabe",
        "queue_plan_pending_signed_alias_member_v1_deadbeef_cafebabe_deadbeef",
        "queue_plan_signed_alias_terminal_v1_deadbeef_cafebabe",
        "nexus_fee_receipt_settled_deadbeef",
        "nexus_fee_settlement_settled_1_2_3_deadbeef",
        "sealed_tx_commitment_deadbeef",
    ] {
        assert_eq!(
            CoreHost::contract_state_namespace_access(key),
            ContractStateNamespaceAccess::OpaqueSystem,
            "{key} must remain opaque to generic contract state syscalls"
        );
    }
    for key in [
        "pkdeploy_verified_lane_relay",
        "pkdeploy_verified_lane_relay_1_2_3_deadbeef",
        "pkdeploy_verified_nexus_fee_budget_deadbeef",
        "pkdeploy_verified_fee_sponsor_vault_allocation",
        "pkdeploy_verified_fee_sponsor_vault_allocation_deadbeef",
        "pkdeploy_fee_sponsor_vault_allocation_usage",
        "pkdeploy_fee_sponsor_vault_allocation_usage_deadbeef",
        "pkdeploy_fee_sponsor_vault_allocation_settled_usage",
        "pkdeploy_fee_sponsor_vault_allocation_settled_usage_deadbeef",
        "VerifiedLaneRelays",
        "VerifiedLaneRelays/deadbeef",
    ] {
        assert_eq!(
            CoreHost::contract_state_namespace_access(key),
            ContractStateNamespaceAccess::ReadOnlySystem,
            "{key} is public contract state but must remain native-authored"
        );
    }
    for key in [
        "retail_day_policy_v1x/deadbeef",
        "retail_day_activation_v1x/deadbeef",
        "retail_day_identity_v1x/deadbeef",
        "retail_day_usage_v1x/deadbeef",
        "retail_day_monetary_operation_v1x/deadbeef",
        "scatter/counter",
        "da_ingest_quota_v1x",
        "faucet_claim_consumed_v1x",
        "merge_lane_frontier_v1x",
        "queue_plan_admission_v2x",
        "queue_plan_pending_obligation_v1x",
        "queue_plan_pending_route_member_v1x",
        "queue_plan_pending_signed_alias_member_v1x",
        "queue_plan_signed_alias_terminal_v1x",
        "pkdeploy_verified_lane_relayx",
        "pkdeploy_verified_fee_sponsor_vault_allocationx",
        "pkdeploy_fee_sponsor_vault_allocation_usagex",
        "pkdeploy_fee_sponsor_vault_allocation_settled_usagex",
        "counter",
    ] {
        assert_eq!(
            CoreHost::contract_state_namespace_access(key),
            ContractStateNamespaceAccess::User,
            "delimiter-aware matching must not reserve similarly named user state"
        );
    }
}

#[test]
fn retail_daily_state_paths_reject_generic_read_write_and_delete_admission() {
    for root in [
        crate::state::retail_daily_limit_state::POLICY_ROOT,
        crate::state::retail_daily_limit_state::ACTIVATION_ROOT,
        crate::state::retail_daily_limit_state::IDENTITY_ROOT,
        crate::state::retail_daily_limit_state::USAGE_ROOT,
        crate::state::retail_daily_limit_state::MONETARY_OPERATION_ROOT,
    ] {
        let path: StatePath = format!("{root}deadbeef/7")
            .parse()
            .expect("bounded native retail path");
        assert_eq!(
            CoreHost::ensure_contract_state_read_allowed(&path),
            Err(ivm::VMError::PermissionDenied),
            "raw and contract-scoped STATE_GET/SCAN must hide {path}"
        );
        assert_eq!(
            CoreHost::ensure_contract_state_write_allowed(&path),
            Err(ivm::VMError::PermissionDenied),
            "raw and contract-scoped STATE_SET/DEL must reject {path}"
        );
    }
}
#[test]
fn verified_fee_sponsor_state_is_readable_but_not_generically_mutable() {
    let paths = [
        format!(
            "{VERIFIED_FEE_SPONSOR_VAULT_ALLOCATION_STATE_KEY_PREFIX}_{}",
            "11".repeat(32)
        ),
        format!(
            "{VERIFIED_FEE_SPONSOR_VAULT_ALLOCATION_USAGE_STATE_KEY_PREFIX}_{}",
            "22".repeat(32)
        ),
        format!(
            "{VERIFIED_FEE_SPONSOR_VAULT_ALLOCATION_SETTLED_USAGE_STATE_KEY_PREFIX}_{}",
            "33".repeat(32)
        ),
    ]
    .map(|key| key.parse::<StatePath>().expect("fee sponsor system key"));
    let value = norito::to_bytes(&42_u64).expect("encode public record fixture");
    let mut world = World::new();
    for path in &paths {
        world
            .smart_contract_state
            .insert(path.clone(), value.clone());
    }
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    super::pointer_abi_tests::establish_authenticated_axt_ledger_time(&state, 1);
    let mut host =
        CoreHost::from_state(fixture_account("alice"), &state).expect("canonical state snapshots");
    host.set_local_contract_debug_execution();
    let mut vm = IVM::new(100_000);
    for path in &paths {
        let path_ptr = store_state_path_tlv(&mut vm, path);
        vm.set_register(10, path_ptr);
        host.syscall(ivm_sys::SYSCALL_STATE_GET, &mut vm)
            .expect("verified fee sponsor state remains readable");
        let value_tlv = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("verified fee sponsor value TLV");
        assert_eq!(
            norito::decode_from_bytes::<u64>(value_tlv.payload)
                .expect("decode public fee sponsor record"),
            42
        );
        let forged = norito::to_bytes(&99_u64).expect("encode forged record fixture");
        let value_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &forged);
        vm.set_register(10, path_ptr);
        vm.set_register(11, value_ptr);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_STATE_SET, &mut vm),
            Err(ivm::VMError::PermissionDenied),
            "{path} must be native-authored"
        );
        vm.set_register(10, path_ptr);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_STATE_DEL, &mut vm),
            Err(ivm::VMError::PermissionDenied),
            "{path} must not be deleted generically"
        );
    }
    assert!(
        host.durable_state_overlay.is_empty(),
        "rejected fee sponsor state mutations must not be staged"
    );
}
#[test]
fn state_syscall_unscoped_overlay_overrides_base_value_without_context() {
    let mut world = World::new();
    let path: StatePath = "counter".parse().unwrap();
    world.smart_contract_state.insert(
        path.clone(),
        norito::to_bytes(&7_u64).expect("encode base state value"),
    );
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    super::pointer_abi_tests::establish_authenticated_axt_ledger_time(&state, 1);
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::from_state(authority, &state).expect("canonical state snapshots");
    host.set_local_contract_debug_execution();
    let mut vm = IVM::new(10_000);
    let path_ptr = store_state_path_tlv(&mut vm, &path);
    let value_ptr = store_tlv(
        &mut vm,
        PointerType::NoritoBytes,
        &norito::to_bytes(&22_u64).expect("encode overlay state value"),
    );
    vm.set_register(10, path_ptr);
    vm.set_register(11, value_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_SET, &mut vm),
        Ok(test_state_value_gas(
            &path,
            norito::to_bytes(&22_u64)
                .expect("encode overlay state value")
                .len()
        )),
        "STATE_SET should stage an unscoped overlay value without runtime context"
    );
    vm.set_register(10, path_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_GET, &mut vm),
        Ok(test_state_value_gas(
            &path,
            norito::to_bytes(&22_u64)
                .expect("encode overlay state value")
                .len()
        )),
        "unscoped overlay should override the persisted base value"
    );
    let tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("overlay state tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let value: u64 = norito::decode_from_bytes(tlv.payload).expect("decode overlay state");
    assert_eq!(value, 22);
    let overlay = host.drain_durable_state_overlay();
    let stored = overlay
        .get(&path)
        .and_then(Option::as_ref)
        .expect("unscoped overlay entry");
    let stored_value: u64 =
        norito::decode_from_bytes(stored).expect("decode raw persisted overlay state");
    assert_eq!(stored_value, 22);
}
#[test]
fn state_syscall_unscoped_delete_shadows_base_value_without_context() {
    let mut world = World::new();
    let path: StatePath = "counter".parse().unwrap();
    world.smart_contract_state.insert(
        path.clone(),
        norito::to_bytes(&7_u64).expect("encode base state value"),
    );
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    super::pointer_abi_tests::establish_authenticated_axt_ledger_time(&state, 1);
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::from_state(authority, &state).expect("canonical state snapshots");
    host.set_local_contract_debug_execution();
    let mut vm = IVM::new(10_000);
    let path_ptr = store_state_path_tlv(&mut vm, &path);
    vm.set_register(10, path_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_DEL, &mut vm),
        Ok(test_state_path_gas(&path)),
        "STATE_DEL should stage an unscoped tombstone without runtime context"
    );
    vm.set_register(10, path_ptr);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_STATE_GET, &mut vm),
        Ok(test_state_path_gas(&path)),
        "unscoped tombstone should shadow the persisted base value"
    );
    assert_eq!(vm.register(10), 0);
    let overlay = host.drain_durable_state_overlay();
    assert_eq!(
        overlay.len(),
        1,
        "unscoped delete should only record one tombstone"
    );
    assert_eq!(overlay.get(&path), Some(&None));
}
#[test]
fn generic_ivm_host_rejects_all_durable_state_access() {
    let authority: AccountId = fixture_account("alice");
    for prefix in [
        "sc",
        crate::smartcontracts::code::CONTRACT_LIFECYCLE_STATE_PREFIX,
        "sns",
        "sealed",
        "system",
    ] {
        let mut host = CoreHost::new(authority.clone());
        host.set_generic_execution();
        let mut vm = IVM::new(10_000);
        let suffix = if prefix == "sc" { "/secret" } else { "" };
        let reserved_path: StatePath = format!("{prefix}/{}{suffix}", "00".repeat(Hash::LENGTH))
            .parse()
            .expect("valid reserved state path");
        let path_ptr = store_state_path_tlv(&mut vm, &reserved_path);
        let value_ptr = store_tlv(
            &mut vm,
            PointerType::NoritoBytes,
            &norito::to_bytes(&7_u64).expect("encode state value"),
        );
        vm.set_register(10, path_ptr);
        vm.set_register(11, value_ptr);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_STATE_SET, &mut vm),
            Err(ivm::VMError::GenericSyscallNotAllowed {
                syscall: ivm_sys::SYSCALL_STATE_SET,
            }),
            "generic IVM must not write `{prefix}`"
        );
        assert!(host.durable_state_overlay.is_empty());
        vm.set_register(10, path_ptr);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_STATE_GET, &mut vm),
            Err(ivm::VMError::GenericSyscallNotAllowed {
                syscall: ivm_sys::SYSCALL_STATE_GET,
            }),
            "generic IVM must not read `{prefix}`"
        );
        vm.set_register(10, path_ptr);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_STATE_DEL, &mut vm),
            Err(ivm::VMError::GenericSyscallNotAllowed {
                syscall: ivm_sys::SYSCALL_STATE_DEL,
            }),
            "generic IVM must not tombstone `{prefix}`"
        );
        let reserved_prefix: StatePath = prefix.parse().expect("valid reserved state prefix");
        let prefix_ptr = store_state_path_tlv(&mut vm, &reserved_prefix);
        vm.set_register(10, prefix_ptr);
        vm.set_register(11, 0);
        vm.set_register(12, ivm_sys::STATE_SCAN_MAX_ITEMS_V1);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_STATE_SCAN, &mut vm),
            Err(ivm::VMError::GenericSyscallNotAllowed {
                syscall: ivm_sys::SYSCALL_STATE_SCAN,
            }),
            "generic IVM must not enumerate `{prefix}`"
        );
    }
}

#[test]
fn state_get_reserves_exact_available_gas_for_base_overlay_miss_and_tombstone() {
    use ivm::state_value::{
        StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
        StateValueSchemaV1, state_value_schema_hash_v1,
    };
    let path: StatePath = "small".parse().expect("state path");
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Bool)],
    };
    let value = norito::to_bytes(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&norito::to_bytes(&schema).expect("state schema")),
        atoms: vec![StateValueAtomV1::Bool(true)],
    })
    .expect("canonical state value");
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm_sys::SYSCALL_STATE_GET as u8,
    );
    let program = build_authenticated_test_contract_program_with_states(
        &syscall.to_le_bytes(),
        0,
        false,
        vec![ivm::EmbeddedStateDescriptor {
            name: path.to_string(),
            ty: ivm::EmbeddedStateType::Bool,
        }],
    );
    let code_offset = ivm::ProgramMetadata::parse(&program)
        .expect("parse program")
        .code_offset;
    let instruction_gas = program[code_offset..]
        .chunks_exact(4)
        .map(|word| ivm::gas::cost_of(u32::from_le_bytes(word.try_into().unwrap())).unwrap())
        .sum::<u64>();
    // The authenticated fixture returns one Unit table slot. Its schema node and
    // word validation are charged separately from the emitted JALR instruction.
    let return_table_gas = ivm::call_gas::NODE + ivm::call_gas::WORD;
    let root_table_gas = authenticated_test_probe_setup_gas()
        - authenticated_test_probe_prologue()
            .into_iter()
            .map(|word| ivm::gas::cost_of(word).unwrap())
            .sum::<u64>();
    for source in ["base", "overlay", "missing", "tombstone"] {
        for affordable in [false, true] {
            let present = matches!(source, "base" | "overlay");
            let actual = test_state_value_gas(&path, if present { value.len() } else { 0 });
            let limit = if affordable {
                root_table_gas + instruction_gas + return_table_gas + actual + 7
            } else {
                authenticated_test_probe_setup_gas() + ivm::gas::cost_of(syscall).unwrap() + actual
                    - 1
            };
            assert!(limit < ivm_sys::STATE_MAX_VALUE_BYTES as u64);
            let mut host = local_contract_host(fixture_account("alice")).with_access_logging();
            if matches!(source, "base" | "overlay" | "tombstone") {
                host.durable_state_base.insert(path.clone(), value.clone());
            }
            if source == "overlay" {
                host.durable_state_base.insert(path.clone(), vec![0xff]);
                host.durable_state_overlay
                    .insert(path.clone(), Some(value.clone()));
            } else if source == "tombstone" {
                host.durable_state_overlay.insert(path.clone(), None);
            }
            let base_before = host.durable_state_base.clone();
            let overlay_before = host.durable_state_overlay.clone();
            let mut vm = IVM::new(limit);
            vm.load_program(&program)
                .expect("load actual authenticated read program");
            let path_ptr = store_state_path_tlv(&mut vm, &path);
            vm.set_register(14, path_ptr);
            vm.set_register(15, 0xfeed);
            let input_before = store_tlv(&mut vm, PointerType::Blob, b"before");
            let result = vm.run_with_host(&mut host);
            assert_eq!(host.durable_state_base, base_before);
            assert_eq!(host.durable_state_overlay, overlay_before);
            assert!(host.queued.is_empty());
            if affordable {
                result.expect("the exact bounded read fits the original caller's gas");
                assert_eq!(vm.remaining_gas(), 7);
                assert!(host.state_access_log.read_keys.contains(path.as_ref()));
                let output = authenticated_test_probe_result(&vm);
                if present {
                    let tlv = vm.validate_tlv(output).expect("canonical read output");
                    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
                    assert_eq!(tlv.payload, value.as_slice());
                } else {
                    assert_eq!(output, 0);
                }
            } else {
                assert_eq!(result, Err(ivm::VMError::OutOfGas));
                assert_eq!(vm.register(10), path_ptr);
                assert_eq!(vm.register(11), 0xfeed);
                assert!(host.state_access_log.read_keys.is_empty());
                assert!(host.state_access_log.durable_read_paths.is_empty());
                assert_eq!(vm.remaining_gas(), if present { 0 } else { actual - 1 });
                let input_after = store_tlv(&mut vm, PointerType::Blob, b"after");
                let before_len = make_tlv(PointerType::Blob as u16, b"before").len() as u64;
                assert_eq!(input_after, input_before + before_len.next_multiple_of(8));
            }
        }
    }
}
