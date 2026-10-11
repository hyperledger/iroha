// Native event regressions use a real installed compiler artifact and exact invocation binding.
fn native_event_runtime(source: &str, selector: &str) -> (State, ContractAddress, CoreHost, IVM) {
    let authority = ALICE_ID.clone();
    let state = contract_test_state(&authority);
    let address = install_contract(&state, &authority, source, 601);
    let view = state.view();
    let record = crate::smartcontracts::code::fetch_bound_contract_record(&view, &address)
        .expect("registry read")
        .expect("installed native event artifact");
    let prepared = ivm::prepare_contract(Arc::<[u8]>::from(record.code_bytes.clone()))
        .expect("admitted native event artifact");
    let metadata = ivm::ProgramMetadata::parse(&record.code_bytes).unwrap();
    let entry_pc =
        metadata.prefix_len() as u64 + prepared.entrypoint_descriptor(selector).unwrap().entry_pc;
    let mut host = CoreHost::new(authority);
    host.set_prepared_contract_cache(view.prepared_contract_cache());
    host.bind_authorized_deployed_contract_runtime_context(
        &view, &address, None, &prepared, selector,
    )
    .map_err(crate::execution_attempt::expect_completed_rejection)
    .expect("authorized event entrypoint");
    let mut vm = IVM::new(1_000_000);
    vm.load_program(&record.code_bytes)
        .expect("load exact event artifact");
    vm.set_register(1, vm.memory.code_len());
    vm.set_program_counter(entry_pc).unwrap();
    drop(view);
    (state, address, host, vm)
}

#[test]
fn native_event_capture_preserves_signed_schema_caller_and_mixed_effect_order() {
    let source = r#"
seiyaku NativeEventOrder {
  enum Status { Pending = 1, Accepted = 7 }
  event Changed { Status status; }
  event Started { bool active; }
  kotoage fn run() authorize(anyone) {
    emit Started { active: true };
    ledger::account::set_metadata(account: context::seiyaku_subject(), key: Name::parse("event_marker"), value: Json::parse("true"));
    emit Changed { status: Status::Accepted };
  }
}
"#;
    let (state, address, mut host, mut vm) = native_event_runtime(source, "run");
    vm.run_with_host(&mut host).expect("execute event bytecode");
    assert!(!host.finish_contract_result(&vm).unwrap());
    assert_eq!(host.queued.len(), 3);
    assert!(matches!(
        host.queued[1].payload,
        QueuedEffectPayload::Instruction(_)
    ));
    let mut names = Vec::new();
    for effect in &host.queued {
        if let QueuedEffectPayload::Emission(emission) = &effect.payload {
            let value = &emission.value;
            assert_eq!(value.contract, address);
            assert_eq!(value.caller, *ALICE_ID);
            assert_eq!(value.code_hash, Hash::prehashed(vm.code_hash()));
            assert!(
                emission
                    .metadata_charges
                    .belongs_to(&state.view().execution_budget())
            );
            assert!(
                emission
                    .value_charges
                    .belongs_to(&state.view().execution_budget())
            );
            HostExecutionArtifacts::validate_emission_provenance(
                state.view().world(),
                value,
                effect.contract_runtime_context.as_ref(),
                effect.entrypoint_authorization.as_ref(),
            )
            .unwrap();
            names.push(value.definition.name.to_string());
            let rendered = ivm::value_record::render_entrypoint_return_record(
                &value.definition.payload_type,
                &value.payload,
            )
            .unwrap();
            if value.definition.name.as_ref() == "Changed" {
                assert_eq!(rendered, norito::json!({"status":"Accepted"}));
                assert_eq!(value.event, 0, "ordinal follows signed declaration order");
            } else {
                assert_eq!(rendered, norito::json!({"active":true}));
                assert_eq!(value.event, 1);
            }
        }
    }
    assert_eq!(
        names,
        ["Started", "Changed"],
        "execution order differs from declaration order"
    );
    let first = &host.queued[0];
    let QueuedEffectPayload::Emission(emission) = &first.payload else {
        unreachable!()
    };
    let mut forged = emission.value.clone();
    forged.event = 0;
    assert!(
        HostExecutionArtifacts::validate_emission_provenance(
            state.view().world(),
            &forged,
            first.contract_runtime_context.as_ref(),
            first.entrypoint_authorization.as_ref()
        )
        .is_err()
    );
    forged = emission.value.clone();
    forged.caller = BOB_ID.clone();
    assert!(
        HostExecutionArtifacts::validate_emission_provenance(
            state.view().world(),
            &forged,
            first.contract_runtime_context.as_ref(),
            first.entrypoint_authorization.as_ref()
        )
        .is_err()
    );
}

#[test]
fn native_event_result_error_destroys_emission_graph_and_original_credit() {
    let source = r#"
seiyaku RejectedNativeEvent {
  error enum Reason { Refused = 1 }
  event Staged { bool active; }
  kotoage fn run() authorize(anyone) -> Result<(), Reason> {
    emit Staged { active: true };
    return Result::err(Reason::Refused);
  }
}
"#;
    let (state, _, mut host, mut vm) = native_event_runtime(source, "run");
    let budget = state.view().execution_budget();
    let before = budget.reserved_bytes();
    vm.run_with_host(&mut host).unwrap();
    assert_eq!(host.queued.len(), 1);
    assert!(budget.reserved_bytes() > before);
    assert!(host.finish_contract_result(&vm).unwrap());
    assert!(host.queued.is_empty());
    assert_eq!(
        budget.reserved_bytes(),
        before,
        "rollback releases every original event allocation"
    );
}

#[test]
fn native_event_rejects_invalid_ordinal_boolean_and_unauthenticated_context_before_capture() {
    let source = r#"
seiyaku GuardedNativeEvent {
  event Changed { bool flag; }
  kotoage fn run() authorize(anyone) {}
}
"#;
    let (state, _, mut host, mut vm) = native_event_runtime(source, "run");
    let budget = state.view().execution_budget();
    let base = vm.alloc_heap(8).unwrap();
    vm.store_u64(base, 1).unwrap();
    vm.set_register(10, 1);
    vm.set_register(11, base);
    vm.set_register(12, 1);
    let before = budget.reserved_bytes();
    assert_eq!(
        host.prepare_syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &vm),
        Err(ivm::VMError::DecodeError)
    );
    assert!(host.queued.is_empty());
    vm.set_register(10, 0);
    vm.store_u64(base, 2).unwrap();
    assert!(
        host.syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &mut vm)
            .is_err()
    );
    assert!(host.queued.is_empty());
    assert_eq!(budget.reserved_bytes(), before);
    vm.store_u64(base, 1).unwrap();
    host.execution_class = HostExecutionClass::View;
    assert_eq!(
        host.prepare_syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &vm),
        Err(ivm::VMError::PermissionDenied)
    );
    host.execution_class = HostExecutionClass::Contract;
    host.current_entrypoint_authorization = None;
    assert_eq!(
        host.prepare_syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &vm),
        Err(ivm::VMError::PermissionDenied)
    );
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn native_event_private_operands_and_foreign_program_cannot_capture() {
    let source = r#"
seiyaku PrivateEventOperands {
  event Changed { bool flag; }
  kotoage fn run() authorize(anyone) {}
}
"#;
    let (state, _, mut host, mut vm) = native_event_runtime(source, "run");
    let table = vm.alloc_heap(8).unwrap();
    vm.store_u64(table, 1).unwrap();
    vm.set_register(10, 0);
    vm.set_register(11, table);
    vm.set_register(12, 1);
    vm.set_zk_mode(true).unwrap();
    let budget = state.view().execution_budget();
    let before = budget.reserved_bytes();
    for register in [10, 11, 12] {
        vm.registers.set_tag(register, true);
        assert_eq!(
            host.prepare_syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &vm),
            Err(ivm::VMError::PrivacyViolation)
        );
        assert!(host.queued.is_empty());
        assert_eq!(budget.reserved_bytes(), before);
        vm.registers.set_tag(register, false);
    }
    vm.set_zk_mode(false).unwrap();
    let authorization = host.current_entrypoint_authorization.as_mut().unwrap();
    authorization.code_hash = Hash::new(b"different authenticated program");
    assert_eq!(
        host.prepare_syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &vm),
        Err(ivm::VMError::PermissionDenied)
    );
    assert!(host.queued.is_empty());
}

#[test]
fn native_event_local_capacity_refusal_has_no_effect_and_retries_with_original_budget() {
    let source = r#"
seiyaku EventCapacity {
  event Changed { bool flag; }
  kotoage fn run() authorize(anyone) {}
}
"#;
    let (state, _, mut host, mut vm) = native_event_runtime(source, "run");
    let table = vm.alloc_heap(8).unwrap();
    vm.store_u64(table, 1).unwrap();
    vm.set_register(10, 0);
    vm.set_register(11, table);
    vm.set_register(12, 1);
    let budget = state.view().execution_budget();
    let before = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    budget.set_limit_bytes(before);
    let error = host
        .syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &mut vm)
        .unwrap_err();
    assert!(error.execution_deferral().is_some(), "{error:?}");
    assert!(host.queued.is_empty());
    assert_eq!(budget.reserved_bytes(), before);
    budget.set_limit_bytes(limit);
    host.syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &mut vm)
        .unwrap();
    assert_eq!(host.queued.len(), 1);
    let QueuedEffectPayload::Emission(emission) = &host.queued[0].payload else {
        panic!("native emission")
    };
    assert!(emission.metadata_charges.belongs_to(&budget));
    assert!(emission.value_charges.belongs_to(&budget));
    host.queued.clear();
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn native_event_preparation_does_not_traverse_guest_values_before_gas_reservation() {
    let source = "seiyaku MeteredEvent { event Changed { bool flag; } kotoage fn run() authorize(anyone) {} }";
    let (_, _, mut host, mut vm) = native_event_runtime(source, "run");
    vm.set_register(10, 0);
    vm.set_register(11, u64::MAX);
    vm.set_register(12, 1);
    vm.set_gas_limit(32);
    assert_eq!(
        host.prepare_syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &vm)
            .unwrap(),
        32
    );
    // A malformed table is examined during execution and retains its quote work.
    let error = host
        .syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &mut vm)
        .unwrap_err();
    assert_eq!(error.as_unmetered(), &ivm::VMError::DecodeError);
    assert_eq!(error.metered_gas(), Some(32));
    assert!(host.queued.is_empty());
    let base = vm.alloc_heap(8).unwrap();
    vm.store_u64(base, 1).unwrap();
    vm.set_register(11, base);
    let error = host
        .syscall(ivm_sys::SYSCALL_EMIT_CONTRACT_EVENT, &mut vm)
        .unwrap_err();
    assert_eq!(error.as_unmetered(), &ivm::VMError::OutOfGas);
    assert_eq!(error.metered_gas(), Some(32));
    assert!(host.queued.is_empty());
}
