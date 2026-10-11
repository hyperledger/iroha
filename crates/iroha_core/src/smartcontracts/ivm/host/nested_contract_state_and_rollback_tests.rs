#[test]
fn nested_state_reads_log_the_callee_scope_not_only_the_root_scope() {
    let authority: AccountId = fixture_account("alice");
    let state = contract_test_state(&authority);
    let caller_contract = install_contract(
        &state,
        &authority,
        r#"
seiyaku Caller {
  view fn main() authorize(anyone) -> int { return 0; }
}
"#,
        0,
    );
    let callee_contract = install_contract(
        &state,
        &authority,
        r#"
seiyaku Callee {
  state StateMap<int, int> Values;

  view fn value() authorize(anyone) -> int {
    return Values.get(1).unwrap_or(0);
  }
}
"#,
        1,
    );
    let (result, log) = call_contract_syscall_access_log(
        &state,
        &authority,
        &caller_contract,
        &callee_contract,
        "value",
        Json::new(()),
    );
    result.expect("nested StateMap read");
    let logical_path = log
        .read_keys
        .iter()
        .find(|key| key.starts_with("Values/"))
        .expect("StateMap read key must be logged");
    assert!(
        !log.durable_read_paths.contains(logical_path),
        "deployed contracts must not read the raw unscoped namespace"
    );
    let callee_digest = hex::encode(Hash::new(callee_contract.to_string().as_bytes()).as_ref());
    let caller_digest = hex::encode(Hash::new(caller_contract.to_string().as_bytes()).as_ref());
    assert!(
        log.durable_read_paths
            .contains(&format!("sc/{callee_digest}/{logical_path}")),
        "selective retry must fingerprint the actual nested contract namespace"
    );
    assert!(
        !log.durable_read_paths
            .contains(&format!("sc/{caller_digest}/{logical_path}")),
        "nested reads must not be mislabeled as root-contract state"
    );
}
#[test]
fn nested_view_rollback_preserves_reads_but_discards_writes() {
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::new(authority).with_access_logging();
    host.state_access_log.durable_read_paths_complete = true;
    let key: StatePath = "counter".parse().expect("state key");
    host.durable_state_overlay
        .insert(key.clone(), Some(vec![1]));
    let snapshot = host.snapshot_nested_contract_call();
    host.stage_durable_state_update(key.clone(), Some(vec![9]));
    host.log_state_read_key(key.as_ref());
    host.log_state_write_key(key.as_ref());
    host.finish_nested_contract_call(snapshot, NestedContractCallOutcome::RollbackPreservingReads)
        .expect("roll back view effects");
    assert_eq!(
        host.durable_state_overlay.get(&key),
        Some(&Some(vec![1])),
        "view state writes must not escape"
    );
    assert!(host.state_access_log.read_keys.contains(key.as_ref()));
    assert!(
        host.state_access_log
            .durable_read_paths
            .contains(key.as_ref())
    );
    assert!(!host.state_access_log.write_keys.contains(key.as_ref()));
    assert!(host.state_access_log.state_writes.is_empty());
}
#[test]
fn failed_nested_call_discards_reads_and_composed_state_changes() {
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::new(authority).with_access_logging();
    host.state_access_log.durable_read_paths_complete = true;
    let key: StatePath = "counter".parse().expect("state key");
    host.durable_state_overlay
        .insert(key.clone(), Some(vec![1]));
    let outer = host.snapshot_nested_contract_call();
    host.stage_durable_state_update(key.clone(), Some(vec![2]));
    let inner = host.snapshot_nested_contract_call();
    host.stage_durable_state_update(key.clone(), Some(vec![3]));
    host.log_state_read_key(key.as_ref());
    host.finish_nested_contract_call(inner, NestedContractCallOutcome::Commit)
        .expect("commit inner call into outer frame");
    assert_eq!(host.durable_state_overlay.get(&key), Some(&Some(vec![3])));
    host.finish_nested_contract_call(outer, NestedContractCallOutcome::Rollback)
        .expect("roll back outer call");
    assert_eq!(host.durable_state_overlay.get(&key), Some(&Some(vec![1])));
    assert!(!host.state_access_log.read_keys.contains(key.as_ref()));
    assert!(host.state_access_log.durable_read_paths.is_empty());
}
#[test]
fn nested_snapshot_shares_large_rollback_state_until_mutated() {
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::new(authority);
    let verified_ballot = Arc::clone(&host.zk_verified_ballot);
    let proof_cache = Arc::clone(&host.axt_proof_cache);
    host.fastpq_batch_entries = Some(Vec::new());
    let snapshot = host.snapshot_nested_contract_call();
    assert!(Arc::ptr_eq(&snapshot.zk_verified_ballot, &verified_ballot));
    assert!(Arc::ptr_eq(&snapshot.axt_proof_cache, &proof_cache));
    assert!(
        host.fastpq_batch_entries.is_none(),
        "frame-local batch storage must be moved, not cloned"
    );
    Arc::make_mut(&mut host.zk_verified_ballot).push_back([7; 32]);
    assert!(!Arc::ptr_eq(&host.zk_verified_ballot, &verified_ballot));
    host.finish_nested_contract_call(snapshot, NestedContractCallOutcome::Rollback)
        .expect("restore shared rollback state");
    assert!(Arc::ptr_eq(&host.zk_verified_ballot, &verified_ballot));
    assert!(Arc::ptr_eq(&host.axt_proof_cache, &proof_cache));
    assert!(host.zk_verified_ballot.is_empty());
    assert!(host.fastpq_batch_entries.is_some());
}

fn installed_contract_artifact(state: &State, address: &ContractAddress) -> Vec<u8> {
    let view = state.view();
    let hash = *view.world().contract_instances().get(address).unwrap();
    let key = ContractArtifactId::for_address(address, hash).unwrap();
    view.world().contract_code().get(&key).unwrap().clone()
}
fn compile_bound_contract_import(
    state: &State,
    imported: &ContractAddress,
    path: &str,
    source: &str,
) -> Vec<u8> {
    use kotodama_lang::linker::{SourceContractArtifact, SourceLinkRequest, SourceModuleUnit};
    kotodama_lang::driver::BuildDriver::new(
        kotodama_lang::session::CompilerSession::default(),
        "core-nested-call-test",
    )
    .compile_project(
        SourceLinkRequest {
            root: SourceModuleUnit {
                source_name: "fixture.ko".into(),
                source: source.into(),
            },
            artifacts: vec![SourceContractArtifact {
                source_name: path.into(),
                artifact: installed_contract_artifact(state, imported),
            }],
            sources: vec![],
            imports: vec![],
            packages: vec![],
        },
        "fixture.ko",
    )
    .expect("compile exact immutable nested contract interface")
    .artifact
}

#[test]
fn nested_result_error_returns_payload_and_rolls_back_successful_descendants() {
    let authority: AccountId = fixture_account("alice");
    let state = contract_test_state(&authority);
    let root = install_contract(
        &state,
        &authority,
        "seiyaku Root { kotoage fn main() authorize(anyone) -> int { 0 } }",
        0,
    );
    let descendant = install_contract(
        &state,
        &authority,
        r#"
seiyaku Descendant { permission AssetOps;
  state StateMap<int, quantity> Values;
  kotoage fn quote(quantity amount_in, quantity min_out) authorize(AssetOps) -> quantity {
    Values[1] = amount_in;
    return amount_in;
  }
}
"#,
        1,
    );
    let source = format!(
        r#"
seiyaku Callee {{ permission AssetOps;
  import seiyaku "descendant.to" as Descendant;
  state StateMap<int, int> Values;
  kotoage fn attempt(bool succeed) authorize(AssetOps) -> Result<quantity, int> {{
    Values[1] = 9;
    let child = Descendant::at(address: b"{descendant}");
    let amount = child.quote(amount_in: 5, min_out: 0);
    if succeed {{ return Result::ok(amount); }}
    return Result::err(7);
  }}
}}
"#
    );
    let code = compile_bound_contract_import(&state, &descendant, "descendant.to", &source);
    let callee = install_contract_artifact_with_interface_and_lifecycle(
        &state,
        &authority,
        code,
        2,
        false,
        |_| {},
    );
    grant_contract_entrypoint_to_account(&state, &authority, root.subject_id(), &callee, "attempt");
    grant_contract_entrypoint_to_account(
        &state,
        &authority,
        callee.subject_id(),
        &descendant,
        "quote",
    );
    let code = installed_contract_artifact(&state, &callee);
    let interface = ivm::ProgramMetadata::parse(&code)
        .unwrap()
        .contract_interface
        .unwrap();
    let schema = interface
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "attempt")
        .unwrap()
        .return_schema
        .as_ref()
        .unwrap();
    for succeed in [false, true] {
        let (outcome, vm, overlay) = call_contract_syscall(
            &state,
            &authority,
            &root,
            &callee,
            "attempt",
            Json::from(norito::json!({"succeed": succeed})),
        );
        assert!(
            outcome.expect("Result is recoverable return data") > 0,
            "both outcomes retain gas"
        );
        let record = captured_nested_result(&vm, schema);
        let value =
            super::super::return_value::render_entrypoint_return_record(schema, &record).unwrap();
        if succeed {
            assert_eq!(value, norito::json!({"ok": "5"}));
            assert_eq!(
                overlay.len(),
                2,
                "successful caller and descendant both commit"
            );
        } else {
            assert_eq!(value, norito::json!({"err": "7"}));
            assert!(
                overlay.is_empty(),
                "Err rolls back callee and successful descendants"
            );
        }
    }
}

#[test]
fn nested_calls_reject_direct_and_indirect_reentry_including_views() {
    let authority: AccountId = fixture_account("alice");
    let state = contract_test_state(&authority);
    let root = install_contract(
        &state,
        &authority,
        r#"
seiyaku Root {
  kotoage fn main() authorize(anyone) {}
  view fn quote(quantity amount_in, quantity min_out) authorize(anyone) -> quantity { amount_in }
}
"#,
        0,
    );
    let source = format!(
        r#"
seiyaku Callback {{ permission AssetOps;
  import seiyaku "root.to" as RootContract;
  state StateMap<int, int> Values;
  kotoage fn quote(quantity amount_in, quantity min_out) authorize(AssetOps) -> quantity {{
    Values[1] = 9;
    let root = RootContract::at(address: b"{root}");
    return root.quote(amount_in: amount_in, min_out: min_out);
  }}
}}
"#
    );
    let code = compile_bound_contract_import(&state, &root, "root.to", &source);
    let callee = install_contract_artifact_with_interface_and_lifecycle(
        &state,
        &authority,
        code,
        1,
        false,
        |_| {},
    );
    grant_contract_entrypoint_to_account(&state, &authority, root.subject_id(), &callee, "quote");
    for target in [&root, &callee] {
        let (outcome, _, overlay) = call_contract_syscall(
            &state,
            &authority,
            &root,
            target,
            "quote",
            Json::from(norito::json!({"amount_in":"5","min_out":"0"})),
        );
        let error = outcome.expect_err("active addresses cannot be entered again");
        assert!(
            matches!(error.as_unmetered(), ivm::VMError::ReentrantCall),
            "{error:?}"
        );
        assert!(
            overlay.is_empty(),
            "callback rejection rolls back its preceding write"
        );
    }
    // A completed invocation leaves no active-stack entry behind.
    let independent = install_contract(
        &state,
        &authority,
        "seiyaku Independent { view fn main() authorize(anyone) -> int { 0 } }",
        2,
    );
    call_contract_syscall(
        &state,
        &authority,
        &independent,
        &root,
        "quote",
        Json::from(norito::json!({"amount_in":"5","min_out":"0"})),
    )
    .0
    .expect("inactive target remains callable");
}

#[test]
fn recoverable_nested_rollback_keeps_reads_and_parent_writes() {
    let authority: AccountId = fixture_account("alice");
    let mut host = CoreHost::new(authority).with_access_logging();
    host.state_access_log.durable_read_paths_complete = true;
    let key: StatePath = "counter".parse().unwrap();
    host.stage_durable_state_update(key.clone(), Some(vec![1]));
    host.log_state_write_key(key.as_ref());
    let snapshot = host.snapshot_nested_contract_call();
    host.stage_durable_state_update(key.clone(), Some(vec![2]));
    host.log_state_read_key(key.as_ref());
    let descendant = host.snapshot_nested_contract_call();
    host.stage_durable_state_update(key.clone(), Some(vec![3]));
    host.finish_nested_contract_call(descendant, NestedContractCallOutcome::Commit)
        .unwrap();
    host.finish_nested_contract_call(snapshot, NestedContractCallOutcome::RollbackPreservingReads)
        .unwrap();
    assert_eq!(host.durable_state_overlay.get(&key), Some(&Some(vec![1])));
    assert!(
        host.state_access_log.write_keys.contains(key.as_ref()),
        "parent write survives"
    );
    assert!(
        host.state_access_log.read_keys.contains(key.as_ref()),
        "recoverable result depends on the read"
    );
}

#[test]
fn root_and_local_result_errors_discard_effects_but_preserve_values_and_reads() {
    let source = r#"
seiyaku RootResult { permission AssetOps;
  state StateMap<int, int> Values;
  kotoage fn fail() authorize(AssetOps) -> Result<int, int> {
    let previous = Values.get(1).unwrap_or(0);
    Values[1] = previous + 9;
    return Result::err(7);
  }
  kotoage fn succeed() authorize(AssetOps) -> Result<int, int> {
    Values[1] = 9;
    return Result::ok(9);
  }
}
"#;
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let parsed = ivm::ProgramMetadata::parse(&code).unwrap();
    let interface = parsed.contract_interface.as_ref().unwrap();
    let authority: AccountId = fixture_account("alice");
    let state = contract_test_state(&authority);
    let address = install_contract(&state, &authority, source, 0);
    for local in [false, true] {
        for (selector, expected_error) in [("fail", true), ("succeed", false)] {
            let descriptor = interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == selector)
                .unwrap();
            let mut vm = IVM::new(1_000_000);
            vm.load_program(&code).unwrap();
            vm.set_register(1, vm.memory.code_len());
            vm.set_program_counter(parsed.prefix_len() as u64 + descriptor.entry_pc)
                .unwrap();
            let mut host = CoreHost::new(authority.clone()).with_access_logging();
            host.set_local_contract_debug_execution();
            vm.run_with_host(&mut host)
                .expect("execute actual state mutation");
            let gas_before = vm.remaining_gas();
            assert!(!host.durable_state_overlay.is_empty());
            if local {
                assert_eq!(
                    host.finish_local_contract_result(&vm, selector).unwrap(),
                    expected_error
                );
            } else {
                host.set_contract_runtime_context(Some(ContractRuntimeExecutionContext {
                    contract_address: address.clone(),
                    contract_subject: address.subject_id(),
                    contract_alias: None,
                    entrypoint: selector.to_owned(),
                }));
                assert_eq!(host.finish_contract_result(&vm).unwrap(), expected_error);
            }
            assert_eq!(host.durable_state_overlay.is_empty(), expected_error);
            assert_eq!(
                vm.remaining_gas(),
                gas_before,
                "rollback cannot refund executed work"
            );
            assert_eq!(
                ivm::sum::entrypoint_return_is_error(
                    &vm,
                    descriptor.return_schema.as_ref().unwrap()
                ),
                Ok(expected_error)
            );
            if expected_error {
                assert!(host.state_access_log.write_keys.is_empty());
                assert!(
                    !host.state_access_log.read_keys.is_empty(),
                    "returned error depends on the read"
                );
            }
        }
    }
}

#[test]
fn nested_numeric_fault_keeps_callee_artifact_and_rolls_back_its_state() {
    use iroha_data_model::executor::fault::{
        IvmFaultKindV1, IvmFaultPositionV1, IvmInvocationSelectorV1, NumericFaultV1,
    };
    let authority = fixture_account("alice");
    let state = contract_test_state(&authority);
    let root = install_contract(
        &state,
        &authority,
        "seiyaku FaultCaller { view fn main() authorize(anyone) -> int { return 0; } }",
        0,
    );
    let child = install_contract(
        &state,
        &authority,
        r#"
seiyaku FaultChild {
  state StateMap<int, int> Values;
  kotoage fn divide(int divisor) authorize(anyone) -> int {
    Values[1] = 9;
    return 8 / divisor;
  }
}
"#,
        1,
    );
    let (hash, ordinal) = {
        let view = state.view();
        let hash = *view.world().contract_instances().get(&child).unwrap();
        let artifact =
            iroha_data_model::smart_contract::ContractArtifactId::for_address(&child, hash)
                .unwrap();
        let ordinal = view
            .world()
            .contract_manifests()
            .get(&artifact)
            .unwrap()
            .entrypoints
            .as_ref()
            .unwrap()
            .iter()
            .position(|entry| entry.name == "divide")
            .unwrap() as u32;
        (hash, ordinal)
    };
    let (outcome, vm, overlay, _) = dispatch_call_contract_syscall(
        &state,
        &authority,
        &root,
        &child,
        "divide",
        Json::new(norito::json!({"divisor":"0"})),
        1_000_000,
    );
    let error = outcome.expect_err("division by zero must trap after the staged write");
    assert_eq!(
        error.as_unmetered(),
        &ivm::VMError::NumericFault(ivm::numeric::NumericFaultV1::DivisionByZero)
    );
    let ValidationFail::IvmFault(fault) = crate::execution_attempt::expect_completed_rejection(
        crate::smartcontracts::ivm::map_vm_error_with_context_to_validation(&vm, error),
    ) else {
        panic!("expected bounded runtime fault");
    };
    assert_eq!(
        fault.kind,
        IvmFaultKindV1::Numeric(NumericFaultV1::DivisionByZero)
    );
    assert_eq!(fault.site.code_hash, hash);
    assert_eq!(
        fault.site.selector,
        IvmInvocationSelectorV1::Entrypoint(ordinal)
    );
    assert!(
        matches!(fault.site.position, IvmFaultPositionV1::Execute {pc_offset} if pc_offset > 0)
    );
    assert!(overlay.is_empty());
    assert!(vm.remaining_gas() < 1_000_000);
}
