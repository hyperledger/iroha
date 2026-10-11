//! Actual native execution, complete failure identity, permissions and transaction rollback.

use super::common;
use iroha_primitives::numeric_abi::{DecimalValueV1, QuantityValueV1};
use ivm::{
    CoreHost, IVM, PermissionToken, PointerType, ProgramMetadata, VMError,
    host::{DefaultHost, IVMHost},
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    numeric::NumericFaultV1,
    parallel::StateAccessSet,
};
#[path = "../../../fixtures/kotodama/local_emission/cases.rs"]
mod cases;

fn pair(id: &str) -> cases::Pair {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    cases::load_pairs(&root)
        .remove(id)
        .expect("complete genuine source-bound native pair")
}
fn run_entry(
    program: &[u8],
    entrypoint: &str,
    gas: u64,
    host: &mut dyn IVMHost,
) -> (IVM, Result<(), VMError>) {
    let mut vm = IVM::new(gas);
    vm.load_program(program)
        .expect("actual current canonical artifact admission");
    common::select_kotodama_entrypoint(&mut vm, program, entrypoint);
    let result = vm.run_with_host(host);
    if gas > 0 {
        assert!(vm.remaining_gas() < gas, "actual paid VM work");
    }
    (vm, result)
}
fn initialize(program: &[u8], host: &mut dyn IVMHost) {
    let parsed = ProgramMetadata::parse(program).unwrap();
    assert!(
        parsed
            .contract_interface
            .as_ref()
            .unwrap()
            .callables
            .iter()
            .all(|callable| callable.validate())
    );
    if parsed
        .contract_interface
        .unwrap()
        .entrypoints
        .iter()
        .any(|entrypoint| entrypoint.name == "hajimari")
    {
        let (vm, result) = run_entry(program, "hajimari", 4_000_000, host);
        assert_eq!(result, Ok(()));
        assert_eq!(vm.public_call_result_word(0), Ok(0));
    }
}
fn assert_outcome(case: &cases::Case, program: &[u8], vm: &IVM, result: &Result<(), VMError>) {
    match case.outcome {
        cases::Outcome::Success(words) => {
            assert_eq!(*result, Ok(()), "actual complete result for {}", case.id);
            assert_eq!(vm.call_result_word_count(), Ok(words.len()));
            for (index, expected) in words.iter().enumerate() {
                match expected {
                    cases::Word::Int(expected) => {
                        assert_eq!(common::decode_i64_return_word(vm, index), *expected)
                    }
                    cases::Word::Unit => assert_eq!(vm.public_call_result_word(index), Ok(0)),
                    cases::Word::Decimal(expected) => {
                        let tlv = vm
                            .validate_tlv(vm.public_call_result_word(index).unwrap())
                            .unwrap();
                        assert_eq!(tlv.type_id, PointerType::Decimal);
                        assert_eq!(
                            DecimalValueV1::decode_frame(tlv.payload)
                                .unwrap()
                                .as_numeric()
                                .to_string(),
                            *expected
                        );
                    }
                    cases::Word::Quantity(expected) => {
                        let tlv = vm
                            .validate_tlv(vm.public_call_result_word(index).unwrap())
                            .unwrap();
                        assert_eq!(tlv.type_id, PointerType::Quantity);
                        assert_eq!(
                            QuantityValueV1::decode_frame(tlv.payload)
                                .unwrap()
                                .as_quantity()
                                .to_string(),
                            *expected
                        );
                    }
                }
            }
        }
        cases::Outcome::Abort { code, name } => {
            let interface = ProgramMetadata::parse(program)
                .unwrap()
                .contract_interface
                .unwrap();
            // The source declares Failure and the canonical compiler also
            // includes the finite builtin ListError and NumericError schemas.
            // Check their complete original table, then bind this actual abort
            // to Failure's exact namespace, variants and schema hash.
            use iroha_data_model::smart_contract::manifest::{
                ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
            };
            let descriptor = ContractErrorTypeDescriptor {
                identity: format!("{}::Failure", interface.seiyaku_name),
                variants: vec![
                    ContractErrorVariantDescriptor {
                        name: "Low".to_owned(),
                        code: 3,
                    },
                    ContractErrorVariantDescriptor {
                        name: "High".to_owned(),
                        code: 9,
                    },
                ],
            };
            assert!(descriptor.validate());
            assert_eq!(
                interface.error_types,
                vec![
                    descriptor.clone(),
                    ivm_abi::error_types::list_error_type(),
                    ivm_abi::error_types::numeric_error_type(),
                ],
                "complete original declared and builtin error descriptors"
            );
            assert_eq!(descriptor.variant(code).unwrap().name, name);
            let expected = VMError::ContractAbort {
                contract: interface.seiyaku_name.clone().into_boxed_str(),
                name: name.to_owned(),
                error_type: descriptor.identity.clone(),
                schema_hash: descriptor.schema_hash(),
                code,
                message: None,
            };
            assert_eq!(
                result.as_ref().unwrap_err().as_unmetered(),
                &expected,
                "complete original nominal failure identity for {}",
                case.id
            );
            assert!(vm.public_call_result_word(0).is_err());
        }
        cases::Outcome::DivisionByZero => {
            assert_eq!(
                result.as_ref().unwrap_err().as_unmetered(),
                &VMError::NumericFault(NumericFaultV1::DivisionByZero)
            );
            assert!(vm.public_call_result_word(0).is_err());
        }
        cases::Outcome::InvalidScale => {
            assert_eq!(
                result.as_ref().unwrap_err().as_unmetered(),
                &VMError::NumericFault(NumericFaultV1::InvalidScale)
            );
            assert!(vm.public_call_result_word(0).is_err());
        }
        cases::Outcome::QuantityUnderflow => {
            assert_eq!(
                result.as_ref().unwrap_err().as_unmetered(),
                &VMError::NumericFault(NumericFaultV1::QuantityUnderflow)
            );
            assert!(vm.public_call_result_word(0).is_err());
        }
        cases::Outcome::Permission => panic!("permission has a dedicated actual WSV control"),
    }
}
fn state(host: &CoreHost) -> std::collections::BTreeMap<String, Vec<u8>> {
    host.state_paths()
        .into_iter()
        .map(|path| {
            let value = host
                .state_bytes(&path)
                .expect("complete actual durable value");
            (path, value)
        })
        .collect()
}
fn assert_case(id: &str) {
    let case = cases::CASES.iter().find(|case| case.id == id).unwrap();
    let pair = pair(id);
    let mut snapshots = Vec::new();
    for program in [&pair.before, &pair.after] {
        let mut default = DefaultHost::new();
        initialize(program, &mut default);
        let (vm, result) = run_entry(program, "main", 4_000_000, &mut default);
        assert_outcome(case, program, &vm, &result);
        let mut core = CoreHost::new();
        initialize(program, &mut core);
        let checkpoint = core
            .checkpoint()
            .expect("actual transaction rollback owner");
        let initial = state(&core);
        let mut access = StateAccessSet::new();
        if case.trace.is_some() {
            access.read_keys.insert("trace".to_owned());
            access.write_keys.insert("trace".to_owned());
        }
        core.begin_tx(&access).unwrap();
        let (vm, result) = run_entry(program, "main", 4_000_000, &mut core);
        assert_outcome(case, program, &vm, &result);
        let reached = state(&core);
        if let Some(expected) = case.trace {
            assert_eq!(
                common::decode_int_state_value(&reached["trace"]),
                expected,
                "original complete preceding writes for {id}"
            );
        } else {
            assert!(reached.is_empty());
        }
        let log = core.finish_tx().expect("actual transactional finish");
        assert!(log.read_keys.is_subset(&access.read_keys));
        assert!(log.write_keys.is_subset(&access.write_keys));
        if result.is_err() {
            core.restore(checkpoint.as_ref()).unwrap();
            assert_eq!(
                state(&core),
                initial,
                "actual complete transaction rollback for {id}"
            );
        }
        snapshots.push((reached, state(&core)));
    }
    assert_eq!(
        snapshots[0], snapshots[1],
        "every original raw and committed durable effect for {id}"
    );
}
#[test]
fn actual_local_pairs_preserve_all_rounding_modes_typed_numeric_helpers_and_complete_results() {
    assert_case("rounded_values");
}
#[test]
fn actual_local_pairs_preserve_unit_returns_loops_and_complete_wide_argument_tables() {
    assert_case("unit_loop");
    assert_case("wide_arguments");
}
#[test]
fn actual_local_pairs_keep_both_complete_nominal_abort_identities_and_transaction_rollback() {
    // Keep the cross-function complete instruction-boundary admission in its
    // actual VM owner; the compiler crate cannot depend on its runtime consumer.
    let cross_function = pair("abort_second");
    for program in [&cross_function.before, &cross_function.after] {
        let mut vm = IVM::new(4_000_000);
        vm.load_program(program)
            .expect("actual canonical metadata and complete instruction-boundary admission");
    }
    assert_case("abort_first");
    assert_case("abort_second");
}
#[test]
fn actual_local_pairs_preserve_exact_checked_rounding_fault_and_prior_complete_writes() {
    assert_case("rounded_trap");
    assert_case("invalid_scale");
}
#[test]
fn actual_local_pairs_reject_unfunded_execution_before_any_complete_source_effect() {
    for case in cases::CASES
        .iter()
        .filter(|case| !matches!(case.outcome, cases::Outcome::Permission))
    {
        let pair = pair(case.id);
        for program in [&pair.before, &pair.after] {
            let mut host = CoreHost::new();
            initialize(program, &mut host);
            let initial = state(&host);
            let (vm, result) = run_entry(program, "main", 0, &mut host);
            assert_eq!(
                result.as_ref().unwrap_err().as_unmetered(),
                &VMError::OutOfGas
            );
            assert_eq!(state(&host), initial);
            assert!(vm.public_call_result_word(0).is_err());
        }
    }
}
#[test]
fn actual_local_pairs_preserve_permission_authorization_and_denial_before_role_effects() {
    let case = cases::CASES
        .iter()
        .find(|case| case.id == "permission")
        .unwrap();
    assert_eq!(case.outcome, cases::Outcome::Permission);
    let pair = pair(case.id);
    for program in [&pair.before, &pair.after] {
        let interface = ProgramMetadata::parse(program)
            .unwrap()
            .contract_interface
            .unwrap();
        assert_eq!(
            interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == "main")
                .unwrap()
                .authorization,
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "ManageRoles".parse().unwrap()
            )
        );
        for authorized in [false, true] {
            let caller =
                AccountId::parse_encoded("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
                    .unwrap();
            let mut wsv = MockWorldStateView::new();
            wsv.add_account_unchecked(caller.clone());
            if authorized {
                wsv.grant_permission(&caller, PermissionToken::ManageRoles);
            }
            let mut host = WsvHost::new_with_subject(wsv, caller);
            let (vm, result) = run_entry(program, "main", 4_000_000, &mut host);
            if authorized {
                assert_eq!(result, Ok(()));
                assert_eq!(vm.public_call_result_word(0), Ok(0));
            } else {
                assert_eq!(
                    result.as_ref().unwrap_err().as_unmetered(),
                    &VMError::PermissionDenied
                );
                assert!(vm.public_call_result_word(0).is_err());
            }
            assert_eq!(
                host.wsv
                    .create_role("compact", std::collections::HashSet::new()),
                !authorized,
                "role exists only after the original authorized effect"
            );
        }
    }
}

#[test]
fn actual_local_pairs_preserve_repeated_values_across_original_private_calls_and_conditional_writes()
 {
    assert_case("chain_values");
}
fn name_path(key: &str) -> String {
    let name: iroha_model_base::name::Name = key.parse().unwrap();
    let payload = norito::to_bytes(&name).unwrap();
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&(PointerType::Name as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    envelope.extend_from_slice(&payload);
    envelope.extend_from_slice(iroha_crypto::Hash::new(&payload).as_ref());
    format!("Balances/{}", hex::encode(envelope))
}
fn state_quantity(record: &[u8]) -> String {
    let bytes = common::decode_pointer_state_value(
        record,
        ivm_abi::state_value::StateValueKindV1::Quantity,
    );
    let tlv = ivm::pointer_abi::validate_tlv_bytes(&bytes).unwrap();
    assert_eq!(tlv.type_id, PointerType::Quantity);
    QuantityValueV1::decode_frame(tlv.payload)
        .unwrap()
        .into_quantity()
        .to_string()
}
#[test]
fn actual_local_pairs_preserve_canonical_map_custody_metered_consumers_and_quantity_underflow_rollback()
 {
    for id in ["map_values", "map_underflow"] {
        let case = cases::CASES.iter().find(|case| case.id == id).unwrap();
        let pair = pair(id);
        let mut snapshots = Vec::new();
        for program in [&pair.before, &pair.after] {
            let mut default = DefaultHost::new();
            initialize(program, &mut default);
            let (vm, outcome) = run_entry(program, "main", 4_000_000, &mut default);
            assert_outcome(case, program, &vm, &outcome);
            let mut core = CoreHost::new();
            assert!(state(&core).is_empty(), "original host starts empty");
            initialize(program, &mut core);
            let initial = state(&core);
            assert_eq!(
                initial.len(),
                1,
                "actual constructor initializes only Total"
            );
            assert_eq!(state_quantity(&initial["Total"]), "0");
            let checkpoint = core
                .checkpoint()
                .expect("actual map transaction rollback owner");
            let mut access = StateAccessSet::new();
            for key in [name_path("left"), name_path("right"), "Total".to_owned()] {
                access.read_keys.insert(key.clone());
                access.write_keys.insert(key);
            }
            core.begin_tx(&access).unwrap();
            let mut vm = IVM::new(4_000_000);
            vm.load_program(program).unwrap();
            common::select_kotodama_entrypoint(&mut vm, program, "main");
            let step_capacity = 8192;
            let step_bytes = step_capacity
                * std::mem::size_of::<ivm::execution_step_recorder::DiagnosticStepRecord>();
            let budget = iroha_allocation::AllocationBudget::new(step_bytes);
            let mut steps = ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(
                step_capacity,
                &budget,
            )
            .unwrap();
            let outcome = vm.run_with_host_diagnostic_steps(&mut core, &mut steps);
            assert_outcome(case, program, &vm, &outcome);
            for number in [
                ivm::syscalls::SYSCALL_STATE_GET,
                ivm::syscalls::SYSCALL_STATE_SET,
                ivm::syscalls::SYSCALL_POINTER_TO_NORITO,
                ivm::syscalls::SYSCALL_BUILD_PATH_KEY_NORITO,
                ivm::syscalls::SYSCALL_STATE_VALUE_ENCODE,
                ivm::syscalls::SYSCALL_STATE_VALUE_DECODE,
            ] {
                let word = if let Ok(number) = u8::try_from(number) {
                    ivm::encoding::wide::encode_sys(ivm::instruction::wide::system::SCALL, number)
                } else {
                    ivm::encoding::wide::encode_syscallx(number)
                };
                let calls = steps
                    .records()
                    .iter()
                    .filter(|step| step.instruction == Some(word))
                    .collect::<Vec<_>>();
                assert!(
                    !calls.is_empty(),
                    "original authenticated canonical consumer {number} executes for {id}"
                );
                assert!(
                    calls
                        .iter()
                        .all(|step| step.before.gas_remaining > step.after.gas_remaining)
                );
            }
            drop(vm);
            let reached = state(&core);
            assert_eq!(
                reached.len(),
                3,
                "all actual retaining state values outlive the original VM"
            );
            for (key, expected) in [
                (
                    name_path("left"),
                    if id == "map_values" { "60" } else { "100" },
                ),
                (
                    name_path("right"),
                    if id == "map_values" { "40" } else { "0" },
                ),
                ("Total".to_owned(), "100"),
            ] {
                assert_eq!(state_quantity(&reached[&key]), expected);
            }
            let log = core.finish_tx().unwrap();
            assert!(log.read_keys.is_subset(&access.read_keys));
            assert!(log.write_keys.is_subset(&access.write_keys));
            if outcome.is_err() {
                core.restore(checkpoint.as_ref()).unwrap();
                assert_eq!(
                    state(&core),
                    initial,
                    "actual complete checked monetary rollback"
                );
            }
            snapshots.push((reached, state(&core)));
        }
        assert_eq!(
            snapshots[0], snapshots[1],
            "every raw and durable byte and atomic failure for {id}"
        );
    }
}
