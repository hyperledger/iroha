//! Typed local calls use admitted artifacts, exact instance roles, and atomic effects.

use super::*;
use iroha_data_model::smart_contract::{ContractLifecycleControlV1, manifest::EntryPointKind};
use ivm_abi::contract_call::ContractCallBindingV1;

fn install(host: &mut WsvHost, nonce: u64, source: &str) -> ContractAddress {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let hash = crate::contract_code_hash(&artifact);
    let address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        &test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
        nonce,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let mut lifecycle = ContractLifecycleControlV1::direct(test_account_id(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
        "fixture",
    ));
    lifecycle.active_code_hash = Some(hash);
    lifecycle.retained_code_hash = Some(hash);
    host.install_contract_fixture(address.clone(), artifact, lifecycle, None)
        .unwrap();
    address
}
fn caller(host: &mut WsvHost, address: &ContractAddress) -> IVM {
    let artifact = host.contract_fixture(address).unwrap().clone();
    let mut vm = IVM::new(1_000_000);
    vm.load_prepared(&artifact).unwrap();
    vm.select_entrypoint("main").unwrap();
    host.bind_contract_runtime_context(
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
        address.clone(),
        "main".into(),
    )
    .unwrap();
    vm
}
fn request(
    host: &WsvHost,
    vm: &mut IVM,
    target: &ContractAddress,
    selector: &str,
    arguments: &[u64],
) -> [u64; 6] {
    let artifact = host.contract_fixture(target).unwrap();
    let ordinal = artifact
        .contract_interface()
        .entrypoints
        .iter()
        .position(|entry| entry.name == selector)
        .unwrap();
    let entry = &artifact.contract_interface().entrypoints[ordinal];
    let words = entry.return_schema.as_ref().unwrap().word_count().unwrap();
    let address = vm
        .alloc_host_tlv(
            &crate::pointer_abi::encode_tlv(PointerType::Blob, target.as_ref().as_bytes()).unwrap(),
        )
        .unwrap();
    let binding = ContractCallBindingV1 {
        code_hash: artifact.code_hash(),
        entrypoint: ordinal as u32,
    };
    let binding = vm
        .alloc_host_tlv(
            &crate::pointer_abi::encode_tlv(PointerType::NoritoBytes, &binding.to_bytes().unwrap())
                .unwrap(),
        )
        .unwrap();
    let base = if arguments.is_empty() {
        0
    } else {
        let base = vm.alloc_heap((arguments.len() * 8) as u64).unwrap();
        for (index, value) in arguments.iter().enumerate() {
            vm.store_u64(base + (index * 8) as u64, *value).unwrap();
        }
        base
    };
    let result = vm.alloc_heap((words * 8) as u64).unwrap();
    let registers = [
        address,
        binding,
        base,
        arguments.len() as u64,
        result,
        words as u64,
    ];
    for (index, value) in registers.iter().enumerate() {
        vm.set_register(10 + index, *value);
    }
    registers
}
fn render(host: &WsvHost, target: &ContractAddress, selector: &str, vm: &IVM) -> njson::Value {
    let schema = host
        .contract_fixture(target)
        .unwrap()
        .contract_interface()
        .entrypoints
        .iter()
        .find(|entry| entry.name == selector)
        .unwrap()
        .return_schema
        .as_ref()
        .unwrap();
    let value = crate::value_record::capture_value_record(
        vm,
        schema,
        vm.register(14),
        vm.register(15) as usize,
    )
    .unwrap();
    crate::value_record::render_entrypoint_return_record(schema, &value).unwrap()
}

#[test]
fn typed_mock_call_commits_success_and_rolls_back_result_error_and_emissions() {
    let mut host = WsvHost::new_with_subject(
        MockWorldStateView::new(),
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
    );
    let root = install(
        &mut host,
        0,
        "seiyaku Caller { kotoage fn main() authorize(anyone) {} }",
    );
    let callee = install(
        &mut host,
        1,
        r#"seiyaku Child {
      permission Writer;
      state StateMap<int,bool> Values;
      event Saved { bool value; }
      kotoage fn save(bool succeed) authorize(Writer) -> Result<bool,int> {
        Values[1] = true;
        emit Saved { value: succeed };
        if succeed { return Result::ok(true); }
        return Result::err(7);
      }
    }"#,
    );
    let mut vm = caller(&mut host, &root);
    request(&host, &mut vm, &callee, "save", &[1]);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
            .unwrap_err()
            .as_unmetered(),
        VMError::PermissionDenied
    ));
    let token = PermissionToken::ContractPermission {
        contract: callee.clone(),
        permission: "Writer".parse().unwrap(),
    };
    host.wsv.grant_permission(&root.subject_id(), token.clone());
    for succeed in [false, true] {
        let mut vm = caller(&mut host, &root);
        let registers = request(&host, &mut vm, &callee, "save", &[u64::from(succeed)]);
        crate::reset_argument_record_decode_count();
        assert!(
            host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
                .unwrap()
                > 0
        );
        assert_eq!(crate::argument_record_decode_count(), 0);
        assert_eq!(
            (10..16).map(|index| vm.register(index)).collect::<Vec<_>>(),
            registers
        );
        assert_eq!(
            render(&host, &callee, "save", &vm),
            if succeed {
                norito::json!({"ok":true})
            } else {
                norito::json!({"err":"7"})
            }
        );
        assert_eq!(host.wsv.state_overlay.keys().count(), usize::from(succeed));
        let events = host.drain_contract_events();
        assert_eq!(events.len(), usize::from(succeed));
        if succeed {
            assert_eq!(events[0].name().as_ref(), "Saved");
            assert_eq!(events[0].contract(), &callee);
        }
    }
    host.wsv.revoke_permission(&root.subject_id(), &token);
    let mut vm = caller(&mut host, &root);
    request(&host, &mut vm, &callee, "save", &[1]);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
            .unwrap_err()
            .as_unmetered(),
        VMError::PermissionDenied
    ));
    assert!(host.drain_contract_events().is_empty());
}

#[test]
fn typed_mock_call_rejects_wrong_instance_hash_suspension_reentry_and_view_mutation() {
    let mut host = WsvHost::new_with_subject(
        MockWorldStateView::new(),
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
    );
    let root = install(
        &mut host,
        0,
        "seiyaku Caller { view fn main() authorize(anyone) {} }",
    );
    let target = install(
        &mut host,
        1,
        "seiyaku Child { view fn value() authorize(anyone) -> bool { true } kotoage fn write() authorize(anyone) {} }",
    );
    let mut vm = caller(&mut host, &root);
    request(&host, &mut vm, &target, "value", &[]);
    host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
        .unwrap();
    assert_eq!(render(&host, &target, "value", &vm), norito::json!(true));
    for (selector, expected) in [
        ("write", VMError::PermissionDenied),
        ("value", VMError::PermissionDenied),
    ] {
        let mut vm = caller(&mut host, &root);
        let registers = request(&host, &mut vm, &target, selector, &[]);
        if selector == "value" {
            host.wsv
                .contract_instances
                .get_mut(&target)
                .unwrap()
                .lifecycle
                .active_code_hash = None;
        }
        assert_eq!(
            host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
                .unwrap_err()
                .as_unmetered(),
            &expected
        );
        assert_eq!(vm.load_u64(registers[4]).unwrap(), 0);
    }
    let mut vm = caller(&mut host, &root);
    request(&host, &mut vm, &root, "main", &[]);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
            .unwrap_err()
            .as_unmetered(),
        VMError::ReentrantCall
    ));
    let active_hash = host
        .contract_fixture(&target)
        .map(|artifact| artifact.code_hash());
    host.wsv
        .contract_instances
        .get_mut(&target)
        .unwrap()
        .lifecycle
        .active_code_hash = active_hash;
    let mut vm = caller(&mut host, &root);
    let registers = request(&host, &mut vm, &target, "value", &[]);
    let binding = ContractCallBindingV1 {
        code_hash: CryptoHash::new(b"wrong artifact"),
        entrypoint: 0,
    };
    let bad = vm
        .alloc_host_tlv(
            &crate::pointer_abi::encode_tlv(PointerType::NoritoBytes, &binding.to_bytes().unwrap())
                .unwrap(),
        )
        .unwrap();
    vm.set_register(11, bad);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
            .unwrap_err()
            .as_unmetered(),
        VMError::PermissionDenied
    ));
    assert_eq!(vm.load_u64(registers[4]).unwrap(), 0);
}

#[test]
fn mock_replacement_checks_owner_revision_schema_and_real_migration_state() {
    use ivm_abi::state_value::{
        StateValueAtomV1, StateValueRecordV1, state_value_schema_for_embedded_type_v1,
        state_value_schema_hash_v1,
    };
    let mut host = WsvHost::new_with_subject(
        MockWorldStateView::new(),
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
    );
    let address = install(
        &mut host,
        8,
        "seiyaku Upgrade { state StateMap<int,bool> Values; view fn main() authorize(anyone) -> bool { true } }",
    );
    let revision = host.wsv.contract_instances[&address].lifecycle.revision;
    let previous_hash = host.contract_fixture(&address).unwrap().code_hash();
    let replacement = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            r#"seiyaku Upgrade {
        state StateMap<int,bool> Values;
        state bool initialized;
        hajimari() { initialized = false; }
        kaizen() { initialized = true; }
        view fn main() authorize(anyone) -> bool { initialized }
    }"#,
        )
        .unwrap();
    for (authority, revision) in [
        (
            &test_account_id(
                "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
                "fixture",
            ),
            revision,
        ),
        (
            &test_account_id(
                "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
                "fixture",
            ),
            revision - 1,
        ),
    ] {
        assert!(matches!(
            host.replace_contract_fixture(&address, replacement.clone(), authority, revision),
            Err(VMError::PermissionDenied)
        ));
        assert_eq!(
            host.contract_fixture(&address).unwrap().code_hash(),
            previous_hash
        );
    }
    for source in [
        "seiyaku Upgrade { state StateMap<bool,bool> Values; view fn main() authorize(anyone) -> bool { true } }",
        "seiyaku Upgrade { view fn main() authorize(anyone) -> bool { true } }",
        "seiyaku Upgrade { state StateMap<int,bool> Values; state bool initialized; hajimari() { initialized = true; } view fn main() authorize(anyone) -> bool { initialized } }",
    ] {
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .unwrap();
        assert!(matches!(
            host.replace_contract_fixture(
                &address,
                artifact,
                &test_account_id(
                    "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
                    "fixture"
                ),
                revision
            ),
            Err(VMError::InvalidMetadata)
        ));
        assert_eq!(
            host.contract_fixture(&address).unwrap().code_hash(),
            previous_hash
        );
    }
    assert_eq!(
        host.replace_contract_fixture(
            &address,
            replacement.clone(),
            &test_account_id(
                "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
                "fixture"
            ),
            revision
        )
        .unwrap(),
        Some(EntryPointKind::Kaizen)
    );
    assert_eq!(
        host.wsv.contract_instances[&address].lifecycle.revision,
        revision + 1
    );
    assert!(matches!(
        host.replace_contract_fixture(
            &address,
            replacement,
            &test_account_id(
                "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
                "fixture"
            ),
            revision + 1
        ),
        Err(VMError::PermissionDenied)
    ));
    assert!(
        host.finish_contract_fixture_hook(&address, EntryPointKind::Hajimari)
            .is_err()
    );
    assert!(
        host.finish_contract_fixture_hook(&address, EntryPointKind::Kaizen)
            .is_err()
    );
    assert_eq!(
        host.wsv.contract_instances[&address].pending,
        Some(EntryPointKind::Kaizen)
    );
    let path = contract_state_path(&address, &"initialized".parse().unwrap()).unwrap();
    host.wsv.sc_set(path.as_ref(), b"true".to_vec()).unwrap();
    assert!(
        host.finish_contract_fixture_hook(&address, EntryPointKind::Kaizen)
            .is_err()
    );
    let schema = state_value_schema_for_embedded_type_v1(&crate::EmbeddedStateType::Bool).unwrap();
    let record = StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&norito::encode_canonical(&schema).unwrap()),
        atoms: vec![StateValueAtomV1::Bool(true)],
    };
    host.wsv
        .sc_set(path.as_ref(), norito::encode_canonical(&record).unwrap())
        .unwrap();
    host.finish_contract_fixture_hook(&address, EntryPointKind::Kaizen)
        .unwrap();
    assert_eq!(host.wsv.contract_instances[&address].pending, None);
    assert!(
        host.finish_contract_fixture_hook(&address, EntryPointKind::Kaizen)
            .is_err()
    );
}

#[test]
fn diagnostic_fixture_state_scope_does_not_grant_runtime_invocation_authority() {
    let mut host = WsvHost::new_with_subject(
        MockWorldStateView::new(),
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
    );
    let root = install(
        &mut host,
        9,
        "seiyaku Scope { kotoage fn main() authorize(anyone) {} }",
    );
    let second = install(
        &mut host,
        10,
        "seiyaku Other { kotoage fn main() authorize(anyone) {} }",
    );
    let logical = "entry".parse().unwrap();
    host.set_contract_fixture_state_scope(Some(root.clone()))
        .unwrap();
    assert_eq!(
        host.scoped_state_path(&logical).unwrap(),
        contract_state_path(&root, &logical).unwrap()
    );
    let mut vm = IVM::new(1_000_000);
    vm.load_prepared(host.contract_fixture(&root).unwrap())
        .unwrap();
    vm.select_entrypoint("main").unwrap();
    request(&host, &mut vm, &second, "main", &[]);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_CALL_CONTRACT, &mut vm)
            .unwrap_err()
            .as_unmetered(),
        VMError::PermissionDenied
    ));
    host.bind_contract_runtime_context(
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
        second.clone(),
        "main".into(),
    )
    .unwrap();
    assert_eq!(
        host.scoped_state_path(&logical).unwrap(),
        contract_state_path(&second, &logical).unwrap()
    );
    host.clear_contract_runtime_context(test_account_id(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
        "fixture",
    ));
    assert_eq!(
        host.scoped_state_path(&logical).unwrap(),
        contract_state_path(&root, &logical).unwrap()
    );
}
