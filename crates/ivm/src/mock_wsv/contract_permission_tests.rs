//! Exact instance permission delegation in the local WSV host.

use super::*;

fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(7 + payload.len() + CryptoHash::LENGTH);
    result.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    result.push(1);
    result.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    result.extend_from_slice(payload);
    result.extend_from_slice(CryptoHash::new(payload).as_ref());
    result
}

fn fixture() -> (WsvHost, IVM, ContractAddress, AccountId) {
    let actor = test_account_id(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
        "wonderland",
    );
    let contract = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        &actor,
        1,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku Grants {
                permission Member;
                import permission \"ChainRole\" as Shared;
                kotoage fn manage() authorize(anyone) {}
            }",
        )
        .unwrap();
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    let host = WsvHost::new_with_subject(MockWorldStateView::new(), actor.clone());
    (host, vm, contract, actor)
}

fn call(
    host: &mut WsvHost,
    vm: &mut IVM,
    actor: &AccountId,
    permission: &str,
    syscall: u32,
) -> Result<u64, VMError> {
    let subject = vm
        .alloc_input_tlv(&tlv(
            PointerType::AccountId,
            &norito::to_bytes(actor).unwrap(),
        ))
        .unwrap();
    let name: Name = permission.parse().unwrap();
    let permission = vm
        .alloc_input_tlv(&tlv(PointerType::Name, &norito::to_bytes(&name).unwrap()))
        .unwrap();
    vm.set_register(10, subject);
    vm.set_register(11, permission);
    host.syscall(syscall, vm)
}

#[test]
fn contract_permission_delegation_requires_instance_and_exact_effect_authority() {
    let (mut host, mut vm, contract, actor) = fixture();
    let grant = syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION;
    assert_eq!(
        call(&mut host, &mut vm, &actor, "Member", grant),
        Err(VMError::PermissionDenied)
    );
    host.bind_contract_runtime_context(actor.clone(), contract.clone(), "manage".into())
        .unwrap();
    assert_eq!(
        call(&mut host, &mut vm, &actor, "Member", grant),
        Err(VMError::PermissionDenied)
    );
    let token = PermissionToken::ContractPermission {
        contract: contract.clone(),
        permission: "Member".parse().unwrap(),
    };
    host.wsv.grant_permission(&actor, token.clone());
    assert_eq!(
        call(&mut host, &mut vm, &actor, "Member", grant),
        Err(VMError::PermissionDenied)
    );
    host.wsv.revoke_permission(&actor, &token);
    host.wsv
        .grant_permission(&contract.subject_id(), token.clone());
    call(&mut host, &mut vm, &actor, "Member", grant).unwrap();
    assert!(host.wsv.has_permission(&actor, &token));
    assert_eq!(
        call(&mut host, &mut vm, &actor, "Member", grant),
        Err(VMError::PermissionDenied)
    );
    call(
        &mut host,
        &mut vm,
        &actor,
        "Member",
        syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION,
    )
    .unwrap();
    assert!(!host.wsv.has_permission(&actor, &token));
    assert_eq!(
        call(
            &mut host,
            &mut vm,
            &actor,
            "Member",
            syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION
        ),
        Err(VMError::PermissionDenied)
    );
}

#[test]
fn contract_permission_delegation_rejects_shared_and_undeclared_names() {
    let (mut host, mut vm, contract, actor) = fixture();
    host.bind_contract_runtime_context(actor.clone(), contract.clone(), "manage".into())
        .unwrap();
    for name in ["Shared", "Typo"] {
        host.wsv.grant_permission(
            &contract.subject_id(),
            PermissionToken::ContractPermission {
                contract: contract.clone(),
                permission: name.parse().unwrap(),
            },
        );
        assert_eq!(
            call(
                &mut host,
                &mut vm,
                &actor,
                name,
                syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION
            ),
            Err(VMError::PermissionDenied)
        );
    }
    let wrong_type = vm
        .alloc_input_tlv(&tlv(PointerType::Blob, b"Member"))
        .unwrap();
    vm.set_register(11, wrong_type);
    assert_eq!(
        host.syscall(syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION, &mut vm),
        Err(VMError::NoritoInvalid)
    );
}
