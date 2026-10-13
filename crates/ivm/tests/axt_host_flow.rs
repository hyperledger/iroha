//! AXT V1 host dispatch and fail-closed retirement controls.

use iroha_crypto::KeyPair;
use iroha_model_base::topology::DataSpaceId;
use ivm::{
    IVM, IVMHost, PointerType, VMError,
    axt::{self, TouchManifest},
    host::DefaultHost,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};

fn store_tlv(vm: &mut IVM, ty: PointerType, payload: &[u8]) -> u64 {
    let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
    tlv.extend_from_slice(&(ty as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    tlv.extend_from_slice(&hash);
    vm.alloc_input_tlv(&tlv)
        .expect("allocate canonical input TLV")
}

#[test]
fn default_host_accepts_descriptor_and_touch_but_requires_proof() {
    let mut vm = IVM::new(1_000_000);
    let mut host = DefaultHost::new();
    let dsid = DataSpaceId::new(7);
    let descriptor = axt::AxtDescriptor {
        dsids: vec![dsid],
        touches: vec![axt::AxtTouchSpec {
            dsid,
            read: vec!["orders".into()],
            write: vec!["ledger".into()],
        }],
    };
    let descriptor_bytes = norito::to_bytes(&descriptor).expect("encode descriptor");
    let descriptor_ptr = store_tlv(&mut vm, PointerType::AxtDescriptor, &descriptor_bytes);
    vm.set_register(10, descriptor_ptr);
    assert!(host.syscall(syscalls::SYSCALL_AXT_BEGIN, &mut vm).is_ok());
    let dsid_bytes = norito::to_bytes(&dsid).expect("encode dataspace");
    let manifest = TouchManifest {
        read: vec!["orders/item".into()],
        write: vec!["ledger/item".into()],
    };
    let manifest_bytes = norito::to_bytes(&manifest).expect("encode touch manifest");
    let dsid_ptr = store_tlv(&mut vm, PointerType::DataSpaceId, &dsid_bytes);
    let manifest_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &manifest_bytes);
    vm.set_register(10, dsid_ptr);
    vm.set_register(11, manifest_ptr);
    assert!(host.syscall(syscalls::SYSCALL_AXT_TOUCH, &mut vm).is_ok());
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_AXT_COMMIT, &mut vm),
        Err(VMError::PermissionDenied)
    ));
}

#[test]
fn hosts_reject_retired_handle_syscall_before_input_access() {
    let mut vm = IVM::new(1_000_000);
    vm.set_register(10, u64::MAX);
    vm.set_register(11, u64::MAX);
    let mut default = DefaultHost::new();
    let before = vm.remaining_gas();
    assert!(
        matches!(default.syscall(0xB4, &mut vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (0xB4))
    );
    assert_eq!(vm.remaining_gas(), before);
    let caller = AccountId::new(
        KeyPair::try_random()
            .expect("generate caller keypair")
            .public_key()
            .clone(),
    );
    let mut wsv = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    assert!(
        matches!(wsv.syscall(0xB4, &mut vm), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (0xB4))
    );
    assert_eq!(vm.remaining_gas(), before);
}

#[test]
fn default_host_rejects_empty_descriptor_without_mutation() {
    let mut vm = IVM::new(1_000_000);
    let mut host = DefaultHost::new();
    let descriptor = axt::AxtDescriptor {
        dsids: Vec::new(),
        touches: Vec::new(),
    };
    let bytes = norito::to_bytes(&descriptor).expect("encode descriptor");
    let ptr = store_tlv(&mut vm, PointerType::AxtDescriptor, &bytes);
    vm.set_register(10, ptr);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_AXT_BEGIN, &mut vm),
        Err(VMError::PermissionDenied)
    ));
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_AXT_COMMIT, &mut vm),
        Err(VMError::PermissionDenied)
    ));
}
