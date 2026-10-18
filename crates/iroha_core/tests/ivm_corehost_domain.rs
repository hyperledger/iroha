//! `CoreHost` domain syscall bridging and TLV validation tests.

use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use ivm::IVMHost; // bring trait into scope for `.syscall()`
use ivm::{IVM, Memory, ProgramMetadata, syscalls};
fn build_tlv<T: norito::NoritoSerialize>(type_id: u16, val: &T) -> Vec<u8> {
    use iroha_crypto::Hash;
    let payload = norito::to_bytes(val).expect("encode payload");
    let mut v = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    v.extend_from_slice(&type_id.to_be_bytes());
    v.push(1u8);
    v.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    v.extend_from_slice(&payload);
    let h: [u8; 32] = Hash::new(&payload).into();
    v.extend_from_slice(&h);
    v
}
#[test]
fn register_and_unregister_domain_queue_instructions() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    vm.load_program(&ProgramMetadata::default().encode())
        .unwrap();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let tlv = build_tlv(0x0008, &domain_id);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    let ptr = Memory::INPUT_START;
    vm.set_register(10, ptr);
    // Register
    let res = host.syscall(syscalls::SYSCALL_REGISTER_DOMAIN, &mut vm);
    assert!(res.is_ok());
    let queued = host.drain_instructions();
    assert_eq!(queued.len(), 1);
    // Unregister (reset host)
    let mut host2 = CoreHost::new(ALICE_ID.clone());
    vm.set_register(10, ptr);
    let res2 = host2.syscall(syscalls::SYSCALL_UNREGISTER_DOMAIN, &mut vm);
    assert!(res2.is_ok());
    let queued2 = host2.drain_instructions();
    assert_eq!(queued2.len(), 1);
}
#[test]
fn transfer_domain_queues_instruction() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    vm.load_program(&ProgramMetadata::default().encode())
        .unwrap();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let tlv_dom = build_tlv(0x0008, &domain_id);
    vm.memory.preload_input(0, &tlv_dom).expect("preload input");
    let p_dom = Memory::INPUT_START;
    let tlv_to = build_tlv(0x0001, &BOB_ID.clone());
    vm.memory
        .preload_input(256, &tlv_to)
        .expect("preload input");
    let p_to = Memory::INPUT_START + 256;
    vm.set_register(10, p_dom);
    vm.set_register(11, p_to);
    let res = host.syscall(syscalls::SYSCALL_TRANSFER_DOMAIN, &mut vm);
    assert!(res.is_ok());
    let queued = host.drain_instructions();
    assert_eq!(queued.len(), 1);
}
#[test]
fn register_domain_rejects_wrong_type() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    vm.load_program(&ProgramMetadata::default().encode())
        .unwrap();
    // Use AccountId TLV where DomainId expected (type mismatch)
    let bad = build_tlv(0x0001, &ALICE_ID.clone());
    vm.memory.preload_input(0, &bad).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let res = host.syscall(syscalls::SYSCALL_REGISTER_DOMAIN, &mut vm);
    assert!(matches!(res, Err(ivm::VMError::NoritoInvalid)));
}
#[test]
fn register_domain_rejects_corrupted_hash() {
    use iroha_crypto::Hash;
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    vm.load_program(&ProgramMetadata::default().encode())
        .unwrap();
    let did: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let payload = norito::to_bytes(&did).expect("encode domain id");
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0008u16.to_be_bytes());
    blob.push(1);
    blob.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(&payload);
    let mut h: [u8; 32] = Hash::new(&payload).into();
    h[0] ^= 0xAA; // corrupt
    blob.extend_from_slice(&h);
    vm.memory.preload_input(0, &blob).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let res = host.syscall(syscalls::SYSCALL_REGISTER_DOMAIN, &mut vm);
    assert!(matches!(res, Err(ivm::VMError::NoritoInvalid)));
}
