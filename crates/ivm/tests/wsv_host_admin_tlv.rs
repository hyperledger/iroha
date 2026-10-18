use crate::common;
use common::assemble_syscalls;
use iroha_crypto::Hash;
use iroha_data_model::peer::Peer;
use ivm::{
    IVM, Memory, PointerType,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};
use std::str::FromStr;
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let payload = PointerType::from_u16(type_id)
        .map(|pty| common::payload_for_type(pty, payload))
        .unwrap_or_else(|| payload.to_vec());
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn sample_account() -> AccountId {
    let _domain: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("domain", "universal").expect("domain id");
    AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("public key"),
    )
}
#[test]
fn register_peer_then_unregister() {
    let alice: AccountId = sample_account();
    let wsv = MockWorldStateView::new();
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    const SAMPLE_PEER: &str =
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774@127.0.0.1:1337";
    let peer_json = format!(r#"{{"peer":"{SAMPLE_PEER}"}}"#);
    let peer_payload = peer_json.into_bytes();
    // Unregister unknown peer: should fail
    let p = make_tlv(PointerType::Json as u16, &peer_payload);
    vm.memory.preload_input(0, &p).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_unreg = assemble_syscalls(&[syscalls::SYSCALL_UNREGISTER_PEER as u8]);
    vm.load_program(&prog_unreg).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::PermissionDenied)));
    // Register peer
    vm.memory.preload_input(0, &p).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_reg = assemble_syscalls(&[syscalls::SYSCALL_REGISTER_PEER as u8]);
    vm.load_program(&prog_reg).unwrap();
    vm.run().expect("register peer");
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        let peer = Peer::from_str(SAMPLE_PEER).expect("valid peer");
        assert!(host.wsv.has_peer(&peer));
    }
    // Unregister peer should now succeed
    vm.memory.preload_input(0, &p).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.load_program(&prog_unreg).unwrap();
    vm.run().expect("unregister peer");
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        let peer = Peer::from_str(SAMPLE_PEER).expect("valid peer");
        assert!(!host.wsv.has_peer(&peer));
    }
}
#[test]
fn create_enable_disable_remove_trigger() {
    let alice: AccountId = sample_account();
    let wsv = MockWorldStateView::new();
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // Missing name -> invalid
    let tr_bad = make_tlv(PointerType::Json as u16, br#"{"type":"data"}"#);
    vm.memory.preload_input(0, &tr_bad).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_ct = assemble_syscalls(&[syscalls::SYSCALL_CREATE_TRIGGER as u8]);
    vm.load_program(&prog_ct).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::NoritoInvalid)));
    // Valid create (with name)
    let tr_ok = make_tlv(PointerType::Json as u16, br#"{"name":"t1"}"#);
    vm.memory.preload_input(0, &tr_ok).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.load_program(&prog_ct).unwrap();
    vm.run().expect("create trigger");
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        assert_eq!(host.wsv.trigger_state("t1"), Some(true));
    }
    // Disable trigger t1
    let name = make_tlv(PointerType::Name as u16, b"t1");
    vm.memory.preload_input(0, &name).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, 0); // disable
    let prog_set = assemble_syscalls(&[syscalls::SYSCALL_SET_TRIGGER_ENABLED as u8]);
    vm.load_program(&prog_set).unwrap();
    vm.run().expect("disable trigger");
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        assert_eq!(host.wsv.trigger_state("t1"), Some(false));
    }
    // Remove trigger t1
    vm.memory.preload_input(0, &name).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_rm = assemble_syscalls(&[syscalls::SYSCALL_REMOVE_TRIGGER as u8]);
    vm.load_program(&prog_rm).unwrap();
    vm.run().expect("remove trigger");
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        assert_eq!(host.wsv.trigger_state("t1"), None);
    }
    // Removing non-existent trigger should fail
    vm.memory.preload_input(0, &name).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.load_program(&prog_rm).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::PermissionDenied)));
    // Toggling unknown trigger should fail
    vm.memory.preload_input(0, &name).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, 1);
    vm.load_program(&prog_set).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::PermissionDenied)));
}
