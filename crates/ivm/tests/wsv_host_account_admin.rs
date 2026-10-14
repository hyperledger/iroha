//! WSV host account administration syscall tests.
use crate::common;
use common::assemble_syscalls;
use iroha_crypto::{Hash, PublicKey};
use iroha_primitives::json::Json;
use ivm::{
    IVM, Memory, PointerType,
    mock_wsv::{AccountId, MockWorldStateView, PermissionToken, WsvHost},
    syscalls,
};
use norito::to_bytes;
fn make_tlv(type_id: PointerType, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(type_id, payload);
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&(type_id as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn make_domain_tlv(name: &str) -> Vec<u8> {
    make_tlv(PointerType::DomainId, name.as_bytes())
}
fn make_account_tlv(account: &AccountId) -> Vec<u8> {
    let account = account.to_string();
    make_tlv(PointerType::AccountId, account.as_bytes())
}
fn make_account_norito_tlv(account: &AccountId) -> Vec<u8> {
    let payload = to_bytes(account).expect("encode account into Norito");
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&(PointerType::AccountId as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(&payload).into();
    out.extend_from_slice(&h);
    out
}
fn account(_domain: &str, public_key: &str) -> AccountId {
    let public_key: PublicKey = public_key.parse().unwrap();
    AccountId::new(public_key)
}
fn load_and_run(vm: &mut IVM, program: &[u8]) -> Result<(), ivm::VMError> {
    vm.load_program(program)?;
    vm.run()
}
#[test]
fn add_signatory_syscall_updates_account() {
    let alice = account(
        "domain",
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
    );
    let signatory_key = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(alice.clone());
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let acct = make_account_tlv(&alice);
    let sig_json = make_tlv(PointerType::Json, format!("\"{signatory_key}\"").as_bytes());
    vm.memory.preload_input(0, &acct).expect("preload input");
    vm.memory
        .preload_input(acct.len() as u64 + 8, &sig_json)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + acct.len() as u64 + 8);
    let add_sig = assemble_syscalls(&[syscalls::SYSCALL_ADD_SIGNATORY as u8]);
    load_and_run(&mut vm, &add_sig).expect("add signatory");
    let host_any = vm.host_mut_any().unwrap();
    let host = host_any.downcast_mut::<WsvHost>().expect("WsvHost");
    let signers = host.wsv.account_signatories(&alice).expect("signatories");
    assert!(signers.contains(&signatory_key.to_string()));
}
#[test]
fn remove_signatory_syscall_updates_account() {
    let alice = account(
        "domain",
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
    );
    let signatory_key = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(alice.clone());
    assert!(wsv.add_signatory(&alice, &alice, signatory_key.to_string()));
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let acct = make_account_tlv(&alice);
    let sig_json = make_tlv(PointerType::Json, format!("\"{signatory_key}\"").as_bytes());
    vm.memory.preload_input(0, &acct).expect("preload input");
    vm.memory
        .preload_input(acct.len() as u64 + 8, &sig_json)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + acct.len() as u64 + 8);
    let remove_sig = assemble_syscalls(&[syscalls::SYSCALL_REMOVE_SIGNATORY as u8]);
    load_and_run(&mut vm, &remove_sig).expect("remove signatory");
    let host_any = vm.host_mut_any().unwrap();
    let host = host_any.downcast_mut::<WsvHost>().expect("WsvHost");
    let signers = host.wsv.account_signatories(&alice).expect("signatories");
    assert!(!signers.contains(&signatory_key.to_string()));
}
#[test]
fn set_account_quorum_syscall_updates_account() {
    let alice = account(
        "domain",
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
    );
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(alice.clone());
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let acct = make_account_tlv(&alice);
    vm.memory.preload_input(0, &acct).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, 2);
    let set_quorum = assemble_syscalls(&[syscalls::SYSCALL_SET_ACCOUNT_QUORUM as u8]);
    load_and_run(&mut vm, &set_quorum).expect("set quorum");
    let host_any = vm.host_mut_any().unwrap();
    let host = host_any.downcast_mut::<WsvHost>().expect("WsvHost");
    assert_eq!(host.wsv.account_quorum(&alice), Some(2));
}
#[test]
fn set_account_detail_with_permissions() {
    let alice = account(
        "domain",
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
    );
    let bob = account(
        "wonder",
        "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4",
    );
    let mut wsv = MockWorldStateView::new();
    wsv.grant_permission(&alice, PermissionToken::RegisterDomain);
    wsv.grant_permission(&alice, PermissionToken::RegisterAccount);
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // Register domain wonder and bob account
    let dom = make_domain_tlv("wonder");
    vm.memory.preload_input(0, &dom).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let reg_domain = assemble_syscalls(&[syscalls::SYSCALL_REGISTER_DOMAIN as u8]);
    load_and_run(&mut vm, &reg_domain).expect("register domain");
    let reg_acct = make_account_norito_tlv(&bob);
    vm.memory
        .preload_input(0, &reg_acct)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let reg_account = assemble_syscalls(&[syscalls::SYSCALL_REGISTER_ACCOUNT as u8]);
    load_and_run(&mut vm, &reg_account).expect("register account");
    // Grant permissions to set account detail.
    {
        let host_any = vm.host_mut_any().unwrap();
        let host = host_any.downcast_mut::<WsvHost>().expect("WsvHost");
        host.wsv
            .grant_permission(&alice, PermissionToken::SetAccountDetail(bob.clone()));
    }
    // Alternate lexical spellings fail before a Json pointer can enter the ABI.
    assert!(Json::from_str_norito(r#"{ "msg" : "hello" }"#).is_err());
    // Set account detail with the exact canonical JSON spelling.
    let key = make_tlv(PointerType::Name, b"greeting");
    let detail = make_tlv(PointerType::Json, br#"{"msg":"hello"}"#);
    let acct = make_account_tlv(&bob);
    vm.memory.preload_input(0, &acct).expect("preload input");
    vm.memory
        .preload_input(acct.len() as u64 + 8, &key)
        .expect("preload input");
    vm.memory
        .preload_input(acct.len() as u64 + key.len() as u64 + 16, &detail)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + acct.len() as u64 + 8);
    vm.set_register(
        12,
        Memory::INPUT_START + acct.len() as u64 + key.len() as u64 + 16,
    );
    let set_detail = assemble_syscalls(&[syscalls::SYSCALL_SET_ACCOUNT_DETAIL as u8]);
    load_and_run(&mut vm, &set_detail).expect("set detail");
    let host_any = vm.host_mut_any().unwrap();
    let host = host_any.downcast_mut::<WsvHost>().expect("WsvHost");
    let stored = host
        .wsv
        .account_detail_value(&bob, "greeting")
        .expect("detail stored");
    assert_eq!(stored, br#"{"msg":"hello"}"#);
}
