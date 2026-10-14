use crate::common;
use common::assemble_syscalls;
use iroha_crypto::{Hash, PublicKey};
use iroha_model_base::domain::DomainId;
use ivm::{
    IVM, Memory, PointerType,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};
use norito::to_bytes;
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
fn test_account(_domain: DomainId, public_key: PublicKey) -> AccountId {
    AccountId::new(public_key)
}
fn make_account_tlv(account: &AccountId) -> Vec<u8> {
    let account = account.to_string();
    make_tlv(PointerType::AccountId as u16, account.as_bytes())
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
#[test]
fn nft_burn_asset_then_unregister_account_succeeds() {
    // Caller starts as alice; later we switch caller to bob for the burn.
    let alice_domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap();
    let bob_domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("wonder", "universal").unwrap();
    let alice_pk: PublicKey =
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .unwrap();
    let bob_pk: PublicKey =
        "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
            .parse()
            .unwrap();
    let alice = test_account(alice_domain, alice_pk);
    let bob = test_account(bob_domain, bob_pk);
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(alice.clone());
    // Alice can register domain/account
    wsv.grant_permission(&alice, ivm::mock_wsv::PermissionToken::RegisterDomain);
    wsv.grant_permission(&alice, ivm::mock_wsv::PermissionToken::RegisterAccount);
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // Register domain wonder
    let dom = make_tlv(PointerType::DomainId as u16, b"wonder");
    vm.memory.preload_input(0, &dom).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_dom = assemble_syscalls(&[syscalls::SYSCALL_REGISTER_DOMAIN as u8]);
    vm.load_program(&prog_dom).unwrap();
    vm.run().expect("register domain");
    // Register the recipient account
    let acc = make_account_norito_tlv(&bob);
    vm.memory.preload_input(0, &acc).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_acc = assemble_syscalls(&[syscalls::SYSCALL_REGISTER_ACCOUNT as u8]);
    vm.load_program(&prog_acc).unwrap();
    vm.run().expect("register account");
    // Mint NFT owned by bob
    let nft_id = b"rose:uuid:ok$wonder";
    let tlv_nft = make_tlv(PointerType::NftId as u16, nft_id);
    let tlv_owner = make_account_tlv(&bob);
    vm.memory.preload_input(0, &tlv_nft).expect("preload input");
    vm.memory
        .preload_input(tlv_nft.len() as u64 + 8, &tlv_owner)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + tlv_nft.len() as u64 + 8);
    let prog_nft = assemble_syscalls(&[syscalls::SYSCALL_NFT_MINT_ASSET as u8]);
    vm.load_program(&prog_nft).unwrap();
    vm.run().expect("mint nft");
    // Attempt to unregister bob: fails because NFT exists
    let acc = make_account_tlv(&bob);
    vm.memory.preload_input(0, &acc).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_uacc = assemble_syscalls(&[syscalls::SYSCALL_UNREGISTER_ACCOUNT as u8]);
    vm.load_program(&prog_uacc).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::PermissionDenied)));
    // Switch caller to bob to burn NFT
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        host.set_caller_subject(bob.clone());
    }
    // Burn NFT (owner=bob)
    let tlv_nft = make_tlv(PointerType::NftId as u16, nft_id);
    vm.memory.preload_input(0, &tlv_nft).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_burn = assemble_syscalls(&[syscalls::SYSCALL_NFT_BURN_ASSET as u8]);
    vm.load_program(&prog_burn).unwrap();
    vm.run().expect("burn nft");
    // Switch back to alice and unregister bob: should now succeed
    if let Some(any) = vm.host_mut_any() {
        let host = any.downcast_mut::<WsvHost>().expect("downcast WsvHost");
        host.set_caller_subject(alice.clone());
    }
    let acc = make_account_tlv(&bob);
    vm.memory.preload_input(0, &acc).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.load_program(&prog_uacc).unwrap();
    vm.run().expect("unregister account after burning NFT");
}
