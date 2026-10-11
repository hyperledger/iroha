use iroha_crypto::{Hash, PublicKey};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use ivm::{
    IVM, Memory, PointerType,
    mock_wsv::{AccountId, AssetDefinitionId, MockWorldStateView, PermissionToken, WsvHost},
    syscalls,
};
use norito::to_bytes;
mod common;
use common::assemble_syscalls;
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
fn make_quantity_tlv(amount: impl Into<Quantity>) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(&amount.into()).expect("encode quantity pointer envelope")
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
fn make_asset_definition_norito_tlv(asset_definition: &AssetDefinitionId) -> Vec<u8> {
    let payload = to_bytes(asset_definition).expect("encode asset definition into Norito");
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&(PointerType::AssetDefinitionId as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(&payload).into();
    out.extend_from_slice(&h);
    out
}
fn test_account(_domain: DomainId, public_key: PublicKey) -> AccountId {
    AccountId::new(public_key)
}
#[test]
fn unregister_flow_with_opaque_asset_definition_dependencies() {
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
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("wonder", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(alice.clone());
    // Grant required permissions
    wsv.grant_permission(&alice, PermissionToken::RegisterDomain);
    wsv.grant_permission(&alice, PermissionToken::RegisterAccount);
    wsv.grant_permission(&alice, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&alice, PermissionToken::MintAsset(rose.clone()));
    wsv.grant_permission(&alice, PermissionToken::BurnAsset(rose.clone()));
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
    // Register asset def rose#wonder
    let ad = make_asset_definition_norito_tlv(&rose);
    vm.memory.preload_input(0, &ad).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    // r11 = display name, r12 = unconstrained numeric spec, r13 = infinitely mintable.
    let display_name = make_tlv(PointerType::Blob as u16, b"Rose");
    vm.memory
        .preload_input(ad.len() as u64 + 8, &display_name)
        .expect("preload input");
    vm.set_register(11, Memory::INPUT_START + ad.len() as u64 + 8);
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let prog_ad = assemble_syscalls(&[syscalls::SYSCALL_REGISTER_ASSET as u8]);
    vm.load_program(&prog_ad).unwrap();
    vm.run().expect("register asset def");
    // Mint 7 units of rose to bob
    let tlv_bob = make_account_tlv(&bob);
    let tlv_rose = make_asset_definition_norito_tlv(&rose);
    vm.memory.preload_input(0, &tlv_bob).expect("preload input");
    vm.memory
        .preload_input(tlv_bob.len() as u64 + 8, &tlv_rose)
        .expect("preload input");
    let tlv_amount = make_quantity_tlv(7_u64);
    let amount_offset = tlv_bob.len() as u64 + tlv_rose.len() as u64 + 16;
    vm.memory
        .preload_input(amount_offset, &tlv_amount)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + tlv_bob.len() as u64 + 8);
    vm.set_register(12, Memory::INPUT_START + amount_offset);
    let prog_mint = assemble_syscalls(&[syscalls::SYSCALL_MINT_ASSET as u8]);
    vm.load_program(&prog_mint).unwrap();
    vm.run().expect("mint asset");
    // Opaque canonical asset definition ids do not carry a domain projection,
    // so the domain can be unregistered even while the asset definition and its
    // balances still exist.
    let dom = make_tlv(PointerType::DomainId as u16, b"wonder");
    vm.memory.preload_input(0, &dom).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_udom = assemble_syscalls(&[syscalls::SYSCALL_UNREGISTER_DOMAIN as u8]);
    vm.load_program(&prog_udom).unwrap();
    vm.run().expect("unregister opaque domain");
    // Attempt to unregister asset def -> should fail (balances exist)
    let ad = make_asset_definition_norito_tlv(&rose);
    vm.memory.preload_input(0, &ad).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_uad = assemble_syscalls(&[syscalls::SYSCALL_UNREGISTER_ASSET as u8]);
    vm.load_program(&prog_uad).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::PermissionDenied)));
    // Burn 7 units from bob to clear balances
    let tlv_bob = make_account_tlv(&bob);
    let tlv_rose = make_asset_definition_norito_tlv(&rose);
    vm.memory.preload_input(0, &tlv_bob).expect("preload input");
    vm.memory
        .preload_input(tlv_bob.len() as u64 + 8, &tlv_rose)
        .expect("preload input");
    let tlv_amount = make_quantity_tlv(7_u64);
    let amount_offset = tlv_bob.len() as u64 + tlv_rose.len() as u64 + 16;
    vm.memory
        .preload_input(amount_offset, &tlv_amount)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + tlv_bob.len() as u64 + 8);
    vm.set_register(12, Memory::INPUT_START + amount_offset);
    let prog_burn = assemble_syscalls(&[syscalls::SYSCALL_BURN_ASSET as u8]);
    vm.load_program(&prog_burn).unwrap();
    vm.run().expect("burn asset");
    // Now unregister asset def -> success
    let ad = make_asset_definition_norito_tlv(&rose);
    vm.memory.preload_input(0, &ad).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.load_program(&prog_uad).unwrap();
    vm.run().expect("unregister asset def");
    // Unregister account bob -> success
    let acc = make_account_tlv(&bob);
    vm.memory.preload_input(0, &acc).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog_uacc = assemble_syscalls(&[syscalls::SYSCALL_UNREGISTER_ACCOUNT as u8]);
    vm.load_program(&prog_uacc).unwrap();
    vm.run().expect("unregister account");
}
