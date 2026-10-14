use crate::common;
use common::assemble_syscalls;
use iroha_crypto::{Hash, PublicKey};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use iroha_primitives::{numeric::Quantity, numeric_abi::QuantityValueV1};
use ivm::{
    IVM, PointerType, VMError,
    mock_wsv::{AccountId, AssetDefinitionId, MockWorldStateView, PermissionToken, WsvHost},
    syscalls,
};
use std::str::FromStr;
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn unwrap_some_word(vm: &IVM) -> u64 {
    let layout = ivm::sum::SumLayoutV1::option(1).expect("Option layout");
    let (is_some, words) =
        ivm::sum::read_words(vm, vm.register(10), layout).expect("read typed JSON getter Option");
    assert!(is_some, "typed JSON getter must return Option::some");
    assert_eq!(words.len(), 1);
    words[0]
}
fn make_quantity_tlv(amount: impl Into<Quantity>) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(&amount.into()).expect("encode quantity pointer envelope")
}
fn make_account_tlv(account: &AccountId) -> Vec<u8> {
    make_tlv(
        PointerType::AccountId as u16,
        &norito::to_bytes(account).expect("encode account id"),
    )
}
fn make_asset_tlv(asset: &AssetDefinitionId) -> Vec<u8> {
    make_tlv(
        PointerType::AssetDefinitionId as u16,
        &norito::to_bytes(asset).expect("encode asset definition id"),
    )
}
fn make_dataspace_tlv(dataspace: DataSpaceId) -> Vec<u8> {
    let buf = norito::to_bytes(&dataspace).expect("encode DataSpaceId into Norito");
    make_tlv(PointerType::DataSpaceId as u16, &buf)
}
fn test_account(_domain: DomainId, public_key: PublicKey) -> AccountId {
    AccountId::new(public_key)
}
#[test]
fn test_balance_syscall_permission() {
    let domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap();
    let pk1: PublicKey = "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
        .parse()
        .unwrap();
    let pk2: PublicKey = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        .parse()
        .unwrap();
    let alice = test_account(domain.clone(), pk1);
    let bob = test_account(domain, pk2);
    let asset: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap(),
            "asset".parse().unwrap(),
        );
    let wsv = MockWorldStateView::with_balances(&[(
        (alice.clone(), asset.clone()),
        Quantity::from(50_u64),
    )]);
    // Bob has no permission initially
    let host = WsvHost::new_with_subject(wsv, bob.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let account_tlv = make_tlv(
        PointerType::AccountId as u16,
        &norito::to_bytes(&alice).expect("encode account id"),
    );
    let account_ptr = vm
        .alloc_input_tlv(&account_tlv)
        .expect("allocate account id");
    let asset_tlv = make_tlv(
        PointerType::AssetDefinitionId as u16,
        &norito::to_bytes(&asset).expect("encode asset definition id"),
    );
    let asset_ptr = vm
        .alloc_input_tlv(&asset_tlv)
        .expect("allocate asset definition id");
    vm.set_register(10, account_ptr);
    vm.set_register(11, asset_ptr);
    let prog = assemble_syscalls(&[syscalls::SYSCALL_GET_ACCOUNT_BALANCE as u8]);
    vm.load_program(&prog).unwrap();
    let result = vm.run();
    assert!(matches!(result, Err(VMError::PermissionDenied)));
    // Grant permission and retry using a fresh WSV instance
    let mut wsv2 = MockWorldStateView::with_balances(&[(
        (alice.clone(), asset.clone()),
        Quantity::from(50_u64),
    )]);
    wsv2.grant_permission(&bob, PermissionToken::ReadAccountAssets(alice.clone()));
    let host = WsvHost::new_with_subject(wsv2, bob);
    vm.set_host(host);
    vm.set_register(10, account_ptr);
    vm.set_register(11, asset_ptr);
    vm.load_program(&prog).unwrap();
    vm.run().expect("balance syscall failed");
    let tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("balance tlv");
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode balance")
        .into_quantity();
    assert_eq!(value, Quantity::from(50_u64));
}
#[test]
fn test_transfer_syscall_permission() {
    let domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap();
    let pk1: PublicKey = "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
        .parse()
        .unwrap();
    let pk2: PublicKey = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        .parse()
        .unwrap();
    let alice = test_account(domain.clone(), pk1);
    let bob = test_account(domain, pk2);
    let asset: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap(),
            "asset".parse().unwrap(),
        );
    let wsv = MockWorldStateView::with_balances(&[
        ((alice.clone(), asset.clone()), Quantity::from(50_u64)),
        ((bob.clone(), asset.clone()), Quantity::zero()),
    ]);
    let host = WsvHost::new_with_subject(wsv, bob.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let alice_ptr = vm
        .alloc_input_tlv(&make_account_tlv(&alice))
        .expect("allocate source account");
    let bob_ptr = vm
        .alloc_input_tlv(&make_account_tlv(&bob))
        .expect("allocate destination account");
    let asset_ptr = vm
        .alloc_input_tlv(&make_asset_tlv(&asset))
        .expect("allocate asset definition");
    vm.set_register(10, alice_ptr);
    vm.set_register(11, bob_ptr);
    vm.set_register(12, asset_ptr);
    let amount_tlv = make_quantity_tlv(10_u64);
    let amount_ptr = vm.alloc_input_tlv(&amount_tlv).expect("alloc amount tlv");
    vm.set_register(13, amount_ptr); // amount
    let dataspace_tlv = make_dataspace_tlv(DataSpaceId::UNIVERSAL);
    let dataspace_ptr = vm
        .alloc_input_tlv(&dataspace_tlv)
        .expect("alloc dataspace tlv");
    vm.set_register(14, dataspace_ptr); // dataspace
    let prog = assemble_syscalls(&[syscalls::SYSCALL_TRANSFER_ASSET_SCOPED as u8]);
    vm.load_program(&prog).unwrap();
    let result = vm.run();
    assert!(matches!(result, Err(VMError::PermissionDenied)));
    let mut wsv2 = MockWorldStateView::with_balances(&[
        ((alice.clone(), asset.clone()), Quantity::from(50_u64)),
        ((bob.clone(), asset.clone()), Quantity::zero()),
    ]);
    wsv2.grant_permission(&bob, PermissionToken::TransferAsset(asset.clone()));
    let host = WsvHost::new_with_subject(wsv2, bob.clone());
    vm.set_host(host);
    vm.load_program(&prog).unwrap();
    vm.run().expect("transfer syscall failed");
}
#[test]
fn test_mint_syscall_permission() {
    let domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap();
    let pk1: PublicKey = "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
        .parse()
        .unwrap();
    let pk2: PublicKey = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4"
        .parse()
        .unwrap();
    let _alice = test_account(domain.clone(), pk1);
    let bob = test_account(domain, pk2);
    let asset: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("domain", "universal").unwrap(),
            "asset".parse().unwrap(),
        );
    let wsv =
        MockWorldStateView::with_balances(&[((bob.clone(), asset.clone()), Quantity::zero())]);
    let host = WsvHost::new_with_subject(wsv, bob.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let bob_ptr = vm
        .alloc_input_tlv(&make_account_tlv(&bob))
        .expect("allocate account");
    let asset_ptr = vm
        .alloc_input_tlv(&make_asset_tlv(&asset))
        .expect("allocate asset definition");
    vm.set_register(10, bob_ptr);
    vm.set_register(11, asset_ptr);
    let amount_tlv = make_quantity_tlv(20_u64);
    let amount_ptr = vm.alloc_input_tlv(&amount_tlv).expect("alloc amount tlv");
    vm.set_register(12, amount_ptr); // amount
    let prog = assemble_syscalls(&[syscalls::SYSCALL_MINT_ASSET as u8]);
    vm.load_program(&prog).unwrap();
    let result = vm.run();
    assert!(matches!(result, Err(VMError::PermissionDenied)));
    let mut wsv2 =
        MockWorldStateView::with_balances(&[((bob.clone(), asset.clone()), Quantity::zero())]);
    wsv2.grant_permission(&bob, PermissionToken::MintAsset(asset.clone()));
    let host = WsvHost::new_with_subject(wsv2, bob.clone());
    vm.set_host(host);
    vm.load_program(&prog).unwrap();
    vm.run().expect("mint syscall failed");
}
#[test]
fn test_json_get_quantity_reads_canonical_decimal_strings() {
    let domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("domain", "universal").expect("domain");
    let public_key: PublicKey =
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("public key");
    let scoped_subject = test_account(domain, public_key);
    let host = WsvHost::new_with_subject(MockWorldStateView::new(), scoped_subject.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    let json = Json::from_str_norito(r#"{"amount":"0.00001"}"#).expect("json");
    let json_payload = norito::to_bytes(&json).expect("encode json");
    let key_payload =
        norito::to_bytes(&Name::from_str("amount").expect("name")).expect("encode key");
    let json_ptr = vm
        .alloc_input_tlv(&make_tlv(PointerType::Json as u16, &json_payload))
        .expect("alloc json");
    let key_ptr = vm
        .alloc_input_tlv(&make_tlv(PointerType::Name as u16, &key_payload))
        .expect("alloc key");
    vm.set_register(10, json_ptr);
    vm.set_register(11, key_ptr);
    let prog = assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_QUANTITY]);
    vm.load_program(&prog).unwrap();
    vm.run().expect("json_get_quantity syscall failed");
    let tlv = vm
        .memory
        .validate_tlv(unwrap_some_word(&vm))
        .expect("quantity tlv");
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode quantity")
        .into_quantity();
    assert_eq!(
        value,
        "0.00001".parse::<Quantity>().expect("parse quantity")
    );
}
