use crate::common;
use iroha_crypto::{Hash, PublicKey};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use ivm::{CoreHost, IVM, Memory, PointerType, encoding, instruction::wide, syscalls};
use norito::to_bytes;
const SAMPLE_NFT_ID: &[u8] = b"rose$wonderland.universal";
const ALT_NFT_ID: &[u8] = b"lily$wonderland.universal";
fn account_id_literal(public_key: &str) -> Vec<u8> {
    let public_key: PublicKey = public_key.parse().expect("valid public key");
    ivm::mock_wsv::AccountId::new(public_key)
        .to_string()
        .into_bytes()
}
fn alice_account_id_literal() -> Vec<u8> {
    account_id_literal("ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03")
}
fn bob_account_id_literal() -> Vec<u8> {
    account_id_literal("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4")
}
fn assemble(code: &[u8]) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    };
    let mut out = meta.encode();
    out.extend_from_slice(code);
    out
}
fn encode_prog_syscall(num: u32) -> Vec<u8> {
    let scall = wide::system::SCALL;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encoding::wide::encode_sys(scall, num as u8).to_le_bytes());
    bytes.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    assemble(&bytes)
}
fn make_tlv(type_id: u16, version: u8, payload: &[u8]) -> Vec<u8> {
    let payload = PointerType::from_u16(type_id)
        .map(|pty| common::payload_for_type(pty, payload))
        .unwrap_or_else(|| payload.to_vec());
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(version);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn make_quantity_tlv(amount: impl Into<Quantity>) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(&amount.into()).expect("encode quantity pointer envelope")
}
fn make_dataspace_tlv(dataspace: DataSpaceId) -> Vec<u8> {
    let buf = to_bytes(&dataspace).expect("encode DataSpaceId into Norito");
    make_tlv(PointerType::DataSpaceId as u16, 1, &buf)
}
#[test]
fn set_account_detail_validates_tlvs() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Prepare TLVs in INPUT
    let acc = make_tlv(
        PointerType::AccountId as u16,
        1,
        alice_account_id_literal().as_slice(),
    );
    let key = make_tlv(PointerType::Name as u16, 1, b"cursor");
    let val = make_tlv(PointerType::Json as u16, 1, br#"{"k":1}"#);
    let mut off = 0u64;
    vm.memory.preload_input(off, &acc).expect("preload input");
    let p_acc = Memory::INPUT_START + off;
    off += acc.len() as u64 + 16; // pad between items
    vm.memory.preload_input(off, &key).expect("preload input");
    let p_key = Memory::INPUT_START + off;
    off += key.len() as u64 + 16;
    vm.memory.preload_input(off, &val).expect("preload input");
    let p_val = Memory::INPUT_START + off;
    vm.set_register(10, p_acc);
    vm.set_register(11, p_key);
    vm.set_register(12, p_val);
    let prog = encode_prog_syscall(syscalls::SYSCALL_SET_ACCOUNT_DETAIL);
    vm.load_program(&prog).unwrap();
    vm.run().expect("set_account_detail tlvs should validate");
}
#[test]
fn set_account_detail_rejects_wrong_type() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Place AccountId in r11 (expected Name)
    let acc = make_tlv(
        PointerType::AccountId as u16,
        1,
        alice_account_id_literal().as_slice(),
    );
    vm.memory.preload_input(0, &acc).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START); // wrong type here
    // Minimal JSON for r12
    let json = make_tlv(PointerType::Json as u16, 1, br#"{}"#);
    vm.memory
        .preload_input(acc.len() as u64 + 16, &json)
        .expect("preload input");
    vm.set_register(12, Memory::INPUT_START + acc.len() as u64 + 16);
    let prog = encode_prog_syscall(syscalls::SYSCALL_SET_ACCOUNT_DETAIL);
    vm.load_program(&prog).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn nft_mint_asset_validates_tlvs() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let nft = make_tlv(PointerType::NftId as u16, 1, SAMPLE_NFT_ID);
    vm.memory.preload_input(0, &nft).expect("preload input");
    let acc = make_tlv(
        PointerType::AccountId as u16,
        1,
        alice_account_id_literal().as_slice(),
    );
    vm.memory
        .preload_input(nft.len() as u64 + 8, &acc)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + nft.len() as u64 + 8);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_MINT_ASSET);
    vm.load_program(&prog).unwrap();
    vm.run().expect("nft_mint_asset tlvs should validate");
}
#[test]
fn transfer_asset_validates_tlvs() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let from = make_tlv(
        PointerType::AccountId as u16,
        1,
        alice_account_id_literal().as_slice(),
    );
    vm.memory.preload_input(0, &from).expect("preload input");
    let to = make_tlv(
        PointerType::AccountId as u16,
        1,
        bob_account_id_literal().as_slice(),
    );
    vm.memory
        .preload_input(from.len() as u64 + 8, &to)
        .expect("preload input");
    let asset = make_tlv(
        PointerType::AssetDefinitionId as u16,
        1,
        b"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    );
    vm.memory
        .preload_input(from.len() as u64 + to.len() as u64 + 16, &asset)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + from.len() as u64 + 8);
    vm.set_register(
        12,
        Memory::INPUT_START + from.len() as u64 + to.len() as u64 + 16,
    );
    let amount = make_quantity_tlv(42_u64);
    let amount_offset = from.len() as u64 + to.len() as u64 + asset.len() as u64 + 24;
    vm.memory
        .preload_input(amount_offset, &amount)
        .expect("preload input");
    vm.set_register(13, Memory::INPUT_START + amount_offset);
    let dataspace = make_dataspace_tlv(DataSpaceId::UNIVERSAL);
    let dataspace_offset = amount_offset + amount.len() as u64 + 8;
    vm.memory
        .preload_input(dataspace_offset, &dataspace)
        .expect("preload dataspace");
    vm.set_register(14, Memory::INPUT_START + dataspace_offset);
    let prog = encode_prog_syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED);
    vm.load_program(&prog).unwrap();
    vm.run().expect("transfer_asset tlvs should validate");
}
#[test]
fn transfer_asset_rejects_wrong_asset_type() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Put Name instead of AssetDefinitionId in r12
    let from = make_tlv(
        PointerType::AccountId as u16,
        1,
        alice_account_id_literal().as_slice(),
    );
    let to = make_tlv(
        PointerType::AccountId as u16,
        1,
        bob_account_id_literal().as_slice(),
    );
    let wrong = make_tlv(PointerType::Name as u16, 1, b"not-an-asset-id");
    vm.memory.preload_input(0, &from).expect("preload input");
    vm.memory
        .preload_input(from.len() as u64 + 8, &to)
        .expect("preload input");
    vm.memory
        .preload_input(from.len() as u64 + to.len() as u64 + 16, &wrong)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + from.len() as u64 + 8);
    vm.set_register(
        12,
        Memory::INPUT_START + from.len() as u64 + to.len() as u64 + 16,
    );
    let amount = make_quantity_tlv(1_u64);
    let amount_offset = from.len() as u64 + to.len() as u64 + wrong.len() as u64 + 24;
    vm.memory
        .preload_input(amount_offset, &amount)
        .expect("preload input");
    vm.set_register(13, Memory::INPUT_START + amount_offset);
    let prog = encode_prog_syscall(syscalls::SYSCALL_TRANSFER_ASSET_SCOPED);
    vm.load_program(&prog).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn nft_set_metadata_validates_tlvs() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let nft = make_tlv(PointerType::NftId as u16, 1, SAMPLE_NFT_ID);
    vm.memory.preload_input(0, &nft).expect("preload input");
    let key = make_tlv(PointerType::Name as u16, 1, b"dpn_metadata");
    let key_offset = nft.len() as u64 + 8;
    vm.memory
        .preload_input(key_offset, &key)
        .expect("preload input");
    let json = make_tlv(PointerType::Json as u16, 1, br#"{"k":"v"}"#);
    let json_offset = key_offset + key.len() as u64 + 8;
    vm.memory
        .preload_input(json_offset, &json)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + key_offset);
    vm.set_register(12, Memory::INPUT_START + json_offset);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_SET_METADATA);
    vm.load_program(&prog).unwrap();
    vm.run().expect("nft_set_metadata tlvs should validate");
}
#[test]
fn nft_set_metadata_rejects_wrong_type() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let nft = make_tlv(PointerType::NftId as u16, 1, SAMPLE_NFT_ID);
    vm.memory.preload_input(0, &nft).expect("preload input");
    // Put Json instead of Name in r11.
    let wrong = make_tlv(PointerType::Json as u16, 1, br#"{"not":"name"}"#);
    let wrong_offset = nft.len() as u64 + 8;
    vm.memory
        .preload_input(wrong_offset, &wrong)
        .expect("preload input");
    let json = make_tlv(PointerType::Json as u16, 1, br#"{"k":"v"}"#);
    let json_offset = wrong_offset + wrong.len() as u64 + 8;
    vm.memory
        .preload_input(json_offset, &json)
        .expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    vm.set_register(11, Memory::INPUT_START + wrong_offset);
    vm.set_register(12, Memory::INPUT_START + json_offset);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_SET_METADATA);
    vm.load_program(&prog).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn nft_burn_asset_validates_tlv() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let nft = make_tlv(PointerType::NftId as u16, 1, ALT_NFT_ID);
    vm.memory.preload_input(0, &nft).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_BURN_ASSET);
    vm.load_program(&prog).unwrap();
    vm.run().expect("nft_burn_asset tlv should validate");
}
#[test]
fn nft_burn_asset_rejects_wrong_type() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    // Put AccountId instead of NftId in r10
    let wrong = make_tlv(
        PointerType::AccountId as u16,
        1,
        alice_account_id_literal().as_slice(),
    );
    vm.memory.preload_input(0, &wrong).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_BURN_ASSET);
    vm.load_program(&prog).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn nft_burn_asset_rejects_name_type() {
    // Pass &Name where &NftId is required
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let wrong = make_tlv(PointerType::Name as u16, 1, b"not-an-nft-id");
    vm.memory.preload_input(0, &wrong).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_BURN_ASSET);
    vm.load_program(&prog).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn nft_burn_asset_rejects_blob_type() {
    // Pass &Blob where &NftId is required
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let wrong = make_tlv(PointerType::Blob as u16, 1, b"opaque-bytes");
    vm.memory.preload_input(0, &wrong).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = encode_prog_syscall(syscalls::SYSCALL_NFT_BURN_ASSET);
    vm.load_program(&prog).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
