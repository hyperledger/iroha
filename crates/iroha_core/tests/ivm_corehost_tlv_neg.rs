//! Host-level negative tests for typed TLV decoding via `CoreHost`.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes;
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, IVMHost, Memory, PointerType, ProgramMetadata, syscalls};
fn build_tlv(type_id: u16, version: u8, payload: &[u8], corrupt_hash: bool) -> Vec<u8> {
    use iroha_crypto::Hash;
    let mut v = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    v.extend_from_slice(&type_id.to_be_bytes());
    v.push(version);
    v.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    v.extend_from_slice(payload);
    let h = Hash::new(payload);
    let mut hb = h.as_ref().to_vec();
    if corrupt_hash {
        hb[0] ^= 0xFF;
    }
    v.extend_from_slice(&hb);
    v
}
fn quantity_tlv(value: u64) -> Vec<u8> {
    ivm_abi::numeric_tlv::encode_quantity(&Quantity::from(value))
        .expect("encode quantity pointer envelope")
}
fn local_contract_debug_host(authority: AccountId) -> CoreHost {
    let mut host = CoreHost::new(authority);
    host.set_local_contract_debug_execution();
    host
}
#[test]
fn get_authority_spills_to_owned_heap_after_input_exhaustion() {
    let authority = ALICE_ID.clone();
    let mut host = CoreHost::new(authority.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.alloc_input_tlv(&vec![0; Memory::INPUT_SIZE as usize])
        .expect("fill INPUT arena");
    host.syscall(syscalls::SYSCALL_GET_AUTHORITY, &mut vm)
        .expect("return authority from owned HEAP");
    let pointer = vm.register(10);
    assert!(
        (Memory::HEAP_START..Memory::HEAP_START + Memory::HEAP_SIZE).contains(&pointer),
        "authority output must spill into HEAP after INPUT exhaustion"
    );
    let tlv = vm.validate_tlv(pointer).expect("validate owned HEAP TLV");
    assert_eq!(tlv.type_id, PointerType::AccountId);
    let decoded: AccountId = norito::decode_from_bytes(tlv.payload).expect("decode authority");
    assert_eq!(decoded, authority);
}
#[test]
fn execute_instruction_rejects_retired_blob_carriers_without_register_mutation() {
    use iroha_crypto::Hash;
    let authority = ALICE_ID.clone();
    let instruction = InstructionBox::from(RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            Hash::new(b"strict-instruction-carrier"),
        ),
        code: vec![0x01, 0x02, 0x03],
    });
    let canonical = norito::to_bytes(&instruction).expect("encode instruction");
    for (label, payload) in [
        ("raw binary", canonical.clone()),
        ("hex text", hex::encode(&canonical).into_bytes()),
    ] {
        let mut host = local_contract_debug_host(authority.clone());
        let mut vm = IVM::new(u64::MAX);
        let envelope = build_tlv(PointerType::Blob as u16, 1, &payload, false);
        let pointer = vm
            .alloc_input_tlv(&envelope)
            .unwrap_or_else(|error| panic!("allocate {label} Blob carrier: {error:?}"));
        vm.set_register(10, pointer);
        vm.set_register(11, 0);
        assert!(
            matches!(
                host.syscall(syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm,),
                Err(ivm::VMError::NoritoInvalid)
            ),
            "{label} Blob carrier must be rejected before instruction dispatch"
        );
        assert_eq!(vm.register(10), pointer);
    }
}
#[test]
fn mint_asset_rejects_assetid_tlv_instead_of_assetdefinitionid() {
    // Authority and host
    let authority: AccountId = ALICE_ID.clone();
    let mut host = CoreHost::new(authority.clone());
    // Minimal VM with header
    let mut vm = IVM::new(0);
    let header = ProgramMetadata::default().encode();
    vm.load_program(&header).unwrap();
    // Build valid AccountId TLV for r10
    let acct_payload = norito::to_bytes(&authority).expect("encode account");
    let acct_tlv = build_tlv(0x0001, 1, &acct_payload, false);
    vm.memory
        .preload_input(0, &acct_tlv)
        .expect("preload input");
    let p_acct = Memory::INPUT_START;
    // Build AssetId TLV for r11 where AssetDefinitionId is expected (type mismatch)
    let asset_id: AssetId = AssetId::of(
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        authority.clone(),
    );
    let asset_id_payload = norito::to_bytes(&asset_id).expect("encode asset id");
    let assetid_tlv = build_tlv(0x0007, 1, &asset_id_payload, false);
    let off = (acct_tlv.len() as u64 + 7) & !7; // align a bit
    vm.memory
        .preload_input(off, &assetid_tlv)
        .expect("preload input");
    let p_asset = Memory::INPUT_START + off;
    let amount_tlv = quantity_tlv(42);
    let off_amount = (off + assetid_tlv.len() as u64 + 7) & !7;
    vm.memory
        .preload_input(off_amount, &amount_tlv)
        .expect("preload input");
    let p_amount = Memory::INPUT_START + off_amount;
    // r12 = amount
    vm.set_register(10, p_acct);
    vm.set_register(11, p_asset);
    vm.set_register(12, p_amount);
    let res = host.syscall(syscalls::SYSCALL_MINT_ASSET, &mut vm);
    assert!(matches!(res, Err(ivm::VMError::NoritoInvalid)));
}
#[test]
fn mint_asset_rejects_corrupted_accountid_hash() {
    let authority: AccountId = ALICE_ID.clone();
    let mut host = CoreHost::new(authority.clone());
    let mut vm = IVM::new(0);
    let header = ProgramMetadata::default().encode();
    vm.load_program(&header).unwrap();
    // Corrupted AccountId TLV for r10
    let acct_payload = norito::to_bytes(&authority).expect("encode account");
    let acct_tlv_bad = build_tlv(0x0001, 1, &acct_payload, true);
    vm.memory
        .preload_input(0, &acct_tlv_bad)
        .expect("preload input");
    let p_acct = Memory::INPUT_START;
    // Valid AssetDefinitionId for r11
    let asset_def = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let assetdef_payload = norito::to_bytes(&asset_def).expect("encode asset definition");
    let assetdef_tlv = build_tlv(0x0002, 1, &assetdef_payload, false);
    let off = 64;
    vm.memory
        .preload_input(off, &assetdef_tlv)
        .expect("preload input");
    let p_assetdef = Memory::INPUT_START + off;
    let amount_tlv = quantity_tlv(100);
    let off_amount = (off + assetdef_tlv.len() as u64 + 7) & !7;
    vm.memory
        .preload_input(off_amount, &amount_tlv)
        .expect("preload input");
    let p_amount = Memory::INPUT_START + off_amount;
    vm.set_register(10, p_acct);
    vm.set_register(11, p_assetdef);
    vm.set_register(12, p_amount);
    let res = host.syscall(syscalls::SYSCALL_MINT_ASSET, &mut vm);
    assert!(matches!(res, Err(ivm::VMError::NoritoInvalid)));
}
#[test]
fn mint_asset_rejects_unknown_typeid() {
    let authority: AccountId = ALICE_ID.clone();
    let mut host = CoreHost::new(authority.clone());
    let mut vm = IVM::new(0);
    let header = ProgramMetadata::default().encode();
    vm.load_program(&header).unwrap();
    // Valid AccountId TLV for r10
    let acct_payload = norito::to_bytes(&authority).expect("encode account");
    let acct_tlv = build_tlv(0x0001, 1, &acct_payload, false);
    vm.memory
        .preload_input(0, &acct_tlv)
        .expect("preload input");
    let p_acct = Memory::INPUT_START;
    // Unknown type id (e.g., 0x00AA) for r11
    let payload = norito::to_bytes(&AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    ))
    .expect("encode asset definition");
    let bad_tlv = build_tlv(0x00AA, 1, &payload, false);
    let off = 128;
    vm.memory
        .preload_input(off, &bad_tlv)
        .expect("preload input");
    let p_bad = Memory::INPUT_START + off;
    let amount_tlv = quantity_tlv(1);
    let off_amount = (off + bad_tlv.len() as u64 + 7) & !7;
    vm.memory
        .preload_input(off_amount, &amount_tlv)
        .expect("preload input");
    let p_amount = Memory::INPUT_START + off_amount;
    vm.set_register(10, p_acct);
    vm.set_register(11, p_bad);
    vm.set_register(12, p_amount);
    let res = host.syscall(syscalls::SYSCALL_MINT_ASSET, &mut vm);
    assert!(matches!(res, Err(ivm::VMError::NoritoInvalid)));
}
#[test]
fn register_contract_bytes_enforces_tlv_provenance_type_hash_and_payload() {
    use iroha_crypto::Hash;
    let authority = ALICE_ID.clone();
    let request = RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            Hash::new(b"provenance-checked-contract"),
        ),
        code: vec![0xAA, 0xBB, 0xCC],
    };
    let payload = norito::to_bytes(&request).expect("encode register-bytes request");
    let tlv = build_tlv(PointerType::NoritoBytes as u16, 1, &payload, false);
    let mut heap_vm = IVM::new(1_000);
    let heap_pointer = heap_vm
        .alloc_heap(u64::try_from(tlv.len()).expect("TLV length fits u64"))
        .expect("allocate owned HEAP envelope");
    heap_vm
        .store_bytes(heap_pointer, &tlv)
        .expect("store owned HEAP envelope");
    heap_vm.set_register(10, heap_pointer);
    assert!(
        local_contract_debug_host(authority.clone())
            .syscall(
                syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
                &mut heap_vm
            )
            .is_ok(),
        "an allocated HEAP envelope is valid V1 pointer provenance"
    );
    for (label, pointer) in [
        ("unallocated HEAP", Memory::HEAP_START),
        ("OUTPUT", Memory::OUTPUT_START),
        ("stack", Memory::STACK_START),
    ] {
        let mut vm = IVM::new(1_000);
        vm.store_bytes(pointer, &tlv)
            .unwrap_or_else(|error| panic!("store {label} fixture: {error:?}"));
        vm.set_register(10, pointer);
        assert!(
            matches!(
                local_contract_debug_host(authority.clone())
                    .syscall(syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES, &mut vm),
                Err(ivm::VMError::NoritoInvalid)
            ),
            "{label} must fail provenance validation"
        );
    }
    let mut code_vm = IVM::new(1_000);
    let mut code = ivm::encoding::wide::encode_halt().to_le_bytes().to_vec();
    let code_pointer = u64::try_from(code.len()).expect("code offset fits u64");
    code.extend_from_slice(&tlv);
    code_vm
        .load_code(&code)
        .expect("load non-literal code bytes");
    code_vm.set_register(10, code_pointer);
    assert!(
        matches!(
            local_contract_debug_host(authority.clone()).syscall(
                syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
                &mut code_vm,
            ),
            Err(ivm::VMError::NoritoInvalid)
        ),
        "an arbitrary code offset is not a loader-authenticated literal"
    );
    let mut partial_vm = IVM::new(1_000);
    let owned_bytes = tlv
        .len()
        .checked_sub(8)
        .expect("TLV exceeds one HEAP allocation unit");
    let partial_pointer = partial_vm
        .alloc_heap(u64::try_from(owned_bytes).expect("partial length fits u64"))
        .expect("allocate partial HEAP ownership");
    partial_vm
        .store_bytes(partial_pointer, &tlv)
        .expect("store bytes beyond the owned HEAP range");
    partial_vm.set_register(10, partial_pointer);
    assert!(
        matches!(
            local_contract_debug_host(authority.clone()).syscall(
                syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
                &mut partial_vm,
            ),
            Err(ivm::VMError::NoritoInvalid)
        ),
        "the complete envelope must be inside one owned HEAP allocation"
    );
    let mut corrupted = tlv.clone();
    *corrupted.last_mut().expect("TLV has a digest") ^= 1;
    for (label, envelope, expected) in [
        (
            "wrong nominal pointer type",
            build_tlv(PointerType::Blob as u16, 1, &payload, false),
            ivm::VMError::NoritoInvalid,
        ),
        (
            "corrupted payload digest",
            corrupted,
            ivm::VMError::NoritoInvalid,
        ),
        (
            "malformed Norito request",
            build_tlv(PointerType::NoritoBytes as u16, 1, b"not a request", false),
            ivm::VMError::DecodeError,
        ),
    ] {
        let mut vm = IVM::new(1_000);
        let pointer = vm
            .alloc_host_tlv(&envelope)
            .unwrap_or_else(|error| panic!("allocate {label} fixture: {error:?}"));
        vm.set_register(10, pointer);
        let actual = local_contract_debug_host(authority.clone())
            .syscall(syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES, &mut vm);
        assert!(
            matches!(
                (actual, expected),
                (
                    Err(ivm::VMError::NoritoInvalid),
                    ivm::VMError::NoritoInvalid
                ) | (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
            ),
            "{label} must fail closed"
        );
    }
}
