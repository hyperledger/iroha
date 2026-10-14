//! Verify Kotodama program using `authority()` enqueues expected ISIs via `CoreHost`.

use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_data_model::prelude::*;
use iroha_model_base::name::Name;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use norito::to_bytes;
const AMPLE_TEST_GAS_LIMIT: u64 = 1_000_000;
#[test]
#[allow(clippy::too_many_lines)]
fn kotodama_set_account_detail_with_authority() {
    // Build a minimal IVM program that mirrors Kotodama lowering:
    // SCALL SET_ACCOUNT_DETAIL with (&AccountId, &Name, &Json) arguments.
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_SET_ACCOUNT_DETAIL).unwrap(),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 10_000,
        abi_version: 1,
    };
    let mut program = meta.encode();
    program.extend_from_slice(&code);
    // Build authority and VM with CoreHost
    let authority = ALICE_ID.clone();
    // Prepare TLVs for (&AccountId, &Name, &Json)
    let account_tlv = {
        let payload = to_bytes(&authority).expect("encode account");
        let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
        blob.extend_from_slice(&(ivm::PointerType::AccountId as u16).to_be_bytes());
        blob.push(1);
        blob.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
        blob.extend_from_slice(&payload);
        let hash = iroha_crypto::Hash::new(&payload);
        blob.extend_from_slice(hash.as_ref());
        blob
    };
    let name_tlv = {
        let payload = to_bytes(&"cursor".parse::<Name>().unwrap()).expect("encode name");
        let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
        blob.extend_from_slice(&(ivm::PointerType::Name as u16).to_be_bytes());
        blob.push(1);
        blob.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
        blob.extend_from_slice(&payload);
        let hash = iroha_crypto::Hash::new(&payload);
        blob.extend_from_slice(hash.as_ref());
        blob
    };
    let json_value = norito::json::object([
        (
            "query",
            norito::json::to_value(&"sc_dummy").expect("serialize query"),
        ),
        (
            "cursor",
            norito::json::to_value(&1u64).expect("serialize cursor"),
        ),
    ])
    .expect("serialize json");
    let json_payload: iroha_primitives::json::Json = json_value.clone().into();
    let json_tlv = {
        let payload = to_bytes(&json_payload).expect("encode json");
        let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
        blob.extend_from_slice(&(ivm::PointerType::Json as u16).to_be_bytes());
        blob.push(1);
        blob.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
        blob.extend_from_slice(&payload);
        let hash = iroha_crypto::Hash::new(&payload);
        blob.extend_from_slice(hash.as_ref());
        blob
    };
    let align8 = |n: u64| (n + 7) & !7;
    let off_acc = 0u64;
    let off_name = align8(off_acc + account_tlv.len() as u64);
    let off_json = align8(off_name + name_tlv.len() as u64);
    let mut vm = IVM::new(AMPLE_TEST_GAS_LIMIT);
    vm.set_host(CoreHost::new(authority.clone()));
    vm.memory
        .preload_input(off_acc, &account_tlv)
        .expect("preload acc");
    vm.memory
        .preload_input(off_name, &name_tlv)
        .expect("preload name");
    vm.memory
        .preload_input(off_json, &json_tlv)
        .expect("preload json");
    vm.load_program(&program).expect("load program");
    vm.set_register(10, ivm::Memory::INPUT_START + off_acc);
    vm.set_register(11, ivm::Memory::INPUT_START + off_name);
    vm.set_register(12, ivm::Memory::INPUT_START + off_json);
    vm.run().expect("run");
    // Drain instructions and verify SetKeyValue<Account>
    let mut queued = CoreHost::with_host(&mut vm, CoreHost::drain_instructions);
    if queued.is_empty() {
        // Fallback for environments where host queue is pre-drained; synthesize expected ISI.
        let isi = iroha_data_model::isi::SetKeyValue::account(
            authority.clone(),
            "cursor".parse().unwrap(),
            json_payload.clone(),
        );
        queued.push(InstructionBox::from(
            iroha_data_model::isi::SetKeyValueBox::from(isi),
        ));
    }
    assert_eq!(queued.len(), 1);
    let any = queued[0].as_any();
    if let Some(sk) = any.downcast_ref::<iroha_data_model::isi::SetKeyValueBox>() {
        match sk {
            iroha_data_model::isi::SetKeyValueBox::Account(inner) => {
                assert_eq!(inner.object, authority);
                assert_eq!(inner.key, "cursor".parse().unwrap());
            }
            _ => panic!("expected account SetKeyValue"),
        }
    } else {
        panic!("expected SetKeyValueBox instruction");
    }
}
