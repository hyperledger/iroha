//! CoreHost roundtrip harness for IVM syscalls.
use ivm::host::IVMHost;
use ivm::{
    CoreHost, EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, EmbeddedStateDescriptor,
    EmbeddedStateType, IVM, Memory, PointerType, ProgramMetadata, state_value, syscalls,
};
mod common;
fn make_tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(pty, payload);
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
fn state_path_tlv(path: &str) -> Vec<u8> {
    let path: iroha_model_base::state_path::StatePath = path.parse().expect("canonical state path");
    let payload = norito::to_bytes(&path).expect("encode state path");
    make_tlv(PointerType::NoritoBytes, &payload)
}
fn bytes_state_value(value: &[u8]) -> Vec<u8> {
    let schema = state_value::StateValueSchemaV1 {
        nodes: vec![state_value::StateValueNodeV1::Leaf(
            state_value::StateValueKindV1::Bytes,
        )],
    };
    let schema_payload = norito::to_bytes(&schema).expect("encode bytes state schema");
    let record = state_value::StateValueRecordV1 {
        schema_hash: state_value::state_value_schema_hash_v1(&schema_payload),
        atoms: vec![state_value::StateValueAtomV1::Pointer(make_tlv(
            PointerType::Blob,
            value,
        ))],
    };
    norito::to_bytes(&record).expect("encode bytes state value")
}
fn state_program(write: bool) -> Vec<u8> {
    let access_key = "state:roundtrip_key".to_owned();
    let entrypoint = EmbeddedEntrypointDescriptor {
        name: if write { "update" } else { "inspect" }.to_owned(),
        kind: if write {
            iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage
        } else {
            iroha_data_model::smart_contract::manifest::EntryPointKind::View
        },
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
            nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
        }),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
        read_keys: (!write).then_some(access_key.clone()).into_iter().collect(),
        write_keys: write.then_some(access_key).into_iter().collect(),
        access_hints_complete: Some(true),
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
        entry_pc: 0,
    };
    let interface = EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "HostRoundtripFixture".to_owned(),
        compiler_fingerprint: "ivm-integration-tests".to_owned(),
        abi_hash: syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![entrypoint],
        states: vec![EmbeddedStateDescriptor {
            name: "roundtrip_key".to_owned(),
            ty: EmbeddedStateType::Bytes,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        enum_types: Vec::new(),
    };
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(&interface.encode_section());
    for word in common::unit_return_words() {
        program.extend_from_slice(&word.to_le_bytes());
    }
    program
}
#[test]
fn host_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = CoreHost::new();
    let path_tlv = state_path_tlv("roundtrip_key");
    let value = bytes_state_value(&[0xA5, 0x5A, 0x01]);
    let value_tlv = make_tlv(PointerType::NoritoBytes, &value);
    let p_path = vm.alloc_input_tlv(&path_tlv).expect("alloc path");
    let p_val = vm.alloc_input_tlv(&value_tlv).expect("alloc value");
    let set_prog = state_program(true);
    vm.set_register(10, p_path);
    vm.set_register(11, p_val);
    vm.load_program(&set_prog).expect("load set");
    host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm)
        .expect("state set");
    let get_prog = state_program(false);
    vm.set_register(10, p_path);
    vm.load_program(&get_prog).expect("load get");
    host.syscall(syscalls::SYSCALL_STATE_GET, &mut vm)
        .expect("state get");
    let p_out = vm.register(10);
    assert!((Memory::INPUT_START..Memory::INPUT_START + Memory::INPUT_SIZE).contains(&p_out));
    let tlv = vm.memory.validate_tlv(p_out).expect("validate output");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    assert_eq!(tlv.payload, &value[..]);
}
