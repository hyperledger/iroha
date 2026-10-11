//! Shared fixtures and helpers for IVM integration tests.
#![allow(dead_code)]
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use std::vec::Vec;
// --- CompactProofBundle helpers via syscalls (test-only utilities) ---
use iroha_data_model::{prelude::*, smart_contract::manifest::EntryPointKind};
use iroha_primitives::{bigint::BigInt, json::Json, numeric_abi::IntValueV1};
use ivm::{
    EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, EmbeddedStateDescriptor,
    EmbeddedStateType, IVM, PointerType, ProgramMetadata, encoding, instruction, syscalls,
};
use ivm_abi::metadata::LITERAL_SECTION_MAGIC;
use ivm_abi::state_value::{
    StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1, StateValueSchemaV1,
    state_value_schema_hash_v1,
};
const HALT_WORD: u32 = encoding::wide::encode_halt();
pub const HALT: [u8; 4] = HALT_WORD.to_le_bytes();
/// Build a deterministic exact network identity for VM fixtures.
pub fn test_network_id(marker: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([marker; Hash::LENGTH]),
    ))
}
/// Select a named Kotodama V1 entrypoint after loading its artifact.
///
/// V1 artifacts deliberately begin with a non-dispatching `HALT`; raw VM tests
/// must exercise the same CNTR selector-to-PC mapping used by production hosts
/// instead of relying on source declaration order.
pub fn select_kotodama_entrypoint(vm: &mut IVM, program: &[u8], name: &str) {
    let parsed = ProgramMetadata::parse(program).expect("parse Kotodama V1 artifact");
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .expect("Kotodama V1 artifact must embed CNTR")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == name)
        .unwrap_or_else(|| panic!("missing Kotodama V1 entrypoint `{name}`"));
    let pc =
        u64::try_from(parsed.prefix_len()).expect("program prefix fits u64") + entrypoint.entry_pc;
    vm.set_program_counter(pc)
        .unwrap_or_else(|error| panic!("select Kotodama V1 entrypoint `{name}`: {error:?}"));
}
/// Encode a small fixture integer using the schema-bound Kotodama V1 `int` record.
pub fn encode_int_state_value(value: i64) -> Vec<u8> {
    let frame = IntValueV1::try_new(BigInt::from_i128(i128::from(value)))
        .expect("i64 is inside V1 int domain")
        .encode_frame()
        .expect("encode canonical int frame");
    encode_pointer_state_value(StateValueKindV1::Int, PointerType::Int, &frame)
}
/// Decode and validate a Kotodama V1 `int` state record known to fit `i64`.
pub fn decode_int_state_value(payload: &[u8]) -> i64 {
    let envelope = decode_pointer_state_value(payload, StateValueKindV1::Int);
    ivm::numeric_tlv::decode_int_bytes(&envelope)
        .expect("decode canonical int envelope")
        .try_to_i64()
        .expect("test state int fits i64")
}
/// Decode one pointer-backed Kotodama `int` word.
pub fn decode_int_word(vm: &IVM, pointer: u64) -> BigInt {
    let tlv = vm
        .validate_tlv(pointer)
        .unwrap_or_else(|error| panic!("validate int pointer 0x{pointer:08x}: {error:?}"));
    assert_eq!(
        tlv.type_id,
        PointerType::Int,
        "word 0x{pointer:08x} must contain an Int pointer"
    );
    IntValueV1::decode_frame(tlv.payload)
        .unwrap_or_else(|error| panic!("decode int pointer 0x{pointer:08x}: {error:?}"))
        .into_int()
}
/// Decode one pointer-backed Kotodama `int` word known to fit an `i64`.
pub fn decode_i64_word(vm: &IVM, pointer: u64) -> i64 {
    decode_int_word(vm, pointer)
        .try_to_i64()
        .unwrap_or_else(|| panic!("int pointer 0x{pointer:08x} does not fit i64"))
}
/// Decode one pointer-backed Kotodama `int` return table word.
pub fn decode_int_return_word(vm: &IVM, index: usize) -> BigInt {
    decode_int_word(
        vm,
        vm.public_call_result_word(index)
            .expect("completed int word"),
    )
}
/// Decode one pointer-backed Kotodama `int` return known to fit an `i64`.
pub fn decode_i64_return_word(vm: &IVM, index: usize) -> i64 {
    decode_i64_word(
        vm,
        vm.public_call_result_word(index)
            .expect("completed int word"),
    )
}
/// Encode raw bytes as a schema-bound Kotodama V1 `Bytes` state record.
pub fn encode_bytes_state_value(value: &[u8]) -> Vec<u8> {
    encode_pointer_state_value(StateValueKindV1::Bytes, PointerType::Blob, value)
}
/// Decode a schema-bound Kotodama V1 `Bytes` state record.
pub fn decode_bytes_state_value(payload: &[u8]) -> Vec<u8> {
    let envelope = decode_pointer_state_value(payload, StateValueKindV1::Bytes);
    let tlv = ivm::pointer_abi::validate_tlv_bytes(&envelope)
        .expect("bytes state record must contain a valid pointer envelope");
    assert_eq!(tlv.type_id, PointerType::Blob);
    tlv.payload.to_vec()
}
/// Decode one non-negative pointer-backed Kotodama `int` return as `u64`.
pub fn decode_u64_return_word(vm: &IVM, index: usize) -> u64 {
    decode_int_return_word(vm, index)
        .try_to_u64()
        .unwrap_or_else(|| panic!("int return word {index} does not fit u64"))
}
/// Encode one pointer-backed value using the schema-bound Kotodama V1 record.
pub fn encode_pointer_state_value(
    kind: StateValueKindV1,
    pointer_type: PointerType,
    payload: &[u8],
) -> Vec<u8> {
    assert!(kind.is_pointer(), "state kind must use a pointer word");
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(kind)],
    };
    let schema_bytes = norito::to_bytes(&schema).expect("encode pointer state schema");
    let mut envelope = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
    envelope.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test pointer payload fits u32")
            .to_be_bytes(),
    );
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(iroha_crypto::Hash::new(payload).as_ref());
    norito::to_bytes(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&schema_bytes),
        atoms: vec![StateValueAtomV1::Pointer(envelope)],
    })
    .expect("encode pointer state record")
}
/// Decode and structurally validate one pointer-backed Kotodama V1 state record.
pub fn decode_pointer_state_value(payload: &[u8], kind: StateValueKindV1) -> Vec<u8> {
    assert!(kind.is_pointer(), "state kind must use a pointer word");
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(kind)],
    };
    let schema_bytes = norito::to_bytes(&schema).expect("encode pointer state schema");
    let record: StateValueRecordV1 =
        norito::decode_from_bytes(payload).expect("decode pointer state record");
    assert_eq!(
        record.schema_hash,
        state_value_schema_hash_v1(&schema_bytes),
        "pointer state schema hash"
    );
    assert!(schema.validate_atoms(&record.atoms));
    let [StateValueAtomV1::Pointer(envelope)] = record.atoms.as_slice() else {
        panic!("pointer state record must contain exactly one pointer atom");
    };
    envelope.clone()
}
/// Canonical zero-argument, Unit-result table signature for a fixture function.
pub fn unit_callable(entry_pc: u64) -> ivm_abi::call::EmbeddedCallableV1 {
    ivm_abi::call::EmbeddedCallableV1 {
        entry_pc,
        frame_bytes: 0,
        arguments: ivm_abi::call::CallSchemaV1::empty(),
        results: ivm_abi::call::CallSchemaV1::unit(),
    }
}
/// Complete frameless Unit return through the caller-owned result table.
pub fn unit_return_words() -> [u32; 4] {
    use instruction::wide;
    [
        encoding::wide::encode_store(wide::memory::STORE64, 12, 0, 0),
        encoding::wide::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
        encoding::wide::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
        encoding::wide::encode_rr(wide::control::JALR, 0, 1, 0),
    ]
}
fn assemble_schema_contract_with_states(
    states: Vec<EmbeddedStateDescriptor>,
    write_keys: Vec<String>,
) -> Vec<u8> {
    let interface = EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables: vec![unit_callable(0)],
        seiyaku_name: "SyscallFixture".to_owned(),
        compiler_fingerprint: "ivm-integration-tests".to_owned(),
        abi_hash: syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![EmbeddedEntrypointDescriptor {
            name: "execute".to_owned(),
            kind: EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization:
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys,
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        states,
        error_messages: Vec::new(),
        error_types: Vec::new(),
        enum_types: Vec::new(),
    };
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(&interface.encode_section());
    for word in unit_return_words() {
        program.extend_from_slice(&word.to_le_bytes());
    }
    program
}
/// Assemble an admitted contract fixture over declared `Bytes` durable state.
pub fn assemble_bytes_state_schema_contract(state_names: &[&str]) -> Vec<u8> {
    let states = state_names
        .iter()
        .map(|name| EmbeddedStateDescriptor {
            name: (*name).to_owned(),
            ty: EmbeddedStateType::Bytes,
        })
        .collect();
    let write_keys = state_names
        .iter()
        .map(|name| format!("state:{name}"))
        .collect();
    assemble_schema_contract_with_states(states, write_keys)
}
fn assemble_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assemble(&bytes)
}
fn syscall_prog(syscall: u8) -> Vec<u8> {
    assemble_words(&[
        encoding::wide::encode_sys(instruction::wide::system::SCALL, syscall),
        HALT_WORD,
    ])
}
/// Issue GET_MERKLE_COMPACT via SCALL and decode into a CompactProofBundle.
pub fn syscall_memory_compact_bundle(
    vm: &mut IVM,
    addr: u64,
    depth_cap: Option<usize>,
) -> ivm::merkle_utils::CompactProofBundle {
    let out_ptr = ivm::Memory::OUTPUT_START;
    let root_out = out_ptr + 8192;
    vm.set_register(10, addr);
    vm.set_register(11, out_ptr);
    vm.set_register(12, depth_cap.unwrap_or(0) as u64);
    vm.set_register(13, root_out);
    let prog = syscall_prog(syscalls::SYSCALL_GET_MERKLE_COMPACT as u8);
    vm.load_program(&prog).expect("load program");
    vm.run().expect("syscall");
    // Parse header and decode typed compact proof
    let mut hdr = [0u8; 1 + 4 + 4];
    vm.memory.load_bytes(out_ptr, &mut hdr).expect("hdr");
    let depth = hdr[0] as usize;
    let total = 1 + 4 + 4 + depth * 32;
    let mut buf = vec![0u8; total];
    vm.memory.load_bytes(out_ptr, &mut buf).expect("body");
    let (cp, _) = ivm::merkle_utils::decode_compact_proof_bytes(&buf).expect("decode");
    // Read root
    let mut root = [0u8; 32];
    vm.memory.load_bytes(root_out, &mut root).expect("root");
    // Build bundle
    let siblings: Vec<[u8; 32]> = cp
        .siblings()
        .iter()
        .map(|opt| opt.map(|h| *h.as_ref()).unwrap_or([0u8; 32]))
        .collect();
    ivm::merkle_utils::CompactProofBundle {
        depth: cp.depth(),
        dirs: cp.dirs(),
        siblings,
        root,
    }
}
pub const MODE_VECTOR: u8 = 0x02;
pub const MODE_ZK: u8 = ivm::ivm_mode::ZK;
pub fn assemble_with_mode(code: &[u8], mode: u8) -> Vec<u8> {
    let vector_length = if (mode & MODE_VECTOR) != 0 { 4 } else { 0 };
    let meta = ProgramMetadata {
        mode,
        vector_length,
        max_cycles: 0,
        abi_version: 1,
        ..ProgramMetadata::default()
    };
    let mut v = meta.encode();
    v.extend_from_slice(code);
    v
}
pub fn assemble(code: &[u8]) -> Vec<u8> {
    assemble_with_mode(code, 0)
}
/// Assemble a program with an `LTLB` literal section and return the program
/// bytes plus the literal addresses inside the loaded code region.
pub fn assemble_with_literal_section(code: &[u8], literals: &[&[u8]]) -> (Vec<u8>, Vec<u64>) {
    let mut program = ProgramMetadata::default().encode();
    let offsets_len = literals.len() * 8;
    let data_start = 16 + offsets_len;
    let data_len: usize = literals.iter().map(|literal| literal.len()).sum();
    let mut offsets = Vec::with_capacity(literals.len());
    let mut data = Vec::with_capacity(data_len);
    let mut cursor = data_start as u64;
    for literal in literals {
        offsets.push(cursor);
        data.extend_from_slice(literal);
        cursor += literal.len() as u64;
    }
    program.extend_from_slice(&LITERAL_SECTION_MAGIC);
    program.extend_from_slice(&(literals.len() as u32).to_le_bytes());
    let post_pad = (4 - ((16 + offsets_len + data.len()) % 4)) % 4;
    program.extend_from_slice(&(post_pad as u32).to_le_bytes());
    program.extend_from_slice(&(data.len() as u32).to_le_bytes());
    for offset in &offsets {
        program.extend_from_slice(&offset.to_le_bytes());
    }
    program.extend_from_slice(&data);
    program.extend(std::iter::repeat_n(0u8, post_pad));
    let literal_addrs = offsets.into_iter().collect();
    program.extend_from_slice(code);
    (program, literal_addrs)
}
/// Assemble a program that consists of one or more syscall instructions followed by HALT.
pub fn assemble_syscalls<T>(syscalls: &[T]) -> Vec<u8>
where
    T: Copy + Into<u32>,
{
    let mut code = Vec::with_capacity((syscalls.len() + 1) * 4);
    for &num in syscalls {
        let num = num.into();
        let word = u8::try_from(num).map_or_else(
            |_| encoding::wide::encode_syscallx(num),
            |compact| encoding::wide::encode_sys(instruction::wide::system::SCALL, compact),
        );
        code.extend_from_slice(&word.to_le_bytes());
    }
    code.extend_from_slice(&HALT);
    assemble(&code)
}
/// Assemble a SCALL/HALT program with a literal-table prefix and return the
/// program bytes plus literal addresses inside the loaded code region.
pub fn assemble_syscalls_with_literal_section<T>(
    syscalls: &[T],
    literals: &[&[u8]],
) -> (Vec<u8>, Vec<u64>)
where
    T: Copy + Into<u32>,
{
    let mut code = Vec::with_capacity((syscalls.len() + 1) * 4);
    for &num in syscalls {
        let num = num.into();
        let word = u8::try_from(num).map_or_else(
            |_| encoding::wide::encode_syscallx(num),
            |compact| encoding::wide::encode_sys(instruction::wide::system::SCALL, compact),
        );
        code.extend_from_slice(&word.to_le_bytes());
    }
    code.extend_from_slice(&HALT);
    assemble_with_literal_section(&code, literals)
}
pub fn assemble_zk(code: &[u8], max_cycles: u64) -> Vec<u8> {
    let mut header = assemble_with_mode(code, MODE_ZK);
    // overwrite max_cycles in header (bytes 8..16)
    header[8..16].copy_from_slice(&max_cycles.to_le_bytes());
    header
}
pub fn payload_for_type(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    match pointer_type {
        PointerType::AccountId => encode_account_id_payload(payload),
        PointerType::AssetDefinitionId => {
            encode_from_str::<AssetDefinitionId>(payload, "AssetDefinitionId")
        }
        PointerType::AssetId => encode_from_str::<AssetId>(payload, "AssetId"),
        PointerType::DomainId => encode_domain_id_payload(payload),
        PointerType::Name => encode_name_payload(payload),
        PointerType::NftId => encode_from_str::<NftId>(payload, "NftId"),
        PointerType::Json => encode_json_payload(payload),
        _ => payload.to_vec(),
    }
}
pub fn json_from_payload(payload: &[u8]) -> norito::json::Value {
    let json: Json = norito::decode_from_bytes(payload).expect("decode Json payload");
    norito::json::from_str(json.get()).expect("parse Json payload")
}
fn encode_from_str<T>(payload: &[u8], label: &str) -> Vec<u8>
where
    T: core::str::FromStr + norito::NoritoSerialize,
    <T as core::str::FromStr>::Err: core::fmt::Display,
{
    let raw = core::str::from_utf8(payload).expect("payload must be utf-8");
    let value: T = raw
        .parse()
        .unwrap_or_else(|e| panic!("{label} literal `{raw}` failed to parse: {e}"));
    norito::to_bytes(&value).expect("encode payload")
}
fn encode_account_id_payload(payload: &[u8]) -> Vec<u8> {
    // Some tests already provide Norito-encoded AccountId payload bytes.
    if norito::decode_from_bytes::<AccountId>(payload).is_ok() {
        return payload.to_vec();
    }
    let raw = core::str::from_utf8(payload).expect("payload must be utf-8");
    let account = AccountId::parse_encoded(raw)
        .unwrap_or_else(|err| panic!("AccountId literal `{raw}` failed to parse: {err}"));
    norito::to_bytes(&account).expect("encode payload")
}
fn encode_json_payload(payload: &[u8]) -> Vec<u8> {
    let raw = core::str::from_utf8(payload).expect("json payload must be utf-8");
    let json = Json::from_str_norito(raw).expect("parse json payload");
    norito::to_bytes(&json).expect("encode json payload")
}
fn encode_name_payload(payload: &[u8]) -> Vec<u8> {
    // Some tests already provide Norito-encoded Name payload bytes.
    if norito::decode_from_bytes::<Name>(payload).is_ok() {
        return payload.to_vec();
    }
    let raw = core::str::from_utf8(payload).expect("payload must be utf-8");
    match raw.parse::<Name>() {
        Ok(name) => norito::to_bytes(&name).expect("encode payload"),
        // Permission token literals like `mint_asset:rose#wonder` are intentionally
        // not `Name`; pass them through as raw bytes so host-side parsing decides.
        Err(_) => payload.to_vec(),
    }
}
fn encode_domain_id_payload(payload: &[u8]) -> Vec<u8> {
    if norito::decode_from_bytes::<DomainId>(payload).is_ok() {
        return payload.to_vec();
    }
    let raw = core::str::from_utf8(payload).expect("payload must be utf-8");
    // Older IVM pointer-TLV tests still pass bare domain labels. Canonicalize
    // those onto the universal dataspace so the helper matches the checked-in
    // TLV examples and existing fixture usage.
    let domain = if raw.contains('.') {
        DomainId::parse_fully_qualified(raw)
    } else {
        DomainId::try_new(raw, "universal")
    }
    .unwrap_or_else(|err| panic!("DomainId literal `{raw}` failed to parse: {err}"));
    norito::to_bytes(&domain).expect("encode payload")
}

/// Retain an explicitly funded diagnostic fixture without raw owning exports.
pub fn diagnostic_snapshot(vm: &IVM) -> ivm::zk::DiagnosticTraceSnapshot {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    vm.try_diagnostic_snapshot(&budget)
        .expect("fund diagnostic fixture")
}
