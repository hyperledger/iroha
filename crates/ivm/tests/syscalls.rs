use iroha_crypto::{
    Hash, HashOf, MerkleProof,
    blake2::{
        Blake2bVar,
        digest::{Update as Blake2Update, VariableOutput},
    },
};
use iroha_data_model::prelude::AccountId;
use iroha_model_base::name::Name;
use ivm::{
    ExecutionSummary, IVM, IVMHost, PointerType, VMError, encoding, host::DefaultHost, instruction,
    syscalls,
};
use sha2::Digest as Sha2Digest;
use sha3_hash::{Digest as Sha3Digest, Keccak256, Sha3_256};
use std::{cell::Cell, collections::BTreeMap};
mod common;
use common::{assemble, assemble_zk};
const HALT: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
fn assemble_syscall(syscall: u8) -> Vec<u8> {
    let mut code = Vec::with_capacity(8);
    let word = encoding::wide::encode_sys(instruction::wide::system::SCALL, syscall);
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&HALT);
    assemble(&code)
}
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
    AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("public key"),
    )
}
fn raw_blake2b256(payload: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2b output size");
    hasher.update(payload);
    hasher
        .finalize_variable(&mut digest)
        .expect("fixed output buffer has the requested length");
    digest
}
#[test]
fn debug_print_is_handled_by_default_host() {
    let mut vm = IVM::new(u64::MAX);
    // Program: SCALL 0x00; HALT
    let prog = assemble_syscall(syscalls::SYSCALL_DEBUG_PRINT as u8);
    vm.load_program(&prog).unwrap();
    let result = vm.run();
    assert!(result.is_ok(), "debug_print should be handled");
}
#[test]
fn syscall_policy_gating_allows_known_and_rejects_unknown_v1() {
    // Build a tiny program making a known allowed syscall (ALLOC)
    // and then HALT. Set ABI version to 1 in the header to exercise policy.
    let mut bytes = assemble_syscall(syscalls::SYSCALL_ALLOC as u8);
    // Header layout: magic(4) major(1) minor(1) mode(1) vl(1) max_cycles(8) abi(1)
    // Set abi_version (last header byte) to 1
    bytes[4 + 1 + 1 + 1 + 1 + 8] = 1;
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&bytes).unwrap();
    vm.run().expect("known syscall should be allowed under V1");
    // Unknown ABI numbers are rejected during authenticated program admission.
    let mut bad = assemble_syscall(0xDF);
    bad[4 + 1 + 1 + 1 + 1 + 8] = 1; // ABI v1
    let mut vm2 = IVM::new(u64::MAX);
    assert!(
        matches!(vm2.load_program(&bad), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (0xDF))
    );
}
#[test]
fn syscall_exit_halts_execution() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(10, 5);
    let mut code = Vec::new();
    let exit_sys = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        syscalls::SYSCALL_EXIT as u8,
    );
    code.extend_from_slice(&exit_sys.to_le_bytes());
    let addi = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 10, 0, 9);
    code.extend_from_slice(&addi.to_le_bytes());
    code.extend_from_slice(&HALT);
    let prog = assemble(&code);
    vm.load_program(&prog).unwrap();
    vm.run().expect("exit syscall should halt");
    assert_eq!(vm.register(10), 5);
}
#[test]
fn syscall_abort_marks_failure() {
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscall(syscalls::SYSCALL_ABORT as u8);
    vm.load_program(&prog).unwrap();
    vm.set_register(10, 0xA11CE);
    let result = vm.run();
    assert!(matches!(result, Err(VMError::AssertionFailed)));
    assert_eq!(vm.register(10), 0xA11CE, "abort code must survive in r10");
}
#[test]
fn debug_log_accepts_json_tlv() {
    let mut vm = IVM::new(u64::MAX);
    let payload = br#"{"msg":"hello"}"#;
    let tlv = make_tlv(PointerType::Json as u16, payload);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    let prog = assemble_syscall(syscalls::SYSCALL_DEBUG_LOG as u8);
    vm.load_program(&prog).unwrap();
    vm.run().expect("debug log should succeed");
}
#[test]
fn hash_syscalls_return_expected_digest_blobs() {
    let message = b"ivm deterministic hash syscalls";
    let sha256 = sha2::Sha256::digest(message).to_vec();
    let sha3 = <Sha3_256 as Sha3Digest>::digest(message).to_vec();
    let blake2b = raw_blake2b256(message).to_vec();
    let keccak = <Keccak256 as Sha3Digest>::digest(message).to_vec();
    let iroha_hash: [u8; 32] = Hash::new(message).into();
    for (syscall, expected) in [
        (syscalls::SYSCALL_SHA256_HASH, sha256),
        (syscalls::SYSCALL_SHA3_HASH, sha3),
        (syscalls::SYSCALL_BLAKE2B256_HASH, blake2b),
        (syscalls::SYSCALL_KECCAK256_HASH, keccak),
        (syscalls::SYSCALL_IROHA_HASH, iroha_hash.to_vec()),
    ] {
        let mut vm = IVM::new(10_000);
        let tlv = make_tlv(PointerType::Blob as u16, message);
        let ptr = vm.alloc_input_tlv(&tlv).expect("alloc input blob");
        vm.set_register(10, ptr);
        let prog = assemble_syscall(syscall as u8);
        vm.load_program(&prog).expect("load program");
        vm.run().expect("hash syscall should succeed");
        let out = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("validate hash output");
        assert_eq!(out.type_id, PointerType::Blob);
        assert_eq!(out.payload, expected.as_slice());
    }
}
#[test]
fn get_public_input_returns_named_tlv() {
    let mut vm = IVM::new(u64::MAX);
    let name: Name = "public_key".parse().unwrap();
    let payload = b"hello".to_vec();
    let value_tlv = make_tlv(PointerType::Blob as u16, &payload);
    let mut inputs = BTreeMap::new();
    inputs.insert(name.clone(), value_tlv);
    let mut host = ivm::host::DefaultHost::new().with_public_inputs(BTreeMap::new());
    host.set_public_inputs(inputs);
    vm.set_host(host);
    let name_tlv = make_tlv(PointerType::Name as u16, name.as_ref().as_bytes());
    let ptr = vm.alloc_input_tlv(&name_tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_PUBLIC_INPUT as u8);
    vm.load_program(&prog).unwrap();
    vm.run().expect("get public input should succeed");
    let out_ptr = vm.register(10);
    let out_tlv = vm.memory.validate_tlv(out_ptr).expect("validate output");
    assert_eq!(out_tlv.type_id, PointerType::Blob);
    assert_eq!(out_tlv.payload, payload.as_slice());
}
#[test]
fn get_public_input_missing_name_errors() {
    let mut vm = IVM::new(u64::MAX);
    let name: Name = "missing_key".parse().unwrap();
    vm.set_host(ivm::host::DefaultHost::new());
    let name_tlv = make_tlv(PointerType::Name as u16, name.as_ref().as_bytes());
    let ptr = vm.alloc_input_tlv(&name_tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_PUBLIC_INPUT as u8);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::PermissionDenied)));
}
#[test]
fn get_public_input_zero_pointer_errors() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(ivm::host::DefaultHost::new());
    vm.set_register(10, 0);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_PUBLIC_INPUT as u8);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::NoritoInvalid)));
}
#[test]
fn add_signatory_syscall_accepts_account_and_json() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(ivm::host::DefaultHost::new());
    let account: AccountId = sample_account();
    let account_raw = account.to_string();
    let account_tlv = make_tlv(PointerType::AccountId as u16, account_raw.as_bytes());
    let account_ptr = vm.alloc_input_tlv(&account_tlv).expect("alloc account");
    let signatory_key = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
    let signatory_json = format!("\"{signatory_key}\"");
    let signatory_tlv = make_tlv(PointerType::Json as u16, signatory_json.as_bytes());
    let signatory_ptr = vm.alloc_input_tlv(&signatory_tlv).expect("alloc signatory");
    vm.set_register(10, account_ptr);
    vm.set_register(11, signatory_ptr);
    let prog = assemble_syscall(syscalls::SYSCALL_ADD_SIGNATORY as u8);
    vm.load_program(&prog).unwrap();
    vm.run().expect("add signatory should succeed");
}
#[test]
fn remove_signatory_syscall_accepts_account_and_json() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(ivm::host::DefaultHost::new());
    let account: AccountId = sample_account();
    let account_raw = account.to_string();
    let account_tlv = make_tlv(PointerType::AccountId as u16, account_raw.as_bytes());
    let account_ptr = vm.alloc_input_tlv(&account_tlv).expect("alloc account");
    let signatory_key = "ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4";
    let signatory_json = format!("\"{signatory_key}\"");
    let signatory_tlv = make_tlv(PointerType::Json as u16, signatory_json.as_bytes());
    let signatory_ptr = vm.alloc_input_tlv(&signatory_tlv).expect("alloc signatory");
    vm.set_register(10, account_ptr);
    vm.set_register(11, signatory_ptr);
    let prog = assemble_syscall(syscalls::SYSCALL_REMOVE_SIGNATORY as u8);
    vm.load_program(&prog).unwrap();
    vm.run().expect("remove signatory should succeed");
}
#[test]
fn set_account_quorum_accepts_nonzero() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(ivm::host::DefaultHost::new());
    let account: AccountId = sample_account();
    let account_raw = account.to_string();
    let account_tlv = make_tlv(PointerType::AccountId as u16, account_raw.as_bytes());
    let account_ptr = vm.alloc_input_tlv(&account_tlv).expect("alloc account");
    vm.set_register(10, account_ptr);
    vm.set_register(11, 2);
    let prog = assemble_syscall(syscalls::SYSCALL_SET_ACCOUNT_QUORUM as u8);
    vm.load_program(&prog).unwrap();
    vm.run().expect("set account quorum should succeed");
}
#[test]
fn set_account_quorum_rejects_zero() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(ivm::host::DefaultHost::new());
    let account: AccountId = sample_account();
    let account_raw = account.to_string();
    let account_tlv = make_tlv(PointerType::AccountId as u16, account_raw.as_bytes());
    let account_ptr = vm.alloc_input_tlv(&account_tlv).expect("alloc account");
    vm.set_register(10, account_ptr);
    vm.set_register(11, 0);
    let prog = assemble_syscall(syscalls::SYSCALL_SET_ACCOUNT_QUORUM as u8);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::DecodeError)));
}
struct AddHost;
impl ivm::IVMHost for AddHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        if number == 1 {
            Ok(0)
        } else {
            Err(VMError::UnknownSyscall(number))
        }
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        if number == 1 {
            let a0 = vm.register(10);
            let a1 = vm.register(11);
            vm.set_register(10, a0.wrapping_add(a1));
            Ok(0)
        } else {
            Err(VMError::UnknownSyscall(number))
        }
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
#[test]
fn downcast_add_host() {
    let mut host: Box<dyn ivm::IVMHost> = Box::new(AddHost);
    assert!(host.as_any().downcast_mut::<AddHost>().is_some());
}
#[test]
fn test_custom_syscall() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(AddHost);
    vm.set_register(10, 5);
    vm.set_register(11, 7);
    let prog = assemble_syscall(1);
    vm.load_program(&prog).unwrap();
    vm.run().expect("custom syscall failed");
    assert_eq!(vm.register(10), 12);
}
#[test]
fn removed_hw_probe_syscalls_reject() {
    for number in [0xF2, 0xF3] {
        let mut vm = IVM::new(u64::MAX);
        let program = assemble_syscall(number);
        assert!(
            matches!(vm.load_program(&program), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (u32::from(number)))
        );
    }
}
#[test]
fn test_verify_proof_syscall() {
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscall(syscalls::SYSCALL_VERIFY_PROOF as u8);
    vm.load_program(&prog).unwrap();
    let summary = norito::to_bytes(&vm.execution_summary()).expect("encode execution summary");
    let proof_tlv = make_tlv(PointerType::NoritoBytes as u16, &summary);
    let proof_pointer = vm
        .alloc_input_tlv(&proof_tlv)
        .expect("allocate proof input");
    vm.set_register(10, proof_pointer);
    let err = vm.run().expect_err("VERIFY_PROOF should be unimplemented");
    assert!(matches!(
        err,
        VMError::NotImplemented { syscall } if syscall == syscalls::SYSCALL_VERIFY_PROOF
    ));
}
#[test]
fn test_execution_summary_syscall_returns_deterministic_summary() {
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscall(syscalls::SYSCALL_EXECUTION_SUMMARY as u8);
    vm.load_program(&prog).unwrap();
    vm.run()
        .expect("EXECUTION_SUMMARY should produce a summary");
    assert_eq!(vm.register(11), 0);
    let ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(ptr).expect("summary TLV");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let summary: ExecutionSummary = norito::decode_from_bytes(tlv.payload).expect("decode summary");
    assert_eq!(summary.version, ivm::EXECUTION_SUMMARY_VERSION_V1);
    assert_eq!(summary.code_hash, vm.code_hash());
    assert!(summary.gas_used > 0);
    let first_payload = tlv.payload.to_vec();
    let mut vm_again = IVM::new(u64::MAX);
    vm_again.load_program(&prog).unwrap();
    vm_again.run().expect("second summary run");
    let tlv_again = vm_again
        .memory
        .validate_tlv(vm_again.register(10))
        .expect("second summary TLV");
    assert_eq!(
        first_payload, tlv_again.payload,
        "execution summaries must be byte-identical for identical input"
    );
}

#[test]
fn traced_execution_summary_quotes_and_commits_the_invocation_register_log() {
    struct RecordingSummaryHost {
        inner: DefaultHost,
        quote: Cell<Option<u64>>,
        actual: Option<u64>,
    }

    impl IVMHost for RecordingSummaryHost {
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
            let quote = self.inner.prepare_syscall(number, vm)?;
            self.quote.set(Some(quote));
            Ok(quote)
        }

        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            let actual = self.inner.syscall(number, vm)?;
            self.actual = Some(actual);
            Ok(actual)
        }

        fn as_any(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    let mut code = encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, 5, 0, 7)
        .to_le_bytes()
        .to_vec();
    code.extend_from_slice(
        &encoding::wide::encode_syscallx(syscalls::SYSCALL_EXECUTION_SUMMARY).to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = assemble_zk(&code, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load traced summary program");
    vm.set_zk_trace_enabled(true);
    let mut host = RecordingSummaryHost {
        inner: DefaultHost::new(),
        quote: Cell::new(None),
        actual: None,
    };

    vm.run_with_host(&mut host)
        .expect("EXECUTION_SUMMARY should preserve the active invocation log");
    assert_eq!(host.quote.get(), host.actual);
    let tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("summary TLV");
    let summary: ExecutionSummary = norito::decode_from_bytes(tlv.payload).expect("decode summary");
    assert!(
        summary.register_log_len > 0,
        "summary generated inside the callback must include earlier register events"
    );
}
#[test]
fn test_get_merkle_path_syscall() {
    let mut vm = IVM::new(u64::MAX);
    let addr = ivm::Memory::HEAP_START;
    vm.memory.store_u32(addr, 0xABCD).unwrap();
    vm.memory.commit();
    vm.set_register(10, addr);
    vm.set_register(11, ivm::Memory::OUTPUT_START);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_MERKLE_PATH as u8);
    vm.load_program(&prog).unwrap();
    let expected = vm.memory.merkle_path(addr).unwrap();
    vm.run().expect("merkle path syscall failed");
    let len = vm.register(10) as usize;
    assert_eq!(len, expected.len());
    let mut out = vec![0u8; expected.len() * 32];
    vm.memory
        .load_bytes(ivm::Memory::OUTPUT_START, &mut out)
        .unwrap();
    for (i, node) in expected.iter().enumerate() {
        assert_eq!(&out[i * 32..(i + 1) * 32], node);
    }
}
#[test]
fn test_get_merkle_path_with_root_syscall() {
    let mut vm = IVM::new(u64::MAX);
    let addr = ivm::Memory::HEAP_START;
    vm.memory.store_u64(addr, 0x0123_4567_89AB_CDEF).unwrap();
    vm.memory.commit();
    let root_out = ivm::Memory::OUTPUT_START + 1024;
    vm.set_register(10, addr);
    vm.set_register(11, ivm::Memory::OUTPUT_START);
    vm.set_register(12, root_out);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_MERKLE_PATH as u8);
    vm.load_program(&prog).unwrap();
    let expected_root = vm.memory.current_root();
    vm.run().expect("merkle path syscall failed");
    let mut out_root = [0u8; 32];
    vm.memory.load_bytes(root_out, &mut out_root).unwrap();
    assert_eq!(out_root, *expected_root.as_ref());
}
#[test]
fn test_get_merkle_compact_syscall() {
    let mut vm = IVM::new(u64::MAX);
    let addr = ivm::Memory::HEAP_START + 64; // pick a different leaf
    vm.memory.store_u32(addr, 0xAAAA5555).unwrap();
    vm.memory.commit();
    let out = ivm::Memory::OUTPUT_START;
    let root_out = ivm::Memory::OUTPUT_START + 2048;
    vm.set_register(10, addr);
    vm.set_register(11, out);
    vm.set_register(12, 16); // cap depth to 16
    vm.set_register(13, root_out);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_MERKLE_COMPACT as u8);
    vm.load_program(&prog).unwrap();
    let path = vm.memory.merkle_path(addr).unwrap();
    let root = vm.memory.current_root();
    vm.run().expect("merkle compact syscall failed");
    // Parse header
    let mut hdr = [0u8; 1 + 4 + 4];
    vm.memory.load_bytes(out, &mut hdr).unwrap();
    let depth = hdr[0] as usize;
    let dirs = u32::from_le_bytes(hdr[1..5].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[5..9].try_into().unwrap()) as usize;
    assert_eq!(depth, count);
    assert!(depth <= 16 && depth <= path.len());
    // Check siblings equal to truncated path
    let mut sibs = vec![0u8; depth * 32];
    vm.memory
        .load_bytes(out + (1 + 4 + 4) as u64, &mut sibs)
        .unwrap();
    for i in 0..depth {
        assert_eq!(&sibs[i * 32..(i + 1) * 32], &path[i]);
    }
    // Check root
    let mut out_root = [0u8; 32];
    vm.memory.load_bytes(root_out, &mut out_root).unwrap();
    let leaf_idx = (addr / 32) as u32;
    let mask = (1u64 << depth) - 1;
    assert_eq!(dirs as u64, (leaf_idx as u64) & mask);
    let siblings: Vec<Option<HashOf<[u8; 32]>>> = path
        .iter()
        .take(depth)
        .map(|b| {
            if *b == [0u8; 32] {
                None
            } else {
                Some(HashOf::from_untyped_unchecked(Hash::prehashed(*b)))
            }
        })
        .collect();
    let proof = MerkleProof::from_audit_path(dirs, siblings);
    let mut chunk = [0u8; 32];
    vm.memory.load_bytes((addr / 32) * 32, &mut chunk).unwrap();
    let leaf_digest = ivm::merkle_utils::compute_memory_leaf_digest(&chunk);
    let leaf_hash = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf_digest));
    let expected_root = if depth < path.len() {
        proof
            .compute_partial_root_sha256(&leaf_hash, depth)
            .expect("proof height equals compact depth")
    } else {
        root
    };
    assert_eq!(out_root, *expected_root.as_ref());
    // Basic sanity on dirs: at least has bits set within range
    assert_eq!(dirs >> depth, 0);
}
#[test]
fn test_get_merkle_path_syscall_out_of_bounds() {
    let mut vm = IVM::new(u64::MAX);
    let max_addr = vm
        .memory
        .stack_top()
        .saturating_add(ivm::Memory::STACK_SLOP);
    vm.set_register(10, max_addr);
    vm.set_register(11, ivm::Memory::OUTPUT_START);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_MERKLE_PATH as u8);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::MemoryOutOfBounds)));
}
#[test]
fn test_get_merkle_compact_syscall_out_of_bounds() {
    let mut vm = IVM::new(u64::MAX);
    let max_addr = vm
        .memory
        .stack_top()
        .saturating_add(ivm::Memory::STACK_SLOP);
    let out = ivm::Memory::OUTPUT_START;
    let root_out = out + 2048;
    vm.set_register(10, max_addr);
    vm.set_register(11, out);
    vm.set_register(12, 0);
    vm.set_register(13, root_out);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_MERKLE_COMPACT as u8);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::MemoryOutOfBounds)));
}
#[test]
fn test_get_register_merkle_compact_syscall_out_of_bounds() {
    let mut vm = IVM::new(u64::MAX);
    let out = ivm::Memory::OUTPUT_START;
    let root_out = out + 2048;
    vm.set_register(10, ivm::parallel::REGISTER_COUNT as u64);
    vm.set_register(11, out);
    vm.set_register(12, 0);
    vm.set_register(13, root_out);
    let prog = assemble_syscall(syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT as u8);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::RegisterOutOfBounds)));
}
