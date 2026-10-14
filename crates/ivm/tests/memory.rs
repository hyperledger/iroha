use crate::common;
use common::assemble;
use ivm::{IVM, Memory, Perm, VMError, encoding, instruction};
fn push_word(code: &mut Vec<u8>, word: u32) {
    code.extend_from_slice(&word.to_le_bytes());
}
fn halt(code: &mut Vec<u8>) {
    push_word(code, encoding::wide::encode_halt());
}
fn store64(code: &mut Vec<u8>, base: u8, rs: u8, imm: i8) {
    push_word(
        code,
        encoding::wide::encode_store(instruction::wide::memory::STORE64, base, rs, imm),
    );
}
fn load64(code: &mut Vec<u8>, rd: u8, base: u8, imm: i8) {
    push_word(
        code,
        encoding::wide::encode_load(instruction::wide::memory::LOAD64, rd, base, imm),
    );
}
fn addi(code: &mut Vec<u8>, rd: u8, rs: u8, imm: i8) {
    push_word(
        code,
        encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, rd, rs, imm),
    );
}
fn sll(code: &mut Vec<u8>, rd: u8, rs1: u8, rs2: u8) {
    push_word(
        code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::SLL, rd, rs1, rs2),
    );
}
fn srl(code: &mut Vec<u8>, rd: u8, rs1: u8, rs2: u8) {
    push_word(
        code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::SRL, rd, rs1, rs2),
    );
}
fn sra(code: &mut Vec<u8>, rd: u8, rs1: u8, rs2: u8) {
    push_word(
        code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::SRA, rd, rs1, rs2),
    );
}
#[test]
fn test_memory_access() {
    let mut vm = IVM::new(u64::MAX);
    // 1. Test basic store and load: store 0x12345678 at an address, load it back
    let addr = Memory::HEAP_START;
    vm.set_register(1, addr);
    vm.set_register(2, 0x12345678);
    let mut program = Vec::new();
    store64(&mut program, 1, 2, 0);
    load64(&mut program, 3, 1, 0);
    halt(&mut program);
    let prog = assemble(&program);
    vm.load_program(&prog).unwrap();
    vm.run().expect("Store/Load failed");
    assert_eq!(vm.register(3), 0x12345678);
    // 2. Test misaligned access: attempt SH at an odd address -> MisalignedAccess error
    vm.set_register(1, Memory::HEAP_START + 1);
    vm.set_register(2, 0xABCD);
    let mut misalign_prog = Vec::new();
    store64(&mut misalign_prog, 1, 2, 0);
    halt(&mut misalign_prog);
    let prog = assemble(&misalign_prog);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(
        matches!(res, Err(VMError::MisalignedAccess { .. })),
        "Expected misaligned access error"
    );
    // 3. Test out-of-bounds access: SB to an address outside defined regions -> MemoryAccessViolation
    let out_addr = Memory::HEAP_START + Memory::HEAP_SIZE; // just beyond heap
    vm.set_register(1, out_addr);
    vm.set_register(2, 0xAA);
    let mut oob_prog = Vec::new();
    store64(&mut oob_prog, 1, 2, 0);
    halt(&mut oob_prog);
    let prog = assemble(&oob_prog);
    vm.load_program(&prog).unwrap();
    let res2 = vm.run();
    assert!(
        matches!(res2, Err(VMError::MemoryAccessViolation { perm: _, .. }))
            && if let Err(VMError::MemoryAccessViolation { perm, .. }) = res2 {
                perm == Perm::WRITE
            } else {
                false
            },
        "Expected MemoryAccessViolation with WRITE perm"
    );
    // 4. Test manual sign/zero extension for byte-sized value using shifts.
    vm.set_register(1, Memory::HEAP_START);
    vm.set_register(2, 0xFF);
    let mut signext_prog = Vec::new();
    // store64/ load64 into r3
    store64(&mut signext_prog, 1, 2, 0);
    load64(&mut signext_prog, 3, 1, 0);
    // shift amount 56 in r4
    addi(&mut signext_prog, 4, 0, 56);
    // sign-extend low byte: ((x3 << 56) >> 56) arith
    sll(&mut signext_prog, 5, 3, 4);
    sra(&mut signext_prog, 5, 5, 4);
    // zero-extend low byte: ((x3 << 56) >> 56) logical
    sll(&mut signext_prog, 6, 3, 4);
    srl(&mut signext_prog, 6, 6, 4);
    halt(&mut signext_prog);
    let prog = assemble(&signext_prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("Sign-extension load failed");
    // r5 should be sign-extended 0xFF -> -1 (0xFFFF_FFFF_FFFF_FFFF)
    // r6 should be zero-extended 0xFF -> 255
    assert_eq!(vm.register(5), 0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(vm.register(6), 0x0000_00FF);
}
#[test]
fn test_doubleword_load_store() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, Memory::HEAP_START);
    vm.set_register(2, 0x1122_3344_5566_7788);
    let mut prog = Vec::new();
    store64(&mut prog, 1, 2, 0);
    load64(&mut prog, 3, 1, 0);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("sd/ld failed");
    assert_eq!(vm.register(3), 0x1122_3344_5566_7788);
}
#[test]
fn test_code_region_is_read_only() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0);
    vm.set_register(2, 0xDEAD_BEEF);
    let mut prog = Vec::new();
    store64(&mut prog, 1, 2, 0);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    match res {
        Err(VMError::MemoryAccessViolation { perm, .. }) => {
            assert_eq!(perm, Perm::WRITE);
        }
        _ => panic!("Expected MemoryAccessViolation"),
    }
}
#[test]
fn test_misaligned_load() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, Memory::HEAP_START + 1);
    let mut prog = Vec::new();
    load64(&mut prog, 5, 1, 0);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::MisalignedAccess { .. })));
}
#[test]
fn test_halfword_sign_extension() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, Memory::HEAP_START);
    vm.set_register(2, 0xFF00u64);
    let mut prog = Vec::new();
    store64(&mut prog, 1, 2, 0);
    load64(&mut prog, 3, 1, 0);
    // shift amount 48 in r4
    addi(&mut prog, 4, 0, 48);
    // sign-extend lower 16 bits
    sll(&mut prog, 5, 3, 4);
    sra(&mut prog, 5, 5, 4);
    // zero-extend lower 16 bits
    sll(&mut prog, 6, 3, 4);
    srl(&mut prog, 6, 6, 4);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("half sign extension");
    assert_eq!(vm.register(5), 0xFFFF_FFFF_FFFF_FF00);
    assert_eq!(vm.register(6), 0x0000_0000_0000_FF00u64);
}
#[test]
fn test_misaligned_store_word() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, Memory::HEAP_START + 2);
    vm.set_register(2, 0xDEADBEEF);
    let mut prog = Vec::new();
    store64(&mut prog, 1, 2, 0);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::MisalignedAccess { .. })));
}
#[test]
fn test_stack_region_bounds() {
    // Valid access at the end of stack
    let mut vm = IVM::new(u64::MAX);
    let last = Memory::STACK_START + Memory::STACK_SIZE - 8;
    vm.set_register(1, last);
    vm.set_register(2, 0xAA55AA55);
    let mut ok_prog = Vec::new();
    store64(&mut ok_prog, 1, 2, 0);
    halt(&mut ok_prog);
    let prog = assemble(&ok_prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("stack store should succeed");
    // Out of bounds
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, Memory::STACK_START + Memory::STACK_SIZE);
    vm2.set_register(2, 0x11);
    let prog = assemble(&ok_prog);
    vm2.load_program(&prog).unwrap();
    let res = vm2.run();
    assert!(matches!(
        res,
        Err(VMError::MemoryAccessViolation {
            perm: Perm::WRITE,
            ..
        })
    ));
}
#[test]
fn test_input_output_regions() {
    let mut vm = IVM::new(u64::MAX);
    vm.store_u32(Memory::OUTPUT_START, 0xABCD1234)
        .expect("write output");
    let val = vm.load_u32(Memory::OUTPUT_START).unwrap();
    assert_eq!(val, 0xABCD1234);
    let err = vm.store_u32(Memory::INPUT_START, 1).unwrap_err();
    assert!(matches!(
        err,
        VMError::MemoryAccessViolation {
            perm: Perm::WRITE,
            ..
        }
    ));
}
#[test]
fn test_heap_is_not_executable() {
    let mut vm = IVM::new(u64::MAX);
    // Place a HALT instruction in the heap region
    vm.store_u32(Memory::HEAP_START, 0).unwrap();
    // Program: JALR x0, x4, 0 -> jump to heap start
    // followed by HALT (never reached if jump succeeds)
    let mut prog = Vec::new();
    push_word(
        &mut prog,
        encoding::wide::encode_ri(instruction::wide::control::JALR, 0, 4, 0),
    );
    halt(&mut prog);
    let program = assemble(&prog);
    vm.load_program(&program).unwrap();
    vm.set_register(4, Memory::HEAP_START);
    let res = vm.run();
    assert!(
        matches!(res, Err(VMError::MemoryAccessViolation { perm, .. }) if perm.contains(Perm::EXECUTE))
    );
}
#[test]
fn test_signed_word_load() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, Memory::HEAP_START);
    vm.set_register(2, 0xFFFF_FF80u64); // store -128 in low 32 bits
    let mut prog = Vec::new();
    store64(&mut prog, 1, 2, 0);
    load64(&mut prog, 6, 1, 0);
    // sign-extend lower 32 bits via shift
    addi(&mut prog, 7, 0, 32);
    sll(&mut prog, 6, 6, 7);
    sra(&mut prog, 6, 6, 7);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("signed word load");
    assert_eq!(vm.register(6), 0xFFFF_FFFF_FFFF_FF80_u64);
}
#[test]
fn test_vector_load_store() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, Memory::HEAP_START);
    vm.set_register(2, 0x0102_0304_0506_0708);
    vm.set_register(3, 0x1112_1314_1516_1718);
    let mut prog = Vec::new();
    store64(&mut prog, 1, 2, 0);
    store64(&mut prog, 1, 3, 8);
    load64(&mut prog, 4, 1, 0);
    load64(&mut prog, 5, 1, 8);
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("vector load/store");
    assert_eq!(vm.register(4), 0x0102_0304_0506_0708);
    assert_eq!(vm.register(5), 0x1112_1314_1516_1718);
}
#[test]
fn test_heap_alloc_syscall() {
    use ivm::syscalls;
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(10, 16);
    let mut prog = Vec::new();
    push_word(
        &mut prog,
        encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            syscalls::SYSCALL_ALLOC as u8,
        ),
    );
    halt(&mut prog);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().expect("alloc syscall failed");
    let addr = vm.register(10);
    assert!((Memory::HEAP_START..Memory::HEAP_START + Memory::HEAP_SIZE).contains(&addr));
}
#[test]
fn test_bulk_store_and_load() {
    let mut vm = IVM::new(u64::MAX);
    let buf = [0x11u8; 16];
    vm.store_bytes(Memory::HEAP_START, &buf)
        .expect("bulk store failed");
    let mut out = [0u8; 16];
    vm.load_bytes(Memory::HEAP_START, &mut out)
        .expect("bulk load failed");
    assert_eq!(out, buf);
}
