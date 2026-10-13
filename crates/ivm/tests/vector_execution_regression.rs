//! Regression tests for vector execution semantics and syscall policy guards.
use ivm::{IVM, IVMHost, ProgramMetadata, VMError, encoding, instruction, ivm_mode};
use std::any::Any;
const VECTOR_BASE: usize = 32;
fn program_with(meta: ProgramMetadata, words: &[u32]) -> Vec<u8> {
    let mut program = meta.encode();
    for word in words {
        program.extend_from_slice(&word.to_le_bytes());
    }
    program
}
fn vector_meta(max_cycles: u64, vector_length: u8) -> ProgramMetadata {
    ProgramMetadata {
        mode: ivm_mode::VECTOR,
        vector_length,
        max_cycles,
        abi_version: 1,
        ..ProgramMetadata::default()
    }
}
fn run_vadd32(max_cycles: u64) -> Vec<u64> {
    let vadd = encoding::wide::encode_rr(instruction::wide::crypto::VADD32, 2, 0, 1);
    let halt = encoding::wide::encode_halt();
    let program = program_with(vector_meta(max_cycles, 4), &[vadd, halt]);
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).expect("load program");
    let lhs = [
        0xffff_ffff_0000_0001,
        0x0000_0001_ffff_ffff,
        0x0000_0001_0000_0000,
        0xffff_ffff_ffff_ffff,
    ];
    let rhs = [1, 2, 3, 1];
    for (idx, value) in lhs.into_iter().enumerate() {
        vm.set_register(VECTOR_BASE + idx, value);
    }
    for (idx, value) in rhs.into_iter().enumerate() {
        vm.set_register(VECTOR_BASE + 4 + idx, value);
    }
    vm.run().expect("execute vadd32");
    (0..4)
        .map(|idx| vm.register(VECTOR_BASE + 8 + idx))
        .collect()
}
#[test]
fn vadd32_matches_with_and_without_cycle_limit() {
    let unbounded = run_vadd32(0);
    let bounded = run_vadd32(100);
    let expected = vec![2, 1, 3, 0];
    assert_eq!(unbounded, expected);
    assert_eq!(bounded, expected);
}
#[test]
fn vadd64_rejects_odd_vector_length() {
    let vadd = encoding::wide::encode_rr(instruction::wide::crypto::VADD64, 0, 0, 0);
    let halt = encoding::wide::encode_halt();
    let program = program_with(vector_meta(0, 3), &[vadd, halt]);
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).expect("load program");
    let err = vm.run().expect_err("odd VADD64 vector length must trap");
    assert!(matches!(
        err,
        VMError::InvalidVectorLength { vector_length: 3 }
    ));
}
#[test]
fn setvl_rejects_lengths_above_abi_max() {
    let setvl = encoding::wide::encode_rr(instruction::wide::crypto::SETVL, 0, 0, 65);
    let halt = encoding::wide::encode_halt();
    let program = program_with(vector_meta(0, 4), &[setvl, halt]);
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).expect("load program");
    let err = vm.run().expect_err("SETVL above ABI max must trap");
    assert!(matches!(
        err,
        VMError::InvalidVectorLength { vector_length: 65 }
    ));
}
struct PermissiveHost {
    called: bool,
}
impl IVMHost for PermissiveHost {
    fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        self.called = true;
        Ok(0)
    }
    fn as_any(&mut self) -> &mut dyn Any
    where
        Self: 'static,
    {
        self
    }
}
#[test]
fn program_admission_enforces_syscall_policy_before_host_dispatch() {
    let scall = encoding::wide::encode_sys(instruction::wide::system::SCALL, 0xDF);
    let halt = encoding::wide::encode_halt();
    let program = program_with(ProgramMetadata::default(), &[scall, halt]);
    let mut vm = IVM::new(10_000);
    vm.set_host(PermissiveHost { called: false });
    assert!(
        matches!(vm.load_program(&program), Err(VMError::UnknownSyscall(__actual_error_field)) if __actual_error_field == (0xDF))
    );
    let host = vm
        .host_mut_any()
        .expect("permissive host remains attached")
        .downcast_mut::<PermissiveHost>()
        .expect("permissive host type");
    assert!(!host.called);
}
#[test]
fn huge_program_counter_traps_without_overflow_panic() {
    let jalr = encoding::wide::encode_ri(instruction::wide::control::JALR, 0, 1, 0);
    let halt = encoding::wide::encode_halt();
    let program = program_with(ProgramMetadata::default(), &[jalr, halt]);
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).expect("load program");
    vm.set_register(1, u64::MAX - 3);
    let err = vm
        .run()
        .expect_err("huge aligned PC must trap instead of panicking");
    assert!(matches!(err, VMError::MemoryAccessViolation { .. }));
}
