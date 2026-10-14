//! Crypto opcode and helper regression tests.
use crate::common;
use common::assemble;
use ivm::{
    AccelerationConfig, ByteMerkleTree, IVM, SimdChoice, acceleration_runtime_status, encoding,
    instruction, poseidon2, poseidon6, vector_supported,
};
use std::sync::{Mutex, MutexGuard, OnceLock};
const HALT_WORD: u32 = encoding::wide::encode_halt();
fn words(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for &word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}
struct AccelConfigGuard {
    _lock: MutexGuard<'static, ()>,
    original: AccelerationConfig,
}
impl AccelConfigGuard {
    fn new() -> Self {
        fn accel_test_lock() -> &'static Mutex<()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
        }
        let lock = accel_test_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Self {
            _lock: lock,
            original: ivm::acceleration_config(),
        }
    }
}
impl Drop for AccelConfigGuard {
    fn drop(&mut self) {
        ivm::set_acceleration_config(self.original);
    }
}
fn run_poseidon2_program(a: u64, b: u64) -> u64 {
    let mut vm = IVM::new(u64::MAX);
    let instr = encoding::wide::encode_poseidon2(9, 10, 11);
    let prog = assemble(&words(&[instr, HALT_WORD]));
    vm.load_program(&prog).unwrap();
    vm.set_register(10, a);
    vm.set_register(11, b);
    vm.run().unwrap();
    vm.register(9)
}
fn run_poseidon6_program(vals: [u64; 6]) -> u64 {
    let mut vm = IVM::new(u64::MAX);
    let instr = encoding::wide::encode_poseidon6(9, 10);
    let prog = assemble(&words(&[instr, HALT_WORD]));
    vm.load_program(&prog).unwrap();
    for (idx, val) in vals.iter().enumerate() {
        vm.set_register(10 + idx, *val);
    }
    vm.run().unwrap();
    vm.register(9)
}
#[test]
fn test_poseidon2() {
    let mut vm = IVM::new(u64::MAX);
    let instr = encoding::wide::encode_poseidon2(9, 10, 11);
    let prog = assemble(&words(&[instr, HALT_WORD]));
    vm.load_program(&prog).unwrap();
    vm.set_register(10, 5);
    vm.set_register(11, 7);
    vm.run().unwrap();
    let expected = poseidon2(5, 7);
    assert_eq!(vm.register(9), expected);
}
#[test]
fn test_poseidon6() {
    let mut vm = IVM::new(u64::MAX);
    let instr = encoding::wide::encode_poseidon6(9, 10);
    let prog = assemble(&words(&[instr, HALT_WORD]));
    vm.load_program(&prog).unwrap();
    for i in 0..6u64 {
        vm.set_register(10 + i as usize, i + 1);
    }
    vm.run().unwrap();
    let mut vals = [0u64; 6];
    for i in 0..6u64 {
        vals[i as usize] = i + 1;
    }
    let expected = poseidon6(vals);
    assert_eq!(vm.register(9), expected);
}
#[test]
fn poseidon_rejects_private_tuples_without_a_declassification_path() {
    let poseidon2_word = encoding::wide::encode_poseidon2(9, 10, 11);
    let program = common::assemble_zk(&words(&[poseidon2_word, HALT_WORD]), 2);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    vm.set_register(10, 0x0123_4567_89ab_cdef);
    vm.set_register(11, 0xfedc_ba98_7654_3210);
    vm.registers.set_tag(10, true);
    vm.registers.set_tag(11, true);
    assert!(matches!(vm.run(), Err(ivm::VMError::PrivacyViolation)));
    assert_eq!(vm.register(9), 0);
    assert!(!vm.registers.tag(9));
    let inputs = [3, 5, 8, 13, 21, 34];
    let poseidon6_word = encoding::wide::encode_poseidon6(9, 10);
    let program = common::assemble_zk(&words(&[poseidon6_word, HALT_WORD]), 2);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    for (offset, value) in inputs.into_iter().enumerate() {
        vm.set_register(10 + offset, value);
        vm.registers.set_tag(10 + offset, true);
    }
    assert!(matches!(vm.run(), Err(ivm::VMError::PrivacyViolation)));
    assert_eq!(vm.register(9), 0);
    assert!(!vm.registers.tag(9));
}
#[test]
fn poseidon_rejects_mixed_public_and_private_inputs() {
    let poseidon2_word = encoding::wide::encode_poseidon2(9, 10, 11);
    let program = common::assemble_zk(&words(&[poseidon2_word, HALT_WORD]), 2);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    vm.registers.set_tag(10, true);
    assert!(matches!(vm.run(), Err(ivm::VMError::PrivacyViolation)));
    let poseidon6_word = encoding::wide::encode_poseidon6(9, 10);
    let program = common::assemble_zk(&words(&[poseidon6_word, HALT_WORD]), 2);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    for register in 10..16 {
        vm.registers.set_tag(register, true);
    }
    vm.registers.set_tag(13, false);
    assert!(matches!(vm.run(), Err(ivm::VMError::PrivacyViolation)));
}
#[test]
fn poseidon6_rejects_noncanonical_operand_slot() {
    let malformed = encoding::wide::encode_rr(instruction::wide::crypto::POSEIDON6, 9, 10, 1);
    let program = assemble(&words(&[malformed, HALT_WORD]));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    assert!(matches!(vm.run(), Err(ivm::VMError::DecodeError)));
}
#[test]
fn poseidon_instructions_match_across_acceleration_configs() {
    let guard = AccelConfigGuard::new();
    let inputs2 = (11u64, 17u64);
    let inputs6 = [1u64, 2, 3, 4, 5, 6];
    ivm::set_acceleration_config(AccelerationConfig {
        enable_simd: true,
        enable_cuda: false,
        enable_metal: false,
        ..guard.original
    });
    let cpu_poseidon2 = run_poseidon2_program(inputs2.0, inputs2.1);
    let cpu_poseidon6 = run_poseidon6_program(inputs6);
    let status_cpu = acceleration_runtime_status();
    assert!(
        !status_cpu.cuda.configured,
        "CUDA should be marked disabled in CPU-only config"
    );
    assert!(
        !status_cpu.metal.configured,
        "Metal should be marked disabled in CPU-only config"
    );
    ivm::set_acceleration_config(AccelerationConfig {
        enable_cuda: true,
        enable_metal: true,
        ..guard.original
    });
    let accel_poseidon2 = run_poseidon2_program(inputs2.0, inputs2.1);
    let accel_poseidon6 = run_poseidon6_program(inputs6);
    let status_accel = acceleration_runtime_status();
    assert!(
        status_accel.cuda.configured,
        "CUDA should be marked enabled when acceleration is allowed"
    );
    assert!(
        status_accel.metal.configured,
        "Metal should be marked enabled when acceleration is allowed"
    );
    assert_eq!(accel_poseidon2, cpu_poseidon2);
    assert_eq!(accel_poseidon6, cpu_poseidon6);
    #[cfg(feature = "cuda")]
    {
        if ivm::cuda_available() {
            if let Some(cuda_poseidon2) = ivm::poseidon2_cuda(inputs2.0, inputs2.1) {
                assert_eq!(cuda_poseidon2, accel_poseidon2);
            }
            if let Some(cuda_poseidon6) = ivm::poseidon6_cuda(inputs6) {
                assert_eq!(cuda_poseidon6, accel_poseidon6);
            }
        }
    }
}
#[test]
fn simd_disable_forces_scalar_without_affecting_outputs() {
    let guard = AccelConfigGuard::new();
    let inputs = (3u64, 9u64);
    ivm::set_acceleration_config(AccelerationConfig {
        enable_simd: false,
        ..guard.original
    });
    let scalar_status = acceleration_runtime_status();
    assert!(
        !scalar_status.simd.configured,
        "SIMD backend should report disabled when enable_simd = false"
    );
    let scalar_poseidon = run_poseidon2_program(inputs.0, inputs.1);
    ivm::set_acceleration_config(AccelerationConfig {
        enable_simd: true,
        ..guard.original
    });
    let simd_status = acceleration_runtime_status();
    assert!(
        simd_status.simd.configured,
        "SIMD backend should report configured when re-enabled"
    );
    let simd_poseidon = run_poseidon2_program(inputs.0, inputs.1);
    assert_eq!(
        scalar_poseidon, simd_poseidon,
        "Disabling SIMD must not change cryptographic outputs"
    );
}
#[test]
fn merkle_roots_match_across_simd_modes() {
    let guard = AccelConfigGuard::new();
    let payload: Vec<u8> = (0..(32 * 128))
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(7))
        .collect();
    ivm::set_acceleration_config(AccelerationConfig {
        enable_simd: true,
        enable_cuda: false,
        enable_metal: false,
        ..guard.original
    });
    let simd_status = acceleration_runtime_status();
    assert!(simd_status.simd.configured);
    assert_eq!(simd_status.simd.available, vector_supported());
    let simd_root = ByteMerkleTree::from_bytes_accel(&payload, 32)
        .unwrap()
        .root();
    ivm::set_acceleration_config(AccelerationConfig {
        enable_simd: false,
        enable_cuda: false,
        enable_metal: false,
        ..guard.original
    });
    let scalar_status = acceleration_runtime_status();
    assert!(!scalar_status.simd.configured);
    assert_eq!(ivm::simd_choice(), SimdChoice::Scalar);
    assert!(!scalar_status.simd.available);
    let scalar_root = ByteMerkleTree::from_bytes_accel(&payload, 32)
        .unwrap()
        .root();
    assert_eq!(scalar_root, simd_root);
}
