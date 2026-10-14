#[cfg(feature = "cuda")]
use crate::common;
#[cfg(feature = "cuda")]
use common::{MODE_VECTOR, assemble_with_mode};
#[cfg(feature = "cuda")]
use ivm::{IVM, Memory, encoding, instruction};
#[cfg(feature = "cuda")]
fn make_program() -> Vec<u8> {
    const HALT: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
    let instr = encoding::wide::encode_rr(instruction::wide::crypto::SHA256BLOCK, 0, 1, 0);
    let mut prog = Vec::new();
    prog.extend_from_slice(&instr.to_le_bytes());
    prog.extend_from_slice(&HALT);
    assemble_with_mode(&prog, MODE_VECTOR)
}
#[cfg(feature = "cuda")]
struct MockNode {
    use_cuda: bool,
}
#[cfg(feature = "cuda")]
impl MockNode {
    fn execute(&self, prog: &[u8], block: &[u8; 64], initial: &[u32; 8]) -> [u32; 8] {
        if !self.use_cuda {
            unsafe {
                std::env::set_var("IVM_DISABLE_CUDA", "1");
            }
        }
        let mut vm = IVM::new(u64::MAX);
        for (i, b) in block.iter().enumerate() {
            vm.store_u8(Memory::HEAP_START + i as u64, *b).unwrap();
        }
        vm.set_register(1, Memory::HEAP_START);
        vm.set_vector_register(0, [initial[0], initial[1], initial[2], initial[3]]);
        vm.set_vector_register(1, [initial[4], initial[5], initial[6], initial[7]]);
        vm.load_program(prog).unwrap();
        vm.run().unwrap();
        if !self.use_cuda {
            unsafe {
                std::env::remove_var("IVM_DISABLE_CUDA");
            }
        }
        let mut out = [0u32; 8];
        out[..4].copy_from_slice(&vm.vector_register(0));
        out[4..].copy_from_slice(&vm.vector_register(1));
        out
    }
}
#[cfg(feature = "cuda")]
#[test]
fn test_consistent_across_hardware() {
    if !ivm::cuda_available() {
        eprintln!("No CUDA GPU available; skipping test");
        return;
    }
    let prog = make_program();
    let block = [0u8; 64];
    let initial = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let gpu_node = MockNode { use_cuda: true };
    let cpu_node = MockNode { use_cuda: false };
    let gpu_res = gpu_node.execute(&prog, &block, &initial);
    let cpu_res = cpu_node.execute(&prog, &block, &initial);
    assert_eq!(gpu_res, cpu_res);
}
