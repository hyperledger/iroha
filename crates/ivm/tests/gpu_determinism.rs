#[cfg(feature = "cuda")]
use crate::common;
#[cfg(feature = "cuda")]
use common::{MODE_VECTOR, assemble_with_mode};
#[cfg(feature = "cuda")]
use ivm::{IVM, Memory, encoding, instruction};
#[cfg(feature = "cuda")]
fn sha256_compress_ref(mut state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for (t, chunk) in block.chunks(4).enumerate().take(16) {
        w[t] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
    state
}
#[cfg(feature = "cuda")]
#[test]
fn merkle_root_accel_matches_cpu_for_large_input() {
    // Build a large buffer to exceed the GPU threshold (8192 leaves * 32 bytes = 262,144 bytes)
    let chunk = 32usize;
    let leaves = 10_000usize;
    let mut data = vec![0u8; leaves * chunk];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    if !ivm::cuda_available() {
        eprintln!("CUDA not available; skipping merkle accel test");
        return;
    }
    let t_cpu = ivm::ByteMerkleTree::from_bytes_parallel(&data, chunk).unwrap();
    let root_gpu = ivm::ByteMerkleTree::root_from_bytes_accel(&data, chunk).unwrap();
    assert_eq!(t_cpu.root(), root_gpu);
}
#[cfg(all(target_os = "macos", feature = "metal"))]
#[test]
fn merkle_root_accel_metal_matches_cpu_for_large_input() {
    if !ivm::metal_available() {
        eprintln!("Metal not available; skipping merkle accel test");
        return;
    }
    let chunk = 32usize;
    let leaves = 10_000usize;
    let mut data = vec![0u8; leaves * chunk];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    let t_cpu = ivm::ByteMerkleTree::from_bytes_parallel(&data, chunk).unwrap();
    let root_gpu = ivm::ByteMerkleTree::root_from_bytes_accel(&data, chunk).unwrap();
    assert_eq!(t_cpu.root(), root_gpu);
}
#[cfg(feature = "cuda")]
#[test]
fn test_gpu_cpu_determinism_sha256block() {
    if !ivm::cuda_available() {
        eprintln!("No CUDA GPU available; skipping test");
        return;
    }
    const HALT: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
    let block = [0u8; 64];
    let initial = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let instr = encoding::wide::encode_rr(instruction::wide::crypto::SHA256BLOCK, 0, 1, 0);
    let mut prog = Vec::new();
    prog.extend_from_slice(&instr.to_le_bytes());
    prog.extend_from_slice(&HALT);
    let prog = assemble_with_mode(&prog, MODE_VECTOR);
    let run_once = || {
        let mut vm = IVM::new(u64::MAX);
        for (i, b) in block.iter().enumerate() {
            vm.store_u8(Memory::HEAP_START + i as u64, *b).unwrap();
        }
        vm.set_register(1, Memory::HEAP_START);
        vm.set_vector_register(0, [initial[0], initial[1], initial[2], initial[3]]);
        vm.set_vector_register(1, [initial[4], initial[5], initial[6], initial[7]]);
        vm.load_program(&prog).unwrap();
        vm.run().unwrap();
        let mut out = [0u32; 8];
        out[..4].copy_from_slice(&vm.vector_register(0));
        out[4..].copy_from_slice(&vm.vector_register(1));
        out
    };
    let gpu_first = run_once();
    let gpu_second = run_once();
    assert_eq!(gpu_first, gpu_second);
    let cpu_expected = sha256_compress_ref(initial, &block);
    assert_eq!(gpu_first, cpu_expected);
}
