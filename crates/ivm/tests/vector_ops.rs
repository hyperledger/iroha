use crate::common;
use common::{MODE_VECTOR, assemble, assemble_with_mode};
use ivm::{IVM, Memory, ProgramMetadata, encoding, instruction};
const HALT_WORD: u32 = encoding::wide::encode_halt();
const VECTOR_BASE: usize = 32;
fn words(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for &word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}
#[test]
fn test_vadd32_basic() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_vector_register(0, [1, 2, 3, 4]);
    vm.set_vector_register(1, [5, 6, 7, 8]);
    let instr = encoding::wide::encode_rr(instruction::wide::crypto::VADD32, 2, 0, 1);
    let prog = assemble_with_mode(&words(&[instr, HALT_WORD]), MODE_VECTOR);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.vector_register(2), [6, 8, 10, 12]);
}
#[test]
fn test_vadd64_basic() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_vector_register(0, [0xffff_ffff, 0, 0x1234_5678, 0]);
    vm.set_vector_register(1, [1, 0, 0xffff_ffff, 0]);
    let instr = encoding::wide::encode_rr(instruction::wide::crypto::VADD64, 2, 0, 1);
    let prog = assemble_with_mode(&words(&[instr, HALT_WORD]), MODE_VECTOR);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.vector_register(2), [0, 1, 0x1234_5677, 1]);
}
#[test]
fn test_vector_bit_ops() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_vector_register(0, [0xffff_0000, 0xaaaa_aaaa, 0x1234_5678, 0]);
    vm.set_vector_register(1, [0xff00_ff00, 0x5555_5555, 0xffff_ffff, 0xffff_ffff]);
    let instr_and = encoding::wide::encode_rr(instruction::wide::crypto::VAND, 2, 0, 1);
    let instr_xor = encoding::wide::encode_rr(instruction::wide::crypto::VXOR, 3, 0, 1);
    let prog = assemble_with_mode(&words(&[instr_and, instr_xor, HALT_WORD]), MODE_VECTOR);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(
        vm.vector_register(2),
        [0xff00_0000, 0x0000_0000, 0x1234_5678, 0]
    );
    assert_eq!(
        vm.vector_register(3),
        [0x00ff_ff00, 0xffff_ffff, 0xedcb_a987, 0xffff_ffff]
    );
}
#[test]
fn test_vrot32_basic() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_vector_register(0, [0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888]);
    let instr = encoding::wide::encode_ri(instruction::wide::crypto::VROT32, 1, 0, 8);
    let prog = assemble_with_mode(&words(&[instr, HALT_WORD]), MODE_VECTOR);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(
        vm.vector_register(1),
        [0x1122_2211, 0x3344_4433, 0x5566_6655, 0x7788_8877]
    );
}
#[test]
fn vector_add_chunked_stride_eight() {
    let meta = ProgramMetadata {
        mode: MODE_VECTOR,
        vector_length: 8,
        abi_version: 1,
        ..ProgramMetadata::default()
    };
    let add = encoding::wide::encode_rr(instruction::wide::crypto::VADD32, 2, 0, 1);
    let mut prog = meta.encode();
    prog.extend_from_slice(&add.to_le_bytes());
    prog.extend_from_slice(&HALT_WORD.to_le_bytes());
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&prog).unwrap();
    let base = VECTOR_BASE;
    let stride = 8usize;
    let lhs = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let rhs = [10u32, 20, 30, 40, 50, 60, 70, 80];
    for (i, &val) in lhs.iter().enumerate() {
        vm.set_register(base + i, val as u64);
    }
    for (i, &val) in rhs.iter().enumerate() {
        vm.set_register(base + stride + i, val as u64);
    }
    vm.run().unwrap();
    let out_base = base + 2 * stride;
    let expected = [11u64, 22, 33, 44, 55, 66, 77, 88];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(vm.register(out_base + i), exp);
    }
}
#[test]
fn vector_bit_ops_cover_tail_lanes() {
    let meta = ProgramMetadata {
        mode: MODE_VECTOR,
        vector_length: 6,
        abi_version: 1,
        ..ProgramMetadata::default()
    };
    let op = encoding::wide::encode_rr(instruction::wide::crypto::VXOR, 3, 0, 1);
    let mut prog = meta.encode();
    prog.extend_from_slice(&op.to_le_bytes());
    prog.extend_from_slice(&HALT_WORD.to_le_bytes());
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&prog).unwrap();
    let base = VECTOR_BASE;
    let stride = 6usize;
    let lhs = [
        0xffff_0000u32,
        0xaaaa_aaaa,
        0x1234_5678,
        0,
        0xdeaf_beef,
        0xffff_ffff,
    ];
    let rhs = [
        0xff00_ff00u32,
        0x5555_5555,
        0xffff_ffff,
        0xffff_ffff,
        0x0,
        0x1357_9bdf,
    ];
    for (i, &val) in lhs.iter().enumerate() {
        vm.set_register(base + i, val as u64);
    }
    for (i, &val) in rhs.iter().enumerate() {
        vm.set_register(base + stride + i, val as u64);
    }
    vm.run().unwrap();
    let out_base = base + 3 * stride;
    let expected = [
        0x00ff_ff00u64,
        0xffff_ffff,
        0xedcb_a987,
        0xffff_ffff,
        0xdeaf_beef,
        0xeca8_6420,
    ];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(vm.register(out_base + i), exp);
    }
}
#[test]
fn vrot32_chunked_stride_eight() {
    let meta = ProgramMetadata {
        mode: MODE_VECTOR,
        vector_length: 8,
        abi_version: 1,
        ..ProgramMetadata::default()
    };
    let rot = encoding::wide::encode_ri(instruction::wide::crypto::VROT32, 1, 0, 8);
    let mut prog = meta.encode();
    prog.extend_from_slice(&rot.to_le_bytes());
    prog.extend_from_slice(&HALT_WORD.to_le_bytes());
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&prog).unwrap();
    let base = VECTOR_BASE;
    let stride = 8usize;
    let values = [
        0x1111_2222u32,
        0x3333_4444,
        0x5555_6666,
        0x7777_8888,
        0xaaaa_bbbb,
        0xcccc_dddd,
        0x0102_0304,
        0x0f0e_0d0c,
    ];
    for (i, &val) in values.iter().enumerate() {
        vm.set_register(base + i, val as u64);
    }
    vm.run().unwrap();
    let out_base = base + stride;
    let expected = [
        0x1122_2211u64,
        0x3344_4433,
        0x5566_6655,
        0x7788_8877,
        0xaabb_bbaa,
        0xccdd_ddcc,
        0x0203_0401,
        0x0e0d_0c0f,
    ];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(vm.register(out_base + i), exp);
    }
}
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
#[test]
fn test_sha256block_and_gas() {
    let block = [0u8; 64];
    let initial = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let expected = sha256_compress_ref(initial, &block);
    // Prepare VM
    let mut vm = IVM::new(u64::MAX);
    for (i, b) in block.iter().enumerate() {
        vm.store_u8(Memory::HEAP_START + i as u64, *b).unwrap();
    }
    vm.set_register(1, Memory::HEAP_START);
    vm.set_vector_register(0, [initial[0], initial[1], initial[2], initial[3]]);
    vm.set_vector_register(1, [initial[4], initial[5], initial[6], initial[7]]);
    let instr = encoding::wide::encode_rr(instruction::wide::crypto::SHA256BLOCK, 0, 1, 0);
    let code = words(&[instr, HALT_WORD]);
    // Enough gas
    let prog_vec = assemble_with_mode(&code, MODE_VECTOR);
    vm.load_program(&prog_vec).unwrap();
    vm.set_gas_limit(50);
    vm.run().expect("sha256 should succeed");
    let mut result = [0u32; 8];
    result[..4].copy_from_slice(&vm.vector_register(0));
    result[4..].copy_from_slice(&vm.vector_register(1));
    assert_eq!(result, expected);
    // Insufficient gas
    let mut vm2 = IVM::new(u64::MAX);
    for (i, b) in block.iter().enumerate() {
        vm2.store_u8(Memory::HEAP_START + i as u64, *b).unwrap();
    }
    vm2.set_register(1, Memory::HEAP_START);
    vm2.set_vector_register(0, [initial[0], initial[1], initial[2], initial[3]]);
    vm2.set_vector_register(1, [initial[4], initial[5], initial[6], initial[7]]);
    let prog_vec = assemble_with_mode(&code, MODE_VECTOR);
    vm2.load_program(&prog_vec).unwrap();
    vm2.set_gas_limit(49);
    let res = vm2.run();
    assert!(res.is_err());
}
#[test]
fn test_vector_disabled_error() {
    let block = [0u8; 64];
    let initial = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut vm = IVM::new(u64::MAX);
    for (i, b) in block.iter().enumerate() {
        vm.store_u8(Memory::HEAP_START + i as u64, *b).unwrap();
    }
    vm.set_register(1, Memory::HEAP_START);
    vm.set_vector_register(0, [initial[0], initial[1], initial[2], initial[3]]);
    vm.set_vector_register(1, [initial[4], initial[5], initial[6], initial[7]]);
    let instr = encoding::wide::encode_rr(instruction::wide::crypto::SHA256BLOCK, 0, 1, 0);
    // assemble without vector mode
    let prog = assemble(&words(&[instr, HALT_WORD]));
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(50);
    let res = vm.run();
    assert!(matches!(res, Err(ivm::VMError::VectorExtensionDisabled)));
}
#[test]
fn test_auto_vector_helpers() {
    let lanes = ivm::simd_lanes();
    let a: Vec<u32> = (0..lanes as u32).collect();
    let b: Vec<u32> = vec![1; lanes];
    let plan = ivm::execution_memory::ExecutionMemoryPlan::array::<u32>(lanes).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(plan.requested_bytes());
    let mut lease = ivm::execution_memory::ExecutionMemoryLease::reserve(&budget, plan).unwrap();
    let mut output = ivm::zero_vector(lanes, &mut lease).unwrap();
    drop(lease);
    assert_eq!(budget.reserved_bytes(), lanes * std::mem::size_of::<u32>());
    ivm::vadd32_auto_into(&a, &b, output.as_mut_slice());
    let out = output.as_slice();
    assert_eq!(out.len(), lanes);
    for i in 0..lanes {
        assert_eq!(out[i], a[i].wrapping_add(b[i]));
    }
}
#[cfg(target_os = "macos")]
#[test]
fn test_metal_bit_pipeline_loads_bundled_library() {
    if !ivm::metal_available() {
        return;
    }
    ivm::release_metal_state();
    assert!(ivm::metal_available());
    let a = [1u32, 2, 3, 4];
    let b = [5u32, 6, 7, 8];
    assert_eq!(ivm::vand(a, b), [1, 2, 3, 0]);
    assert_eq!(ivm::vxor(a, b), [4, 4, 4, 12]);
    assert_eq!(ivm::vor(a, b), [5, 6, 7, 12]);
}

#[test]
fn funded_auto_vector_destinations_preserve_all_operations_and_final_owner_charge() {
    use ivm::execution_memory::{ExecutionMemoryLease, ExecutionMemoryPlan};
    let lanes = 10;
    let plan = ExecutionMemoryPlan::array::<u32>(lanes).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(plan.requested_bytes());
    let mut lease = ExecutionMemoryLease::reserve(&budget, plan).unwrap();
    let mut output = ivm::zero_vector(lanes, &mut lease).unwrap();
    drop(lease);
    assert_eq!(output.as_slice(), vec![0; lanes]);
    let left: Vec<_> = (0..lanes)
        .map(|i| u32::MAX.wrapping_sub(i as u32))
        .collect();
    let right: Vec<_> = (0..lanes).map(|i| (i as u32).wrapping_add(2)).collect();
    ivm::vadd32_auto_into(&left, &right, output.as_mut_slice());
    assert!(output.as_slice().iter().all(|&v| v == 1));
    for (operation, scalar) in [
        (
            ivm::vand_auto_into as fn(&[u32], &[u32], &mut [u32]),
            (|a, b| a & b) as fn(u32, u32) -> u32,
        ),
        (ivm::vxor_auto_into, |a, b| a ^ b),
        (ivm::vor_auto_into, |a, b| a | b),
    ] {
        operation(&left, &right, output.as_mut_slice());
        for i in 0..lanes {
            assert_eq!(output.as_slice()[i], scalar(left[i], right[i]));
        }
    }
    ivm::vrot32_auto_into(&left, 13, output.as_mut_slice());
    for (i, value) in left.iter().enumerate() {
        assert_eq!(output.as_slice()[i], value.rotate_left(13));
    }
    ivm::vadd64_auto_into(&left, &right, output.as_mut_slice());
    for i in (0..lanes).step_by(2) {
        let a = u64::from(left[i]) | (u64::from(left[i + 1]) << 32);
        let b = u64::from(right[i]) | (u64::from(right[i + 1]) << 32);
        let expected = a.wrapping_add(b);
        assert_eq!(output.as_slice()[i], expected as u32);
        assert_eq!(output.as_slice()[i + 1], (expected >> 32) as u32);
    }
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
    drop(output);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn zero_vector_cannot_readmit_or_grow_a_parent_with_insufficient_credit() {
    use ivm::execution_memory::{ExecutionMemoryLease, ExecutionMemoryPlan};
    let required = ExecutionMemoryPlan::array::<u32>(ivm::simd_lanes()).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(required.requested_bytes());
    let mut empty = ExecutionMemoryLease::reserve(&budget, ExecutionMemoryPlan::default()).unwrap();
    assert!(ivm::zero_vector(ivm::simd_lanes(), &mut empty).is_err());
    assert_eq!(empty.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn host_width_output_geometry_is_checked_before_any_vector_write() {
    let lanes = 10;
    let left = vec![1; lanes];
    let right = vec![2; lanes];
    let mut short = vec![77; lanes - 1];
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ivm::vadd32_auto_into(&left, &right, &mut short);
    }));
    assert!(refused.is_err());
    assert_eq!(short, vec![77; lanes - 1]);
}
