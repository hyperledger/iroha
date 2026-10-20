//! SIMD and scalar parity against the independently selected parameter banks.
#![cfg(feature = "ivm_zk_tests")]
use halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField},
};
use ivm::{poseidon2, poseidon2_simd, poseidon6, poseidon6_simd, simd_bits};
#[path = "../../../fixtures/poseidon/reader.rs"]
mod reference;

fn captured<const W: usize, const R: usize>(text: &str) -> ([[Fr; W]; R], [[Fr; W]; W]) {
    let (rounds, mds) = reference::parameters::<W, R>(text);
    let field = |bytes: [u8; 32]| Fr::from_repr(bytes.into()).expect("canonical reference field");
    (
        rounds.map(|row| row.map(field)),
        mds.map(|row| row.map(field)),
    )
}
fn fr_to_u64(f: Fr) -> u64 {
    let repr = f.to_repr();
    let b = repr.as_ref();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
const POSEIDON2_VECTORS: &[(u64, u64, u64)] = &[
    (0, 0, 0x291e_f55c_ed50_4e95),
    (1, 0, 0x7e84_e466_0f9c_8602),
    (0, 1, 0xbe23_3ae4_87cc_493c),
    (1, 1, 0xc129_be07_2c4b_4483),
    (u64::MAX, u64::MAX, 0xc389_da81_dbdd_ae68),
];
const POSEIDON6_VECTORS: &[([u64; 6], u64)] = &[
    ([0, 0, 0, 0, 0, 0], 0xb528_4c49_a2aa_43dd),
    ([1, 2, 3, 4, 5, 6], 0xea55_3770_3da8_51ec),
    ([1, 0, 0, 0, 0, 0], 0x4412_6d18_7028_4f85),
    ([0, 1, 0, 0, 0, 0], 0x741c_dca6_d198_88b3),
    ([u64::MAX; 6], 0x732e_c89a_4e97_2a38),
];
#[test]
fn test_poseidon2_simd_matches_scalar() {
    if simd_bits() <= 64 {
        return;
    }
    let a = 5u64;
    let b = 7u64;
    let simd = poseidon2_simd(a, b);
    let scalar = poseidon2(a, b);
    assert_eq!(simd, scalar);
}
#[test]
fn test_poseidon6_simd_matches_scalar() {
    if simd_bits() <= 64 {
        return;
    }
    let inputs = [1u64, 2, 3, 4, 5, 6];
    let simd = poseidon6_simd(inputs);
    let scalar = poseidon6(inputs);
    assert_eq!(simd, scalar);
}
#[test]
fn test_poseidon6_first_round() {
    use ivm::bn254_vec::{self as field_vec, FieldElem};
    let inputs = [1u64, 2, 3, 4, 5, 6];
    let (rc, mds) = captured::<6, 68>(include_str!("../../../fixtures/poseidon/bn254-w6-rp60.hex"));
    let mut st = [
        FieldElem::from_fr(Fr::from(1u64)),
        FieldElem::from_fr(Fr::from(2u64)),
        FieldElem::from_fr(Fr::from(3u64)),
        FieldElem::from_fr(Fr::from(4u64)),
        FieldElem::from_fr(Fr::from(5u64)),
        FieldElem::from_fr(Fr::from(6u64)),
    ];
    let rc_fe: [FieldElem; 6] = rc[0].map(FieldElem::from_fr);
    let mds_fe = mds.map(|row| row.map(FieldElem::from_fr));
    let sbox = |x: FieldElem| {
        let x2 = field_vec::mul(x, x);
        let x4 = field_vec::mul(x2, x2);
        field_vec::mul(x4, x)
    };
    for i in 0..6 {
        st[i] = sbox(field_vec::add(st[i], rc_fe[i]));
    }
    let mut ns = [FieldElem([0u64; 4]); 6];
    for i in 0..6 {
        let mut acc = FieldElem([0u64; 4]);
        for j in 0..6 {
            acc = field_vec::add(acc, field_vec::mul(mds_fe[i][j], st[j]));
        }
        ns[i] = acc;
    }
    st = ns;
    let mut scalar = inputs.map(Fr::from);
    for i in 0..6 {
        scalar[i] = (scalar[i] + rc[0][i]).pow_vartime([5]);
    }
    let mut ns2 = [Fr::ZERO; 6];
    for i in 0..6 {
        for j in 0..6 {
            ns2[i] += mds[i][j] * scalar[j];
        }
    }
    scalar = ns2;
    for i in 0..6 {
        assert_eq!(st[i].to_fr(), scalar[i]);
    }
}
#[test]
fn test_poseidon6_full_permutation() {
    let inputs = [1u64, 2, 3, 4, 5, 6];
    let (rc, mds) = captured::<6, 68>(include_str!("../../../fixtures/poseidon/bn254-w6-rp60.hex"));
    let mut state = [
        Fr::from_u128(6_u128 << 64),
        Fr::from(inputs[0]),
        Fr::from(inputs[1]),
        Fr::from(inputs[2]),
        Fr::from(inputs[3]),
        Fr::from(inputs[4]),
    ];
    let rf_half = 8 / 2;
    let rp = 60;
    let apply_mds = |s: &mut [Fr; 6]| {
        let mut out = [Fr::ZERO; 6];
        for i in 0..6 {
            for j in 0..6 {
                out[i] += mds[i][j] * s[j];
            }
        }
        *s = out;
    };
    for block in 0..2 {
        if block == 1 {
            state[1] += Fr::from(inputs[5]);
        }
        for round_constants in rc.iter().take(rf_half) {
            for i in 0..6 {
                state[i] = (state[i] + round_constants[i]).pow_vartime([5]);
            }
            apply_mds(&mut state);
        }
        for r in 0..rp {
            let idx = rf_half + r;
            for i in 0..6 {
                state[i] += rc[idx][i];
            }
            state[0] = (state[0]).pow_vartime([5]);
            apply_mds(&mut state);
        }
        for r in 0..rf_half {
            let idx = rf_half + rp + r;
            for i in 0..6 {
                state[i] = (state[i] + rc[idx][i]).pow_vartime([5]);
            }
            apply_mds(&mut state);
        }
    }
    let expected = fr_to_u64(state[1]);
    assert_eq!(poseidon6(inputs), expected);
}
#[test]
fn test_poseidon2_vectors() {
    for &(a, b, expected) in POSEIDON2_VECTORS {
        assert_eq!(poseidon2(a, b), expected);
        let simd = poseidon2_simd(a, b);
        assert_eq!(simd, expected);
    }
}
#[cfg(feature = "cuda")]
#[test]
fn test_poseidon2_cuda_vectors() {
    if !ivm::cuda_available() {
        eprintln!("CUDA hardware unavailable; skipping Poseidon2 parity test");
        return;
    }
    for &(a, b, expected) in POSEIDON2_VECTORS {
        match ivm::poseidon2_cuda(a, b) {
            Some(gpu) => assert_eq!(gpu, expected),
            None => {
                eprintln!("CUDA Poseidon2 backend disabled at runtime; skipping");
                return;
            }
        }
    }
}
#[cfg(feature = "cuda")]
#[test]
fn test_poseidon6_cuda_vectors() {
    if !ivm::cuda_available() {
        eprintln!("CUDA hardware unavailable; skipping Poseidon6 parity test");
        return;
    }
    for &(inputs, expected) in POSEIDON6_VECTORS {
        match ivm::poseidon6_cuda(inputs) {
            Some(gpu) => assert_eq!(gpu, expected),
            None => {
                eprintln!("CUDA Poseidon6 backend disabled at runtime; skipping");
                return;
            }
        }
    }
}
#[test]
fn test_poseidon6_vectors() {
    for &(inputs, expected) in POSEIDON6_VECTORS {
        assert_eq!(poseidon6(inputs), expected);
        let simd = poseidon6_simd(inputs);
        assert_eq!(simd, expected);
    }
}
#[test]
fn test_poseidon2_first_round() {
    use ivm::bn254_vec::{self as field_vec, FieldElem};
    let a = 1u64;
    let b = 2u64;
    let (rc, mds) = captured::<3, 65>(include_str!("../../../fixtures/poseidon/bn254-w3-rp57.hex"));
    let mut st = [
        FieldElem::from_fr(Fr::from(a)),
        FieldElem::from_fr(Fr::from(b)),
        FieldElem([0u64; 4]),
    ];
    let rc_fe: [FieldElem; 3] = rc[0].map(FieldElem::from_fr);
    let mds_fe = mds.map(|row| row.map(FieldElem::from_fr));
    let sbox = |x: FieldElem| {
        let x2 = field_vec::mul(x, x);
        let x4 = field_vec::mul(x2, x2);
        field_vec::mul(x4, x)
    };
    for i in 0..3 {
        st[i] = sbox(field_vec::add(st[i], rc_fe[i]));
    }
    let mut ns = [FieldElem([0u64; 4]); 3];
    for i in 0..3 {
        let mut acc = FieldElem([0u64; 4]);
        for j in 0..3 {
            acc = field_vec::add(acc, field_vec::mul(mds_fe[i][j], st[j]));
        }
        ns[i] = acc;
    }
    st = ns;
    let mut scalar = [Fr::from(a), Fr::from(b), Fr::ZERO];
    for i in 0..3 {
        scalar[i] = (scalar[i] + rc[0][i]).pow_vartime([5]);
    }
    let mut ns2 = [Fr::ZERO; 3];
    for i in 0..3 {
        for j in 0..3 {
            ns2[i] += mds[i][j] * scalar[j];
        }
    }
    scalar = ns2;
    for i in 0..3 {
        assert_eq!(st[i].to_fr(), scalar[i]);
    }
}
#[test]
fn test_poseidon2_many_matches_scalar() {
    let inputs = [
        (0u64, 0u64),
        (1u64, 2u64),
        (u64::MAX, 0x1234_5678_9abc_def0),
    ];
    let mut outputs = [0; 3];
    assert!(ivm::poseidon2_many_into(&inputs, &mut outputs));
    assert_eq!(outputs.len(), inputs.len());
    for ((a, b), result) in inputs.iter().copied().zip(outputs.iter()) {
        assert_eq!(*result, ivm::poseidon2(a, b));
    }
}
#[test]
fn test_poseidon6_many_matches_scalar() {
    let inputs = [
        [0u64; 6],
        [1u64, 2, 3, 4, 5, 6],
        [0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321, 7, 8, 9, 10],
    ];
    let mut outputs = [0; 3];
    assert!(ivm::poseidon6_many_into(&inputs, &mut outputs));
    assert_eq!(outputs.len(), inputs.len());
    for (input, result) in inputs.iter().copied().zip(outputs.iter()) {
        assert_eq!(*result, ivm::poseidon6(input));
    }
}

#[test]
fn poseidon_batch_shapes_preserve_caller_storage() {
    let mut untouched = [0xa5];
    assert!(!ivm::poseidon2_many_into(&[(1, 2); 2], &mut untouched));
    assert_eq!(untouched, [0xa5]);
    assert!(!ivm::poseidon6_many_into(&[[1; 6]; 2], &mut untouched));
    assert_eq!(untouched, [0xa5]);
    assert!(ivm::poseidon2_many_into(&[], &mut []));
    assert!(ivm::poseidon6_many_into(&[], &mut []));
}
