//! BN254 arithmetic parity and fixed-width reduction across native word sizes.
#![cfg(feature = "ivm_zk_tests")]
use halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField, derive::rand_core::OsRng},
};
use ivm::bn254_vec::{
    FieldElem, add, add_scalar, mul, mul_scalar, reduce_wide, sub, sub_scalar, wide_mul,
};
fn fr_to_u64(f: Fr) -> u64 {
    let repr = f.to_repr();
    let b = repr.as_ref();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
#[test]
fn test_add_scalar_matches_fr() {
    let a = Fr::from(5u64);
    let b = Fr::from(7u64);
    let expected = a + b;
    let res = add_scalar(FieldElem::from_fr(a), FieldElem::from_fr(b));
    assert_eq!(res.to_fr(), expected);
}
#[test]
fn test_add_wraparound() {
    let a = FieldElem::from_fr(-Fr::one());
    let b = FieldElem::from_fr(Fr::from(2u64));
    let res = add(a, b);
    assert_eq!(res.to_fr(), Fr::from(1u64));
}
#[test]
fn test_sub_underflow() {
    let a = FieldElem::from_fr(Fr::from(1u64));
    let b = FieldElem::from_fr(Fr::from(2u64));
    let res = sub(a, b);
    assert_eq!(res.to_fr(), -Fr::one());
}
#[test]
fn test_add_sub_mul_roundtrip() {
    let vals = [0u64, 1, u64::MAX / 2, u64::MAX - 1];
    for &x in &vals {
        for &y in &vals {
            let a = FieldElem::from_fr(Fr::from(x));
            let b = FieldElem::from_fr(Fr::from(y));
            let add_res = add(a, b);
            let sub_res = sub(add_res, b);
            assert_eq!(sub_res.to_fr(), Fr::from(x));
            let mul_res = mul(a, b);
            assert_eq!(mul_res.to_fr(), Fr::from(x) * Fr::from(y));
        }
    }
}
#[test]
fn test_mul_random() {
    for _ in 0..32 {
        let a = Fr::random(&mut OsRng);
        let b = Fr::random(&mut OsRng);
        let af = FieldElem::from_fr(a);
        let bf = FieldElem::from_fr(b);
        let res = mul(af, bf);
        assert_eq!(res.to_fr(), a * b);
    }
}
#[test]
fn test_mul_edge_cases() {
    let zero = FieldElem([0u64; 4]);
    let one = FieldElem::from_fr(Fr::one());
    let pm1 = FieldElem::from_fr(-Fr::one());
    assert_eq!(mul(zero, pm1).to_fr(), Fr::zero());
    assert_eq!(mul(pm1, pm1).to_fr(), Fr::one());
    assert_eq!(mul(one, zero).to_fr(), Fr::zero());
}
#[test]
fn test_reduce_wide_fixed_width_vectors() {
    // Integer remainder vectors exercise every half-limb and both halves of the
    // 512-bit input, independently of crypto_bigint's native word representation.
    let below_modulus = [
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x8899_aabb_ccdd_eeff,
        0x1234_5678_9abc_def0,
    ];
    assert_eq!(reduce_wide([0; 8]), [0; 4]);
    assert_eq!(
        reduce_wide([
            below_modulus[0],
            below_modulus[1],
            below_modulus[2],
            below_modulus[3],
            0,
            0,
            0,
            0,
        ]),
        below_modulus,
    );
    let modulus = ivm::bn254_vec::MODULUS;
    assert_eq!(
        reduce_wide([modulus[0], modulus[1], modulus[2], modulus[3], 0, 0, 0, 0]),
        [0; 4],
    );
    assert_eq!(
        reduce_wide([0, 0, 0, 0, 1, 0, 0, 0]),
        [
            0xac96_341c_4fff_fffb,
            0x36fc_7695_9f60_cd29,
            0x666e_a36f_7879_462e,
            0x0e0a_77c1_9a07_df2f,
        ],
    );
    assert_eq!(
        reduce_wide([u64::MAX; 8]),
        [
            0x1bb8_e645_ae21_6da6,
            0x53fe_3ab1_e35c_59e3,
            0x8c49_833d_53bb_8085,
            0x0216_d0b1_7f4e_44a5,
        ],
    );
}
#[test]
fn test_reduce_wide_random() {
    for _ in 0..32 {
        let a = Fr::random(&mut OsRng);
        let b = Fr::random(&mut OsRng);
        let af = FieldElem::from_fr(a);
        let bf = FieldElem::from_fr(b);
        let wide = wide_mul(af, bf);
        let reduced = FieldElem(reduce_wide(wide));
        assert_eq!(reduced.to_fr(), a * b);
    }
}
#[test]
fn test_from_to_u64_roundtrip() {
    let vals = [0u64, 1, 42, u64::MAX - 1];
    for &v in &vals {
        let fe = FieldElem::from_u64(v);
        assert_eq!(fe.to_fr(), Fr::from(v));
        assert_eq!(fe.to_u64(), fr_to_u64(Fr::from(v)));
    }
}
fn lt_modulus(a: &FieldElem) -> bool {
    for i in (0..4).rev() {
        if a.0[i] < ivm::bn254_vec::MODULUS[i] {
            return true;
        }
        if a.0[i] > ivm::bn254_vec::MODULUS[i] {
            return false;
        }
    }
    false
}
fn check_backend(name: &str, backend: &'static dyn ivm::field_dispatch::FieldArithmetic) {
    let _guard = ivm::field_dispatch::field_impl_test_lock();
    ivm::field_dispatch::set_field_impl_for_tests(backend);
    for _ in 0..16 {
        let a_fr = Fr::random(&mut OsRng);
        let b_fr = Fr::random(&mut OsRng);
        let a = FieldElem::from_fr(a_fr);
        let b = FieldElem::from_fr(b_fr);
        let add_ref = add_scalar(a, b);
        let sub_ref = sub_scalar(a, b);
        let mul_ref = mul_scalar(a, b);
        let add_res = add(a, b);
        let sub_res = sub(a, b);
        let mul_res = mul(a, b);
        assert_eq!(add_res, add_ref, "{} add", name);
        assert_eq!(sub_res, sub_ref, "{} sub", name);
        assert_eq!(mul_res, mul_ref, "{} mul", name);
        assert!(lt_modulus(&add_res));
        assert!(lt_modulus(&sub_res));
        assert!(lt_modulus(&mul_res));
    }
    ivm::field_dispatch::clear_field_impl_for_tests();
}
#[test]
fn test_all_backends() {
    let mut backends: Vec<(&'static dyn ivm::field_dispatch::FieldArithmetic, &str)> = Vec::new();
    backends.push((&ivm::field_dispatch::ScalarField, "scalar"));
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        backends.push((&ivm::field_dispatch::Sse2Field, "sse2"));
        if std::is_x86_feature_detected!("avx2") {
            backends.push((&ivm::field_dispatch::Avx2Field, "avx2"));
            backends.push((&ivm::field_dispatch::Avx512Field, "avx512"));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            backends.push((&ivm::field_dispatch::NeonField, "neon"));
        }
    }
    for (backend, name) in backends {
        check_backend(name, backend);
    }
}
