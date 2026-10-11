//! Fixed V1 banks and full-state parity against the original pinned Fr oracle.

use super::*;
use crate::field_dispatch::{self, FieldArithmetic, ScalarField};
use ff::Field;
#[path = "../../../../fixtures/poseidon/reader.rs"]
mod reference;

fn captured<const W: usize>(text: &str) -> ([[Fr; W]; 64], [[Fr; W]; W]) {
    let (rounds, mds) = reference::parameters::<W>(text);
    let field = |bytes: [u8; 32]| Fr::from_repr(bytes.into()).expect("canonical reference field");
    (
        rounds.map(|row| row.map(field)),
        mds.map(|row| row.map(field)),
    )
}
fn bytes(field: FieldElem) -> [u8; 32] {
    std::array::from_fn(|i| field.0[i / 8].to_le_bytes()[i % 8])
}
fn check_bank<const W: usize>(
    actual: (&[[FieldElem; W]; ROUND_COUNT], &[[FieldElem; W]; W]),
    canonical: iroha_zkp_halo2::poseidon::Bn254PoseidonParams<W>,
) {
    assert_eq!(actual.0.len(), 64);
    for (field, expected) in actual
        .0
        .iter()
        .flatten()
        .zip(canonical.round_constants.iter().flatten())
    {
        assert!(field.is_canonical());
        assert_eq!(bytes(*field), *expected);
        assert_eq!(bytes(FieldElem::from_fr(field.to_fr())), *expected);
    }
    for (field, expected) in actual
        .1
        .iter()
        .flatten()
        .zip(canonical.mds.iter().flatten())
    {
        assert!(field.is_canonical());
        assert_eq!(bytes(*field), *expected);
    }
}
#[test]
fn all_fixed_ivm_parameter_fields_and_stable_banks_match_canonical_owner() {
    check_bank(
        poseidon2_params(),
        iroha_zkp_halo2::poseidon::bn254_poseidon_params_width3(),
    );
    check_bank(
        poseidon6_params(),
        iroha_zkp_halo2::poseidon::bn254_poseidon_params_width6(),
    );
    assert!(std::ptr::eq(poseidon2_params().0, poseidon2_params().0));
    assert!(std::ptr::eq(poseidon2_params().1, poseidon2_params().1));
    assert!(std::ptr::eq(poseidon6_params().0, poseidon6_params().0));
    assert!(std::ptr::eq(poseidon6_params().1, poseidon6_params().1));
    assert!(
        poseidon6_params()
            .0
            .iter()
            .flatten()
            .any(|field| field.0[3] != 0)
    );
}
fn oracle<const W: usize>(mut state: [Fr; W], rounds: &[[Fr; W]], mds: &[[Fr; W]; W]) -> [Fr; W] {
    assert_eq!(rounds.len(), 64);
    for (round, constants) in rounds.iter().enumerate() {
        for i in 0..W {
            state[i] += constants[i];
        }
        if !(4..60).contains(&round) {
            for value in &mut state {
                *value = value.pow_vartime([5]);
            }
        } else {
            state[0] = state[0].pow_vartime([5]);
        }
        let before = state;
        state =
            std::array::from_fn(|i| (0..W).fold(Fr::ZERO, |sum, j| sum + mds[i][j] * before[j]));
    }
    state
}
pub(crate) fn state2(mut state: [FieldElem; 3]) -> [FieldElem; 3] {
    permute2_with(&mut state, field_vec::add, field_vec::mul);
    state
}
pub(crate) fn state6(mut state: [FieldElem; 6]) -> [FieldElem; 6] {
    permute6_with(&mut state, field_vec::add, field_vec::mul);
    state
}
fn parity(backend: &dyn FieldArithmetic) {
    let (rc3, m3) = captured::<3>(include_str!(
        "../../../../fixtures/poseidon/bn254-w3-rp56.hex"
    ));
    let (rc6, m6) = captured::<6>(include_str!(
        "../../../../fixtures/poseidon/bn254-w6-rp56.hex"
    ));
    let fields = [
        Fr::ZERO,
        -Fr::ONE,
        Fr::from(u64::MAX),
        Fr::from(1u64).double().pow_vartime([127]),
        Fr::from(7u64),
    ];
    for offset in 0..fields.len() {
        let input3 = std::array::from_fn(|i| fields[(i + offset) % fields.len()]);
        let input6 = std::array::from_fn(|i| fields[(i + offset) % fields.len()]);
        let expected3 = oracle(input3, &rc3, &m3).map(FieldElem::from_fr);
        let expected6 = oracle(input6, &rc6, &m6).map(FieldElem::from_fr);
        let mut actual3 = input3.map(FieldElem::from_fr);
        let mut actual6 = input6.map(FieldElem::from_fr);
        permute2_with(
            &mut actual3,
            |a, b| backend.add(a, b),
            |a, b| backend.mul(a, b),
        );
        permute6_with(
            &mut actual6,
            |a, b| backend.add(a, b),
            |a, b| backend.mul(a, b),
        );
        assert_eq!(actual3, expected3);
        assert_eq!(actual6, expected6);
        assert_eq!(state2(input3.map(FieldElem::from_fr)), expected3);
        assert_eq!(state6(input6.map(FieldElem::from_fr)), expected6);
    }
}
#[test]
fn complete_states_match_original_fr_oracle_on_scalar_selected_and_available_simd() {
    let _dispatch_guard = field_dispatch::field_impl_test_lock();
    let original = field_dispatch::field_impl().type_id();
    parity(&ScalarField);
    parity(field_dispatch::field_impl());
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("sse2") {
            parity(&field_dispatch::Sse2Field);
        }
        if std::is_x86_feature_detected!("avx2") {
            parity(&field_dispatch::Avx2Field);
        }
        if std::is_x86_feature_detected!("avx512f") {
            parity(&field_dispatch::Avx512Field);
        }
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        parity(&field_dispatch::NeonField);
    }
    assert_eq!(field_dispatch::field_impl().type_id(), original);
    assert_eq!(bytes(FieldElem::from_fr(Fr::ZERO)), [0; 32]);
    assert!(FieldElem::from_fr(-Fr::ONE).is_canonical());
}

#[test]
fn fixed_parameter_byte_conversion_preserves_zero_high_limbs_and_p_minus_one() {
    for value in [
        Fr::ZERO,
        -Fr::ONE,
        Fr::ONE,
        Fr::from(2u64).pow_vartime([64]),
        Fr::from(2u64).pow_vartime([128]),
        Fr::from(2u64).pow_vartime([192]),
    ] {
        let canonical: [u8; 32] = value.to_repr().into();
        let converted = fixed_field(canonical);
        assert_eq!(converted, FieldElem::from_fr(value));
        assert_eq!(bytes(converted), canonical);
        assert!(converted.is_canonical());
    }
}
