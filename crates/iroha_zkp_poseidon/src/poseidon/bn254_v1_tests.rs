//! Fixed full-field V1 parameters against the independently captured and rederived selected parameters.

use super::*;

#[path = "../../../../fixtures/poseidon/reader.rs"]
mod reference;

fn compare<const W: usize, const R: usize>(fixed: Bn254PoseidonParams<W, R>, captured: &str) {
    let (rounds, mds) = reference::parameters::<W, R>(captured);
    assert_eq!(rounds.len(), R);
    assert_eq!(fixed.round_constants.len(), R);
    for (actual, expected) in fixed
        .round_constants
        .iter()
        .flatten()
        .zip(rounds.iter().flatten())
    {
        assert_eq!(*actual, *expected);
        assert_eq!(field_to_bytes(decode_fixed_field(*actual)), *actual);
    }
    for (actual, expected) in fixed.mds.iter().flatten().zip(mds.iter().flatten()) {
        assert_eq!(*actual, *expected);
        assert_eq!(field_to_bytes(decode_fixed_field(*actual)), *actual);
    }
}
#[test]
fn all_648_fixed_fields_match_selected_v1_grain_mds_and_strict_round_trips() {
    assert_eq!(FULL_ROUNDS, 8);
    assert_eq!((WIDTH3_PARTIAL_ROUNDS, WIDTH6_PARTIAL_ROUNDS), (57, 60));
    assert_eq!((WIDTH3_ROUNDS, WIDTH6_ROUNDS), (65, 68));
    compare(
        bn254_poseidon_params_width3(),
        include_str!("../../../../fixtures/poseidon/bn254-w3-rp57.hex"),
    );
    compare(
        bn254_poseidon_params_width6(),
        include_str!("../../../../fixtures/poseidon/bn254-w6-rp60.hex"),
    );
}
#[test]
fn canonical_field_banks_are_stable_fixed_owners_and_exports_are_exact() {
    assert!(std::ptr::eq(poseidon3_params(), poseidon3_params()));
    assert!(std::ptr::eq(poseidon6_params(), poseidon6_params()));
    for (fixed, decoded) in bn254_poseidon_params_width3()
        .round_constants
        .iter()
        .flatten()
        .zip(poseidon3_params().0.iter().flatten())
    {
        assert_eq!(*fixed, field_to_bytes(*decoded));
    }
    for (fixed, decoded) in bn254_poseidon_params_width6()
        .round_constants
        .iter()
        .flatten()
        .zip(poseidon6_params().0.iter().flatten())
    {
        assert_eq!(*fixed, field_to_bytes(*decoded));
    }
}
