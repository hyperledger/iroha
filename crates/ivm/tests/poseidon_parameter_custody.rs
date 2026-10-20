//! One fresh-process cold/warm census for sole V1 parameter initialization and exports.

#[path = "poseidon_parameter_custody/observer.rs"]
mod observer;
use iroha_zkp_halo2::poseidon::{
    bn254_poseidon_params_width3, bn254_poseidon_params_width6, hash2_bytes, hash6_bytes,
};

fn zero<T>(name: &'static str, operation: impl FnOnce() -> T) -> T {
    let (result, observed) = observer::measured(operation);
    assert_eq!(
        observed.requests, [0; 3],
        "{name}: alloc/alloc_zeroed/realloc requests"
    );
    assert_eq!(observed.bytes, 0, "{name}: requested bytes");
    result
}
#[test]
fn fresh_process_cold_and_warm_fixed_canonical_and_ivm_parameters_allocate_nothing() {
    // This binary contains exactly one test. Dispatch is prepared without hashing
    // or touching either parameter bank before the first measured cold call.
    let backend = ivm::field_dispatch::field_impl().type_id();
    let width3 = zero("cold width3 export", bn254_poseidon_params_width3);
    let width6 = zero("cold width6 export", bn254_poseidon_params_width6);
    assert_eq!(width3.round_constants.len(), 65);
    assert_eq!(width6.round_constants.len(), 68);
    let canonical2 = zero("cold canonical hash2", || hash2_bytes(0, 0));
    let canonical6 = zero("cold canonical hash6", || hash6_bytes([1, 2, 3, 4, 5, 6]));
    let ordinary2 = zero("cold IVM poseidon2", || ivm::poseidon2(0, 0));
    let ordinary6 = zero("cold IVM poseidon6", || ivm::poseidon6([1, 2, 3, 4, 5, 6]));
    assert_eq!(ordinary2, 0x291e_f55c_ed50_4e95);
    assert_eq!(ordinary6, 0xea55_3770_3da8_51ec);
    assert_eq!(&canonical2[..8], &ordinary2.to_le_bytes());
    assert_eq!(&canonical6[..8], &ordinary6.to_le_bytes());
    for _ in 0..8 {
        zero("warm repeated exports and hashes", || {
            assert_eq!(
                bn254_poseidon_params_width3().round_constants,
                width3.round_constants
            );
            assert_eq!(bn254_poseidon_params_width3().mds, width3.mds);
            assert_eq!(
                bn254_poseidon_params_width6().round_constants,
                width6.round_constants
            );
            assert_eq!(bn254_poseidon_params_width6().mds, width6.mds);
            assert_eq!(hash2_bytes(0, 0), canonical2);
            assert_eq!(hash6_bytes([1, 2, 3, 4, 5, 6]), canonical6);
            assert_eq!(ivm::poseidon2(0, 0), ordinary2);
            assert_eq!(ivm::poseidon6([1, 2, 3, 4, 5, 6]), ordinary6);
        });
    }
    assert_eq!(ivm::field_dispatch::field_impl().type_id(), backend);

    // Positive control runs after every cold/warm parameter assertion so it
    // cannot warm those banks or hide an inactive allocation observer.
    census_detects_all_three_request_kinds();
}

#[allow(unsafe_code)]
fn census_detects_all_three_request_kinds() {
    use std::alloc::{Layout, alloc, alloc_zeroed, dealloc, realloc};
    let layout = Layout::from_size_align(8, 8).unwrap();
    let (_, observed) = observer::measured(|| {
        // SAFETY: each nonnull original allocation is returned once with its
        // exact layout; realloc receives that original allocation and alignment.
        unsafe {
            let initial = alloc(layout);
            assert!(!initial.is_null());
            std::hint::black_box(initial).write(7);
            let grown = realloc(initial, layout, 16);
            assert!(!grown.is_null());
            assert_eq!(std::hint::black_box(grown).read(), 7);
            dealloc(grown, Layout::from_size_align(16, 8).unwrap());
            let zeroed = alloc_zeroed(layout);
            assert!(!zeroed.is_null());
            assert_eq!(std::hint::black_box(zeroed).read(), 0);
            dealloc(zeroed, layout);
        }
    });
    assert_eq!(observed.requests, [1, 1, 1]);
    assert_eq!(observed.bytes, 32);
}
