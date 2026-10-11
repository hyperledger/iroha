//! Safe live-storage erasure and exact RNG controls for bounded dealer secrets.

use super::dealer_generation_scratch::{
    TrackedRng, coefficients, parameters, reference_generate, reference_import,
};
use super::*;
use crate::test_allocations::without_allocations;
use std::cell::Cell;

#[derive(Clone, Copy)]
pub(super) struct Retirement {
    pub(super) drops: usize,
    pub(super) all_erased: bool,
}
thread_local! {
    static RETIREMENT: Cell<Option<Retirement>> = const { Cell::new(None) };
}

// Inspect only initialized storage while Drop still owns it; never read freed
// memory or publish secret bytes. The observer is per-thread and allocation-free.
pub(in crate::threshold_bls) fn observe_erased(
    values: &[DasRenSecretCoefficientV1; MAX_DEALER_COEFFICIENTS_V1],
    len: usize,
) {
    let _ = RETIREMENT.try_with(|slot| {
        if let Some(mut observed) = slot.get() {
            observed.drops += 1;
            observed.all_erased &=
                len == 0 && values.iter().flatten().flatten().all(|byte| *byte == 0);
            slot.set(Some(observed));
        }
    });
}

pub(super) fn observe_retirement<T>(work: impl FnOnce() -> T) -> (T, Retirement) {
    struct Restore(Option<Retirement>);
    impl Drop for Restore {
        fn drop(&mut self) {
            RETIREMENT.with(|slot| slot.set(self.0));
        }
    }
    let prior = RETIREMENT.with(|slot| {
        slot.replace(Some(Retirement {
            drops: 0,
            all_erased: true,
        }))
    });
    let restore = Restore(prior);
    let result = work();
    let observed = RETIREMENT.with(|slot| slot.get().expect("live erasure observer"));
    drop(restore);
    (result, observed)
}

// Test-local bridge for older independent vector fixtures. Production has no
// vector importer or alternate owner; the source Vec erases on every outcome.
pub(super) fn try_inline_coefficients(
    source: Zeroizing<Vec<DasRenSecretCoefficientV1>>,
) -> Result<DasRenSecretCoefficientsV1, ThresholdBlsError> {
    let mut values = Zeroizing::new([[[0; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]);
    for (target, original) in values.iter_mut().zip(source.iter()) {
        *target = *original;
    }
    let len = source.len();
    drop(source);
    DasRenSecretCoefficientsV1::new(values, len)
}

pub(super) fn inline_coefficients(
    source: Zeroizing<Vec<DasRenSecretCoefficientV1>>,
) -> DasRenSecretCoefficientsV1 {
    try_inline_coefficients(source).expect("test coefficients fit the v1 initialized owner")
}

#[test]
fn initialized_secret_prefix_checks_bounds_and_erases_every_physical_slot() {
    fn has_erasure_contract<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>() {}
    has_erasure_contract::<DasRenSecretCoefficientsV1>();
    for len in [0, 2, MAX_DEALER_COEFFICIENTS_V1] {
        let ((), observed) = observe_retirement(|| {
            without_allocations(|| {
                let mut owner = DasRenSecretCoefficientsV1::new(
                    Zeroizing::new([[[0xa7; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]),
                    len,
                )
                .unwrap();
                assert_eq!(owner.as_slice().len(), len);
                assert!(
                    owner
                        .as_slice()
                        .iter()
                        .flatten()
                        .flatten()
                        .all(|byte| *byte == 0xa7)
                );
                assert!(
                    owner.values[len..]
                        .iter()
                        .flatten()
                        .flatten()
                        .all(|byte| *byte == 0)
                );
                owner.zeroize();
                assert!(owner.as_slice().is_empty());
                assert!(
                    owner
                        .values
                        .iter()
                        .flatten()
                        .flatten()
                        .all(|byte| *byte == 0)
                );
                drop(owner);
            });
        });
        assert_eq!(observed.drops, 1);
        assert!(observed.all_erased);
    }
    let (result, observed) = observe_retirement(|| {
        without_allocations(|| {
            DasRenSecretCoefficientsV1::new(
                Zeroizing::new([[[0x5b; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]),
                MAX_DEALER_COEFFICIENTS_V1 + 1,
            )
            .map(|_| ())
        })
    });
    assert_eq!(result, Err(ThresholdBlsError::InvalidCoefficientCommitment));
    assert_eq!(observed.drops, 1);
    assert!(
        observed.all_erased,
        "rejected initialized backing is erased before return"
    );
}

#[test]
fn inline_secret_moves_and_unwind_retire_only_zeroized_live_storage() {
    fn move_owner(owner: DasRenSecretCoefficientsV1) -> DasRenSecretCoefficientsV1 {
        owner
    }
    let ((), observed) = observe_retirement(|| {
        without_allocations(|| {
            let original = DasRenSecretCoefficientsV1::new(
                Zeroizing::new([[[0x61; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]),
                2,
            )
            .unwrap();
            let retained = move_owner(original);
            assert_eq!(retained.len(), 2);
            drop(retained);
        });
        let unwound = std::panic::catch_unwind(|| {
            let _retained = DasRenSecretCoefficientsV1::new(
                Zeroizing::new([[[0x62; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]),
                MAX_DEALER_COEFFICIENTS_V1,
            )
            .unwrap();
            panic!("unwind the initialized bounded secret owner");
        });
        assert!(unwound.is_err());
    });
    assert_eq!(
        observed.drops, 2,
        "moves do not create another secret owner"
    );
    assert!(
        observed.all_erased,
        "normal and unwind drops erase live physical storage"
    );
}

#[test]
fn inline_secret_validation_and_partial_rng_failures_erase_original_slots() {
    fn check<P: ThresholdBlsPurpose>() {
        for n in [4, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1] {
            let parameters = parameters::<P>(n);
            for malformed_scalar in [false, true] {
                let mut source = coefficients(parameters.session().threshold(), 1);
                let index = u16::from(malformed_scalar);
                if malformed_scalar {
                    source[0][0] = [0xff; 32];
                }
                let reference_source = source.clone();
                let owner = inline_coefficients(source);
                let mut actual_rng = TrackedRng::new(0x63, None);
                let mut expected_rng = TrackedRng::new(0x63, None);
                let (actual, observed) = observe_retirement(|| {
                    without_allocations(|| {
                        DasRenDealerSecret::from_coefficients_with_rng(
                            &parameters,
                            index,
                            owner,
                            &mut actual_rng,
                        )
                        .map(|_| ())
                    })
                });
                let expected =
                    reference_import(&parameters, index, reference_source, &mut expected_rng)
                        .map(|_| ());
                assert_eq!(actual, expected);
                assert!(actual.is_err());
                assert_eq!(
                    (actual_rng.calls, actual_rng.bytes),
                    (expected_rng.calls, expected_rng.bytes)
                );
                assert_eq!(observed.drops, 1);
                assert!(observed.all_erased);
            }
            let mut complete_rng = TrackedRng::new(0x64, None);
            let complete = DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut complete_rng)
                .expect("successful reference request boundary");
            let last_request = complete_rng
                .calls
                .checked_sub(1)
                .expect("proof nonce request");
            drop(complete);
            for fail_after in [0, 1, 2, last_request] {
                let mut actual_rng = TrackedRng::new(0x64, Some(fail_after));
                let mut expected_rng = TrackedRng::new(0x64, Some(fail_after));
                let (actual, observed) = observe_retirement(|| {
                    without_allocations(|| {
                        DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut actual_rng)
                            .map(|_| ())
                    })
                });
                let expected = reference_generate(&parameters, 1, &mut expected_rng).map(|_| ());
                assert_eq!(actual, Err(ThresholdBlsError::RandomnessUnavailable));
                assert_eq!(actual, expected);
                assert_eq!(
                    (actual_rng.calls, actual_rng.bytes),
                    (expected_rng.calls, expected_rng.bytes)
                );
                assert_eq!(actual_rng.calls, fail_after + 1);
                assert_eq!(observed.drops, 1);
                assert!(
                    observed.all_erased,
                    "partial coefficients and proof-nonce refusal erase the owner"
                );
            }
        }
    }
    check::<BeaconPurpose>();
    check::<TleReleasePurpose>();
}
