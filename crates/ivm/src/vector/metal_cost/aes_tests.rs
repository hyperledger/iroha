//! Exact CPU fallback identity and local calibration-change controls.

use super::*;
use crate::aes::cpu::{Backend, Direction};
use crate::vector::SimdChoice;

// Pure cost fixtures must not observe another test's pending/admitted native
// transition. The thread-local scalar baseline keeps the production identity
// gate active and restores the original override on every exit.
pub(super) struct ScalarOverride(Option<SimdChoice>);
impl ScalarOverride {
    pub(super) fn new() -> Self {
        Self(super::super::set_thread_forced_simd(Some(
            SimdChoice::Scalar,
        )))
    }
}
impl Drop for ScalarOverride {
    fn drop(&mut self) {
        super::super::set_thread_forced_simd(self.0);
    }
}

#[test]
fn measured_cpu_traversal_matches_ordered_fallback_without_replacing_storage() {
    let _forced = ScalarOverride::new();
    let original: [[u8; 16]; 5] =
        std::array::from_fn(|block| std::array::from_fn(|lane| (block * 17 + lane) as u8));
    let keys: [[u8; 16]; 9] = std::array::from_fn(|round| {
        std::array::from_fn(|lane| {
            (round as u8)
                .wrapping_mul(19)
                .wrapping_add(lane as u8)
                .wrapping_add(11)
        })
    });
    for (decrypt, direction) in [(false, Direction::Encrypt), (true, Direction::Decrypt)] {
        for rounds in [0, 1, 9] {
            let mut destination = original;
            let pointer = destination.as_ptr();
            let expected: Vec<_> = original
                .iter()
                .map(|block| {
                    keys[..rounds]
                        .iter()
                        .fold(*block, |state, key| direction.scalar(state, *key))
                })
                .collect();
            assert_eq!(
                crate::aes::cpu::measure_backend(direction, Backend::Scalar, || {
                    crate::aes::rounds_cpu_in_place(&mut destination, &keys[..rounds], decrypt)
                }),
                Some(())
            );
            assert_eq!(destination.as_slice(), expected);
            assert_eq!(destination.as_ptr(), pointer);
        }
    }
}

#[test]
fn retained_work_defines_every_direction_round_count_and_fused_pipeline() {
    for (work, direction, decrypt, fused, rounds) in [
        (MetalBatchWork::Encrypt, Direction::Encrypt, false, false, 1),
        (MetalBatchWork::Decrypt, Direction::Decrypt, true, false, 1),
        (
            MetalBatchWork::EncryptRounds(9),
            Direction::Encrypt,
            false,
            true,
            9,
        ),
        (
            MetalBatchWork::DecryptRounds(64),
            Direction::Decrypt,
            true,
            true,
            64,
        ),
    ] {
        assert_eq!(work.direction(), direction);
        assert_eq!(work.decrypt(), decrypt);
        assert_eq!(work.fused(), fused);
        assert_eq!(work.rounds(), rounds);
    }
}

#[test]
fn qualified_owner_can_sample_aes_without_production_receipts() {
    if !super::super::metal_available() {
        return;
    }
    // A loaded host can miss the bounded deadline; CPU remains the valid
    // path and a later attempt may retry. Parity faults disable Metal.
    let _ = super::super::select_metal_batch(MetalBatchWork::Encrypt, 2_048);
    assert!(super::super::metal_parity_ok());
}
